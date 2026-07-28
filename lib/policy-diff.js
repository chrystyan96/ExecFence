'use strict';

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { configFileName, resolveProjectPath } = require('./paths');
const { loadConfig } = require('./config');
const { resolvePolicy } = require('./policy');

const highRiskPaths = /^(?:mode|policyPack|blockSeverities|allowExecutables|workflowHardening|archiveAudit|runtimeTrace|ci|manifest|supplyChain|deps|policy|approvals|trustStore|baselineFile|signaturesFile|sandboxFile|redaction)/;

function diffPolicy(cwd = process.cwd(), options = {}) {
  const root = path.resolve(cwd);
  const baseRef = options.baseRef || 'HEAD';
  const currentRaw = stripRuntimeConfig(loadConfig(root).config || {});
  const previousRaw = readConfigAtRef(root, baseRef);
  const currentEffective = resolvePolicy(root, currentRaw).config;
  const previousEffective = previousRaw ? resolvePolicy(root, previousRaw).config : null;
  if (!previousRaw) {
    const policyFiles = diffPolicyFiles(root, baseRef, currentRaw, previousRaw);
    const introduced = Object.keys(currentRaw).length > 0;
    const findings = [
      ...(introduced ? [{
        id: 'policy-config-introduced',
        severity: 'high',
        file: configFileName,
        line: 1,
        detail: 'ExecFence policy config was introduced relative to the base ref and requires review.',
        change: { path: '$', before: null, after: currentRaw },
      }] : []),
      ...policyFiles.map((change) => ({
        id: 'policy-controlled-file-change',
        severity: 'high',
        file: change.file,
        line: 1,
        detail: `Security policy/trust file ${change.file} was ${change.changeType}.`,
        change,
      })),
    ];
    return withPolicyHash({
      cwd: root,
      baseRef,
      ok: findings.length === 0,
      bootstrapped: findings.length === 0,
      changes: policyFiles,
      findings,
      current: currentEffective,
      previous: null,
    });
  }
  const changes = [];
  collectChanges(previousEffective, currentEffective, '', changes);
  const relevant = changes.filter((change) => !/^(?:cwd|customPolicyPath|externalSignatures|signaturesPath)$/.test(change.path));
  const findings = relevant
    .filter((change) => highRiskPaths.test(change.path))
    .map((change) => ({
      id: 'policy-security-sensitive-change',
      severity: 'high',
      file: configFileName,
      line: 1,
      detail: `Security-sensitive policy field ${change.path} changed from ${display(change.before)} to ${display(change.after)}.`,
      change,
    }));
  const policyFiles = diffPolicyFiles(root, baseRef, currentRaw, previousRaw);
  for (const change of policyFiles) {
    findings.push({
      id: 'policy-controlled-file-change',
      severity: 'high',
      file: change.file,
      line: 1,
      detail: `Security policy/trust file ${change.file} was ${change.changeType}.`,
      change,
    });
  }
  return withPolicyHash({
    cwd: root,
    baseRef,
    ok: findings.length === 0,
    bootstrapped: false,
    changes: [...relevant, ...policyFiles],
    findings,
    current: currentEffective,
    previous: previousEffective,
  });
}

function withPolicyHash(result) {
  const value = {
    baseRef: result.baseRef,
    changes: result.changes || [],
    current: result.current || null,
  };
  return {
    ...result,
    contentHash: crypto.createHash('sha256').update(stableStringify(value)).digest('hex'),
  };
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function diffPolicyFiles(cwd, ref, currentConfig = {}, previousConfig = {}) {
  const currentFiles = currentPolicyFiles(cwd, currentConfig);
  const previousFiles = refPolicyFiles(cwd, ref, previousConfig);
  const files = Array.from(new Set([...currentFiles, ...previousFiles]))
    .filter((file) => file !== configFileName)
    .sort();
  const changes = [];
  for (const file of files) {
    const before = readFileAtRef(cwd, ref, file);
    const currentPath = path.resolve(cwd, file);
    const after = fs.existsSync(currentPath) && fs.statSync(currentPath).isFile()
      ? normalizePolicyContent(fs.readFileSync(currentPath, 'utf8'))
      : null;
    if (before === after) continue;
    changes.push({
      path: `file:${file}`,
      file,
      changeType: before == null ? 'added' : (after == null ? 'removed' : 'changed'),
      before,
      after,
    });
  }
  return changes;
}

function currentPolicyFiles(cwd, config = {}) {
  config ||= {};
  const directories = ['.execfence/config', '.execfence/trust', config.policy?.customPoliciesDir]
    .filter(Boolean);
  const files = directories.flatMap((directory) => {
    const relative = policyRelativePath(directory);
    if (!relative) return [];
    try {
      return walkJsonFiles(cwd, resolveProjectPath(cwd, relative));
    } catch {
      return [];
    }
  });
  for (const configured of configuredPolicyFiles(config)) {
    const relative = policyRelativePath(configured);
    if (!relative) continue;
    try {
      const fullPath = resolveProjectPath(cwd, relative);
      if (fs.existsSync(fullPath)) files.push(relative);
    } catch {
      // Config validation reports paths that escape the project.
    }
  }
  return Array.from(new Set(files));
}

function walkJsonFiles(cwd, directory) {
  if (!fs.existsSync(directory)) return [];
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walkJsonFiles(cwd, fullPath));
    else if (entry.isFile() && entry.name.endsWith('.json')) files.push(path.relative(cwd, fullPath).replaceAll(path.sep, '/'));
  }
  return files;
}

function refPolicyFiles(cwd, ref, config = {}) {
  config ||= {};
  const directories = ['.execfence/config', '.execfence/trust', config.policy?.customPoliciesDir]
    .map(policyRelativePath)
    .filter(Boolean);
  try {
    const files = execFileSync('git', ['ls-tree', '-r', '--name-only', ref, '--', ...directories], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).split(/\r?\n/).map((file) => file.trim().replaceAll('\\', '/')).filter((file) => file.endsWith('.json'));
    for (const configured of configuredPolicyFiles(config)) {
      const relative = policyRelativePath(configured);
      if (relative && readFileAtRef(cwd, ref, relative) != null) files.push(relative);
    }
    return Array.from(new Set(files));
  } catch {
    return configuredPolicyFiles(config).map(policyRelativePath).filter(Boolean)
      .filter((file) => readFileAtRef(cwd, ref, file) != null);
  }
}

function configuredPolicyFiles(config = {}) {
  config ||= {};
  return [
    config.baselineFile,
    config.signaturesFile,
    config.sandboxFile,
    config.approvals?.path,
    config.approvals?.approversPath,
    ...Object.values(config.trustStore || {}),
  ].filter(Boolean);
}

function policyRelativePath(value) {
  const normalized = String(value || '').replaceAll('\\', '/').replace(/^\.\//, '');
  if (!normalized || path.posix.isAbsolute(normalized) || path.win32.isAbsolute(normalized) || normalized === '..' || normalized.startsWith('../') || normalized.includes('/../')) {
    return null;
  }
  return path.posix.normalize(normalized);
}

function readFileAtRef(cwd, ref, file) {
  try {
    const content = execFileSync('git', ['show', `${ref}:${file}`], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return normalizePolicyContent(content);
  } catch {
    return null;
  }
}

function normalizePolicyContent(content) {
  try {
    return JSON.stringify(JSON.parse(content));
  } catch {
    return String(content);
  }
}

function readConfigAtRef(cwd, ref) {
  try {
    return JSON.parse(execFileSync('git', ['show', `${ref}:${configFileName}`], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }));
  } catch {
    return null;
  }
}

function collectChanges(before, after, prefix, changes) {
  if (deepEqual(before, after)) return;
  if (isObject(before) && isObject(after)) {
    for (const key of Array.from(new Set([...Object.keys(before), ...Object.keys(after)])).sort()) {
      collectChanges(before[key], after[key], prefix ? `${prefix}.${key}` : key, changes);
    }
    return;
  }
  changes.push({ path: prefix || '$', before, after });
}

function stripRuntimeConfig(config) {
  const { externalSignatures, signaturesPath, cwd, customPolicyPath, ...rest } = config;
  return rest;
}

function display(value) {
  const text = JSON.stringify(value);
  return text && text.length > 240 ? `${text.slice(0, 237)}...` : (text ?? 'undefined');
}

function deepEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

module.exports = {
  diffPolicy,
};
