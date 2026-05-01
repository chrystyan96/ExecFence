'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { loadConfig } = require('./config');
const { exactSignatures, regexSignatures } = require('./signatures');

const defaultRoots = ['backend-go', 'backend', 'frontend', 'desktop', 'packages', 'scripts', '.github', '.vscode'];
const defaultIgnoredDirectories = new Set([
  '.angular',
  '.git',
  '.next',
  '.nuxt',
  '.omx',
  '.pytest_cache',
  '.turbo',
  'bin',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'out',
  'playwright-report',
  'target',
  'test-results',
  'vendor',
  'visual-checks',
]);
const defaultSkippedFileNames = new Set([
  'security-malware-guard.cjs',
  'security-guardrails.js',
  'malware_guard_test.go',
]);
const executableExtensions = new Set(['.bat', '.cmd', '.com', '.dll', '.exe', '.scr', '.vbs', '.wsf']);
const maxTextFileBytes = 5 * 1024 * 1024;
const lockfileTextNames = new Set([
  'bun.lock',
  'bun.lockb',
  'Cargo.lock',
  'go.sum',
  'pnpm-lock.yaml',
  'poetry.lock',
  'uv.lock',
  'yarn.lock',
]);

const ruleMetadata = {
  'allowed-executable-hash-mismatch': { severity: 'high', description: 'An executable allowlist entry matched the path but not the expected SHA-256 hash.' },
  'executable-artifact-in-source-tree': { severity: 'high', description: 'Executable artifacts in source/build-input folders can run attacker-controlled code.' },
  'insecure-lockfile-url': { severity: 'high', description: 'Lockfiles resolving artifacts over HTTP allow network tampering.' },
  'lockfile-suspicious-host': { severity: 'medium', description: 'Lockfiles resolving from paste/raw hosts should be reviewed before build.' },
  'long-obfuscated-javascript-line': { severity: 'critical', description: 'Very long JavaScript lines with loader markers are common in injected payloads.' },
  'suspicious-lockfile-url': { severity: 'medium', description: 'Lockfiles resolving from paste/raw hosts should be reviewed before build.' },
  'suspicious-package-script': { severity: 'high', description: 'Lifecycle scripts that download or evaluate code run during install/build.' },
};

function scan(options = {}) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const loaded = loadConfig(cwd, options.configPath);
  const config = { ...loaded.config, ...(options.config || {}) };
  const roots = normalizeRoots(cwd, options.roots || config.roots);
  const selfPackage = isSecurityGuardrailsPackage(cwd);
  const mode = options.mode || config.mode || 'block';
  if (!['audit', 'block'].includes(mode)) {
    throw new Error(`Invalid security-guardrails mode: ${mode}`);
  }
  const blockSeverities = new Set(config.blockSeverities || ['critical', 'high']);
  const findings = [];

  for (const root of roots) {
    walk(root, cwd, findings, { ...options, config, selfPackage });
  }

  return {
    cwd,
    configPath: loaded.configPath,
    mode,
    roots,
    findings,
    blockedFindings: findings.filter((item) => mode !== 'audit' && blockSeverities.has(item.severity || 'high')),
    ok: mode === 'audit' || findings.every((item) => !blockSeverities.has(item.severity || 'high')),
  };
}

function normalizeRoots(cwd, roots) {
  const requested = roots && roots.length > 0 ? roots : defaultRoots;
  const resolved = [];
  for (const root of requested) {
    const fullPath = path.resolve(cwd, root);
    if (fs.existsSync(fullPath)) {
      resolved.push(fullPath);
    }
  }
  if (resolved.length === 0) {
    resolved.push(cwd);
  }
  return resolved;
}

function walk(root, cwd, findings, options) {
  if (!fs.existsSync(root)) {
    return;
  }
  const stat = fs.statSync(root);
  if (stat.isFile()) {
    scanFile(root, cwd, findings, options);
    return;
  }

  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (isIgnoredDirectory(entry.name, options)) {
        continue;
      }
      walk(fullPath, cwd, findings, options);
      continue;
    }
    if (entry.isFile()) {
      scanFile(fullPath, cwd, findings, options);
    }
  }
}

function scanFile(filePath, cwd, findings, options) {
  const baseName = path.basename(filePath);
  const skipFiles = new Set([...(options.config?.skipFiles || []), ...(options.skipFiles || [])]);
  if (defaultSkippedFileNames.has(baseName) || skipFiles.has(baseName)) {
    return;
  }
  if (options.selfPackage && isSelfPackageFixture(cwd, filePath)) {
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  if (executableExtensions.has(ext)) {
    const allowed = executableAllowStatus(cwd, filePath, options.config);
    if (allowed.ok) {
      return;
    }
    if (allowed.reason === 'hash-mismatch') {
      findings.push(finding('allowed-executable-hash-mismatch', cwd, filePath, 1, `Executable hash ${allowed.actual} does not match allowlist SHA-256 ${allowed.expected}.`));
      return;
    }
    findings.push(finding('executable-artifact-in-source-tree', cwd, filePath, 1, `Executable artifact with ${ext} extension is not allowed in source/build inputs.`));
    return;
  }

  const stat = fs.statSync(filePath);
  if (stat.size > maxTextFileBytes) {
    return;
  }

  const buffer = fs.readFileSync(filePath);
  if (buffer.includes(0)) {
    return;
  }

  const content = buffer.toString('utf8');
  const configuredExactSignatures = [
    ...exactSignatures,
    ...(options.config?.extraSignatures || []).map((signature, index) => [`config-extra-signature-${index + 1}`, signature]),
    ...normalizeExternalExactSignatures(options.config?.externalSignatures),
  ];
  const configuredRegexSignatures = [
    ...regexSignatures,
    ...(options.config?.extraRegexSignatures || []).map((signature, index) => [`config-extra-regex-${index + 1}`, new RegExp(signature)]),
    ...normalizeExternalRegexSignatures(options.config?.externalSignatures),
  ];
  for (const [id, signature] of configuredExactSignatures) {
    const index = content.indexOf(signature);
    if (index >= 0) {
      findings.push(finding(id, cwd, filePath, lineNumberFor(content, index), `Matched ${signature}`));
    }
  }

  for (const [id, pattern] of configuredRegexSignatures) {
    const match = pattern.exec(content);
    if (match?.index >= 0) {
      findings.push(finding(id, cwd, filePath, lineNumberFor(content, match.index), `Matched ${pattern}`));
    }
  }

  if (baseName === 'package.json') {
    auditPackageScripts(cwd, filePath, content, findings, options.config);
  }
  if (baseName === 'package-lock.json' || baseName === 'npm-shrinkwrap.json') {
    auditNpmLockfile(cwd, filePath, content, findings);
  }
  if (lockfileTextNames.has(baseName)) {
    auditTextLockfile(cwd, filePath, content, findings);
  }

  const lines = content.split(/\r?\n/);
  lines.forEach((line, index) => {
    if (line.length < 2000) {
      return;
    }
    if (/String\.fromCharCode\(127\)|global\[[^\]]+\]\s*=\s*require|var\s+_\$_[A-Za-z0-9_]+/.test(line)) {
      findings.push(finding('long-obfuscated-javascript-line', cwd, filePath, index + 1, 'Very long line contains obfuscated JavaScript loader markers.'));
    }
  });
}

function isSecurityGuardrailsPackage(cwd) {
  const packagePath = path.join(cwd, 'package.json');
  if (!fs.existsSync(packagePath)) {
    return false;
  }
  try {
    return JSON.parse(fs.readFileSync(packagePath, 'utf8')).name === 'security-guardrails';
  } catch {
    return false;
  }
}

function isSelfPackageFixture(cwd, filePath) {
  const rel = path.relative(cwd, filePath).replaceAll(path.sep, '/');
  return rel === 'README.md' ||
    rel === 'lib/signatures.js' ||
    rel === 'skill/security-guardrails/SKILL.md' ||
    rel.startsWith('test/');
}

function isIgnoredDirectory(name, options = {}) {
  if (defaultIgnoredDirectories.has(name) || name.startsWith('target-')) {
    return true;
  }
  return Boolean((options.config?.ignoreDirs || []).includes(name) || (options.ignoreDirs || []).includes(name));
}

function lineNumberFor(content, index) {
  return content.slice(0, index).split(/\r?\n/).length;
}

function finding(id, cwd, filePath, line, detail, severity) {
  const metadata = ruleMetadata[id] || {};
  return {
    id,
    severity: severity || metadata.severity || 'high',
    file: path.relative(cwd, filePath).replaceAll(path.sep, '/'),
    line,
    detail,
  };
}

function formatFindings(findings) {
  if (findings.length === 0) {
    return '[security-guardrails] OK';
  }
  return [
    '[security-guardrails] Suspicious artifact(s) blocked:',
    ...findings.map((item) => `- ${item.id}: ${item.file}:${item.line} - ${item.detail}`),
  ].join('\n');
}

function executableAllowStatus(cwd, filePath, config = {}) {
  const rel = path.relative(cwd, filePath).replaceAll(path.sep, '/');
  for (const allowed of config.allowExecutables || []) {
    if (typeof allowed === 'string') {
      if (rel === allowed || rel.endsWith(`/${allowed}`)) {
        return { ok: true };
      }
      continue;
    }
    const allowedPath = allowed.path || allowed.file;
    if (!allowedPath || (rel !== allowedPath && !rel.endsWith(`/${allowedPath}`))) {
      continue;
    }
    if (!allowed.sha256) {
      return { ok: true };
    }
    const actual = sha256File(filePath);
    if (actual === String(allowed.sha256).toLowerCase()) {
      return { ok: true };
    }
    return { ok: false, reason: 'hash-mismatch', actual, expected: String(allowed.sha256).toLowerCase() };
  }
  return { ok: false };
}

function auditPackageScripts(cwd, filePath, content, findings, config = {}) {
  let pkg;
  try {
    pkg = JSON.parse(content);
  } catch {
    return;
  }
  const scripts = pkg.scripts || {};
  const lifecycleScripts = new Set(['preinstall', 'install', 'postinstall', 'prepare']);
  const suspicious = [
    /\b(?:curl|wget)\b/i,
    /\bpowershell\b|\bInvoke-WebRequest\b|\biwr\b/i,
    /\bnode\s+-e\b/i,
    /\beval\s*\(/i,
    /\b(?:base64|atob|certutil)\b/i,
    /\b(?:bash|sh)\s+-c\b/i,
    /\bchild_process\b/i,
  ];
  for (const [name, command] of Object.entries(scripts)) {
    if (!config.auditAllPackageScripts && !lifecycleScripts.has(name)) {
      continue;
    }
    for (const pattern of suspicious) {
      if (pattern.test(String(command))) {
        findings.push(finding(
          'suspicious-package-script',
          cwd,
          filePath,
          lineNumberFor(content, content.indexOf(`"${name}"`)),
          `Suspicious package script "${name}" matches ${pattern}: ${command}`,
        ));
      }
    }
  }
}

function auditNpmLockfile(cwd, filePath, content, findings) {
  let lockfile;
  try {
    lockfile = JSON.parse(content);
  } catch {
    return;
  }
  const packages = lockfile.packages || {};
  for (const [name, entry] of Object.entries(packages)) {
    const resolved = String(entry?.resolved || '');
    if (resolved.startsWith('http://')) {
      findings.push(finding('insecure-lockfile-url', cwd, filePath, lineNumberFor(content, content.indexOf(resolved)), `Package ${name || '<root>'} resolves over insecure HTTP: ${resolved}`));
    }
    if (/pastebin\.com|gist\.githubusercontent\.com|raw\.githubusercontent\.com/i.test(resolved)) {
      findings.push(finding('suspicious-lockfile-url', cwd, filePath, lineNumberFor(content, content.indexOf(resolved)), `Package ${name || '<root>'} resolves from a suspicious host: ${resolved}`));
    }
  }
}

function auditTextLockfile(cwd, filePath, content, findings) {
  const insecure = /http:\/\/[^\s"'<>]+/gi;
  const suspicious = /https?:\/\/[^\s"'<>]*(?:pastebin\.com|gist\.githubusercontent\.com|raw\.githubusercontent\.com)[^\s"'<>]*/gi;
  for (const pattern of [insecure, suspicious]) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const id = match[0].startsWith('http://') ? 'insecure-lockfile-url' : 'lockfile-suspicious-host';
      findings.push(finding(id, cwd, filePath, lineNumberFor(content, match.index), `Lockfile contains ${match[0]}`));
    }
  }
}

function normalizeExternalExactSignatures(external = {}) {
  return normalizeExternalSignatures(external.exact || external.exactSignatures || []);
}

function normalizeExternalRegexSignatures(external = {}) {
  return normalizeExternalSignatures(external.regex || external.regexSignatures || [], { regex: true });
}

function normalizeExternalSignatures(entries, options = {}) {
  return (entries || []).map((entry, index) => {
    if (typeof entry === 'string') {
      return [options.regex ? `external-regex-signature-${index + 1}` : `external-exact-signature-${index + 1}`, options.regex ? new RegExp(entry) : entry];
    }
    const id = entry.id || (options.regex ? `external-regex-signature-${index + 1}` : `external-exact-signature-${index + 1}`);
    const value = entry.value || entry.signature || entry.pattern;
    return [id, options.regex ? new RegExp(value) : value];
  }).filter(([, value]) => value);
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

module.exports = {
  defaultRoots,
  ruleMetadata,
  scan,
  formatFindings,
};
