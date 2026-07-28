'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { sha256File } = require('./baseline');
const { depsDiff } = require('./deps');
const { loadConfig } = require('./config');
const { resolveProjectPath } = require('./paths');

const dangerousPackExtensions = new Set(['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.wsf', '.asar']);
const suspiciousPackExtensions = new Set(['.ps1', '.sh', '.jar', '.node', '.so', '.dylib']);

function packAudit(cwd = process.cwd()) {
  const packagePath = path.join(cwd, 'package.json');
  if (!fs.existsSync(packagePath)) {
    return { cwd, ok: true, skipped: 'package.json not found', files: [], findings: [] };
  }
  const findings = [];
  let files = [];
  let packListSource = 'npm';
  try {
    const output = npmPackDryRun(cwd);
    const parsed = JSON.parse(output);
    files = (Array.isArray(parsed) ? parsed[0]?.files : parsed.files) || [];
  } catch (error) {
    files = fallbackPackFiles(cwd);
    packListSource = 'fallback';
  }
  for (const file of files) {
    const name = file.path || file.name || '';
    const ext = path.extname(name).toLowerCase();
    const filePath = path.join(cwd, name);
    if (dangerousPackExtensions.has(ext)) {
      findings.push({ id: 'pack-dangerous-artifact', severity: 'high', file: name, line: 1, detail: `Packed artifact includes ${ext} file.` });
    }
    if (suspiciousPackExtensions.has(ext)) {
      findings.push({ id: 'pack-suspicious-artifact', severity: 'medium', file: name, line: 1, detail: `Packed artifact includes executable-adjacent ${ext} file.` });
    }
    if (path.basename(name).startsWith('.') && !/^\.(npmignore|gitignore)$/.test(path.basename(name))) {
      findings.push({ id: 'pack-hidden-file', severity: 'medium', file: name, line: 1, detail: 'Package includes a hidden file.' });
    }
    if (Number(file.size || 0) > 1024 * 1024) {
      findings.push({ id: 'pack-large-file', severity: 'medium', file: name, line: 1, detail: `Package includes large file (${file.size} bytes).` });
    }
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const content = safeReadPrefix(filePath);
      if (/^#!.*(?:node|bash|sh|python|powershell)/.test(content) && !/^bin\//.test(name)) {
        findings.push({ id: 'pack-shebang-outside-bin', severity: 'medium', file: name, line: 1, detail: 'Package includes executable shebang outside bin/.' });
      }
      if (isCodeLikePackedFile(name) && isObfuscated(content)) {
        findings.push({ id: 'pack-obfuscated-file', severity: 'high', file: name, line: 1, detail: 'Package includes file with obfuscation-like content.' });
      }
    }
    if (/\.execfence\/reports\//.test(name)) {
      findings.push({ id: 'pack-includes-execfence-report', severity: 'medium', file: name, line: 1, detail: 'Package includes ExecFence report output.' });
    }
  }
  findings.push(...packageJsonFindings(cwd));
  return { cwd, ok: findings.filter((finding) => finding.severity === 'high').length === 0, files, findings, packListSource };
}

function lockfileDiff(cwd = process.cwd(), options = {}) {
  return depsDiff(cwd, { baseRef: options.baseRef || 'HEAD' });
}

function trustAdd(cwd, target, metadata = {}) {
  if (!target) {
    throw new Error('Usage: execfence trust add <path|registry|action|scope> --type file|registry|action|package-scope --reason <reason> --owner <owner> --expires-at <date>');
  }
  const type = metadata.type || inferTrustType(target, cwd);
  const trustPath = trustFilePath(cwd, type);
  const trust = readJson(trustPath, defaultTrust(type));
  const entry = trustEntry(cwd, target, type, metadata);
  const collection = trustCollection(type);
  trust[collection] = (trust[collection] || []).filter((item) => trustIdentity(item, type) !== trustIdentity(entry, type));
  trust[collection].push(entry);
  fs.mkdirSync(path.dirname(trustPath), { recursive: true });
  fs.writeFileSync(trustPath, `${JSON.stringify(trust, null, 2)}\n`);
  return { filePath: trustPath, type, entry };
}

function trustAudit(cwd = process.cwd()) {
  const findings = [];
  const audited = [];
  for (const type of ['file', 'registry', 'action', 'package-scope', 'package-source']) {
    const trustPath = trustFilePath(cwd, type);
    const trust = readJson(trustPath, defaultTrust(type));
    const collection = trustCollection(type);
    audited.push({ type, filePath: trustPath, entries: (trust[collection] || []).length });
    for (const entry of trust[collection] || []) {
      if (entry.expiresAt && new Date(entry.expiresAt).getTime() < Date.now()) {
        findings.push({ id: `${type}-trust-expired`, severity: 'medium', file: relativeTrustFile(trustPath), line: 1, detail: `Trust entry expired at ${entry.expiresAt}.`, entry });
      }
      if (type === 'file') {
        let filePath;
        try {
          filePath = resolveProjectPath(cwd, entry.path);
        } catch (error) {
          findings.push({ id: 'trusted-file-path-escapes-project', severity: 'high', file: relativeTrustFile(trustPath), line: 1, detail: error.message });
          continue;
        }
        if (!fs.existsSync(filePath)) {
          findings.push({ id: 'trusted-file-missing', severity: 'medium', file: entry.path, line: 1, detail: 'Trusted file no longer exists.' });
          continue;
        }
        const actual = sha256File(filePath);
        if (entry.sha256 && actual !== String(entry.sha256).toLowerCase()) {
          findings.push({ id: 'trusted-file-hash-mismatch', severity: 'high', file: entry.path, line: 1, detail: 'Trusted file hash changed.' });
        }
      }
    }
  }
  return { cwd, ok: !findings.some((finding) => finding.severity === 'high'), findings, audited };
}

function packageJsonFindings(cwd) {
  const packagePath = path.join(cwd, 'package.json');
  const findings = [];
  if (!fs.existsSync(packagePath)) {
    return findings;
  }
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  } catch {
    return findings;
  }
  for (const [name, command] of Object.entries(pkg.scripts || {})) {
    if (/^(pre|post)?(?:install|prepare|pack|publish)$/.test(name) && /curl|wget|Invoke-WebRequest|powershell|bash|sh|node\s+-e|eval/i.test(command)) {
      findings.push({ id: 'pack-lifecycle-script-risk', severity: 'high', file: 'package.json', line: 1, detail: `Package lifecycle script ${name} executes risky command: ${command}` });
    }
  }
  for (const [name, target] of Object.entries(pkg.bin || {})) {
    let filePath;
    try {
      filePath = resolveProjectPath(cwd, target);
    } catch (error) {
      findings.push({ id: 'pack-bin-entry-escapes-project', severity: 'high', file: 'package.json', line: 1, detail: `Package bin ${name} is unsafe: ${error.message}` });
      continue;
    }
    if (!fs.existsSync(filePath)) {
      findings.push({ id: 'pack-bin-entry-missing', severity: 'medium', file: 'package.json', line: 1, detail: `Package bin ${name} points to missing file ${target}.` });
    }
  }
  return findings;
}

function trustEntry(cwd, target, type, metadata) {
  const common = {
    reason: metadata.reason || 'trusted by user',
    owner: metadata.owner || 'unknown',
    expiresAt: metadata.expiresAt || metadata['expires-at'] || '2999-01-01',
    addedAt: new Date().toISOString(),
  };
  if (type === 'file') {
    const filePath = resolveProjectPath(cwd, target);
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${target}`);
    }
    return {
      ...common,
      path: path.relative(cwd, filePath).replaceAll(path.sep, '/'),
      sha256: sha256File(filePath),
    };
  }
  if (type === 'registry') {
    return { ...common, registry: target };
  }
  if (type === 'action') {
    return { ...common, action: target };
  }
  if (type === 'package-scope') {
    return { ...common, scope: target };
  }
  if (type === 'package-source') {
    return { ...common, source: target };
  }
  throw new Error(`Unknown trust type: ${type}`);
}

function inferTrustType(target, cwd = process.cwd()) {
  let projectFile = null;
  try {
    projectFile = resolveProjectPath(cwd, target);
  } catch {
    projectFile = null;
  }
  if (projectFile && fs.existsSync(projectFile)) {
    return 'file';
  }
  if (/^https?:\/\//.test(target) || /^[a-z0-9.-]+\.[a-z]{2,}/i.test(target)) {
    return 'registry';
  }
  if (/^[^/]+\/[^/]+(@[A-Fa-f0-9]{40})?$/.test(target)) {
    return 'action';
  }
  if (/^@/.test(target)) {
    return 'package-scope';
  }
  return 'file';
}

function trustFilePath(cwd, type) {
  const configured = loadConfig(cwd).config?.trustStore || {};
  const relative = {
    file: configured.files || '.execfence/trust/files.json',
    registry: configured.registries || '.execfence/trust/registries.json',
    action: configured.actions || '.execfence/trust/actions.json',
    'package-scope': configured.packageScopes || '.execfence/trust/package-scopes.json',
    'package-source': configured.packageSources || '.execfence/trust/package-sources.json',
  }[type] || `.execfence/trust/${type}.json`;
  return resolveProjectPath(cwd, relative);
}

function defaultTrust(type) {
  return { [trustCollection(type)]: [] };
}

function trustCollection(type) {
  return {
    file: 'files',
    registry: 'registries',
    action: 'actions',
    'package-scope': 'packageScopes',
    'package-source': 'packageSources',
  }[type] || 'entries';
}

function trustIdentity(entry, type) {
  return entry.path || entry.registry || entry.action || entry.scope || entry.source || JSON.stringify(entry);
}

function relativeTrustFile(filePath) {
  return filePath.replaceAll('\\', '/').replace(/^.*?\.execfence\//, '.execfence/');
}

function safeReadPrefix(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8').slice(0, 200000);
  } catch {
    return '';
  }
}

function isObfuscated(content) {
  const hasLoaderPrimitive = /eval\s*\(|Function\s*\(|fromCharCode|atob\s*\(/i.test(content);
  const hasEncodedBlob = /\\x[0-9a-f]{2}|[A-Za-z0-9+/]{800,}={0,2}/i.test(content);
  const hasLongCodeLine = content.split(/\r?\n/).some((line) => line.length > 2000 && /[;{}()[\]]/.test(line));
  return hasLoaderPrimitive && (hasEncodedBlob || hasLongCodeLine);
}

function isCodeLikePackedFile(name) {
  return /\.(?:cjs|js|jsx|mjs|ts|tsx)$/i.test(name) || /^bin\//.test(name);
}

function readJson(filePath, fallback) {
  if (!fs.existsSync(filePath)) {
    return fallback;
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function resolveCommand(command) {
  if (process.platform !== 'win32') {
    return command;
  }
  try {
    return execFileSync('where', [`${command}.cmd`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      .split(/\r?\n/)
      .find(Boolean) || command;
  } catch {
    return command;
  }
}

function npmPackDryRun(cwd) {
  if (process.platform !== 'win32') {
    return execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  }
  const npm = resolveCommand('npm');
  return execFileSync('powershell.exe', ['-NoProfile', '-Command', `& ${JSON.stringify(npm)} pack --dry-run --json`], {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function fallbackPackFiles(cwd) {
  const pkg = readJson(path.join(cwd, 'package.json'), {});
  const selected = new Set(['package.json']);
  for (const name of fs.readdirSync(cwd)) {
    if (/^(?:README|CHANGELOG|LICENSE|LICENCE|NOTICE)(?:\.|$)/i.test(name)) {
      selected.add(name);
    }
  }
  for (const target of Object.values(pkg.bin || {})) {
    selected.add(String(target).replaceAll('\\', '/'));
  }
  const declaredFiles = Array.isArray(pkg.files) ? pkg.files : [];
  if (declaredFiles.length === 0) {
    for (const file of walkPackFiles(cwd)) selected.add(file);
  }
  for (const pattern of declaredFiles) {
    const normalized = String(pattern).replace(/^\.\//, '').replaceAll('\\', '/');
    const base = normalized.split(/[*?[\]]/)[0].replace(/\/$/, '');
    const candidate = path.join(cwd, base || '.');
    if (base && fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      selected.add(base);
      continue;
    }
    if (base && fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) {
      for (const file of walkPackFiles(candidate)) {
        selected.add(`${base}/${file}`.replaceAll('\\', '/'));
      }
      continue;
    }
    const regex = globRegex(normalized);
    for (const file of walkPackFiles(cwd)) {
      if (regex.test(file)) selected.add(file);
    }
  }
  return Array.from(selected)
    .filter((name) => fs.existsSync(path.join(cwd, name)) && fs.statSync(path.join(cwd, name)).isFile())
    .map((name) => ({ path: name, size: fs.statSync(path.join(cwd, name)).size }))
    .sort((a, b) => a.path.localeCompare(b.path));
}

function walkPackFiles(root, current = root, files = []) {
  for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
    if (entry.isDirectory() && ['.git', '.execfence', 'node_modules'].includes(entry.name)) continue;
    const fullPath = path.join(current, entry.name);
    if (entry.isDirectory()) {
      walkPackFiles(root, fullPath, files);
    } else if (entry.isFile()) {
      files.push(path.relative(root, fullPath).replaceAll(path.sep, '/'));
    }
  }
  return files;
}

function globRegex(pattern) {
  const escaped = pattern
    .replace(/[.+^${}()|\\]/g, '\\$&')
    .replace(/\*\*/g, '\0')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/\0/g, '.*');
  return new RegExp(`^${escaped}(?:/.*)?$`);
}

module.exports = {
  fallbackPackFiles,
  lockfileDiff,
  packAudit,
  trustAdd,
  trustAudit,
};
