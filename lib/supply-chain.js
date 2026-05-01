'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { sha256File } = require('./baseline');

const dangerousPackExtensions = new Set(['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.wsf', '.asar']);

function packAudit(cwd = process.cwd()) {
  const packagePath = path.join(cwd, 'package.json');
  if (!fs.existsSync(packagePath)) {
    return { cwd, ok: true, skipped: 'package.json not found', files: [], findings: [] };
  }
  const findings = [];
  let files = [];
  try {
    const output = npmPackDryRun(cwd);
    const parsed = JSON.parse(output);
    files = (Array.isArray(parsed) ? parsed[0]?.files : parsed.files) || [];
  } catch (error) {
    return { cwd, ok: false, files: [], findings: [{ id: 'pack-audit-failed', severity: 'high', detail: error.message }] };
  }
  for (const file of files) {
    const name = file.path || file.name || '';
    const ext = path.extname(name).toLowerCase();
    if (dangerousPackExtensions.has(ext)) {
      findings.push({ id: 'pack-dangerous-artifact', severity: 'high', file: name, line: 1, detail: `Packed artifact includes ${ext} file.` });
    }
    if (/\.execfence\/reports\//.test(name)) {
      findings.push({ id: 'pack-includes-execfence-report', severity: 'medium', file: name, line: 1, detail: 'Package includes ExecFence report output.' });
    }
  }
  return { cwd, ok: findings.filter((finding) => finding.severity === 'high').length === 0, files, findings };
}

function lockfileDiff(cwd = process.cwd(), options = {}) {
  const baseRef = options.baseRef || 'HEAD';
  const findings = [];
  for (const lockfile of ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'Cargo.lock', 'go.sum', 'poetry.lock', 'uv.lock']) {
    const filePath = path.join(cwd, lockfile);
    if (!fs.existsSync(filePath)) {
      continue;
    }
    const current = fs.readFileSync(filePath, 'utf8');
    const previous = gitShow(cwd, `${baseRef}:${lockfile}`);
    if (!previous) {
      continue;
    }
    const currentUrls = urls(current);
    const previousUrls = urls(previous);
    for (const url of currentUrls) {
      if (!previousUrls.has(url) && /raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com|http:\/\//i.test(url)) {
        findings.push({ id: 'lockfile-new-suspicious-source', severity: 'high', file: lockfile, line: 1, detail: `New suspicious lockfile URL: ${url}` });
      }
    }
  }
  return { cwd, ok: findings.length === 0, findings };
}

function trustAdd(cwd, targetPath, metadata = {}) {
  if (!targetPath) {
    throw new Error('Usage: execfence trust add <path> --reason <reason> --owner <owner> --expires-at <date>');
  }
  const filePath = path.resolve(cwd, targetPath);
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${targetPath}`);
  }
  const trustPath = path.join(cwd, '.execfence', 'trust', 'files.json');
  const trust = readJson(trustPath, { files: [] });
  const rel = path.relative(cwd, filePath).replaceAll(path.sep, '/');
  const entry = {
    path: rel,
    sha256: sha256File(filePath),
    reason: metadata.reason || 'trusted by user',
    owner: metadata.owner || 'unknown',
    expiresAt: metadata.expiresAt || metadata['expires-at'] || '2999-01-01',
    addedAt: new Date().toISOString(),
  };
  trust.files = (trust.files || []).filter((item) => item.path !== rel);
  trust.files.push(entry);
  fs.mkdirSync(path.dirname(trustPath), { recursive: true });
  fs.writeFileSync(trustPath, `${JSON.stringify(trust, null, 2)}\n`);
  return { filePath: trustPath, entry };
}

function trustAudit(cwd = process.cwd()) {
  const trustPath = path.join(cwd, '.execfence', 'trust', 'files.json');
  const trust = readJson(trustPath, { files: [] });
  const findings = [];
  for (const entry of trust.files || []) {
    const filePath = path.join(cwd, entry.path);
    if (!fs.existsSync(filePath)) {
      findings.push({ id: 'trusted-file-missing', severity: 'medium', file: entry.path, line: 1, detail: 'Trusted file no longer exists.' });
      continue;
    }
    if (entry.expiresAt && new Date(entry.expiresAt).getTime() < Date.now()) {
      findings.push({ id: 'trusted-file-expired', severity: 'medium', file: entry.path, line: 1, detail: `Trust entry expired at ${entry.expiresAt}.` });
    }
    const actual = sha256File(filePath);
    if (entry.sha256 && actual !== String(entry.sha256).toLowerCase()) {
      findings.push({ id: 'trusted-file-hash-mismatch', severity: 'high', file: entry.path, line: 1, detail: 'Trusted file hash changed.' });
    }
  }
  return { cwd, ok: !findings.some((finding) => finding.severity === 'high'), findings, entries: trust.files || [] };
}

function gitShow(cwd, spec) {
  try {
    return execFileSync('git', ['show', spec], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return '';
  }
}

function urls(text) {
  return new Set(text.match(/https?:\/\/[^\s"'<>]+/g) || []);
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
    return execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd, encoding: 'utf8' });
  }
  const npm = resolveCommand('npm');
  return execFileSync('powershell.exe', ['-NoProfile', '-Command', `& ${JSON.stringify(npm)} pack --dry-run --json`], {
    cwd,
    encoding: 'utf8',
  });
}

module.exports = {
  lockfileDiff,
  packAudit,
  trustAdd,
  trustAudit,
};
