'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const lockfiles = [
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'Cargo.lock',
  'go.sum',
  'poetry.lock',
  'uv.lock',
];

const suspiciousSourcePattern = /raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com|http:\/\/|bitbucket\.org|gitlab\.com|github\.com\/[^/]+\/[^/]+\/(?:archive|releases\/download)/i;

function depsDiff(cwd = process.cwd(), options = {}) {
  const baseRef = options.baseRef || 'HEAD';
  const current = collectDependencies(cwd);
  const previous = collectDependencies(cwd, { ref: baseRef });
  const findings = [];
  const added = [];
  const removed = [];
  const changed = [];
  const beforeMap = new Map(previous.dependencies.map((dep) => [depKey(dep), dep]));
  const afterMap = new Map(current.dependencies.map((dep) => [depKey(dep), dep]));

  for (const [key, dep] of afterMap.entries()) {
    const before = beforeMap.get(key);
    if (!before) {
      added.push(dep);
      findings.push(...findingsForNewDependency(dep, current.dependencies));
      continue;
    }
    if (normalizeSource(before.source) !== normalizeSource(dep.source) || before.version !== dep.version || before.registry !== dep.registry) {
      const item = { before, after: dep };
      changed.push(item);
      findings.push(...findingsForChangedDependency(item));
    }
  }
  for (const [key, dep] of beforeMap.entries()) {
    if (!afterMap.has(key)) {
      removed.push(dep);
    }
  }

  return {
    cwd,
    baseRef,
    ok: !findings.some((finding) => ['critical', 'high'].includes(finding.severity)),
    summary: {
      current: current.dependencies.length,
      previous: previous.dependencies.length,
      added: added.length,
      removed: removed.length,
      changed: changed.length,
      findings: findings.length,
    },
    lockfiles: current.lockfiles,
    added,
    removed,
    changed,
    findings,
  };
}

function collectDependencies(cwd = process.cwd(), options = {}) {
  const dependencies = [];
  const present = [];
  for (const lockfile of lockfiles) {
    const content = readLockfile(cwd, lockfile, options.ref);
    if (!content) {
      continue;
    }
    present.push(lockfile);
    dependencies.push(...parseLockfile(lockfile, content));
  }
  return {
    cwd,
    ref: options.ref || null,
    lockfiles: present,
    dependencies: dedupeDependencies(dependencies),
  };
}

function parseLockfile(lockfile, content) {
  if (lockfile === 'package-lock.json') {
    return parsePackageLock(content, lockfile);
  }
  if (lockfile === 'pnpm-lock.yaml') {
    return parsePnpmLock(content, lockfile);
  }
  if (lockfile === 'yarn.lock') {
    return parseYarnLock(content, lockfile);
  }
  if (lockfile === 'bun.lock') {
    return parseBunLock(content, lockfile);
  }
  if (lockfile === 'Cargo.lock') {
    return parseCargoLock(content, lockfile);
  }
  if (lockfile === 'go.sum') {
    return parseGoSum(content, lockfile);
  }
  if (lockfile === 'poetry.lock') {
    return parsePoetryLock(content, lockfile);
  }
  if (lockfile === 'uv.lock') {
    return parseUvLock(content, lockfile);
  }
  return [];
}

function parsePackageLock(content, lockfile) {
  try {
    const parsed = JSON.parse(content);
    return Object.entries(parsed.packages || {})
      .filter(([name]) => name && name !== '')
      .map(([name, value]) => dependency({
        ecosystem: 'npm',
        name: name.replace(/^node_modules\//, ''),
        version: value.version || '',
        source: value.resolved || '',
        registry: registryFor(value.resolved || ''),
        lockfile,
        metadata: {
          hasInstallScript: Boolean(value.hasInstallScript),
          bin: value.bin || null,
        },
      }));
  } catch {
    return [];
  }
}

function parsePnpmLock(content, lockfile) {
  const deps = [];
  const blocks = content.split(/\n(?=\s{2}[^\s].*?:\s*$)/);
  for (const block of blocks) {
    const match = block.match(/^\s{2}([/@A-Za-z0-9._-]+)@([^:\r\n]+):/m);
    if (!match) {
      continue;
    }
    const resolution = (block.match(/tarball:\s*([^\s]+)/) || block.match(/resolution:\s*\{[^}]*tarball:\s*([^,\s}]+)/) || [])[1] || '';
    deps.push(dependency({
      ecosystem: 'npm',
      name: match[1],
      version: match[2],
      source: stripQuotes(resolution),
      registry: registryFor(resolution),
      lockfile,
      metadata: {
        hasInstallScript: /hasBin|prepare|install|postinstall/.test(block),
        bin: /hasBin:\s*true/.test(block),
      },
    }));
  }
  return deps;
}

function parseYarnLock(content, lockfile) {
  const deps = [];
  for (const block of content.split(/\n(?=\S)/)) {
    const first = block.split(/\r?\n/)[0] || '';
    const nameMatch = first.match(/^"?(@?[^@\s"]+(?:\/[^@\s"]+)?)@/);
    const version = (block.match(/^\s+version\s+"?([^"\r\n]+)"?/m) || [])[1] || '';
    const source = (block.match(/^\s+resolved\s+"?([^"\r\n]+)"?/m) || [])[1] || '';
    if (nameMatch) {
      deps.push(dependency({
        ecosystem: 'npm',
        name: nameMatch[1],
        version,
        source,
        registry: registryFor(source),
        lockfile,
      }));
    }
  }
  return deps;
}

function parseBunLock(content, lockfile) {
  const deps = [];
  for (const match of content.matchAll(/["']([^"'@\s]+|@[^"'@\s]+\/[^"'@\s]+)@([^"']+)["']\s*:\s*["']([^"']*)["']/g)) {
    deps.push(dependency({
      ecosystem: 'npm',
      name: match[1],
      version: match[2],
      source: match[3],
      registry: registryFor(match[3]),
      lockfile,
    }));
  }
  return deps;
}

function parseCargoLock(content, lockfile) {
  const deps = [];
  for (const block of content.split(/\[\[package\]\]/).slice(1)) {
    const name = (block.match(/name\s*=\s*"([^"]+)"/) || [])[1];
    const version = (block.match(/version\s*=\s*"([^"]+)"/) || [])[1] || '';
    const source = (block.match(/source\s*=\s*"([^"]+)"/) || [])[1] || 'crates.io';
    if (name) {
      deps.push(dependency({ ecosystem: 'cargo', name, version, source, registry: registryFor(source), lockfile }));
    }
  }
  return deps;
}

function parseGoSum(content, lockfile) {
  const deps = [];
  for (const line of content.split(/\r?\n/)) {
    const match = line.match(/^(\S+)\s+(v\S+)/);
    if (match && !match[2].endsWith('/go.mod')) {
      deps.push(dependency({ ecosystem: 'go', name: match[1], version: match[2], source: match[1], registry: registryFor(match[1]), lockfile }));
    }
  }
  return deps;
}

function parsePoetryLock(content, lockfile) {
  const deps = [];
  for (const block of content.split(/\[\[package\]\]/).slice(1)) {
    const name = (block.match(/name\s*=\s*"([^"]+)"/) || [])[1];
    const version = (block.match(/version\s*=\s*"([^"]+)"/) || [])[1] || '';
    const source = (block.match(/url\s*=\s*"([^"]+)"/) || block.match(/reference\s*=\s*"([^"]+)"/) || [])[1] || 'pypi';
    if (name) {
      deps.push(dependency({ ecosystem: 'python', name, version, source, registry: registryFor(source), lockfile }));
    }
  }
  return deps;
}

function parseUvLock(content, lockfile) {
  const deps = [];
  for (const block of content.split(/\[\[package\]\]/).slice(1)) {
    const name = (block.match(/name\s*=\s*"([^"]+)"/) || [])[1];
    const version = (block.match(/version\s*=\s*"([^"]+)"/) || [])[1] || '';
    const source = (block.match(/url\s*=\s*"([^"]+)"/) || [])[1] || 'pypi';
    if (name) {
      deps.push(dependency({ ecosystem: 'python', name, version, source, registry: registryFor(source), lockfile }));
    }
  }
  return deps;
}

function findingsForNewDependency(dep, allDeps) {
  const findings = [];
  if (suspiciousSourcePattern.test(dep.source)) {
    findings.push(finding('dependency-new-suspicious-source', 'high', dep, `New dependency source is suspicious: ${dep.source}`));
  }
  if (dep.ecosystem === 'npm' && !dep.name.startsWith('@') && looksInternalName(dep.name)) {
    findings.push(finding('dependency-confusion-risk', 'medium', dep, `Unscoped package name looks internal and may be resolved from a public registry: ${dep.name}`));
  }
  const typo = similarExistingPackage(dep, allDeps);
  if (typo) {
    findings.push(finding('dependency-typosquat-risk', 'medium', dep, `New dependency name is similar to existing ${typo.name}.`));
  }
  if (dep.metadata?.hasInstallScript) {
    findings.push(finding('dependency-new-lifecycle-entry', 'high', dep, `New dependency has install lifecycle behavior: ${dep.name}`));
  }
  if (dep.metadata?.bin) {
    findings.push(finding('dependency-new-bin-entry', 'medium', dep, `New dependency exposes executable bin entries: ${dep.name}`));
  }
  return findings;
}

function findingsForChangedDependency(change) {
  const findings = [];
  const beforeSource = normalizeSource(change.before.source);
  const afterSource = normalizeSource(change.after.source);
  if (beforeSource !== afterSource && afterSource) {
    findings.push(finding('dependency-registry-drift', 'high', change.after, `Dependency source changed from ${beforeSource || 'unknown'} to ${afterSource}.`));
  }
  if (change.before.registry !== change.after.registry && change.after.registry) {
    findings.push(finding('dependency-registry-drift', 'high', change.after, `Dependency registry changed from ${change.before.registry || 'unknown'} to ${change.after.registry}.`));
  }
  if (suspiciousSourcePattern.test(change.after.source || '')) {
    findings.push(finding('dependency-suspicious-source', 'high', change.after, `Dependency now resolves from suspicious source: ${change.after.source}`));
  }
  return findings;
}

function finding(id, severity, dep, detail) {
  return {
    id,
    severity,
    file: dep.lockfile,
    line: 1,
    detail,
    dependency: dep,
  };
}

function dependency(value) {
  return {
    ecosystem: value.ecosystem,
    name: value.name,
    version: value.version || '',
    source: stripQuotes(value.source || ''),
    registry: value.registry || '',
    lockfile: value.lockfile,
    metadata: value.metadata || {},
  };
}

function depKey(dep) {
  return `${dep.ecosystem}:${dep.name}`;
}

function dedupeDependencies(dependencies) {
  const map = new Map();
  for (const dep of dependencies) {
    map.set(`${depKey(dep)}:${dep.version}:${dep.lockfile}`, dep);
  }
  return Array.from(map.values()).sort((a, b) => depKey(a).localeCompare(depKey(b)));
}

function readLockfile(cwd, lockfile, ref) {
  if (ref) {
    try {
      return execFileSync('git', ['show', `${ref}:${lockfile}`], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    } catch {
      return '';
    }
  }
  const filePath = path.join(cwd, lockfile);
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
}

function registryFor(source) {
  const text = String(source || '');
  const url = text.match(/https?:\/\/([^/\s"'<>]+)/i);
  if (url) {
    return url[1].toLowerCase();
  }
  if (/github\.com|git\+ssh|git\+https/.test(text)) {
    return 'git';
  }
  if (/crates\.io|registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index/.test(text)) {
    return 'crates.io';
  }
  if (/^[a-z0-9.-]+\.[a-z]{2,}\//i.test(text)) {
    return text.split('/')[0].toLowerCase();
  }
  return '';
}

function normalizeSource(source) {
  const text = String(source || '');
  return registryFor(text) || text.replace(/#[A-Fa-f0-9]+$/, '');
}

function stripQuotes(value) {
  return String(value || '').replace(/^['"]|['"]$/g, '').replace(/,$/, '');
}

function looksInternalName(name) {
  return /(?:internal|private|corp|company|workspace|platform|service|backend|frontend|desktop|agent)/i.test(name);
}

function similarExistingPackage(dep, allDeps) {
  if (!dep.name || dep.name.length < 4) {
    return null;
  }
  return allDeps.find((candidate) => candidate.name !== dep.name &&
    candidate.ecosystem === dep.ecosystem &&
    candidate.name.length >= 4 &&
    levenshtein(candidate.name, dep.name) <= 2);
}

function levenshtein(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i += 1) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j += 1) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost);
    }
  }
  return matrix[a.length][b.length];
}

module.exports = {
  collectDependencies,
  depsDiff,
  lockfiles,
  parseLockfile,
};
