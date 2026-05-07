'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const {
  adapterForFile,
  includePackageManager,
  isSuspiciousSource,
  lockfileNames,
  packageManagerForFile,
} = require('./ecosystems');

const lockfiles = lockfileNames();
const rootDependencyFiles = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'bun.lockb',
  'package.json',
  'requirements.txt',
  'requirements-dev.txt',
  'requirements.lock',
  'pyproject.toml',
  'setup.py',
  'Cargo.lock',
  'Cargo.toml',
  'go.mod',
  'go.sum',
  'go.work',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'gradle.lockfile',
  'packages.lock.json',
  'composer.json',
  'composer.lock',
  'Gemfile',
  'Gemfile.lock',
  'poetry.lock',
  'uv.lock',
];

function depsDiff(cwd = process.cwd(), options = {}) {
  const baseRef = options.baseRef || 'HEAD';
  const current = collectDependencies(cwd, { packageManager: options.packageManager || 'auto' });
  const previous = collectDependencies(cwd, { ref: baseRef, files: current.files, packageManager: options.packageManager || 'auto' });
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
  const files = options.files || dependencyFiles(cwd);
  for (const lockfile of files) {
    const content = readLockfile(cwd, lockfile, options.ref);
    if (!content) {
      continue;
    }
    present.push(lockfile);
    dependencies.push(...parseLockfile(lockfile, content).filter((dep) => includePackageManager(dep, options.packageManager || 'auto')));
  }
  return {
    cwd,
    ref: options.ref || null,
    lockfiles: present,
    files: present,
    dependencies: dedupeDependencies(dependencies),
  };
}

function parseLockfile(lockfile, content) {
  if (lockfile === 'package-lock.json') {
    return parsePackageLock(content, lockfile);
  }
  if (lockfile === 'npm-shrinkwrap.json') {
    return parsePackageLock(content, lockfile);
  }
  if (lockfile === 'package.json') {
    return parsePackageJson(content, lockfile);
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
  if (lockfile === 'Cargo.toml') {
    return parseCargoToml(content, lockfile);
  }
  if (lockfile === 'go.mod') {
    return parseGoMod(content, lockfile);
  }
  if (lockfile === 'go.sum') {
    return parseGoSum(content, lockfile);
  }
  if (lockfile === 'go.work') {
    return parseGoWork(content, lockfile);
  }
  if (/^requirements.*\.txt$/i.test(lockfile)) {
    return parseRequirements(content, lockfile);
  }
  if (lockfile === 'pyproject.toml') {
    return parsePyproject(content, lockfile);
  }
  if (lockfile === 'setup.py') {
    return parseSetupPy(content, lockfile);
  }
  if (lockfile === 'poetry.lock') {
    return parsePoetryLock(content, lockfile);
  }
  if (lockfile === 'uv.lock') {
    return parseUvLock(content, lockfile);
  }
  if (lockfile === 'pom.xml') {
    return parsePomXml(content, lockfile);
  }
  if (lockfile === 'build.gradle' || lockfile === 'build.gradle.kts') {
    return parseGradle(content, lockfile);
  }
  if (lockfile === 'gradle.lockfile') {
    return parseGradleLock(content, lockfile);
  }
  if (lockfile === 'packages.lock.json') {
    return parseNugetLock(content, lockfile);
  }
  if (/\.csproj$/i.test(lockfile)) {
    return parseCsproj(content, lockfile);
  }
  if (lockfile === 'composer.json') {
    return parseComposerJson(content, lockfile);
  }
  if (lockfile === 'composer.lock') {
    return parseComposerLock(content, lockfile);
  }
  if (lockfile === 'Gemfile') {
    return parseGemfile(content, lockfile);
  }
  if (lockfile === 'Gemfile.lock') {
    return parseGemfileLock(content, lockfile);
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
          integrity: value.integrity || '',
        },
      }));
  } catch {
    return [];
  }
}

function parsePackageJson(content, lockfile) {
  try {
    const parsed = JSON.parse(content);
    const deps = [];
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const [name, version] of Object.entries(parsed[section] || {})) {
        deps.push(dependency({
          ecosystem: 'npm',
          name,
          version: String(version || ''),
          source: sourceFromSpec(version, 'registry.npmjs.org'),
          registry: registryFor(String(version || 'registry.npmjs.org')),
          lockfile,
          metadata: { manifestSection: section },
        }));
      }
    }
    return deps;
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
    const integrity = (block.match(/integrity:\s*([^\s,}]+)/) || [])[1] || '';
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
        integrity: stripQuotes(integrity),
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
    const integrity = (block.match(/^\s+integrity\s+"?([^"\r\n]+)"?/m) || [])[1] || '';
    if (nameMatch) {
      deps.push(dependency({
        ecosystem: 'npm',
        name: nameMatch[1],
        version,
        source,
        registry: registryFor(source),
        lockfile,
        metadata: { integrity },
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

function parseCargoToml(content, lockfile) {
  const deps = [];
  const dependencySections = content.matchAll(/^\[(dependencies|dev-dependencies|build-dependencies|target\.[^\]]+\.dependencies)\]\s*$([\s\S]*?)(?=^\[|$(?![\s\S]))/gm);
  for (const section of dependencySections) {
    for (const line of section[2].split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*(?:"([^"]+)"|\{([^}]+)\})/);
      if (!match) continue;
      const table = match[3] || '';
      const git = (table.match(/git\s*=\s*"([^"]+)"/) || [])[1] || '';
      const pathSource = (table.match(/path\s*=\s*"([^"]+)"/) || [])[1] || '';
      const version = match[2] || (table.match(/version\s*=\s*"([^"]+)"/) || [])[1] || '';
      deps.push(dependency({
        ecosystem: 'cargo',
        name: match[1],
        version,
        source: git || pathSource || 'crates.io',
        registry: git ? registryFor(git) : (pathSource ? 'path' : 'crates.io'),
        lockfile,
        metadata: { manifestSection: section[1], git: Boolean(git), path: Boolean(pathSource) },
      }));
    }
  }
  return deps;
}

function parseGoMod(content, lockfile) {
  const deps = [];
  const replaceTargets = new Map();
  for (const match of content.matchAll(/^\s*replace\s+(\S+)(?:\s+v\S+)?\s+=>\s+(\S+)(?:\s+(\S+))?/gm)) {
    replaceTargets.set(match[1], [match[2], match[3]].filter(Boolean).join(' '));
  }
  const singleRequires = content.matchAll(/^\s*require\s+(\S+)\s+(v\S+)/gm);
  for (const match of singleRequires) {
    if (match[1] === '(') continue;
    deps.push(goDependency(match[1], match[2], lockfile, replaceTargets));
  }
  const blocks = content.matchAll(/^\s*require\s*\(([\s\S]*?)^\s*\)/gm);
  for (const block of blocks) {
    for (const line of block[1].split(/\r?\n/)) {
      const match = line.match(/^\s*(\S+)\s+(v\S+)/);
      if (match) deps.push(goDependency(match[1], match[2], lockfile, replaceTargets));
    }
  }
  for (const [name, target] of replaceTargets.entries()) {
    if (!deps.some((dep) => dep.name === name)) {
      deps.push(goDependency(name, '', lockfile, replaceTargets));
    }
  }
  return deps;
}

function goDependency(name, version, lockfile, replaceTargets = new Map()) {
  const replace = replaceTargets.get(name) || '';
  const source = replace || name;
  return dependency({
    ecosystem: 'go',
    name,
    version,
    source,
    registry: registryFor(source),
    lockfile,
    metadata: {
      replace: replace || '',
      pseudoVersion: /v\d+\.\d+\.\d+-\d{14}-[a-f0-9]{12}$/i.test(version),
    },
  });
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

function parseGoWork(content, lockfile) {
  const deps = [];
  for (const match of content.matchAll(/^\s*use\s+(\S+)/gm)) {
    deps.push(dependency({ ecosystem: 'go', name: match[1], version: '', source: match[1], registry: 'workspace', lockfile, metadata: { workspace: true } }));
  }
  return deps;
}

function parseRequirements(content, lockfile) {
  const deps = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#') || line.startsWith('-r ') || line.startsWith('--')) continue;
    const direct = line.match(/^(?:git\+|https?:|file:)(\S+)/i);
    const egg = line.match(/#egg=([^&\s]+)/);
    if (direct) {
      deps.push(dependency({ ecosystem: 'python', name: egg?.[1] || direct[1], version: '', source: direct[0], registry: registryFor(direct[0]), lockfile, metadata: { direct: true, hashes: /--hash=/.test(line) } }));
      continue;
    }
    const match = line.match(/^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)\s*(?:==|~=|>=|<=|>|<|=)?\s*([^;\s]*)?/);
    if (match) {
      deps.push(dependency({ ecosystem: 'python', name: match[1], version: match[2] || '', source: 'pypi', registry: 'pypi.org', lockfile, metadata: { hashes: /--hash=/.test(line) } }));
    }
  }
  return deps;
}

function parsePyproject(content, lockfile) {
  const deps = [];
  const arrayMatches = content.matchAll(/(?:dependencies|requires)\s*=\s*\[([\s\S]*?)\]/g);
  for (const arrayMatch of arrayMatches) {
    for (const item of arrayMatch[1].matchAll(/"([^"]+)"/g)) {
      deps.push(...parseRequirements(item[1], lockfile));
    }
  }
  const poetryBlock = content.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?=^\[|$(?![\s\S]))/m);
  if (poetryBlock) {
    for (const line of poetryBlock[1].split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*(?:"([^"]+)"|\{([^}]+)\})/);
      if (!match || match[1].toLowerCase() === 'python') continue;
      const table = match[3] || '';
      const url = (table.match(/(?:url|git|path)\s*=\s*"([^"]+)"/) || [])[1] || '';
      deps.push(dependency({ ecosystem: 'python', name: match[1], version: match[2] || (table.match(/version\s*=\s*"([^"]+)"/) || [])[1] || '', source: url || 'pypi', registry: url ? registryFor(url) : 'pypi.org', lockfile }));
    }
  }
  return deps;
}

function parseSetupPy(content, lockfile) {
  const deps = [];
  const installRequires = content.match(/install_requires\s*=\s*\[([\s\S]*?)\]/);
  if (installRequires) {
    for (const item of installRequires[1].matchAll(/['"]([^'"]+)['"]/g)) {
      deps.push(...parseRequirements(item[1], lockfile));
    }
  }
  if (/\b(?:subprocess|os\.system|eval|exec|curl|wget|powershell)\b/i.test(content)) {
    deps.push(dependency({ ecosystem: 'python', name: '<setup.py>', version: '', source: 'local-build-script', registry: 'local', lockfile, metadata: { setupScript: true, runtimeSensitive: true } }));
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

function parsePomXml(content, lockfile) {
  const deps = [];
  for (const block of content.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const name = xmlTag(block[1], 'artifactId');
    const group = xmlTag(block[1], 'groupId');
    if (!name || !group) continue;
    deps.push(dependency({ ecosystem: 'maven', name: `${group}:${name}`, version: xmlTag(block[1], 'version') || '', source: 'maven-central', registry: 'repo.maven.apache.org', lockfile }));
  }
  return deps;
}

function parseGradle(content, lockfile) {
  const deps = [];
  for (const match of content.matchAll(/(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*(?:\(?\s*)['"]([^:'"]+):([^:'"]+):([^'"]+)['"]/g)) {
    deps.push(dependency({ ecosystem: 'gradle', name: `${match[1]}:${match[2]}`, version: match[3], source: 'maven-compatible', registry: 'gradle', lockfile }));
  }
  for (const match of content.matchAll(/url\s*=\s*uri\(['"]([^'"]+)['"]\)|url\s+['"]([^'"]+)['"]/g)) {
    deps.push(dependency({ ecosystem: 'gradle', name: '<repository>', version: '', source: match[1] || match[2], registry: registryFor(match[1] || match[2]), lockfile }));
  }
  return deps;
}

function parseGradleLock(content, lockfile) {
  const deps = [];
  for (const line of content.split(/\r?\n/)) {
    const match = line.match(/^([^:#\s]+):([^:#\s]+):([^=\s]+)/);
    if (match) deps.push(dependency({ ecosystem: 'gradle', name: `${match[1]}:${match[2]}`, version: match[3], source: 'maven-compatible', registry: 'gradle', lockfile }));
  }
  return deps;
}

function parseNugetLock(content, lockfile) {
  try {
    const parsed = JSON.parse(content);
    const deps = [];
    for (const target of Object.values(parsed.dependencies || {})) {
      for (const [name, value] of Object.entries(target || {})) {
        deps.push(dependency({ ecosystem: 'nuget', name, version: value.resolved || value.requested || '', source: 'nuget.org', registry: 'api.nuget.org', lockfile, metadata: { type: value.type || '' } }));
      }
    }
    return deps;
  } catch {
    return [];
  }
}

function parseCsproj(content, lockfile) {
  const deps = [];
  for (const match of content.matchAll(/<PackageReference[^>]*Include=["']([^"']+)["'][^>]*(?:Version=["']([^"']+)["'])?/g)) {
    deps.push(dependency({ ecosystem: 'nuget', name: match[1], version: match[2] || '', source: 'nuget.org', registry: 'api.nuget.org', lockfile }));
  }
  return deps;
}

function parseComposerJson(content, lockfile) {
  try {
    const parsed = JSON.parse(content);
    const deps = [];
    for (const section of ['require', 'require-dev']) {
      for (const [name, version] of Object.entries(parsed[section] || {})) {
        if (name === 'php') continue;
        deps.push(dependency({ ecosystem: 'composer', name, version: String(version || ''), source: 'packagist', registry: 'repo.packagist.org', lockfile, metadata: { manifestSection: section } }));
      }
    }
    for (const repo of parsed.repositories || []) {
      if (repo?.url) deps.push(dependency({ ecosystem: 'composer', name: '<repository>', version: '', source: repo.url, registry: registryFor(repo.url), lockfile }));
    }
    return deps;
  } catch {
    return [];
  }
}

function parseComposerLock(content, lockfile) {
  try {
    const parsed = JSON.parse(content);
    return [...(parsed.packages || []), ...(parsed['packages-dev'] || [])].map((pkg) => dependency({
      ecosystem: 'composer',
      name: pkg.name,
      version: pkg.version || '',
      source: pkg.source?.url || pkg.dist?.url || 'packagist',
      registry: registryFor(pkg.source?.url || pkg.dist?.url || 'repo.packagist.org'),
      lockfile,
      metadata: { type: pkg.type || '' },
    }));
  } catch {
    return [];
  }
}

function parseGemfile(content, lockfile) {
  const deps = [];
  for (const match of content.matchAll(/^\s*gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?([^\r\n]*)/gm)) {
    const options = match[3] || '';
    const git = (options.match(/git:\s*['"]([^'"]+)['"]/) || [])[1] || '';
    const pathSource = (options.match(/path:\s*['"]([^'"]+)['"]/) || [])[1] || '';
    deps.push(dependency({ ecosystem: 'bundler', name: match[1], version: match[2] || '', source: git || pathSource || 'rubygems', registry: git ? registryFor(git) : (pathSource ? 'path' : 'rubygems.org'), lockfile }));
  }
  return deps;
}

function parseGemfileLock(content, lockfile) {
  const deps = [];
  const specs = content.match(/^\s{4}specs:\r?\n([\s\S]*?)(?=^\S|$(?![\s\S]))/m);
  if (specs) {
    for (const line of specs[1].split(/\r?\n/)) {
      const match = line.match(/^\s{6}([A-Za-z0-9_.-]+)\s+\(([^)]+)\)/);
      if (match) deps.push(dependency({ ecosystem: 'bundler', name: match[1], version: match[2], source: 'rubygems', registry: 'rubygems.org', lockfile }));
    }
  }
  return deps;
}

function findingsForNewDependency(dep, allDeps) {
  const findings = [];
  if (isSuspiciousSource(dep.source)) {
    findings.push(finding('dependency-new-suspicious-source', 'high', dep, `New dependency source is suspicious: ${dep.source}`));
  }
  if (['npm', 'python', 'go', 'cargo', 'maven', 'gradle', 'nuget', 'composer', 'bundler'].includes(dep.ecosystem) && !dep.name.startsWith('@') && looksInternalName(dep.name)) {
    findings.push(finding('dependency-confusion-risk', 'medium', dep, `Unscoped package name looks internal and may be resolved from a public registry: ${dep.name}`));
  }
  if (dep.metadata?.replace) {
    findings.push(finding('go-module-replace-entry', isSuspiciousSource(dep.metadata.replace) ? 'high' : 'medium', dep, `Go module ${dep.name} is replaced with ${dep.metadata.replace}.`));
  }
  if (dep.metadata?.pseudoVersion) {
    findings.push(finding('go-module-pseudo-version', 'medium', dep, `Go module ${dep.name} uses pseudo-version ${dep.version}.`));
  }
  if (dep.metadata?.runtimeSensitive) {
    findings.push(finding('dependency-local-build-script-risk', 'high', dep, `${dep.lockfile} contains runtime-sensitive build/install behavior.`));
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
  if (isSuspiciousSource(change.after.source || '')) {
    findings.push(finding('dependency-suspicious-source', 'high', change.after, `Dependency now resolves from suspicious source: ${change.after.source}`));
  }
  if (change.after.ecosystem === 'go' && change.after.metadata?.replace && change.before.metadata?.replace !== change.after.metadata.replace) {
    findings.push(finding('go-module-replace-drift', isSuspiciousSource(change.after.metadata.replace) ? 'high' : 'medium', change.after, `Go module replace changed to ${change.after.metadata.replace}.`));
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
    packageManager: packageManagerForFile(value.lockfile),
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

function dependencyFiles(cwd) {
  const files = new Set(rootDependencyFiles.filter((file) => fs.existsSync(path.join(cwd, file))));
  for (const file of fs.readdirSync(cwd)) {
    if (/^requirements.*\.txt$/i.test(file) || /\.csproj$/i.test(file)) {
      files.add(file);
    }
  }
  return Array.from(files).filter((file) => adapterForFile(file));
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

function sourceFromSpec(spec, fallback) {
  const text = String(spec || '');
  if (/^(?:https?:|git[+:]|file:|[./~])/.test(text)) {
    return text;
  }
  return fallback;
}

function xmlTag(content, tag) {
  return (content.match(new RegExp(`<${tag}>\\s*([^<]+?)\\s*</${tag}>`, 'i')) || [])[1] || '';
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
  dependencyFiles,
  lockfiles,
  parseLockfile,
};
