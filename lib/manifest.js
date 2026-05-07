'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { projectDirName } = require('./paths');
const { allAdapters } = require('./ecosystems');
const { coverageFor, isDirectGuarded, summarizeCoverage } = require('./entrypoint-coverage');

const manifestFileName = '.execfence/manifest.json';

function generateManifest(cwd = process.cwd()) {
  const root = path.resolve(cwd);
  const entrypoints = [];
  collectPackage(root, root, entrypoints);
  collectMakefile(root, entrypoints);
  collectGithubActions(root, entrypoints);
  collectVscode(root, entrypoints);
  collectLanguageEntrypoints(root, entrypoints);
  collectAgentRules(root, entrypoints);
  const coveredEntrypoints = entrypoints.map((item) => coverageFor(item));
  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    cwd: root,
    entrypoints: coveredEntrypoints.sort((a, b) => `${a.file}:${a.name}`.localeCompare(`${b.file}:${b.name}`)),
    summary: summarizeCoverage(coveredEntrypoints),
  };
}

function writeManifest(cwd = process.cwd(), manifest = generateManifest(cwd), options = {}) {
  const filePath = path.join(cwd, options.path || manifestFileName);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { filePath, manifest };
}

function readManifest(cwd = process.cwd(), explicitPath) {
  const filePath = path.resolve(cwd, explicitPath || manifestFileName);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function diffManifest(current, previous) {
  const before = new Map((previous?.entrypoints || []).map((entry) => [entryKey(entry), entry]));
  const after = new Map((current?.entrypoints || []).map((entry) => [entryKey(entry), entry]));
  const added = [];
  const removed = [];
  const changed = [];
  for (const [key, entry] of after.entries()) {
    if (!before.has(key)) {
      added.push(entry);
      continue;
    }
    const old = before.get(key);
    if (old.command !== entry.command || old.directGuarded !== entry.directGuarded || old.covered !== entry.covered || old.sensitive !== entry.sensitive) {
      changed.push({ before: old, after: entry });
    }
  }
  for (const [key, entry] of before.entries()) {
    if (!after.has(key)) {
      removed.push(entry);
    }
  }
  return {
    ok: added.length === 0 && changed.length === 0,
    added,
    removed,
    changed,
    riskLevel: riskLevel({ added, changed }),
    risk: suspiciousChanges({ added, changed }),
  };
}

function collectPackage(root, cwd, entrypoints) {
  const packagePath = path.join(cwd, 'package.json');
  if (!fs.existsSync(packagePath)) {
    return;
  }
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  } catch {
    return;
  }
  const rel = relative(root, packagePath);
  for (const [name, command] of Object.entries(pkg.scripts || {})) {
    if (!isExecutionScript(name)) {
      continue;
    }
    entrypoints.push(entry({
      type: 'package-script',
      file: rel,
      name,
      command,
      directGuarded: isGuarded(command, pkg.scripts),
      prehookGuarded: isGuarded(pkg.scripts?.[`pre${name}`], pkg.scripts),
      guarded: isGuarded(command, pkg.scripts) || isGuarded(pkg.scripts?.[`pre${name}`], pkg.scripts),
      sensitive: isSensitiveScript(name, command),
    }));
  }
  for (const workspace of normalizeWorkspaces(pkg.workspaces)) {
    const base = path.join(cwd, workspace.replace(/\/\*$/, ''));
    if (!fs.existsSync(base)) {
      continue;
    }
    for (const child of fs.readdirSync(base)) {
      collectPackage(root, path.join(base, child), entrypoints);
    }
  }
}

function collectMakefile(root, entrypoints) {
  const filePath = path.join(root, 'Makefile');
  if (!fs.existsSync(filePath)) {
    return;
  }
  const content = fs.readFileSync(filePath, 'utf8');
  const hasGuard = /^guard:/m.test(content) && isGuarded(content);
  for (const target of ['build', 'test', 'dev', 'run', 'vet', 'test-race']) {
    const match = content.match(new RegExp(`^${target}:([^\\r\\n]*)`, 'm'));
    if (!match) {
      continue;
    }
    entrypoints.push(entry({
      type: 'make-target',
      file: 'Makefile',
      name: target,
      command: `make ${target}`,
      guarded: /guard/.test(match[1]) && hasGuard,
      sensitive: true,
    }));
  }
}

function collectGithubActions(root, entrypoints) {
  const workflows = path.join(root, '.github', 'workflows');
  if (!fs.existsSync(workflows)) {
    return;
  }
  for (const file of fs.readdirSync(workflows).filter((name) => /\.ya?ml$/i.test(name))) {
    const filePath = path.join(workflows, file);
    const content = fs.readFileSync(filePath, 'utf8');
    for (const line of content.split(/\r?\n/).filter((item) => /^\s*-\s*run:/.test(item))) {
      if (/\b(npm|pnpm|yarn|bun|go|cargo|python|pytest|pip|pipx|uv|poetry|mvn|mvnw|gradle|gradlew|dotnet|composer|bundle|bundler|make|node)\b/.test(line)) {
        const command = line.trim().replace(/^\s*-\s*run:\s*/, '');
        const directGuarded = isDirectGuarded(command);
        entrypoints.push(entry({
          type: 'github-action-run',
          file: relative(root, filePath),
          name: line.trim(),
          command,
          directGuarded,
          fileGuarded: /execfence/.test(content) && !directGuarded,
          guarded: isGuarded(command) || /execfence/.test(content),
          sensitive: true,
        }));
      }
    }
  }
}

function collectVscode(root, entrypoints) {
  const filePath = path.join(root, '.vscode', 'tasks.json');
  if (!fs.existsSync(filePath)) {
    return;
  }
  const content = fs.readFileSync(filePath, 'utf8');
  entrypoints.push(entry({
    type: 'vscode-task',
    file: '.vscode/tasks.json',
    name: 'tasks',
    command: 'VS Code tasks',
    guarded: isGuarded(content),
    sensitive: /folderOpen|runOn/i.test(content),
  }));
}

function collectLanguageEntrypoints(root, entrypoints) {
  const candidates = [
    ['go', 'go.mod', 'go test ./...'],
    ['python', 'pyproject.toml', 'python -m pytest'],
    ['python', 'setup.py', 'python setup.py'],
    ['rust', 'Cargo.toml', 'cargo test'],
    ['rust', path.join('src-tauri', 'Cargo.toml'), 'cargo test'],
    ['jvm', 'pom.xml', 'mvn test'],
    ['jvm', 'build.gradle', 'gradle test'],
    ['jvm', 'build.gradle.kts', 'gradle test'],
    ['dotnet', 'packages.lock.json', 'dotnet test'],
    ['php', 'composer.json', 'composer install'],
    ['php', 'composer.lock', 'composer install'],
    ['ruby', 'Gemfile', 'bundle install'],
    ['ruby', 'Gemfile.lock', 'bundle install'],
  ];
  for (const adapter of allAdapters()) {
    for (const file of adapter.files) {
      if (['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb'].includes(file)) {
        continue;
      }
      candidates.push([adapter.ecosystem, file, `${adapter.managers[0]} install/run`]);
    }
  }
  const seen = new Set();
  for (const [type, file, command] of candidates) {
    const key = `${file}:${command}`;
    if (!seen.has(key) && fs.existsSync(path.join(root, file))) {
      seen.add(key);
      entrypoints.push(entry({
        type: `${type}-entrypoint`,
        file: file.replaceAll(path.sep, '/'),
        name: command,
        command,
        guarded: false,
        sensitive: true,
      }));
    }
  }
}

function collectAgentRules(root, entrypoints) {
  const files = ['AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.github/copilot-instructions.md', '.clinerules'];
  for (const file of files) {
    const filePath = path.join(root, file);
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      entrypoints.push(entry({
        type: 'agent-rule',
        file,
        name: file,
        command: 'agent instructions',
        guarded: /execfence/.test(content),
        sensitive: true,
      }));
    }
  }
}

function entry(value) {
  const covered = coverageFor(value);
  return {
    ...value,
    ...covered,
    id: entryKey(value),
    guard: covered.guard || (covered.covered ? covered.coverageSource : null),
  };
}

function entryKey(entryValue) {
  return `${entryValue.type}:${entryValue.file}:${entryValue.name}`;
}

function riskLevel(diff) {
  const riskyAdded = diff.added.filter((entryValue) => entryValue.sensitive);
  const unguarded = diff.added.filter((entryValue) => !entryValue.covered);
  if (riskyAdded.length > 0 && unguarded.length > 0) {
    return 'high';
  }
  if (diff.added.length || diff.changed.length) {
    return 'medium';
  }
  return 'low';
}

function suspiciousChanges(diff) {
  const items = [];
  for (const entryValue of diff.added) {
    if (entryValue.sensitive) {
      items.push({
        reason: `New execution entrypoint: ${entryValue.type} ${entryValue.name}`,
        severity: entryValue.covered ? 'medium' : 'high',
        entrypoint: entryValue,
      });
    }
    if (/preinstall|postinstall|install|prepare/.test(entryValue.name)) {
      items.push({
        reason: `New lifecycle script: ${entryValue.name}`,
        severity: 'high',
        entrypoint: entryValue,
      });
    }
    if (/github-action/.test(entryValue.type) && /permissions:\s*write-all|pull_request_target/.test(entryValue.command)) {
      items.push({
        reason: `New permissive workflow command: ${entryValue.name}`,
        severity: 'high',
        entrypoint: entryValue,
      });
    }
    if (entryValue.file === '.vscode/tasks.json' && /folderOpen|runOn/i.test(entryValue.command)) {
      items.push({
        reason: 'VS Code task can execute automatically',
        severity: 'high',
        entrypoint: entryValue,
      });
    }
  }
  for (const item of diff.changed) {
    items.push({
      reason: `Execution entrypoint changed: ${item.after.type} ${item.after.name}`,
      severity: item.after.covered ? 'medium' : 'high',
      before: item.before,
      after: item.after,
    });
  }
  return items;
}

function isExecutionScript(name) {
  return /^(pre|post)?(build|dev|start|test|watch|prepare|install|postinstall|preinstall|pack|publish|release|serve)$/.test(name);
}

function isSensitiveScript(name, command) {
  return /install|prepare|build|test|dev|start|publish|release/.test(name) ||
    /\b(node|npm|pnpm|yarn|bun|go|cargo|python|pytest|pip|pipx|uv|poetry|mvn|mvnw|gradle|gradlew|dotnet|composer|bundle|bundler|curl|wget|powershell|bash|sh)\b/i.test(String(command));
}

function isGuarded(command = '', scripts = {}) {
  const text = String(command || '');
  if (/(?:execfence(?:\.js)?|bin[\\/]+execfence\.js)\s+(?:run|scan|ci)|execfence:(?:scan|ci)|npm\s+run\s+execfence:(?:scan|ci)/.test(text)) {
    return true;
  }
  const scriptMatch = text.match(/^npm\s+run\s+([^\s]+)/);
  return Boolean(scriptMatch && scripts[scriptMatch[1]] && isGuarded(scripts[scriptMatch[1]], {}));
}

function normalizeWorkspaces(workspaces) {
  if (Array.isArray(workspaces)) {
    return workspaces;
  }
  if (Array.isArray(workspaces?.packages)) {
    return workspaces.packages;
  }
  return [];
}

function relative(root, filePath) {
  return path.relative(root, filePath).replaceAll(path.sep, '/');
}

module.exports = {
  diffManifest,
  generateManifest,
  manifestFileName,
  readManifest,
  writeManifest,
};
