'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const { projectDirName, resolveProjectPath } = require('./paths');
const { adapterForFile } = require('./ecosystems');
const { coverageFor, invokedNpmScripts, isDirectGuarded, summarizeCoverage } = require('./entrypoint-coverage');
const { annotateWorkflowCoverage, workflowRunSteps } = require('./workflow-parser');
const { dependencyFiles } = require('./deps');
const { loadConfig } = require('./config');
const { parseVscodeTasks } = require('./vscode-tasks');

const manifestFileName = '.execfence/manifest.json';

function generateManifest(cwd = process.cwd()) {
  const root = path.resolve(cwd);
  const manifestConfig = loadConfig(root).config?.manifest || {};
  const entrypoints = [];
  const packageFiles = dependencyFiles(root).filter((file) => path.basename(file) === 'package.json');
  for (const packageFile of packageFiles) {
    collectPackage(root, path.dirname(path.join(root, packageFile)), entrypoints, { recurse: false, manifestConfig });
  }
  collectMakefile(root, entrypoints);
  collectGithubActions(root, entrypoints);
  collectVscode(root, entrypoints);
  collectLanguageEntrypoints(root, entrypoints);
  collectAgentRules(root, entrypoints);
  const coveredEntrypoints = entrypoints.map((item) => coverageFor(item));
  const manifest = {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    cwd: root,
    entrypoints: coveredEntrypoints.sort((a, b) => `${a.file}:${a.name}`.localeCompare(`${b.file}:${b.name}`)),
    summary: summarizeCoverage(coveredEntrypoints),
  };
  manifest.contentHash = manifestHash(manifest);
  return manifest;
}

function writeManifest(cwd = process.cwd(), manifest = generateManifest(cwd), options = {}) {
  const configuredPath = loadConfig(cwd).config?.manifest?.path;
  const filePath = options.path
    ? path.resolve(cwd, options.path)
    : resolveProjectPath(cwd, configuredPath, manifestFileName);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { filePath, manifest };
}

function readManifest(cwd = process.cwd(), explicitPath) {
  const configuredPath = loadConfig(cwd).config?.manifest?.path;
  const filePath = explicitPath
    ? path.resolve(cwd, explicitPath)
    : resolveProjectPath(cwd, configuredPath, manifestFileName);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function readManifestAtRef(cwd = process.cwd(), ref = 'HEAD', explicitPath) {
  const configuredPath = loadConfig(cwd).config?.manifest?.path;
  const filePath = resolveProjectPath(cwd, explicitPath || configuredPath, manifestFileName);
  const relative = path.relative(path.resolve(cwd), filePath).replaceAll(path.sep, '/');
  try {
    return JSON.parse(execFileSync('git', ['show', `${ref}:${relative}`], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }));
  } catch {
    return null;
  }
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

function collectPackage(root, cwd, entrypoints, options = {}) {
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
      sensitive: isSensitiveScript(name, command, options.manifestConfig),
    }));
  }
  if (options.recurse === false) {
    return;
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
    for (const step of annotateWorkflowCoverage(workflowRunSteps(content), isDirectGuarded)) {
      if (/\b(npm|pnpm|yarn|bun|go|cargo|python|pytest|pip|pipx|uv|poetry|mvn|mvnw|gradle|gradlew|dotnet|composer|bundle|bundler|make|node)\b/.test(step.command)) {
        entrypoints.push(entry({
          type: 'github-action-run',
          file: relative(root, filePath),
          name: `${step.job}#${step.order + 1}: ${step.command}`,
          command: step.command,
          job: step.job,
          order: step.order,
          directGuarded: step.directGuarded,
          fileGuarded: step.fileGuarded,
          guarded: step.guarded,
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
  for (const task of parseVscodeTasks(content)) {
    entrypoints.push(entry({
      type: 'vscode-task',
      file: '.vscode/tasks.json',
      name: task.name,
      command: task.command,
      guarded: isGuarded(task.command),
      sensitive: task.autoRun,
      autoRun: task.autoRun,
    }));
  }
}

function manifestHash(manifest) {
  const stable = {
    schemaVersion: manifest.schemaVersion || 2,
    entrypoints: (manifest.entrypoints || []).map((entrypoint) => stableObject(entrypoint)),
    summary: stableObject(manifest.summary || {}),
  };
  return crypto.createHash('sha256').update(JSON.stringify(stable)).digest('hex');
}

function stableObject(value) {
  if (Array.isArray(value)) return value.map(stableObject);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableObject(value[key])]));
  }
  return value;
}

function collectLanguageEntrypoints(root, entrypoints) {
  const candidates = dependencyFiles(root).flatMap((file) => {
    const adapter = adapterForFile(file);
    if (!adapter || adapter.ecosystem === 'npm') return [];
    const runtimeCommand = adapter.runtimeLike?.[0] || 'run';
    return [[adapter.ecosystem, file, `${adapter.managers[0]} ${runtimeCommand}`]];
  });
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
    if (entryValue.file === '.vscode/tasks.json' && entryValue.autoRun) {
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

function isSensitiveScript(name, command, manifestConfig = {}) {
  const configured = manifestConfig?.sensitiveEntrypoints || ['build', 'test', 'dev', 'start', 'serve', 'watch', 'prepare', 'install', 'postinstall'];
  return configured.some((item) => name === item || name === `pre${item}` || name === `post${item}`) ||
    /publish|release/.test(name) ||
    /\b(node|npm|pnpm|yarn|bun|go|cargo|python|pytest|pip|pipx|uv|poetry|mvn|mvnw|gradle|gradlew|dotnet|composer|bundle|bundler|curl|wget|powershell|bash|sh)\b/i.test(String(command));
}

function isGuarded(command = '', scripts = {}, seen = new Set()) {
  if (isDirectGuarded(command)) return true;
  for (const name of invokedNpmScripts(command)) {
    if (seen.has(name) || !scripts[name]) continue;
    const nextSeen = new Set(seen).add(name);
    if (isGuarded(scripts[name], scripts, nextSeen)) return true;
  }
  return false;
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
  manifestHash,
  manifestFileName,
  readManifest,
  readManifestAtRef,
  writeManifest,
};
