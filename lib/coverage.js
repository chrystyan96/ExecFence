'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { npmGuardStatus } = require('./npm-guard');
const { effectiveSupplyChainConfig } = require('./deps-review');
const { adapterForFile, packageManagerForFile } = require('./ecosystems');
const { coverageFor, invokedNpmScripts, isDirectGuarded, summarizeCoverage } = require('./entrypoint-coverage');
const { annotateWorkflowCoverage, workflowRunSteps } = require('./workflow-parser');
const { dependencyFiles } = require('./deps');
const { parseVscodeTasks } = require('./vscode-tasks');

function analyzeCoverage(cwd = process.cwd(), options = {}) {
  const npmGuard = npmGuardStatus({ home: options.home, env: options.env });
  const supplyChain = options.supplyChain || effectiveSupplyChainConfig(cwd, options.config);
  const strictSupplyChain = options.strictSupplyChain ?? supplyChain.mode === 'strict';
  const entrypoints = [];
  const globalGuardActive = Boolean(npmGuard.enabled && npmGuard.activeInPath);
  collectPackageEntrypoints(cwd, entrypoints, { npmGuardActive: globalGuardActive });
  collectPackageManagerSurfaces(cwd, entrypoints, { npmGuardActive: globalGuardActive, strictSupplyChain });
  collectMakefileEntrypoints(cwd, entrypoints);
  collectWorkflowEntrypoints(cwd, entrypoints);
  collectConfigEntrypoints(cwd, entrypoints);
  const coveredEntrypoints = entrypoints.map((entry) => coverageFor(entry));
  const uncovered = coveredEntrypoints.filter((entry) => !entry.covered);
  return {
    cwd,
    npmGuard,
    summary: summarizeCoverage(coveredEntrypoints),
    entrypoints: coveredEntrypoints,
    uncovered: uncovered.map((entry) => ({
      ...entry,
      fixSuggestion: fixSuggestionFor(entry),
    })),
    ok: uncovered.length === 0,
  };
}

function collectPackageEntrypoints(cwd, entrypoints, options = {}) {
  const packageFiles = dependencyFiles(cwd).filter((file) => path.basename(file) === 'package.json');
  for (const packageFile of packageFiles) {
    const packagePath = path.join(cwd, packageFile);
    const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    const scripts = pkg.scripts || {};
    const interesting = /^(pre|post)?(build|dev|start|test|watch|prepare|install|postinstall|preinstall|pack|publish|prepack|postpack)$|^prepublishOnly$/;
    for (const [name, command] of Object.entries(scripts)) {
      if (!interesting.test(name)) {
        continue;
      }
      const prehook = scripts[`pre${name}`] || '';
      const directGuarded = isGuarded(command, scripts);
      const prehookGuarded = isGuarded(prehook, scripts);
      entrypoints.push({
        type: 'package-script',
        file: packageFile,
        name,
        command,
        directGuarded,
        prehookGuarded,
        globalGuarded: Boolean(options.npmGuardActive),
        guarded: directGuarded || prehookGuarded || Boolean(options.npmGuardActive),
        guard: directGuarded ? 'execfence-run' : (prehookGuarded ? 'package-prehook' : (options.npmGuardActive ? 'npm-guard' : null)),
      });
    }
  }
}

function collectPackageManagerSurfaces(cwd, entrypoints, options = {}) {
  if (!options.strictSupplyChain) {
    return;
  }
  const surfaces = dependencyFiles(cwd).flatMap((lockfile) => {
    const adapter = adapterForFile(lockfile);
    return adapter ? [{ lockfile, manager: packageManagerForFile(lockfile, adapter.managers[0]), ecosystem: adapter.ecosystem }] : [];
  });
  for (const surface of surfaces) {
    if (!fs.existsSync(path.join(cwd, surface.lockfile))) {
      continue;
    }
    entrypoints.push({
      type: 'package-manager-surface',
      file: surface.lockfile,
      name: surface.manager,
      command: `${surface.manager} install/run`,
      directGuarded: false,
      globalGuarded: Boolean(options.npmGuardActive),
      guarded: Boolean(options.npmGuardActive),
      guard: options.npmGuardActive ? 'global-package-manager-guard' : null,
      strict: true,
      ecosystem: surface.ecosystem,
    });
  }
}

function collectMakefileEntrypoints(cwd, entrypoints) {
  const makefilePath = path.join(cwd, 'Makefile');
  if (!fs.existsSync(makefilePath)) {
    return;
  }
  const content = fs.readFileSync(makefilePath, 'utf8');
  const hasGuardTarget = /^guard:/m.test(content) && /execfence/.test(content);
  for (const target of ['build', 'test', 'dev', 'run', 'pack', 'publish', 'vet', 'test-race']) {
    const match = content.match(new RegExp(`^${target}:([^\\r\\n]*)`, 'm'));
    if (match) {
      entrypoints.push({
        type: 'make-target',
        file: 'Makefile',
        name: target,
        command: `make ${target}`,
        guarded: /guard/.test(match[1]) && hasGuardTarget,
      });
    }
  }
}

function collectWorkflowEntrypoints(cwd, entrypoints) {
  const workflows = path.join(cwd, '.github', 'workflows');
  if (!fs.existsSync(workflows)) {
    return;
  }
  for (const file of fs.readdirSync(workflows).filter((name) => /\.ya?ml$/i.test(name))) {
    const rel = path.join('.github', 'workflows', file).replaceAll(path.sep, '/');
    const content = fs.readFileSync(path.join(workflows, file), 'utf8');
    const steps = annotateWorkflowCoverage(workflowRunSteps(content), isDirectGuarded);
    for (const step of steps) {
      if (/\b(npm|pnpm|yarn|bun|go|cargo|python|pytest|pip|pipx|uv|poetry|mvn|mvnw|gradle|gradlew|dotnet|composer|bundle|bundler|make)\b/.test(step.command)) {
        entrypoints.push({
          type: 'github-action-run',
          file: rel,
          name: `${step.job}#${step.order + 1}: ${step.command}`,
          command: step.command,
          job: step.job,
          order: step.order,
          directGuarded: step.directGuarded,
          fileGuarded: step.fileGuarded,
          guarded: step.guarded,
        });
      }
    }
  }
}

function collectConfigEntrypoints(cwd, entrypoints) {
  const vscodeTasks = path.join(cwd, '.vscode', 'tasks.json');
  if (fs.existsSync(vscodeTasks)) {
    const content = fs.readFileSync(vscodeTasks, 'utf8');
    for (const task of parseVscodeTasks(content)) {
      entrypoints.push({
        type: 'vscode-task',
        file: '.vscode/tasks.json',
        name: task.name,
        command: task.command,
        directGuarded: isDirectGuarded(task.command),
        guarded: isDirectGuarded(task.command),
        autoRun: task.autoRun,
      });
    }
  }
}

function isGuarded(command, scripts = {}, seen = new Set()) {
  if (isDirectGuarded(command)) return true;
  for (const name of invokedNpmScripts(command)) {
    if (seen.has(name) || !scripts[name]) continue;
    const nextSeen = new Set(seen).add(name);
    if (isGuarded(scripts[name], scripts, nextSeen)) return true;
  }
  return false;
}

function fixSuggestionFor(entry) {
  if (entry.type === 'package-script') {
    return {
      file: entry.file,
      action: 'replace script command',
      command: `execfence run -- ${entry.command}`,
    };
  }
  if (entry.type === 'make-target') {
    return {
      file: entry.file,
      action: 'add guard dependency',
      command: `${entry.name}: guard`,
    };
  }
  if (entry.type === 'github-action-run') {
    return {
      file: entry.file,
      action: 'wrap workflow run command',
      command: entry.command.replace(/run:\s*/, 'run: execfence run -- '),
    };
  }
  if (entry.type === 'vscode-task') {
    return {
      file: entry.file,
      action: 'wrap task command',
      command: 'execfence run -- <existing command>',
    };
  }
  if (entry.type === 'package-manager-surface') {
    return {
      file: entry.file,
      action: 'enable package-manager guard or wrap commands',
      command: 'execfence guard global-enable; execfence ci',
    };
  }
  return {
    file: entry.file,
    action: 'wrap execution',
    command: `execfence run -- ${entry.command}`,
  };
}

module.exports = {
  analyzeCoverage,
  fixSuggestionFor,
};
