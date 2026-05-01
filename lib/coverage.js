'use strict';

const fs = require('node:fs');
const path = require('node:path');

function analyzeCoverage(cwd = process.cwd()) {
  const entrypoints = [];
  collectPackageEntrypoints(cwd, entrypoints);
  collectMakefileEntrypoints(cwd, entrypoints);
  collectWorkflowEntrypoints(cwd, entrypoints);
  collectConfigEntrypoints(cwd, entrypoints);
  const uncovered = entrypoints.filter((entry) => !entry.guarded);
  return {
    cwd,
    entrypoints,
    uncovered,
    ok: uncovered.length === 0,
  };
}

function collectPackageEntrypoints(cwd, entrypoints) {
  const packagePath = path.join(cwd, 'package.json');
  if (!fs.existsSync(packagePath)) {
    return;
  }
  const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  const scripts = pkg.scripts || {};
  const interesting = /^(pre|post)?(build|dev|start|test|watch|prepare|install|postinstall|preinstall)$/;
  for (const [name, command] of Object.entries(scripts)) {
    if (!interesting.test(name)) {
      continue;
    }
    const prehook = scripts[`pre${name}`] || '';
    entrypoints.push({
      type: 'package-script',
      file: 'package.json',
      name,
      command,
      guarded: isGuarded(command) || isGuarded(prehook),
    });
  }
  for (const workspace of normalizeWorkspaces(pkg.workspaces)) {
    const workspaceDir = path.join(cwd, workspace.replace(/\/\*$/, ''));
    if (fs.existsSync(workspaceDir)) {
      for (const child of fs.readdirSync(workspaceDir)) {
        collectPackageEntrypoints(path.join(workspaceDir, child), entrypoints);
      }
    }
  }
}

function collectMakefileEntrypoints(cwd, entrypoints) {
  const makefilePath = path.join(cwd, 'Makefile');
  if (!fs.existsSync(makefilePath)) {
    return;
  }
  const content = fs.readFileSync(makefilePath, 'utf8');
  const hasGuardTarget = /^guard:/m.test(content) && /execfence/.test(content);
  for (const target of ['build', 'test', 'dev', 'run', 'vet', 'test-race']) {
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
    const guarded = /execfence/.test(content);
    for (const line of content.split(/\r?\n/).filter((item) => /^\s*-\s*run:/.test(item))) {
      if (/\b(npm|pnpm|yarn|bun|go|cargo|python|pytest|make)\b/.test(line)) {
        entrypoints.push({ type: 'github-action-run', file: rel, name: line.trim(), command: line.trim(), guarded });
      }
    }
  }
}

function collectConfigEntrypoints(cwd, entrypoints) {
  const vscodeTasks = path.join(cwd, '.vscode', 'tasks.json');
  if (fs.existsSync(vscodeTasks)) {
    const content = fs.readFileSync(vscodeTasks, 'utf8');
    entrypoints.push({
      type: 'vscode-task',
      file: '.vscode/tasks.json',
      name: 'tasks',
      command: 'VS Code tasks',
      guarded: /execfence/.test(content),
    });
  }
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

function isGuarded(command) {
  return /(?:execfence(?:\.js)?|bin\/execfence\.js)\s+(?:run|scan)|execfence:scan|npm\s+run\s+execfence:scan/.test(String(command));
}

module.exports = {
  analyzeCoverage,
};
