'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');
const { sha256File } = require('./baseline');
const { scan } = require('./scanner');
const { git } = require('./git');
const { sandboxPreflight } = require('./sandbox');
const { reviewDependencies } = require('./deps-review');

function runWithFence(commandArgs, options = {}) {
  if (!commandArgs.length) {
    throw new Error('Usage: execfence run -- <command>');
  }
  const cwd = path.resolve(options.cwd || process.cwd());
  const startedAt = new Date().toISOString();
  const beforeStatus = safeGit(cwd, ['status', '--short']);
  const beforeFiles = safeChangedFiles(cwd);
  const beforeSnapshot = snapshotFiles(cwd);
  const sandboxEnabled = Boolean(options.sandbox || options.sandboxMode);
  const sandbox = sandboxEnabled
    ? sandboxPreflight(cwd, commandArgs, {
      sandbox: options.sandbox,
      mode: options.sandboxMode || (options.sandbox ? 'enforce' : undefined),
      profile: options.sandboxProfile,
      allowDegraded: options.allowDegraded,
    })
    : null;
  const preflight = scan({ cwd });
  const dependencyBehavior = options.dependencyBehaviorAudit
    ? dependencyBehaviorAudit(cwd, commandArgs, { sandbox, options })
    : null;
  const trace = {
    command: commandArgs,
    display: commandArgs.map(shellDisplayArg).join(' '),
    cwd,
    startedAt,
    environment: redactEnv(process.env),
    preflightOk: preflight.ok,
    blocked: !preflight.ok,
    before: {
      gitStatus: beforeStatus,
      changedFiles: beforeFiles,
      snapshot: summarizeSnapshot(beforeSnapshot),
    },
    sandbox: sandbox ? sandbox.plan : null,
    dependencyBehavior,
  };
  if (sandbox && !sandbox.ok) {
    const findings = [...sandbox.findings, ...(preflight.findings || [])];
    return {
      cwd,
      ok: false,
      mode: 'run',
      sandbox: sandbox.plan,
      config: preflight.config,
      configPath: preflight.configPath,
      baselinePath: preflight.baselinePath,
      roots: preflight.roots,
      findings,
      blockedFindings: [...sandbox.findings, ...(preflight.blockedFindings || [])],
      warningFindings: preflight.warningFindings,
      suppressedFindings: preflight.suppressedFindings,
      runtimeTrace: {
        ...trace,
        preflightOk: false,
        blocked: true,
        finishedAt: new Date().toISOString(),
        durationMs: Date.now() - Date.parse(startedAt),
        exitCode: null,
        signal: null,
        after: {
          gitStatus: beforeStatus,
          changedFiles: beforeFiles,
        },
      },
      command: {
        display: commandArgs.map(shellDisplayArg).join(' '),
        argv: commandArgs,
        shell: false,
      },
    };
  }
  if (!preflight.ok) {
    return {
      cwd,
      ok: false,
      mode: 'run',
      sandbox: sandbox ? sandbox.plan : null,
      config: preflight.config,
      configPath: preflight.configPath,
      baselinePath: preflight.baselinePath,
      roots: preflight.roots,
      findings: preflight.findings,
      blockedFindings: preflight.blockedFindings,
      warningFindings: preflight.warningFindings,
      suppressedFindings: preflight.suppressedFindings,
      runtimeTrace: {
        ...trace,
        finishedAt: new Date().toISOString(),
        durationMs: Date.now() - Date.parse(startedAt),
        exitCode: null,
        signal: null,
        after: {
          gitStatus: beforeStatus,
          changedFiles: beforeFiles,
        },
      },
      command: {
        display: commandArgs.map(shellDisplayArg).join(' '),
        argv: commandArgs,
        shell: false,
      },
    };
  }
  if (dependencyBehavior && !dependencyBehavior.ok) {
    return {
      cwd,
      ok: false,
      mode: 'run',
      sandbox: sandbox ? sandbox.plan : null,
      config: preflight.config,
      configPath: preflight.configPath,
      baselinePath: preflight.baselinePath,
      roots: preflight.roots,
      findings: [...(preflight.findings || []), ...dependencyBehavior.findings],
      blockedFindings: dependencyBehavior.findings.filter((finding) => ['critical', 'high'].includes(finding.severity || 'high')),
      warningFindings: dependencyBehavior.findings.filter((finding) => !['critical', 'high'].includes(finding.severity || 'high')),
      suppressedFindings: preflight.suppressedFindings,
      runtimeTrace: {
        ...trace,
        preflightOk: false,
        blocked: true,
        finishedAt: new Date().toISOString(),
        durationMs: Date.now() - Date.parse(startedAt),
        exitCode: null,
        signal: null,
        after: {
          gitStatus: beforeStatus,
          changedFiles: beforeFiles,
        },
      },
      command: {
        display: commandArgs.map(shellDisplayArg).join(' '),
        argv: commandArgs,
        shell: false,
      },
    };
  }

  const invocation = commandInvocation(commandArgs);
  const child = spawnSync(invocation.command, invocation.args, {
    cwd,
    shell: false,
    stdio: options.stdio || 'inherit',
    env: process.env,
  });
  const afterStatus = safeGit(cwd, ['status', '--short']);
  const afterFiles = safeChangedFiles(cwd);
  const afterSnapshot = snapshotFiles(cwd);
  const fileChanges = diffSnapshots(cwd, beforeSnapshot, afterSnapshot);
  const changedAfter = Array.from(new Set([
    ...afterFiles.filter((file) => !beforeFiles.includes(file)),
    ...fileChanges.created.map((item) => path.resolve(cwd, item.file)),
    ...fileChanges.modified.map((item) => path.resolve(cwd, item.file)),
    ...fileChanges.renamed.map((item) => path.resolve(cwd, item.to)),
  ]));
  const postflight = changedAfter.length ? scan({ cwd, roots: changedAfter }) : emptyScanResult(cwd, preflight);
  const newExecutableArtifacts = [
    ...fileChanges.created.map((item) => path.resolve(cwd, item.file)),
    ...fileChanges.modified.map((item) => path.resolve(cwd, item.file)),
  ].filter((file) => isExecutableArtifact(file));
  const artifactFindings = options.denyOnNewExecutable
    ? newExecutableArtifacts.map((file) => ({
      id: 'runtime-new-executable-artifact',
      severity: 'high',
      file: path.relative(cwd, file).replaceAll(path.sep, '/'),
      line: 1,
      detail: 'Runtime command created or modified an executable/archive artifact.',
    }))
    : [];
  const behaviorFindings = dependencyBehavior?.containmentFindings || [];
  const ok = child.status === 0 && postflight.ok && artifactFindings.length === 0 && !behaviorFindings.some((finding) => ['critical', 'high'].includes(finding.severity));
  return {
    cwd,
    ok,
    mode: 'run',
    sandbox: sandbox ? sandbox.plan : null,
    config: preflight.config,
    configPath: preflight.configPath,
    baselinePath: preflight.baselinePath,
    roots: preflight.roots,
    findings: [...(preflight.findings || []), ...(postflight.findings || []), ...artifactFindings, ...behaviorFindings],
    blockedFindings: [...(preflight.blockedFindings || []), ...(postflight.blockedFindings || []), ...artifactFindings, ...behaviorFindings.filter((finding) => ['critical', 'high'].includes(finding.severity))],
    warningFindings: [...(preflight.warningFindings || []), ...(postflight.warningFindings || []), ...behaviorFindings.filter((finding) => !['critical', 'high'].includes(finding.severity))],
    suppressedFindings: [...(preflight.suppressedFindings || []), ...(postflight.suppressedFindings || [])],
    runtimeTrace: {
      ...trace,
      finishedAt: new Date().toISOString(),
      durationMs: Date.now() - Date.parse(startedAt),
      exitCode: child.status,
      signal: child.signal,
      error: child.error ? child.error.message : null,
      rootProcess: {
        command: invocation.command,
        args: invocation.args,
        pid: child.pid || null,
      },
      after: {
        gitStatus: afterStatus,
        changedFiles: afterFiles,
        changedAfter,
        fileChanges,
      },
      artifacts: options.recordArtifacts ? artifactsFor(cwd, changedAfter) : [],
      newExecutableArtifacts: newExecutableArtifacts.map((file) => path.relative(cwd, file).replaceAll(path.sep, '/')),
      localTools: localTraceTools(),
      postflightOk: postflight.ok,
    },
    command: {
      display: commandArgs.map(shellDisplayArg).join(' '),
      argv: commandArgs,
      shell: false,
    },
  };
}

function dependencyBehaviorAudit(cwd, commandArgs, context = {}) {
  const depsReview = reviewDependencies(cwd, {
    baseRef: context.options?.baseRef || 'HEAD',
    config: context.options?.supplyChain,
  });
  const containmentFindings = [];
  const commandText = commandArgs.join(' ');
  const importsChangedDependencies = depsReview.summary.reviewed > 0 && /\b(?:test|build|start|dev|node|vite|webpack|rollup|next|ts-node|tsx|jest|vitest)\b/i.test(commandText);
  if (importsChangedDependencies && !context.sandbox) {
    containmentFindings.push({
      id: 'dependency-runtime-containment-missing',
      severity: 'medium',
      file: 'package.json',
      line: 1,
      detail: 'Command may import changed dependencies without sandbox/network/process behavior containment.',
    });
  }
  if (importsChangedDependencies && context.sandbox?.plan) {
    const missing = [];
    if (context.sandbox.plan.network?.missingEnforcement) missing.push('network');
    if (context.sandbox.plan.process?.missingEnforcement) missing.push('process');
    if (context.sandbox.plan.fs?.missingEnforcement) missing.push('filesystem');
    if (missing.length) {
      containmentFindings.push({
        id: 'dependency-runtime-containment-degraded',
        severity: 'medium',
        file: 'package.json',
        line: 1,
        detail: `Dependency behavior audit is running with degraded ${missing.join('/')} enforcement.`,
      });
    }
  }
  return {
    ok: depsReview.ok,
    command: commandArgs,
    reviewedDependencies: depsReview.summary.reviewed,
    depsReview,
    containmentFindings,
    containment: context.sandbox?.plan
      ? { status: 'sandboxed', mode: context.sandbox.plan.mode, network: context.sandbox.plan.network, process: context.sandbox.plan.process, fs: context.sandbox.plan.fs }
      : { status: 'not-sandboxed' },
  };
}

function emptyScanResult(cwd, base) {
  return {
    cwd,
    ok: true,
    config: base.config,
    findings: [],
    blockedFindings: [],
    warningFindings: [],
    suppressedFindings: [],
  };
}

function safeGit(cwd, args) {
  try {
    return git(cwd, args);
  } catch {
    return '';
  }
}

function safeChangedFiles(cwd) {
  const status = safeGit(cwd, ['status', '--short']);
  return status.split(/\r?\n/)
    .map((line) => line.replace(/^.{1,2}\s+/, '').trim())
    .filter(Boolean)
    .map((file) => path.resolve(cwd, file.replace(/^"|"$/g, '')));
}

function shellDisplayArg(value) {
  return /\s/.test(String(value)) ? JSON.stringify(String(value)) : String(value);
}

function redactEnv(env) {
  const safeKeys = new Set(['CI', 'NODE_ENV', 'GOOS', 'GOARCH', 'RUSTFLAGS', 'PYTHONPATH']);
  return Object.fromEntries(Object.entries(env)
    .filter(([key]) => safeKeys.has(key) || /^EXECFENCE_/i.test(key))
    .map(([key, value]) => [key, redactValue(key, value)]));
}

function redactValue(key, value) {
  if (/TOKEN|SECRET|KEY|PASSWORD|PWD|AUTH/i.test(key)) {
    return '[redacted]';
  }
  return String(value || '').slice(0, 500);
}

function resolveCommand(command) {
  if (process.platform !== 'win32' || path.extname(command)) {
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

function commandInvocation(commandArgs) {
  const executable = resolveCommand(commandArgs[0]);
  const rest = commandArgs.slice(1);
  if (process.platform === 'win32' && /\.(?:cmd|bat)$/i.test(executable)) {
    return {
      command: process.env.ComSpec || 'cmd.exe',
      args: ['/d', '/s', '/c', [executable, ...rest].map(quoteCmdArg).join(' ')],
    };
  }
  return { command: executable, args: rest };
}

function quoteCmdArg(value) {
  const text = String(value);
  if (!/[\s&()^|<>"]/.test(text)) {
    return text;
  }
  return `"${text.replace(/"/g, '\\"')}"`;
}

function isExecutableArtifact(filePath) {
  return /\.(?:asar|bat|cmd|com|dll|dylib|exe|jar|node|scr|sh|so|tar|tgz|vbs|wsf|zip)$/i.test(filePath);
}

function artifactsFor(cwd, files) {
  return files
    .filter((file) => fs.existsSync(file) && fs.statSync(file).isFile())
    .map((file) => {
      const stat = fs.statSync(file);
      return {
        file: path.relative(cwd, file).replaceAll(path.sep, '/'),
        size: stat.size,
        sha256: sha256File(file),
        suspicious: isExecutableArtifact(file),
      };
    });
}

function snapshotFiles(cwd) {
  const snapshot = new Map();
  walkSnapshot(cwd, cwd, snapshot);
  return snapshot;
}

function walkSnapshot(root, current, snapshot) {
  for (const entry of safeReaddir(current)) {
    const fullPath = path.join(current, entry.name);
    const rel = path.relative(root, fullPath).replaceAll(path.sep, '/');
    if (entry.isDirectory()) {
      if (ignoredSnapshotDir(entry.name)) {
        continue;
      }
      walkSnapshot(root, fullPath, snapshot);
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    try {
      const stat = fs.statSync(fullPath);
      snapshot.set(rel, { file: rel, size: stat.size, mtimeMs: stat.mtimeMs, sha256: stat.size <= 5 * 1024 * 1024 ? sha256File(fullPath) : null });
    } catch {
      // File changed while snapshotting.
    }
  }
}

function diffSnapshots(cwd, before, after) {
  const created = [];
  const modified = [];
  const deleted = [];
  const renamed = [];
  for (const [file, current] of after.entries()) {
    const previous = before.get(file);
    if (!previous) {
      created.push(current);
      continue;
    }
    if (previous.size !== current.size || previous.sha256 !== current.sha256) {
      modified.push({ before: previous, after: current, file });
    }
  }
  for (const [file, previous] of before.entries()) {
    if (!after.has(file)) {
      deleted.push(previous);
    }
  }
  for (const removed of [...deleted]) {
    const match = created.find((item) => item.sha256 && item.sha256 === removed.sha256 && item.size === removed.size);
    if (match) {
      renamed.push({ from: removed.file, to: match.file, sha256: match.sha256, size: match.size });
    }
  }
  return {
    created: created.filter((item) => !renamed.some((rename) => rename.to === item.file)),
    modified,
    deleted: deleted.filter((item) => !renamed.some((rename) => rename.from === item.file)),
    renamed,
    summary: {
      created: created.length,
      modified: modified.length,
      deleted: deleted.length,
      renamed: renamed.length,
    },
  };
}

function summarizeSnapshot(snapshot) {
  return { files: snapshot.size };
}

function safeReaddir(dir) {
  try {
    return fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

function ignoredSnapshotDir(name) {
  return new Set(['.git', '.execfence', 'node_modules', 'dist', 'build', 'coverage', 'target', '.next', '.nuxt', '.turbo', '.pytest_cache']).has(name);
}

function localTraceTools() {
  const candidates = process.platform === 'win32'
    ? ['powershell.exe', 'wmic.exe']
    : ['ps', 'lsof', 'strace', 'dtruss', 'fs_usage'];
  return candidates.map((name) => ({ name, available: Boolean(resolveTool(name)) }));
}

function resolveTool(command) {
  try {
    const lookup = process.platform === 'win32' ? 'where' : 'which';
    return execFileSync(lookup, [command], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split(/\r?\n/).find(Boolean) || null;
  } catch {
    return null;
  }
}

module.exports = {
  artifactsFor,
  dependencyBehaviorAudit,
  diffSnapshots,
  runWithFence,
  snapshotFiles,
};
