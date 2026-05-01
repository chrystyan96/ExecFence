'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const { execFileSync } = require('node:child_process');
const { sha256File } = require('./baseline');
const { scan } = require('./scanner');
const { git } = require('./git');

function runWithFence(commandArgs, options = {}) {
  if (!commandArgs.length) {
    throw new Error('Usage: execfence run -- <command>');
  }
  const cwd = path.resolve(options.cwd || process.cwd());
  const startedAt = new Date().toISOString();
  const beforeStatus = safeGit(cwd, ['status', '--short']);
  const beforeFiles = safeChangedFiles(cwd);
  const preflight = scan({ cwd });
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
    },
  };
  if (!preflight.ok) {
    return {
      cwd,
      ok: false,
      mode: 'run',
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

  const invocation = commandInvocation(commandArgs);
  const child = spawnSync(invocation.command, invocation.args, {
    cwd,
    shell: false,
    stdio: options.stdio || 'inherit',
    env: process.env,
  });
  const afterStatus = safeGit(cwd, ['status', '--short']);
  const afterFiles = safeChangedFiles(cwd);
  const changedAfter = afterFiles.filter((file) => !beforeFiles.includes(file));
  const postflight = changedAfter.length ? scan({ cwd, roots: changedAfter }) : emptyScanResult(cwd, preflight);
  const newExecutableArtifacts = changedAfter.filter((file) => isExecutableArtifact(file));
  const artifactFindings = options.denyOnNewExecutable
    ? newExecutableArtifacts.map((file) => ({
      id: 'runtime-new-executable-artifact',
      severity: 'high',
      file: path.relative(cwd, file).replaceAll(path.sep, '/'),
      line: 1,
      detail: 'Runtime command created or modified an executable/archive artifact.',
    }))
    : [];
  const ok = child.status === 0 && postflight.ok && artifactFindings.length === 0;
  return {
    cwd,
    ok,
    mode: 'run',
    config: preflight.config,
    configPath: preflight.configPath,
    baselinePath: preflight.baselinePath,
    roots: preflight.roots,
    findings: [...(preflight.findings || []), ...(postflight.findings || []), ...artifactFindings],
    blockedFindings: [...(preflight.blockedFindings || []), ...(postflight.blockedFindings || []), ...artifactFindings],
    warningFindings: [...(preflight.warningFindings || []), ...(postflight.warningFindings || [])],
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
      },
      artifacts: options.recordArtifacts ? artifactsFor(cwd, changedAfter) : [],
      newExecutableArtifacts: newExecutableArtifacts.map((file) => path.relative(cwd, file).replaceAll(path.sep, '/')),
      postflightOk: postflight.ok,
    },
    command: {
      display: commandArgs.map(shellDisplayArg).join(' '),
      argv: commandArgs,
      shell: false,
    },
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

module.exports = {
  artifactsFor,
  runWithFence,
};
