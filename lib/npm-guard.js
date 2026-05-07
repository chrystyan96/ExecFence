'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { scan } = require('./scanner');
const { formatFindings } = require('./output');
const { writeReport } = require('./report');
const { formatReviewText, reviewPackageSpecs } = require('./deps-review');
const { adapterForTool, classifyCommand, executableManagers, managerForTool } = require('./ecosystems');

const startMarker = '<!-- EXECFENCE:NPM-GUARD:START -->';
const endMarker = '<!-- EXECFENCE:NPM-GUARD:END -->';
const activeEnv = 'EXECFENCE_NPM_GUARD_ACTIVE';
const riskyNpmCommands = new Set([
  'install',
  'i',
  'add',
  'ci',
  'update',
  'up',
  'rebuild',
  'run',
  'run-script',
  'test',
  't',
  'tst',
  'start',
  'stop',
  'restart',
  'exec',
  'x',
  'pack',
  'publish',
  'version',
  'init',
  'install-test',
  'it',
  'build',
]);
const installLikeCommands = new Set(['install', 'i', 'add', 'ci', 'update', 'up', 'rebuild']);
const unguardedCommands = ['audit', 'cache', 'config', 'doctor', 'fund', 'help', 'login', 'logout', 'outdated', 'owner', 'ping', 'profile', 'search', 'team', 'token', 'view', 'whoami'];
const shimTools = executableManagers;

function shimDir(home = os.homedir()) {
  return path.join(path.resolve(home), '.execfence', 'shims');
}

function defaultExecFenceBin() {
  return path.resolve(__dirname, '..', 'bin', 'execfence.js');
}

function installNpmGuard(options = {}) {
  const home = path.resolve(options.home || os.homedir());
  const dir = shimDir(home);
  const execFenceBin = path.resolve(options.execFenceBin || defaultExecFenceBin());
  fs.mkdirSync(dir, { recursive: true });
  const shims = writeShims(dir, execFenceBin);
  const profiles = updateProfiles(home, dir);
  return {
    enabled: true,
    shimDir: dir,
    execFenceBin,
    shims,
    profiles,
    status: npmGuardStatus({ home, execFenceBin }),
  };
}

function disableNpmGuard(options = {}) {
  const home = path.resolve(options.home || os.homedir());
  const dir = shimDir(home);
  const removed = [];
  for (const name of shimNames()) {
    const filePath = path.join(dir, name);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      removed.push(filePath);
    }
  }
  const profiles = profilePaths(home).map((filePath) => removeMarkedBlock(filePath));
  return {
    enabled: false,
    shimDir: dir,
    removed,
    profiles,
    preserved: ['.execfence/reports/', '.execfence/config/', '.execfence/trust/', '.execfence/cache/', '.execfence/quarantine/'],
    status: npmGuardStatus({ home }),
  };
}

function npmGuardStatus(options = {}) {
  const home = path.resolve(options.home || os.homedir());
  const env = options.env || process.env;
  const dir = shimDir(home);
  const pathEntries = splitPath(env.PATH || env.Path || '');
  const activeInPath = pathEntries.length > 0 && samePath(pathEntries[0], dir);
  const presentInPath = pathEntries.some((entry) => samePath(entry, dir));
  const real = Object.fromEntries(shimTools.map((item) => [item, resolveRealCommand(item, { env, shimDir: dir })]));
  const shims = shimNames().map((name) => {
    const filePath = path.join(dir, name);
    return { filePath, exists: fs.existsSync(filePath) };
  });
  const profiles = profilePaths(home).map((filePath) => ({
    filePath,
    exists: fs.existsSync(filePath),
    hasPathBlock: hasMarker(filePath),
  }));
  const enabled = shims.every((shim) => shim.exists);
  const tools = shimTools.map((tool) => toolStatus(tool, { dir, env, activeInPath, presentInPath, realCommand: real[tool] }));
  const actionPlan = globalGuardActionPlan({ enabled, activeInPath, presentInPath, real, tools, env });
  return {
    enabled,
    activeInPath,
    presentInPath,
    shimDir: dir,
    real,
    recursionGuard: activeEnv,
    shims,
    tools,
    profiles,
    coverageGaps: globalGuardCoverageGaps({ activeInPath, real }),
    actionPlan,
    unsupportedCommands: unguardedCommands,
    note: !enabled
      ? 'package-manager guard shims are not installed.'
      : activeInPath
      ? 'known package managers resolve through ExecFence shims in the current PATH.'
      : presentInPath
      ? 'Move the ExecFence shim directory before package managers in PATH for this session.'
      : 'Open a new shell or add the shim directory to PATH before package-manager commands for this session.',
  };
}

function toolStatus(tool, status) {
  const shimFiles = [`${tool}`, `${tool}.cmd`, `${tool}.ps1`].map((name) => path.join(status.dir, name));
  const installedShim = shimFiles.every((filePath) => fs.existsSync(filePath));
  const adapter = adapterForTool(tool);
  return {
    tool,
    ecosystem: adapter?.ecosystem || 'unknown',
    installedShim,
    realCommand: status.realCommand || null,
    activeInCurrentPath: Boolean(status.activeInPath && installedShim),
    needsNewShell: Boolean(installedShim && !status.activeInPath),
    risk: !installedShim ? 'uninstalled' : (!status.activeInPath ? 'inactive-path' : 'covered'),
  };
}

function globalGuardActionPlan(status) {
  const actions = [];
  if (!status.enabled) {
    actions.push({
      id: 'install-global-shims',
      severity: 'high',
      reason: 'Package-manager guard shims are not fully installed.',
      command: 'execfence guard global-enable',
    });
  }
  if (status.enabled && !status.activeInPath) {
    actions.push({
      id: 'activate-current-shell-path',
      severity: 'high',
      reason: 'The current shell PATH does not resolve through the ExecFence shim directory.',
      command: process.platform === 'win32' ? '$env:Path = "$HOME\\.execfence\\shims;$env:Path"' : 'export PATH="$HOME/.execfence/shims:$PATH"',
    });
    actions.push({
      id: 'open-new-shell',
      severity: 'medium',
      reason: 'Shell profile changes usually require a new terminal session.',
      command: 'Open a new terminal, then run execfence guard global-status.',
    });
  }
  if (Object.keys(status.env).some((key) => /^VOLTA_|^NVM_|^ASDF_|^COREPACK_/i.test(key))) {
    actions.push({
      id: 'verify-version-manager-path',
      severity: 'medium',
      reason: 'A version manager is active and can put package managers ahead of ExecFence shims.',
      command: 'Run where/which for npm, pnpm, yarn, node, go, cargo, pip, and verify the ExecFence shim directory appears first.',
    });
  }
  if (status.env.CI) {
    actions.push({
      id: 'wire-ci-guardrails',
      severity: 'medium',
      reason: 'CI jobs need project-local wrappers because global shell shims are not guaranteed.',
      command: 'execfence guard enable --apply && execfence ci',
    });
  }
  const missingTools = status.tools.filter((tool) => !tool.installedShim);
  if (missingTools.length) {
    actions.push({
      id: 'missing-tool-shims',
      severity: 'medium',
      reason: `Missing shims for ${missingTools.slice(0, 12).map((tool) => tool.tool).join(', ')}${missingTools.length > 12 ? ', ...' : ''}.`,
      command: 'execfence guard global-enable',
    });
  }
  if (actions.length === 0) {
    actions.push({
      id: 'global-guard-ready',
      severity: 'info',
      reason: 'Global package-manager guard is installed and active in the current PATH.',
      command: 'No action required.',
    });
  }
  return actions;
}

function globalGuardCoverageGaps(status) {
  const gaps = [];
  if (!status.activeInPath) {
    gaps.push('current shell PATH does not resolve through ExecFence shims yet');
  }
  if (process.env.CI) {
    gaps.push('CI job detected; verify the workflow invokes execfence ci or execfence run wrappers');
  }
  if (process.env.CONTAINER || fs.existsSync('/.dockerenv')) {
    gaps.push('container runtime detected; install global shims inside the container or use project guardrails');
  }
  if (Object.keys(process.env).some((key) => /^VOLTA_|^NVM_|^ASDF_|^COREPACK_/i.test(key))) {
    gaps.push('version-manager environment detected; verify Corepack/Volta/nvm/asdf resolve through ExecFence shims');
  }
  gaps.push('IDE-integrated package managers and local wrapper scripts still need project/CI guardrails');
  return gaps;
}

function runNpmGuard(tool, args, options = {}) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const env = options.env || process.env;
  const home = path.resolve(options.home || os.homedir());
  const dir = options.shimDir || shimDir(home);
  const normalizedTool = normalizeTool(tool);
  const real = resolveRealCommand(normalizedTool, { env, shimDir: dir });
  if (!real) {
    console.error(`[execfence] Could not resolve the real ${normalizedTool} outside ${dir}`);
    return { ok: false, exitCode: 127, tool: normalizedTool, args };
  }
  if (env[activeEnv] !== '1') {
    const classification = classifyCommand(normalizedTool, args);
    if (classification.risky) {
      const preflight = scan({ cwd, mode: 'block', failOn: ['critical', 'high'] });
      const report = writeReport(preflight, { command: `execfence npm-guard ${normalizedTool} ${args.join(' ')}` });
      if (!preflight.ok) {
        console.error(formatFindings(preflight.findings, preflight));
        console.error(`[execfence] npm guard blocked before ${normalizedTool} started. Report: ${report.filePath}`);
        return { ok: false, blocked: true, exitCode: 1, tool: normalizedTool, args, report: report.filePath, classification };
      }
      if (classification.installLike) {
        const specs = packageSpecsFromArgs(normalizedTool, args);
        if (specs.length > 0 || options.reviewInstallWithoutSpecs) {
          const review = reviewPackageSpecs(cwd, specs, {
            packageManager: packageManagerForTool(normalizedTool),
            config: options.supplyChain,
            fetchMetadata: options.fetchMetadata,
            registryBaseUrl: options.registryBaseUrl,
          });
          if (review.dependencies.length > 0) {
            console.error(formatReviewText(review));
          }
          if (!review.ok) {
            const report = writeReport({
              cwd,
              mode: 'npm-guard-deps-review',
              ok: false,
              findings: review.findings,
              blockedFindings: review.findings.filter((finding) => ['critical', 'high'].includes(finding.severity || 'high')),
              warningFindings: review.findings.filter((finding) => !['critical', 'high'].includes(finding.severity || 'high')),
              suppressedFindings: [],
              config: {},
              roots: [],
            }, { command: `execfence npm-guard ${normalizedTool} ${args.join(' ')}` });
            console.error(`[execfence] package metadata review blocked before ${normalizedTool} started. Report: ${report.filePath}`);
            return { ok: false, blocked: true, exitCode: 1, tool: normalizedTool, args, report: report.filePath, classification, review };
          }
        }
        const policy = enforceInstallScriptPolicy(normalizedTool, args, { real, env, yarnMajor: options.yarnMajor });
        args = policy.args;
        const childEnv = { ...env, ...policy.env };
        console.error(policy.suppressedLifecycleScripts
          ? `[execfence] ${normalizedTool} guard disabled lifecycle scripts for install-like command. Review reports/deps before running lifecycle scripts manually.`
          : `[execfence] ${normalizedTool} guard completed preflight and dependency review. This ecosystem has no universal lifecycle-suppression flag.`);
        return runDelegatedCommand(real, args, { cwd, env: childEnv, stdio: options.stdio, tool: normalizedTool });
      }
    }
  }
  return runDelegatedCommand(real, args, { cwd, env, stdio: options.stdio, tool: normalizedTool });
}

function runDelegatedCommand(real, args, options = {}) {
  const delegated = delegateCommand(real, args);
  const child = spawnSync(delegated.command, delegated.args, {
    cwd: options.cwd,
    stdio: options.stdio || 'inherit',
    env: { ...(options.env || process.env), [activeEnv]: '1' },
    shell: false,
  });
  const exitCode = child.status ?? (child.error ? 1 : 0);
  if (child.error) {
    console.error(`[execfence] Failed to run real ${options.tool || 'package manager'}: ${child.error.message}`);
  }
  return { ok: exitCode === 0, exitCode, tool: options.tool, real, args };
}

function classifyNpmCommand(tool, args = []) {
  const classification = classifyCommand(tool, args);
  return {
    risky: classification.risky,
    installLike: classification.installLike,
    command: classification.command,
  };
}

function firstCommand(args) {
  for (const arg of args) {
    if (!arg || arg === '--') {
      continue;
    }
    if (arg.startsWith('-')) {
      continue;
    }
    return arg;
  }
  return 'install';
}

function enforceIgnoreScripts(args) {
  const next = [...args];
  next.push('--ignore-scripts=true');
  return next;
}

function enforcePnpmIgnoreScripts(args) {
  const next = [...args];
  next.push('--ignore-scripts');
  return next;
}

function enforceInstallScriptPolicy(tool, args, options = {}) {
  if (tool === 'pnpm') {
    return { args: enforcePnpmIgnoreScripts(args), env: {}, suppressedLifecycleScripts: true };
  }
  if (tool === 'yarn' || tool === 'yarnpkg') {
    const major = options.yarnMajor || detectYarnMajor(options.real, options.env);
    if (major === 1) {
      return { args: enforceIgnoreScripts(args), env: {}, suppressedLifecycleScripts: true };
    }
    return { args, env: { YARN_ENABLE_SCRIPTS: '0' }, suppressedLifecycleScripts: true };
  }
  if (['npm', 'npx', 'bun', 'bunx'].includes(tool)) {
    return { args: enforceIgnoreScripts(args), env: {}, suppressedLifecycleScripts: true };
  }
  return { args, env: {}, suppressedLifecycleScripts: false };
}

function resolveRealCommand(tool, options = {}) {
  const env = options.env || process.env;
  const dir = options.shimDir ? path.resolve(options.shimDir) : null;
  for (const entry of splitPath(env.PATH || env.Path || '')) {
    if (!entry || (dir && samePath(entry, dir))) {
      continue;
    }
    for (const name of commandCandidates(tool)) {
      const filePath = path.join(entry, name);
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        return filePath;
      }
    }
  }
  return null;
}

function writeShims(dir, execFenceBin) {
  const shims = [];
  for (const tool of shimTools) {
    const posix = path.join(dir, tool);
    const cmd = path.join(dir, `${tool}.cmd`);
    const ps1 = path.join(dir, `${tool}.ps1`);
    fs.writeFileSync(posix, `#!/bin/sh\nexec node ${shellQuote(execFenceBin)} npm-guard ${tool} "$@"\n`);
    try {
      fs.chmodSync(posix, 0o755);
    } catch {
      // chmod is best-effort on Windows.
    }
    fs.writeFileSync(cmd, `@echo off\r\nnode "${execFenceBin}" npm-guard ${tool} %*\r\n`);
    fs.writeFileSync(ps1, `& node "${execFenceBin}" npm-guard ${tool} @args\r\nexit $LASTEXITCODE\r\n`);
    shims.push(posix, cmd, ps1);
  }
  return shims.map((filePath) => ({ filePath, exists: fs.existsSync(filePath) }));
}

function delegateCommand(real, args) {
  if (process.platform === 'win32' && /\.(?:cmd|bat)$/i.test(real)) {
    return {
      command: process.env.ComSpec || 'cmd.exe',
      args: ['/d', '/c', real, ...args],
    };
  }
  return { command: real, args };
}

function updateProfiles(home, dir) {
  return profilePaths(home).map((filePath) => {
    const block = profileBlock(filePath, dir);
    const changed = writeMarkedBlock(filePath, block);
    return { filePath, changed, hasPathBlock: hasMarker(filePath) };
  });
}

function profilePaths(home) {
  return [
    path.join(home, '.profile'),
    path.join(home, '.bashrc'),
    path.join(home, '.zshrc'),
    path.join(home, 'Documents', 'PowerShell', 'Microsoft.PowerShell_profile.ps1'),
    path.join(home, 'Documents', 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1'),
  ];
}

function profileBlock(filePath, dir) {
  if (/\.ps1$/i.test(filePath)) {
    const escaped = dir.replaceAll('`', '``').replaceAll('"', '`"');
    return `${startMarker}\n$execFenceShim = "${escaped}"\nif ((Test-Path $execFenceShim) -and (($env:Path -split [IO.Path]::PathSeparator) -notcontains $execFenceShim)) {\n  $env:Path = "$execFenceShim$([IO.Path]::PathSeparator)$env:Path"\n}\n${endMarker}\n`;
  }
  const escaped = dir.replaceAll('\\', '/').replaceAll('"', '\\"');
  return `${startMarker}\nif [ -d "${escaped}" ]; then\n  case ":$PATH:" in\n    *":${escaped}:"*) ;;\n    *) export PATH="${escaped}:$PATH" ;;\n  esac\nfi\n${endMarker}\n`;
}

function writeMarkedBlock(filePath, block) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
  const without = removeBlockText(existing);
  const next = `${without.trimEnd()}${without.trimEnd() ? '\n\n' : ''}${block}`;
  if (next === existing) {
    return false;
  }
  fs.writeFileSync(filePath, next);
  return true;
}

function removeMarkedBlock(filePath) {
  if (!fs.existsSync(filePath)) {
    return { filePath, changed: false, deleted: false };
  }
  const existing = fs.readFileSync(filePath, 'utf8');
  const next = removeBlockText(existing).trimEnd();
  if (next === existing.trimEnd()) {
    return { filePath, changed: false, deleted: false };
  }
  if (!next) {
    fs.unlinkSync(filePath);
    return { filePath, changed: true, deleted: true };
  }
  fs.writeFileSync(filePath, `${next}\n`);
  return { filePath, changed: true, deleted: false };
}

function removeBlockText(value) {
  const pattern = new RegExp(`${escapeRegExp(startMarker)}[\\s\\S]*?${escapeRegExp(endMarker)}\\s*`, 'g');
  return value.replace(pattern, '');
}

function hasMarker(filePath) {
  return fs.existsSync(filePath) && fs.readFileSync(filePath, 'utf8').includes(startMarker);
}

function shimNames() {
  return shimTools.flatMap((tool) => [tool, `${tool}.cmd`, `${tool}.ps1`]);
}

function commandCandidates(tool) {
  if (process.platform === 'win32') {
    return [`${tool}.cmd`, `${tool}.exe`, `${tool}.bat`, tool];
  }
  return [tool];
}

function splitPath(value) {
  return String(value || '').split(path.delimiter).filter(Boolean);
}

function samePath(a, b) {
  return path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase();
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeTool(tool) {
  if (shimTools.includes(tool)) {
    return tool;
  }
  return 'npm';
}

function packageManagerForTool(tool) {
  return managerForTool(tool);
}

function packageSpecsFromArgs(tool, args = []) {
  const classification = classifyNpmCommand(tool, args);
  const fullClassification = classifyCommand(tool, args);
  const command = classification.command;
  if (tool === 'npx') {
    return args.filter((arg) => arg && !arg.startsWith('-') && arg !== '--').slice(0, 1);
  }
  if (!fullClassification.installLike) {
    return [];
  }
  if (tool === 'go') {
    if (command === 'get') return args.slice(1).filter((arg) => arg && !arg.startsWith('-'));
    if (command === 'install') return args.slice(1).filter((arg) => /@/.test(arg));
    return [];
  }
  if (tool === 'cargo') {
    if (command === 'add') return args.slice(1).filter((arg) => arg && !arg.startsWith('-'));
    if (command === 'install') return args.slice(1).filter((arg) => arg && !arg.startsWith('-'));
    return [];
  }
  if (tool === 'dotnet') {
    const index = args.indexOf('package');
    return index >= 0 ? args.slice(index + 1).filter((arg) => arg && !arg.startsWith('-')).slice(0, 1) : [];
  }
  const specs = [];
  let seenCommand = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg || arg === '--') {
      continue;
    }
    if (arg.startsWith('-')) {
      if (flagTakesValue(arg)) {
        index += 1;
      }
      continue;
    }
    if (!seenCommand) {
      seenCommand = true;
      continue;
    }
    specs.push(arg);
  }
  return specs;
}

function flagTakesValue(arg) {
  return ['--save-prefix', '--tag', '--registry', '--cache', '--prefix', '--filter', '--workspace', '--cwd'].includes(arg);
}

function detectYarnMajor(real, env = process.env) {
  const yarn = real?.yarn || real?.yarnpkg || real;
  if (!yarn) {
    return 2;
  }
  try {
    const child = spawnSync(yarn, ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], env: { ...env, [activeEnv]: '1' } });
    const major = Number(String(child.stdout || '').trim().split('.')[0]);
    return Number.isFinite(major) && major > 0 ? major : 2;
  } catch {
    return 2;
  }
}

module.exports = {
  activeEnv,
  classifyNpmCommand,
  disableNpmGuard,
  enforceInstallScriptPolicy,
  enforceIgnoreScripts,
  installNpmGuard,
  npmGuardStatus,
  packageSpecsFromArgs,
  profilePaths,
  resolveRealCommand,
  runNpmGuard,
  shimDir,
  startMarker,
};
