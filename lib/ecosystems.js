'use strict';

const path = require('node:path');

const npmManagers = ['npm', 'pnpm', 'yarn', 'bun'];
const executableManagers = ['npm', 'npx', 'pnpm', 'yarn', 'yarnpkg', 'bun', 'bunx', 'pip', 'pip3', 'pipx', 'uv', 'poetry', 'cargo', 'go', 'mvn', 'mvnw', 'gradle', 'gradlew', 'dotnet', 'composer', 'bundle', 'bundler'];
const packageManagerFilters = ['auto', ...npmManagers, 'pip', 'uv', 'poetry', 'cargo', 'go', 'maven', 'gradle', 'nuget', 'composer', 'bundler'];

const suspiciousSourcePattern = /raw\.githubusercontent\.com|gist\.githubusercontent\.com|pastebin\.com|http:\/\/|bitbucket\.org|gitlab\.com|github\.com\/[^/]+\/[^/]+\/(?:archive|releases\/download)|git\+ssh|ssh:\/\/|file:|\.\.\//i;

const adapters = [
  {
    id: 'npm',
    ecosystem: 'npm',
    managers: npmManagers,
    tools: ['npm', 'npx', 'pnpm', 'yarn', 'yarnpkg', 'bun', 'bunx'],
    files: ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb', 'package.json'],
    installLike: ['install', 'i', 'add', 'ci', 'update', 'up', 'rebuild'],
    runtimeLike: ['run', 'run-script', 'test', 'start', 'exec', 'x', 'build', 'pack', 'publish', 'version', 'init'],
    risky: ['install', 'i', 'add', 'ci', 'update', 'up', 'rebuild', 'run', 'run-script', 'test', 't', 'tst', 'start', 'stop', 'restart', 'exec', 'x', 'pack', 'publish', 'version', 'init', 'install-test', 'it', 'build'],
    safeInstallPolicy: 'disable-lifecycle-scripts',
    runtimePattern: /\b(?:npm|npx|pnpm|yarn|yarnpkg|bun|bunx|node|vite|webpack|rollup|next|ts-node|tsx|jest|vitest)\b/i,
  },
  {
    id: 'python',
    ecosystem: 'python',
    managers: ['pip', 'pip3', 'pipx', 'uv', 'poetry'],
    tools: ['pip', 'pip3', 'pipx', 'uv', 'poetry'],
    files: ['requirements.txt', 'requirements-dev.txt', 'requirements.lock', 'pyproject.toml', 'poetry.lock', 'uv.lock', 'setup.py'],
    installLike: ['install', 'add', 'sync', 'update'],
    runtimeLike: ['run', 'pytest', 'build'],
    risky: ['install', 'add', 'sync', 'update', 'run', 'pytest', 'build'],
    runtimePattern: /\b(?:pipx\s+run|uv\s+run|poetry\s+run|python\s+-m\s+(?:pytest|build)|pytest\b|python\s+setup\.py)\b/i,
  },
  {
    id: 'cargo',
    ecosystem: 'cargo',
    managers: ['cargo'],
    tools: ['cargo'],
    files: ['Cargo.toml', 'Cargo.lock', 'build.rs'],
    installLike: ['add', 'install', 'update', 'fetch'],
    runtimeLike: ['build', 'test', 'run', 'check'],
    risky: ['add', 'install', 'update', 'fetch', 'build', 'test', 'run', 'check'],
    runtimePattern: /\bcargo\s+(?:build|test|run|check)\b/i,
  },
  {
    id: 'go',
    ecosystem: 'go',
    managers: ['go'],
    tools: ['go'],
    files: ['go.mod', 'go.sum', 'go.work'],
    installLike: ['get', 'install', 'mod', 'work'],
    runtimeLike: ['run', 'build', 'test', 'generate', 'vet'],
    risky: ['get', 'install', 'mod', 'work', 'run', 'build', 'test', 'generate', 'vet'],
    runtimePattern: /\bgo\s+(?:run|build|install|test|generate|vet)\b/i,
    highRiskRuntime: /\bgo\s+generate\b/i,
  },
  {
    id: 'maven',
    ecosystem: 'maven',
    managers: ['mvn', 'mvnw'],
    tools: ['mvn', 'mvnw'],
    files: ['pom.xml'],
    installLike: ['dependency:get', 'dependency:resolve', 'install'],
    runtimeLike: ['test', 'package', 'verify', 'compile', 'exec:java'],
    risky: ['dependency:get', 'dependency:resolve', 'install', 'test', 'package', 'verify', 'compile', 'exec:java'],
    runtimePattern: /\b(?:mvn|mvnw)\s+(?:test|package|verify|compile|exec:java|install)\b/i,
  },
  {
    id: 'gradle',
    ecosystem: 'gradle',
    managers: ['gradle', 'gradlew'],
    tools: ['gradle', 'gradlew'],
    files: ['build.gradle', 'build.gradle.kts', 'gradle.lockfile'],
    installLike: ['dependencies'],
    runtimeLike: ['build', 'test', 'run', 'check'],
    risky: ['dependencies', 'build', 'test', 'run', 'check'],
    runtimePattern: /\b(?:gradle|gradlew)\s+(?:build|test|run|check|dependencies)\b/i,
  },
  {
    id: 'nuget',
    ecosystem: 'nuget',
    managers: ['dotnet'],
    tools: ['dotnet'],
    files: ['packages.lock.json'],
    installLike: ['add', 'restore'],
    runtimeLike: ['build', 'test', 'run', 'pack'],
    risky: ['add', 'restore', 'build', 'test', 'run', 'pack'],
    runtimePattern: /\bdotnet\s+(?:restore|build|test|run|pack)\b/i,
  },
  {
    id: 'composer',
    ecosystem: 'composer',
    managers: ['composer'],
    tools: ['composer'],
    files: ['composer.json', 'composer.lock'],
    installLike: ['require', 'install', 'update'],
    runtimeLike: ['run-script', 'exec', 'test'],
    risky: ['require', 'install', 'update', 'run-script', 'exec', 'test'],
    runtimePattern: /\bcomposer\s+(?:install|update|run-script|exec|test)\b/i,
  },
  {
    id: 'bundler',
    ecosystem: 'bundler',
    managers: ['bundle', 'bundler'],
    tools: ['bundle', 'bundler'],
    files: ['Gemfile', 'Gemfile.lock'],
    installLike: ['add', 'install', 'update'],
    runtimeLike: ['exec', 'test'],
    risky: ['add', 'install', 'update', 'exec', 'test'],
    runtimePattern: /\b(?:bundle|bundler)\s+(?:install|update|exec|test)\b/i,
  },
];

function allAdapters() {
  return adapters;
}

function adapterForTool(tool) {
  const normalized = normalizeTool(tool);
  return adapters.find((adapter) => adapter.tools.includes(normalized)) || null;
}

function adapterForFile(file) {
  const base = path.basename(file);
  if (/^requirements.*\.txt$/i.test(base)) return adapterById('python');
  if (/\.csproj$/i.test(base)) return adapterById('nuget');
  return adapters.find((adapter) => adapter.files.includes(base)) || null;
}

function adapterById(id) {
  return adapters.find((adapter) => adapter.id === id || adapter.managers.includes(id)) || null;
}

function packageManagerForFile(file, fallback = 'auto') {
  if (!file) return fallback || 'auto';
  const base = path.basename(file);
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return 'npm';
  if (base === 'pnpm-lock.yaml') return 'pnpm';
  if (base === 'yarn.lock') return 'yarn';
  if (base === 'bun.lock' || base === 'bun.lockb') return 'bun';
  if (/^requirements.*\.txt$/i.test(base)) return 'pip';
  if (base === 'poetry.lock') return 'poetry';
  if (base === 'uv.lock') return 'uv';
  if (base === 'pyproject.toml' || base === 'setup.py') return 'pip';
  if (base === 'Cargo.toml' || base === 'Cargo.lock') return 'cargo';
  if (base === 'go.mod' || base === 'go.sum' || base === 'go.work') return 'go';
  if (base === 'pom.xml') return 'maven';
  if (base === 'build.gradle' || base === 'build.gradle.kts' || base === 'gradle.lockfile') return 'gradle';
  if (base === 'packages.lock.json' || /\.csproj$/i.test(base)) return 'nuget';
  if (base === 'composer.json' || base === 'composer.lock') return 'composer';
  if (base === 'Gemfile' || base === 'Gemfile.lock') return 'bundler';
  return fallback || 'auto';
}

function ecosystemForManager(manager) {
  const adapter = adapterById(manager);
  return adapter?.ecosystem || manager || 'unknown';
}

function includePackageManager(dep, filter = 'auto') {
  if (!filter || filter === 'auto') {
    return true;
  }
  const manager = packageManagerForFile(dep.lockfile, dep.packageManager || 'auto');
  const adapter = adapterById(filter);
  if (!adapter) {
    return manager === filter || dep.ecosystem === filter;
  }
  return manager === filter || adapter.managers.includes(manager) || dep.ecosystem === adapter.ecosystem;
}

function classifyCommand(tool, args = []) {
  const normalizedTool = normalizeTool(tool);
  const adapter = adapterForTool(normalizedTool);
  if (!adapter) {
    return { risky: false, installLike: false, runtimeLike: false, command: firstCommand(args), manager: normalizedTool, ecosystem: 'unknown' };
  }
  if (normalizedTool === 'npx' || normalizedTool === 'bunx') {
    return { risky: true, installLike: false, runtimeLike: true, command: 'exec', manager: normalizedTool, ecosystem: adapter.ecosystem };
  }
  const command = commandForTool(normalizedTool, args);
  return {
    risky: adapter.risky.includes(command) || adapter.installLike.includes(command) || adapter.runtimeLike.includes(command),
    installLike: installLikeFor(adapter, normalizedTool, command, args),
    runtimeLike: runtimeLikeFor(adapter, normalizedTool, command, args),
    highRiskRuntime: Boolean(adapter.highRiskRuntime && adapter.highRiskRuntime.test(`${normalizedTool} ${args.join(' ')}`)),
    command,
    manager: managerForTool(normalizedTool),
    ecosystem: adapter.ecosystem,
  };
}

function installLikeFor(adapter, tool, command, args) {
  if (adapter.id === 'go') {
    return command === 'get' || (command === 'install' && args.some((arg) => /@/.test(arg))) || (command === 'mod' && ['download', 'tidy'].includes(args[1])) || (command === 'work' && args[1] === 'sync');
  }
  if (adapter.id === 'nuget') {
    return command === 'restore' || (command === 'add' && args.includes('package'));
  }
  return adapter.installLike.includes(command);
}

function runtimeLikeFor(adapter, tool, command, args) {
  if (adapter.id === 'python') {
    return command === 'run' || args.join(' ') === '-m pytest' || args.join(' ') === '-m build' || args[0] === 'setup.py' || command === 'pytest';
  }
  if (adapter.id === 'go') {
    return adapter.runtimeLike.includes(command) || (command === 'install' && args.some((arg) => /@/.test(arg)));
  }
  return adapter.runtimeLike.includes(command);
}

function commandForTool(tool, args = []) {
  if (tool === 'python' || tool === 'python3') {
    if (args[0] === '-m') return args[1] || '-m';
    if (args[0] === 'setup.py') return 'setup.py';
  }
  if (tool === 'uv' && args[0] === 'pip') {
    return args[1] || 'pip';
  }
  return firstCommand(args);
}

function firstCommand(args = []) {
  for (const arg of args) {
    if (!arg || arg === '--') continue;
    if (arg.startsWith('-')) continue;
    return arg;
  }
  return 'install';
}

function managerForTool(tool) {
  if (tool === 'pip3') return 'pip';
  if (tool === 'yarnpkg') return 'yarn';
  if (tool === 'mvnw') return 'maven';
  if (tool === 'gradlew') return 'gradle';
  if (tool === 'bundler') return 'bundler';
  return tool;
}

function normalizeTool(tool) {
  return String(tool || '').toLowerCase();
}

function commandMatchesRuntimeAudit(commandText) {
  return adapters.some((adapter) => adapter.runtimePattern?.test(commandText));
}

function highRiskRuntimeCommand(commandText) {
  return adapters.some((adapter) => adapter.highRiskRuntime?.test(commandText));
}

function lockfileNames() {
  return Array.from(new Set(adapters.flatMap((adapter) => adapter.files).filter((file) => !file.includes('*'))));
}

function isSuspiciousSource(source) {
  return suspiciousSourcePattern.test(String(source || ''));
}

module.exports = {
  adapters,
  allAdapters,
  adapterById,
  adapterForFile,
  adapterForTool,
  classifyCommand,
  commandMatchesRuntimeAudit,
  ecosystemForManager,
  executableManagers,
  highRiskRuntimeCommand,
  includePackageManager,
  isSuspiciousSource,
  lockfileNames,
  managerForTool,
  packageManagerFilters,
  packageManagerForFile,
};
