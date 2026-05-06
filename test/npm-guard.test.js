'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  classifyNpmCommand,
  disableNpmGuard,
  enforceInstallScriptPolicy,
  enforceIgnoreScripts,
  installNpmGuard,
  npmGuardStatus,
  packageSpecsFromArgs,
  resolveRealCommand,
  runNpmGuard,
  shimDir,
} = require('../lib/npm-guard');

function pathEnv(...entries) {
  return entries.join(path.delimiter);
}

function writeFakeCommand(dir, name, marker) {
  fs.mkdirSync(dir, { recursive: true });
  if (process.platform === 'win32') {
    const filePath = path.join(dir, `${name}.cmd`);
    fs.writeFileSync(filePath, `@echo off\r\necho %* > "${marker}"\r\nexit /b 0\r\n`);
    return filePath;
  }
  const filePath = path.join(dir, name);
  fs.writeFileSync(filePath, `#!/bin/sh\necho "$@" > ${shellQuote(marker)}\n`);
  fs.chmodSync(filePath, 0o755);
  return filePath;
}

test('npm guard installs POSIX, cmd, and PowerShell shims', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-npm-guard-home-'));
  const installed = installNpmGuard({ home, execFenceBin: path.join(home, 'execfence.js') });
  const dir = shimDir(home);

  assert.equal(installed.enabled, true);
  for (const name of ['npm', 'npm.cmd', 'npm.ps1', 'npx', 'npx.cmd', 'npx.ps1', 'pnpm', 'pnpm.cmd', 'pnpm.ps1', 'yarn', 'yarn.cmd', 'yarn.ps1', 'yarnpkg', 'yarnpkg.cmd', 'yarnpkg.ps1']) {
    assert.equal(fs.existsSync(path.join(dir, name)), true);
  }
  assert.equal(npmGuardStatus({ home }).enabled, true);
  assert.ok(installed.profiles.some((profile) => profile.hasPathBlock));
});

test('npm guard resolves real npm outside shim directory', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-npm-resolve-home-'));
  const realDir = path.join(home, 'real-bin');
  const marker = path.join(home, 'called.txt');
  writeFakeCommand(realDir, 'npm', marker);
  fs.mkdirSync(shimDir(home), { recursive: true });
  writeFakeCommand(shimDir(home), 'npm', path.join(home, 'shim-called.txt'));

  const resolved = resolveRealCommand('npm', {
    env: { PATH: pathEnv(shimDir(home), realDir) },
    shimDir: shimDir(home),
  });

  assert.equal(path.dirname(resolved), realDir);
});

test('npm guard classifies risky npm and npx commands', () => {
  assert.deepEqual(classifyNpmCommand('npm', ['install']), { risky: true, installLike: true, command: 'install' });
  assert.deepEqual(classifyNpmCommand('npm', ['run', 'build']), { risky: true, installLike: false, command: 'run' });
  assert.deepEqual(classifyNpmCommand('npm', ['view', 'execfence']), { risky: false, installLike: false, command: 'view' });
  assert.deepEqual(classifyNpmCommand('npx', ['vite', '--version']), { risky: true, installLike: false, command: 'exec' });
  assert.deepEqual(classifyNpmCommand('pnpm', ['add', 'left-pad']), { risky: true, installLike: true, command: 'add' });
  assert.deepEqual(classifyNpmCommand('yarn', ['install']), { risky: true, installLike: true, command: 'install' });
  assert.deepEqual(enforceIgnoreScripts(['install', 'left-pad']), ['install', 'left-pad', '--ignore-scripts=true']);
  assert.deepEqual(enforceInstallScriptPolicy('pnpm', ['add', 'left-pad']).args, ['add', 'left-pad', '--ignore-scripts']);
  assert.deepEqual(enforceInstallScriptPolicy('yarn', ['install'], { yarnMajor: 1 }).args, ['install', '--ignore-scripts=true']);
  assert.equal(enforceInstallScriptPolicy('yarn', ['install'], { yarnMajor: 4 }).env.YARN_ENABLE_SCRIPTS, '0');
  assert.deepEqual(packageSpecsFromArgs('npm', ['install', '--save-dev', 'left-pad@1.3.0']), ['left-pad@1.3.0']);
});

test('npm guard delegates clean projects and adds ignore-scripts for installs', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-npm-clean-'));
  const realDir = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-real-npm-'));
  const marker = path.join(root, 'npm-called.txt');
  writeFakeCommand(realDir, 'npm', marker);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'clean' }, null, 2));

  const result = runNpmGuard('npm', ['install', 'left-pad'], {
    cwd: root,
    home: root,
    env: { PATH: pathEnv(realDir) },
    stdio: 'pipe',
    supplyChain: { metadata: { enabled: false } },
  });

  assert.equal(result.ok, true);
  assert.match(fs.readFileSync(marker, 'utf8'), /--ignore-scripts=true/);
});

test('npm guard blocks suspicious projects before npm starts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-npm-block-'));
  const realDir = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-real-npm-'));
  const marker = path.join(root, 'npm-called.txt');
  writeFakeCommand(realDir, 'npm', marker);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'bad' }, null, 2));
  fs.writeFileSync(path.join(root, 'tailwind.config.js'), "global.i='2-30-4';\n");

  const result = runNpmGuard('npm', ['test'], {
    cwd: root,
    home: root,
    env: { PATH: pathEnv(realDir) },
    stdio: 'pipe',
    supplyChain: { metadata: { enabled: false } },
  });

  assert.equal(result.ok, false);
  assert.equal(result.blocked, true);
  assert.equal(fs.existsSync(marker), false);
});

test('npm guard global disable removes shims and profile blocks', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-npm-disable-home-'));
  installNpmGuard({ home, execFenceBin: path.join(home, 'execfence.js') });

  const disabled = disableNpmGuard({ home });

  assert.equal(disabled.enabled, false);
  assert.equal(npmGuardStatus({ home }).enabled, false);
  assert.ok(disabled.profiles.some((profile) => profile.changed));
});

test('package guard delegates pnpm and yarn with lifecycle scripts disabled', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-pm-clean-'));
  const realDir = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-real-pm-'));
  const pnpmMarker = path.join(root, 'pnpm-called.txt');
  const yarnMarker = path.join(root, 'yarn-called.txt');
  writeFakeCommand(realDir, 'pnpm', pnpmMarker);
  writeFakeCommand(realDir, 'yarn', yarnMarker);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'clean' }, null, 2));

  const pnpm = runNpmGuard('pnpm', ['add', 'left-pad'], {
    cwd: root,
    home: root,
    env: { PATH: pathEnv(realDir) },
    stdio: 'pipe',
    supplyChain: { metadata: { enabled: false } },
  });
  const yarn = runNpmGuard('yarn', ['install'], {
    cwd: root,
    home: root,
    env: { PATH: pathEnv(realDir) },
    stdio: 'pipe',
    yarnMajor: 1,
    supplyChain: { metadata: { enabled: false } },
  });

  assert.equal(pnpm.ok, true);
  assert.equal(yarn.ok, true);
  assert.match(fs.readFileSync(pnpmMarker, 'utf8'), /--ignore-scripts/);
  assert.match(fs.readFileSync(yarnMarker, 'utf8'), /--ignore-scripts=true/);
});

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}
