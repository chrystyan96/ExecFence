'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  guardDisable,
  guardEnable,
  guardGlobalDisable,
  guardGlobalEnable,
  guardGlobalStatus,
  guardPlan,
  guardStatus,
} = require('../lib/guard');

function createGuardFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-guard-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    name: 'guard-app',
    version: '1.0.0',
    scripts: {
      test: 'node --test',
      build: 'vite build',
      dev: 'vite --host 0.0.0.0',
      pack: 'npm pack',
      publish: 'npm publish',
      prepare: 'husky install',
      prepublishOnly: 'npm test',
    },
  }, null, 2));
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), `name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
      - run: go test ./...
      - run: npm publish
`);
  fs.writeFileSync(path.join(root, 'Makefile'), `build:
\tgo build ./...

test:
\tgo test ./...

pack:
\tnpm pack
`);
  fs.mkdirSync(path.join(root, '.vscode'), { recursive: true });
  fs.writeFileSync(path.join(root, '.vscode', 'tasks.json'), JSON.stringify({
    version: '2.0.0',
    tasks: [
      { label: 'test', type: 'shell', command: 'npm test' },
    ],
  }, null, 2));
  return root;
}

test('guard enable dry-run and plan do not mutate project files', () => {
  const root = createGuardFixture();
  const packageBefore = fs.readFileSync(path.join(root, 'package.json'), 'utf8');
  const workflowBefore = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');

  const plan = guardPlan(root);
  const dry = guardEnable(root);

  assert.equal(plan.dryRun, true);
  assert.equal(dry.dryRun, true);
  assert.equal(fs.readFileSync(path.join(root, 'package.json'), 'utf8'), packageBefore);
  assert.equal(fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8'), workflowBefore);
  assert.equal(fs.existsSync(path.join(root, '.execfence')), false);
  assert.ok(dry.wiring.changes.some((change) => change.name === 'prepare'));
});

test('guard enable apply wires project commands, CI, and agent rules', () => {
  const root = createGuardFixture();

  const result = guardEnable(root, { apply: true });
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  const makefile = fs.readFileSync(path.join(root, 'Makefile'), 'utf8');
  const tasks = JSON.parse(fs.readFileSync(path.join(root, '.vscode', 'tasks.json'), 'utf8'));
  const status = guardStatus(root);

  assert.equal(result.dryRun, false);
  assert.equal(pkg.scripts.test, 'execfence run -- node --test');
  assert.equal(pkg.scripts.prepare, 'execfence run -- husky install');
  assert.equal(pkg.scripts.prepublishOnly, 'execfence run -- npm test');
  assert.equal(pkg.scripts['execfence:ci'], 'execfence ci');
  assert.match(workflow, /run: execfence run -- npm test/);
  assert.match(workflow, /run: execfence run -- go test \.\/\.\.\./);
  assert.match(workflow, /run: execfence run -- npm publish/);
  assert.match(makefile, /^build: guard$/m);
  assert.equal(tasks.tasks[0].command, 'execfence run -- npm test');
  assert.equal(fs.existsSync(path.join(root, 'AGENTS.md')), true);
  assert.match(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), /\.execfence\/reports\//);
  assert.equal(status.ok, true);
  assert.equal(status.entrypoints.unprotected, 0);
});

test('guard disable removes generated wrappers and preserves evidence/config directories', () => {
  const root = createGuardFixture();
  guardEnable(root, { apply: true });
  fs.writeFileSync(path.join(root, '.execfence', 'reports', 'sample.json'), '{}\n');

  const result = guardDisable(root);
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  const makefile = fs.readFileSync(path.join(root, 'Makefile'), 'utf8');
  const tasks = JSON.parse(fs.readFileSync(path.join(root, '.vscode', 'tasks.json'), 'utf8'));

  assert.equal(pkg.scripts.test, 'node --test');
  assert.equal(pkg.scripts.prepare, 'husky install');
  assert.equal(pkg.scripts['execfence:ci'], undefined);
  assert.match(workflow, /run: npm test/);
  assert.doesNotMatch(workflow, /run: execfence run -- npm test/);
  assert.match(makefile, /^build:$/m);
  assert.equal(tasks.tasks[0].command, 'npm test');
  assert.equal(fs.existsSync(path.join(root, '.execfence', 'reports', 'sample.json')), true);
  assert.equal(fs.existsSync(path.join(root, '.execfence', 'config', 'execfence.json')), true);
  assert.equal(fs.existsSync(path.join(root, 'AGENTS.md')), false);
  assert.ok(result.changes.some((change) => change.type === 'agent-rule'));
});

test('guard global enable installs skill, agent rules, and npm shims', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-guard-home-'));
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-guard-codex-'));

  const enabled = guardGlobalEnable({ home, codexHome });
  const status = guardGlobalStatus({ home, codexHome });

  assert.equal(enabled.shellInterception.enabled, true);
  assert.equal(status.ok, true);
  assert.equal(status.npmGuard.enabled, true);
  assert.equal(fs.existsSync(path.join(home, '.agents', 'skills', 'execfence', 'defaults.json')), true);
  assert.equal(fs.existsSync(path.join(codexHome, 'skills', 'execfence', 'SKILL.md')), true);
  assert.equal(fs.existsSync(path.join(home, '.execfence', 'shims', 'npm')), true);
  assert.equal(fs.existsSync(path.join(home, '.execfence', 'shims', 'npm.cmd')), true);
  assert.equal(fs.existsSync(path.join(home, '.bashrc')), true);
  assert.equal(fs.existsSync(path.join(home, 'Documents', 'PowerShell', 'Microsoft.PowerShell_profile.ps1')), true);
});

test('guard global disable removes npm shims and leaves agent rules', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-guard-disable-home-'));
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-guard-disable-codex-'));
  guardGlobalEnable({ home, codexHome });

  const disabled = guardGlobalDisable({ home, codexHome });
  const status = guardGlobalStatus({ home, codexHome });

  assert.equal(disabled.ok, true);
  assert.equal(status.npmGuard.enabled, false);
  assert.equal(status.agentRules.every((file) => file.hasRule), true);
  assert.equal(fs.existsSync(path.join(home, '.execfence', 'shims', 'npm')), false);
});
