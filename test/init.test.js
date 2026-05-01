'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { detectStack, initProject } = require('../lib/init');

test('detectStack identifies node and github actions', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-detect-'));
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), '{"scripts":{},"devDependencies":{"electron":"1.0.0"},"engines":{"vscode":"^1.80.0"}}\n');
  fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n');
  fs.writeFileSync(path.join(root, 'mcp.json'), '{}\n');

  const stack = detectStack(root);

  assert.equal(stack.node, true);
  assert.equal(stack.githubActions, true);
  assert.equal(stack.pnpm, true);
  assert.equal(stack.electron, true);
  assert.equal(stack.vscodeExtension, true);
  assert.equal(stack.mcp, true);
});

test('initProject adds npm guard script and prepends existing hooks', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-init-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { prebuild: 'npm test' } }, null, 2));

  const result = initProject({ cwd: root });
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const configPath = path.join(root, '.execfence', 'config', 'execfence.json');
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

  assert.ok(result.changes.length >= 2);
  assert.equal(pkg.scripts['execfence:scan'], 'execfence scan');
  assert.equal(pkg.scripts.prebuild, 'npm run execfence:scan && npm test');
  assert.equal(fs.existsSync(configPath), true);
  assert.equal(fs.existsSync(path.join(root, '.execfence', 'config', 'signatures.json')), true);
  assert.equal(fs.existsSync(path.join(root, '.execfence', 'config', 'baseline.json')), true);
  assert.equal(fs.existsSync(path.join(root, '.execfence', 'reports')), true);
  assert.match(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), /\.execfence\/reports\//);
  assert.equal(config.mode, 'block');
  assert.equal(config.policyPack, 'baseline');
  assert.deepEqual(config.warnSeverities, ['medium', 'low']);
  assert.equal(config.$schema, 'https://raw.githubusercontent.com/chrystyan96/execfence/master/schema/execfence.schema.json');
  assert.equal(config.signaturesFile, '.execfence/config/signatures.json');
  assert.equal(config.baselineFile, '.execfence/config/baseline.json');
  assert.equal(config.reportsDir, '.execfence/reports');
  assert.equal(config.reportsGitignore, true);
});

test('initProject dry-run reports changes without writing files', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-dry-run-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { prebuild: 'npm test' } }, null, 2));

  const result = initProject({ cwd: root, dryRun: true });
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

  assert.ok(result.changes.includes('.execfence/config/execfence.json: added'));
  assert.equal(fs.existsSync(path.join(root, '.execfence', 'config', 'execfence.json')), false);
  assert.equal(pkg.scripts.prebuild, 'npm test');
});

test('initProject honors reportsGitignore false when config already exists', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-gitignore-optout-'));
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'execfence.json'), JSON.stringify({
    reportsGitignore: false,
  }, null, 2));

  initProject({ cwd: root });

  assert.equal(fs.existsSync(path.join(root, '.gitignore')), false);
});

test('initProject go preset creates a guarded Makefile', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-go-init-'));

  const result = initProject({ cwd: root, preset: 'go' });
  const makefile = fs.readFileSync(path.join(root, 'Makefile'), 'utf8');

  assert.equal(result.preset, 'go');
  assert.match(makefile, /guard:/);
  assert.match(makefile, /test: guard/);
});
