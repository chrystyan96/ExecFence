'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { execFileSync } = require('node:child_process');
const { changedFiles, scanHistory } = require('../lib/git');
const { installGitHook } = require('../lib/hooks');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

test('changedFiles returns modified and untracked files', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-git-'));
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
  fs.writeFileSync(path.join(root, 'a.js'), 'ok\n');
  git(root, ['add', 'a.js']);
  git(root, ['commit', '-m', 'initial']);
  fs.writeFileSync(path.join(root, 'a.js'), 'changed\n');
  fs.writeFileSync(path.join(root, 'b.js'), 'new\n');

  const files = changedFiles(root).map((file) => path.basename(file)).sort();

  assert.deepEqual(files, ['a.js', 'b.js']);
});

test('scanHistory finds injected signature in previous commits', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-history-'));
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
  fs.writeFileSync(path.join(root, 'tailwind.config.js'), "global.i='2-30-4';\n");
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'bad']);

  const result = scanHistory(root, { maxCommits: 10 });

  assert.equal(result.ok, false);
  assert.match(result.findings[0].id, /^history-/);
});

test('installGitHook writes an idempotent pre-commit hook', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-hook-'));
  git(root, ['init']);

  const hookPath = installGitHook(root);
  installGitHook(root);

  const hook = fs.readFileSync(hookPath, 'utf8');
  assert.equal((hook.match(/execfence:start/g) || []).length, 1);
  assert.match(hook, /diff-scan --staged/);
});
