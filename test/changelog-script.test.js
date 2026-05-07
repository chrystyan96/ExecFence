'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const repo = path.resolve(__dirname, '..');
const script = path.join(repo, 'scripts', 'update-changelog.cjs');

function copyFixture(dir) {
  fs.copyFileSync(path.join(repo, 'package.json'), path.join(dir, 'package.json'));
  fs.writeFileSync(path.join(dir, 'CHANGELOG.md'), '# Changelog\n\n## Unreleased\n');
  execFileSync('git', ['init'], { cwd: dir, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
  execFileSync('git', ['add', '.'], { cwd: dir, stdio: 'ignore' });
  execFileSync('git', ['commit', '-m', 'initial'], { cwd: dir, stdio: 'ignore' });
}

test('update-changelog help is non-mutating', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-changelog-help-'));
  copyFixture(root);
  const before = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');

  const output = execFileSync(process.execPath, [script, '--help'], { cwd: root, encoding: 'utf8' });

  assert.match(output, /Usage: node scripts\/update-changelog\.cjs/);
  assert.equal(fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8'), before);
});

test('update-changelog dry run prints release section without writing', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-changelog-dry-'));
  copyFixture(root);
  const before = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');

  const output = execFileSync(process.execPath, [script, '--dry-run'], { cwd: root, encoding: 'utf8' });

  assert.match(output, /## v5\.0\.0 - \d{4}-\d{2}-\d{2}/);
  assert.match(output, /- initial/);
  assert.equal(fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8'), before);
});
