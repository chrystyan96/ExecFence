'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { verifySourceIntegrity } = require('../scripts/verify-source-integrity.cjs');

const projectRoot = path.resolve(__dirname, '..');

function git(cwd, args) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function commitAll(cwd, message) {
  git(cwd, ['add', '.']);
  git(cwd, ['commit', '-m', message]);
}

test('source integrity accepts the reviewed worktree entrypoints', () => {
  const result = verifySourceIntegrity(projectRoot, { history: false });

  assert.equal(result.ok, true, result.findings.join('\n'));
});

test('source integrity rejects a loader that was removed only from the current tree', () => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-source-integrity-'));
  fs.mkdirSync(path.join(fixture, 'bin'), { recursive: true });
  fs.mkdirSync(path.join(fixture, 'lib'), { recursive: true });
  const canonicalBin = fs.readFileSync(path.join(projectRoot, 'bin', 'execfence.js'), 'utf8');
  fs.writeFileSync(path.join(fixture, 'bin', 'execfence.js'), canonicalBin);
  fs.writeFileSync(path.join(fixture, 'lib', 'cli.js'), "'use strict';\nmodule.exports = {\n  main() {},\n};\n");
  git(fixture, ['init']);
  git(fixture, ['config', 'user.name', 'Integrity Test']);
  git(fixture, ['config', 'user.email', 'integrity@example.test']);
  commitAll(fixture, 'clean');

  fs.appendFileSync(path.join(fixture, 'bin', 'execfence.js'), `\n${'x'.repeat(2_100)}\n`);
  commitAll(fixture, 'tampered');
  fs.writeFileSync(path.join(fixture, 'bin', 'execfence.js'), canonicalBin);
  commitAll(fixture, 'remove current payload');

  const result = verifySourceIntegrity(fixture);

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.startsWith('history ')));
  assert.ok(result.findings.some((finding) => finding.includes('executable bootstrap')));
});
