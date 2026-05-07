'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const bin = path.join(__dirname, '..', 'bin', 'execfence.js');

function runCli(args, options = {}) {
  return execFileSync(process.execPath, [bin, ...args], {
    cwd: options.cwd || path.join(__dirname, '..'),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

test('help output lists grouped public commands with descriptions', () => {
  const output = runCli(['--help']);

  assert.match(output, /Guarded execution:/);
  assert.match(output, /Scanning:/);
  assert.match(output, /npm\/global guard:/);
  assert.match(output, /CI\/release:/);
  assert.match(output, /Supply chain:/);
  assert.match(output, /Reports\/incidents:/);
  assert.match(output, /Policy\/baseline\/trust:/);
  assert.match(output, /Sandbox:/);
  assert.match(output, /Agent integration:/);
  assert.match(output, /Setup:/);
  assert.match(output, /execfence guard global-enable/);
  assert.match(output, /Install global skill\/rules plus reversible multi-ecosystem package-manager shims\./);
  assert.match(output, /execfence deps review/);
  assert.match(output, /--sandbox enforce requires a verified helper/);
  assert.match(output, /execfence sandbox install-helper \[--metadata <file>\|--binary <file>\]\|uninstall-helper\|helper-audit/);
  assert.match(output, /Manage or audit verified platform helper metadata and binaries\./);
});

test('help subcommand matches --help output', () => {
  assert.equal(runCli(['help']), runCli(['--help']));
});

test('empty command still runs scan', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-help-scan-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'help-scan' }, null, 2));

  const output = runCli([], { cwd: root });

  assert.match(output, /\[execfence\] OK/);
});

test('unknown command fails and prints grouped help', () => {
  assert.throws(
    () => runCli(['not-a-command']),
    (error) => {
      const stderr = String(error.stderr || '');
      assert.equal(error.status, 1);
      assert.match(stderr, /Unknown command: not-a-command/);
      assert.match(stderr, /Commands:/);
      assert.match(stderr, /npm\/global guard:/);
      return true;
    },
  );
});
