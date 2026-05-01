'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { analyzeCoverage } = require('../lib/coverage');
const { runDoctor } = require('../lib/doctor');
const { scan } = require('../lib/scanner');
const { writeReport } = require('../lib/report');

test('coverage detects unguarded and guarded package scripts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-coverage-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    scripts: {
      prebuild: 'security-guardrails scan',
      build: 'vite build',
      test: 'node --test',
    },
  }, null, 2));

  const result = analyzeCoverage(root);

  assert.equal(result.ok, false);
  assert.ok(result.entrypoints.some((entry) => entry.name === 'build' && entry.guarded));
  assert.ok(result.uncovered.some((entry) => entry.name === 'test'));
});

test('doctor proves known malicious fixture is blocked and cleaned up', () => {
  const result = runDoctor();

  assert.equal(result.ok, true);
  assert.equal(fs.existsSync(result.fixtureDir), false);
});

test('report writes markdown and json evidence without deleting payload', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-report-'));
  fs.writeFileSync(path.join(root, 'tailwind.config.js'), "global.i='2-30-4';\n");
  const result = scan({ cwd: root, roots: ['tailwind.config.js'] });

  const report = writeReport(result, { reportDir: 'evidence', command: 'test command' });

  assert.equal(fs.existsSync(path.join(root, 'tailwind.config.js')), true);
  assert.equal(fs.existsSync(path.join(root, 'evidence', 'report.json')), true);
  assert.match(fs.readFileSync(path.join(root, 'evidence', 'report.md'), 'utf8'), /void-dokkaebi-loader-marker/);
  assert.equal(report.files.length, 2);
});
