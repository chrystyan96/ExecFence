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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-coverage-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    scripts: {
      prebuild: 'execfence scan',
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

test('report writes timestamped json evidence without deleting payload', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-evidence-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'sample-app' }, null, 2));
  fs.writeFileSync(path.join(root, 'tailwind.config.js'), "global.i='2-30-4';\n");
  const result = scan({ cwd: root, roots: ['tailwind.config.js'] });

  const report = writeReport(result, { reportDir: 'evidence', command: 'test command' });
  const evidence = JSON.parse(fs.readFileSync(report.filePath, 'utf8'));

  assert.equal(fs.existsSync(path.join(root, 'tailwind.config.js')), true);
  assert.match(path.basename(report.filePath), /^sample-app_\d{4}-\d{2}-\d{2}T/);
  assert.equal(report.files.length, 1);
  assert.equal(evidence.command.display, 'test command');
  assert.equal(evidence.metadata.schemaVersion, 2);
  assert.equal(evidence.summary.totalFindings, 1);
  assert.equal(evidence.findings[0].id, 'void-dokkaebi-loader-marker');
  assert.match(evidence.findings[0].analysis.local, /tailwind\.config\.js:1/);
  assert.ok(evidence.findings[0].research.queries.length > 0);
});
