'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { execFileSync } = require('node:child_process');
const { runWithFence } = require('../lib/runtime');
const { diffManifest, generateManifest, writeManifest } = require('../lib/manifest');
const { htmlReport, incidentFromReport, listReports, diffReports, readReport } = require('../lib/investigation');
const { indicatorsFor, enrichFindings } = require('../lib/enrichment');
const { trustAdd, trustAudit, packAudit } = require('../lib/supply-chain');
const { agentReport } = require('../lib/agent-report');
const { scan } = require('../lib/scanner');
const { writeReport } = require('../lib/report');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

test('runtime gate blocks before executing suspicious projects', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-run-block-'));
  fs.writeFileSync(path.join(root, 'tailwind.config.js'), "global.i='2-30-4';\n");
  const marker = path.join(root, 'should-not-exist.txt');

  const result = runWithFence([process.execPath, '-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, 'ran')`], {
    cwd: root,
    stdio: 'pipe',
  });

  assert.equal(result.ok, false);
  assert.equal(result.runtimeTrace.blocked, true);
  assert.equal(result.runtimeTrace.exitCode, null);
  assert.equal(fs.existsSync(marker), false);
});

test('runtime gate executes clean commands and records trace evidence', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-run-clean-'));
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'run-clean' }, null, 2));
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  const output = path.join(root, 'created.txt');

  const result = runWithFence([process.execPath, '-e', `require('fs').writeFileSync(${JSON.stringify(output)}, 'ok')`], {
    cwd: root,
    stdio: 'pipe',
  });

  assert.equal(result.ok, true);
  assert.equal(result.runtimeTrace.exitCode, 0);
  assert.ok(result.runtimeTrace.durationMs >= 0);
  assert.ok(result.runtimeTrace.after.changedAfter.some((file) => file.endsWith('created.txt')));
  assert.equal(fs.existsSync(output), true);
});

test('execution manifest records entrypoints and diffs new sensitive scripts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-manifest-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    scripts: {
      test: 'execfence run -- node --test',
    },
  }, null, 2));
  const previous = writeManifest(root).manifest;
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    scripts: {
      test: 'execfence run -- node --test',
      build: 'vite build',
    },
  }, null, 2));

  const current = generateManifest(root);
  const diff = diffManifest(current, previous);

  assert.equal(fs.existsSync(path.join(root, '.execfence', 'manifest.json')), true);
  assert.equal(diff.ok, false);
  assert.ok(diff.added.some((entry) => entry.name === 'build'));
  assert.ok(diff.risk.some((entry) => /New execution entrypoint/.test(entry.reason)));
});

test('report investigation commands list, diff, html, and incident artifacts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-investigate-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'investigate-app' }, null, 2));
  fs.writeFileSync(path.join(root, 'tailwind.config.js'), "global.i='2-30-4';\n");
  const suspicious = writeReport(scan({ cwd: root, roots: ['tailwind.config.js'] }), { command: 'execfence scan' });
  fs.unlinkSync(path.join(root, 'tailwind.config.js'));
  const clean = writeReport(scan({ cwd: root }), { command: 'execfence scan' });

  const listed = listReports(root);
  const diff = diffReports(root, suspicious.filePath, clean.filePath);
  const html = htmlReport(root, suspicious.filePath);
  const incident = incidentFromReport(root, suspicious.filePath);

  assert.equal(listed.length, 2);
  assert.equal(readReport(root, suspicious.filePath).report.metadata.schemaVersion, 2);
  assert.equal(diff.removedFindings.length, 1);
  assert.equal(fs.existsSync(html.htmlPath), true);
  assert.equal(fs.existsSync(incident.incidentPath), true);
});

test('enrichment builds redacted public-source work without network for rule-only findings', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-enrich-'));
  const finding = {
    id: 'void-dokkaebi-loader-marker',
    severity: 'critical',
    file: 'tailwind.config.js',
    detail: 'Injected loader marker',
  };

  const indicators = indicatorsFor(finding);
  const enrichment = enrichFindings(root, [finding], { enrichment: { cacheTtlMs: 1000 } });

  assert.deepEqual(indicators.packages, []);
  assert.equal(enrichment.status, 'complete');
  assert.equal(enrichment.results[0].sources[0].name, 'web-query');
});

test('trust store pins files by hash and audits changed trusted files', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-trust-'));
  const file = path.join(root, 'tool.exe');
  fs.writeFileSync(file, 'reviewed');

  const added = trustAdd(root, 'tool.exe', {
    reason: 'Reviewed local helper',
    owner: 'security',
    expiresAt: '2999-01-01',
  });
  fs.writeFileSync(file, 'changed');
  const audit = trustAudit(root);

  assert.equal(fs.existsSync(added.filePath), true);
  assert.equal(audit.ok, false);
  assert.equal(audit.findings[0].id, 'trusted-file-hash-mismatch');
});

test('pack audit flags dangerous files in npm package contents', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-pack-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'pack-app', version: '1.0.0', files: ['payload.exe'] }, null, 2));
  fs.writeFileSync(path.join(root, 'payload.exe'), 'not really executable');

  const result = packAudit(root);

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.id === 'pack-dangerous-artifact'));
});

test('agent report flags sensitive execution surface changes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-agent-report-'));
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
  fs.writeFileSync(path.join(root, 'README.md'), '# ok\n');
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { postinstall: 'node install.js' } }, null, 2));

  const result = agentReport(root);

  assert.equal(result.ok, false);
  assert.deepEqual(result.sensitiveChanges, ['package.json']);
});
