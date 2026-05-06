'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { execFileSync } = require('node:child_process');
const { runWithFence } = require('../lib/runtime');
const { diffManifest, generateManifest, writeManifest } = require('../lib/manifest');
const { htmlReport, incidentBundle, incidentFromReport, latestReport, listReports, diffReports, markdownReport, pruneReports, readReport, riskRegression } = require('../lib/investigation');
const { indicatorsFor, enrichFindings, redactionPreview } = require('../lib/enrichment');
const { trustAdd, trustAudit, packAudit } = require('../lib/supply-chain');
const { agentReport } = require('../lib/agent-report');
const { scan } = require('../lib/scanner');
const { writeReport } = require('../lib/report');
const { depsDiff } = require('../lib/deps');
const { wireProject } = require('../lib/wire');
const { runCi } = require('../lib/ci');
const { addBaselineFromReport } = require('../lib/baseline');
const { adoptProject } = require('../lib/adopt');
const { explainPolicy, testPolicy } = require('../lib/policy');

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
  assert.ok(result.runtimeTrace.after.fileChanges.created.some((file) => file.file === 'created.txt'));
  assert.equal(fs.existsSync(output), true);
});

test('runtime trace detects renamed and deleted files from snapshots', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-run-snapshot-'));
  fs.writeFileSync(path.join(root, 'old.txt'), 'same');
  fs.writeFileSync(path.join(root, 'remove.txt'), 'delete');

  const result = runWithFence([process.execPath, '-e', `
const fs = require('fs');
fs.renameSync('old.txt', 'new.txt');
fs.unlinkSync('remove.txt');
`], { cwd: root, stdio: 'pipe' });

  assert.equal(result.ok, true);
  assert.ok(result.runtimeTrace.after.fileChanges.renamed.some((entry) => entry.from === 'old.txt' && entry.to === 'new.txt'));
  assert.ok(result.runtimeTrace.after.fileChanges.deleted.some((entry) => entry.file === 'remove.txt'));
});

test('runtime gate can record artifacts and deny new executable outputs', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-run-artifact-'));
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'artifact-app' }, null, 2));
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  const output = path.join(root, 'payload.exe');

  const result = runWithFence([process.execPath, '-e', `require('fs').writeFileSync(${JSON.stringify(output)}, 'exe')`], {
    cwd: root,
    stdio: 'pipe',
    recordArtifacts: true,
    denyOnNewExecutable: true,
  });

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.id === 'runtime-new-executable-artifact'));
  assert.ok(result.runtimeTrace.artifacts.some((artifact) => artifact.file === 'payload.exe' && artifact.suspicious));
});

test('runtime dependency behavior audit records containment gaps for changed deps', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-run-dep-behavior-'));
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'dep-behavior' }, null, 2));
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'dep-behavior' } } }, null, 2));
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'dep-behavior' },
      'node_modules/left-pad': { version: '1.3.0', resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz', integrity: 'sha512-left' },
    },
  }, null, 2));

  const result = runWithFence([process.execPath, '-e', 'console.log("ok")'], {
    cwd: root,
    stdio: 'pipe',
    dependencyBehaviorAudit: true,
    supplyChain: { metadata: { enabled: false } },
  });

  assert.equal(result.ok, true);
  assert.equal(result.runtimeTrace.dependencyBehavior.reviewedDependencies, 1);
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-runtime-containment-missing'));
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
  const markdown = markdownReport(root, suspicious.filePath);
  const incident = incidentFromReport(root, suspicious.filePath);
  const bundle = incidentBundle(root, suspicious.filePath);
  const latest = latestReport(root);

  assert.equal(listed.length, 2);
  assert.equal(readReport(root, suspicious.filePath).report.metadata.schemaVersion, 2);
  assert.equal(diff.removedFindings.length, 1);
  assert.equal(fs.existsSync(html.htmlPath), true);
  assert.equal(fs.existsSync(markdown.markdownPath), true);
  assert.equal(fs.existsSync(incident.incidentPath), true);
  assert.equal(fs.existsSync(path.join(bundle.bundleDir, 'report.json')), true);
  assert.ok(latest.id);
  assert.equal(riskRegression(root, { left: clean.filePath, right: suspicious.filePath }).regression, true);
  const pruned = pruneReports(root, { maxReports: 1 });
  assert.equal(pruned.remaining, 1);
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
  const preview = redactionPreview([{ ...finding, file: 'C:/Users/Alice/project/tailwind.config.js' }], { redaction: { redactLocalPaths: true } });
  assert.equal(preview.findings[0].redactedFile, '[local-path]');
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

test('trust store supports registries, actions, and package scopes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-trust-types-'));
  const registry = trustAdd(root, 'https://registry.npmjs.org', { type: 'registry', reason: 'npm', owner: 'security', expiresAt: '2999-01-01' });
  const action = trustAdd(root, 'actions/checkout@1234567890123456789012345678901234567890', { type: 'action', reason: 'pinned', owner: 'security', expiresAt: '2999-01-01' });
  const scope = trustAdd(root, '@company', { type: 'package-scope', reason: 'internal', owner: 'security', expiresAt: '2999-01-01' });

  const audit = trustAudit(root);

  assert.equal(registry.type, 'registry');
  assert.equal(action.type, 'action');
  assert.equal(scope.type, 'package-scope');
  assert.equal(audit.ok, true);
});

test('pack audit flags dangerous files in npm package contents', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-pack-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'pack-app', version: '1.0.0', files: ['payload.exe'] }, null, 2));
  fs.writeFileSync(path.join(root, 'payload.exe'), 'not really executable');

  const result = packAudit(root);

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.id === 'pack-dangerous-artifact'));
});

test('dependency diff flags suspicious new lockfile sources and lifecycle entries', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-'));
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'deps-app' },
      'node_modules/react': { version: '18.0.0', resolved: 'https://registry.npmjs.org/react/-/react-18.0.0.tgz' },
    },
  }, null, 2));
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'deps-app' },
      'node_modules/react': { version: '18.0.0', resolved: 'https://registry.npmjs.org/react/-/react-18.0.0.tgz' },
      'node_modules/backend-agent': { version: '1.0.0', resolved: 'https://gist.githubusercontent.com/x/y/raw/pkg.tgz', hasInstallScript: true, bin: { run: 'index.js' } },
    },
  }, null, 2));

  const result = depsDiff(root);

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-new-suspicious-source'));
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-new-lifecycle-entry'));
});

test('wire can dry-run and apply execfence wrappers', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-wire-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { test: 'node --test', build: 'vite build' } }, null, 2));

  const dry = wireProject(root, { dryRun: true });
  const applied = wireProject(root, { dryRun: false });
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

  assert.equal(dry.dryRun, true);
  assert.ok(dry.changes.some((change) => change.file === 'package.json'));
  assert.equal(applied.dryRun, false);
  assert.equal(pkg.scripts.test, 'execfence run -- node --test');
  assert.equal(pkg.scripts['execfence:ci'], 'execfence ci');
});

test('ci command aggregates scan, manifest, deps, pack, and trust checks', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-ci-'));
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'ci-app', version: '1.0.0', scripts: { test: 'execfence run -- node --test' } }, null, 2));
  writeManifest(root);
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'ci-app', version: '1.0.0', scripts: { test: 'execfence run -- node --test', build: 'vite build' } }, null, 2));

  const result = runCi(root);

  assert.equal(result.ok, false);
  assert.ok(result.ci.scan);
  assert.ok(result.ci.manifestDiff);
  assert.ok(result.findings.some((finding) => finding.id === 'manifest-new-entrypoint'));
});

test('baseline helper adds report findings with owner reason expiry and hash', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-baseline-add-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'baseline-add' }, null, 2));
  fs.writeFileSync(path.join(root, 'tailwind.config.js'), "global.i='2-30-4';\n");
  const report = writeReport(scan({ cwd: root, roots: ['tailwind.config.js'] }), { command: 'execfence scan' });

  const result = addBaselineFromReport(root, report.filePath, {
    owner: 'security',
    reason: 'reviewed fixture',
    expiresAt: '2999-01-01',
  });
  const baseline = JSON.parse(fs.readFileSync(result.baselinePath, 'utf8'));

  assert.equal(result.added.length, 1);
  assert.equal(baseline.findings[0].owner, 'security');
  assert.match(baseline.findings[0].sha256, /^[a-f0-9]{64}$/);
});

test('adopt mode produces a low-noise correction plan and optional suggested baseline', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-adopt-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'adopt-app', scripts: { test: 'node --test' } }, null, 2));
  fs.writeFileSync(path.join(root, 'tailwind.config.js'), "global.i='2-30-4';\n");

  const result = adoptProject(root, { writeSuggestedBaseline: true });

  assert.equal(result.ok, true);
  assert.ok(result.suggestedBaseline.length >= 1);
  assert.ok(result.remediationPlan.some((item) => /execfence run/.test(item.action)));
  assert.equal(fs.existsSync(result.suggestedBaselinePath), true);
});

test('policy explain and test support custom policy packs', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-policy-'));
  const policies = path.join(root, '.execfence', 'config', 'policies');
  fs.mkdirSync(policies, { recursive: true });
  fs.writeFileSync(path.join(policies, 'team.json'), JSON.stringify({
    roots: ['src'],
    blockSeverities: ['critical', 'high', 'medium'],
    warnSeverities: ['low'],
  }, null, 2));

  const explained = explainPolicy(root, { policyPack: 'team' });
  const tested = testPolicy(root, { policyPack: 'team' });

  assert.equal(explained.customPolicyPath.endsWith('team.json'), true);
  assert.deepEqual(explained.blockSeverities, ['critical', 'high', 'medium']);
  assert.equal(tested.ok, true);
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
