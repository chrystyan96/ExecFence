'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const zlib = require('node:zlib');
const { privacyDecision, reviewDependencies, reviewPackageSpecs } = require('../lib/deps-review');
const bin = path.join(__dirname, '..', 'bin', 'execfence.js');
const cleanReputation = () => ({ ok: true, json: {} });

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function initRepo(root) {
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
}

function runCli(cwd, args) {
  return execFileSync(process.execPath, [bin, ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function metadataResponse(name, version, extra = {}) {
  return {
    ok: true,
    json: {
      name,
      'dist-tags': { latest: version },
      maintainers: extra.maintainers || [{ name: 'reviewer' }],
      time: {
        created: extra.createdAt || '2000-01-01T00:00:00.000Z',
        modified: extra.modifiedAt || '2000-01-02T00:00:00.000Z',
        [version]: extra.publishedAt || '2000-01-01T00:00:00.000Z',
      },
      versions: {
        [version]: {
          version,
          deprecated: extra.deprecated || '',
          dist: {
            tarball: extra.tarball || '',
            integrity: extra.integrity || 'sha512-test',
            signatures: extra.noProvenance ? undefined : [{ keyid: 'test', sig: 'test' }],
          },
        },
      },
    },
  };
}

function tarGz(files) {
  const chunks = [];
  for (const [name, content] of Object.entries(files)) {
    const body = Buffer.from(content);
    const header = Buffer.alloc(512, 0);
    header.write(`package/${name}`);
    header.write('0000777\0', 100);
    header.write('0000000\0', 108);
    header.write('0000000\0', 116);
    header.write(body.length.toString(8).padStart(11, '0') + '\0', 124);
    header.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0', 136);
    header.fill(' ', 148, 156);
    header.write('0', 156);
    header.write('ustar', 257);
    let sum = 0;
    for (const byte of header) sum += byte;
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    chunks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512, 0));
  }
  chunks.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(Buffer.concat(chunks));
}

function integrity(bytes) {
  return `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`;
}

test('dependency review covers npm, pnpm, and yarn lockfile changes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-all-'));
  initRepo(root);
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'review-app' } } }, null, 2));
  fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9\npackages: {}\n');
  fs.writeFileSync(path.join(root, 'yarn.lock'), '# yarn lockfile v1\n');
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);

  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'review-app' },
      'node_modules/left-pad': {
        version: '1.3.0',
        resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
        integrity: 'sha512-left',
      },
    },
  }, null, 2));
  fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), `lockfileVersion: 9
packages:
  chalk@5.0.0:
    resolution: {integrity: sha512-chalk, tarball: https://registry.npmjs.org/chalk/-/chalk-5.0.0.tgz}
`);
  fs.writeFileSync(path.join(root, 'yarn.lock'), `"debug@^4.0.0":
  version "4.4.1"
  resolved "https://registry.npmjs.org/debug/-/debug-4.4.1.tgz"
  integrity sha512-debug
`);

  const result = reviewDependencies(root, {
    fetchReputation: cleanReputation,
    fetchMetadata: (_url, dep) => metadataResponse(dep.name, dep.version),
  });

  assert.equal(result.summary.reviewed, 3);
  assert.deepEqual(result.dependencies.map((item) => item.packageManager).sort(), ['npm', 'pnpm', 'yarn']);
  assert.ok(result.dependencies.some((item) => item.name === 'left-pad' && item.integrity === 'sha512-left'));
});

test('dependency review privacy gates skip scoped packages and private registries', () => {
  const config = {
    metadata: {
      enabled: true,
      allowedRegistries: ['registry.npmjs.org'],
      allowedPublicScopes: [],
      privateScopePolicy: 'skip',
    },
  };

  assert.equal(privacyDecision({
    ecosystem: 'npm',
    name: '@company/tool',
    registry: 'registry.npmjs.org',
  }, config.metadata).allowed, false);
  assert.equal(privacyDecision({
    ecosystem: 'npm',
    name: 'left-pad',
    registry: 'npm.internal.example',
  }, config.metadata).allowed, false);
  assert.equal(privacyDecision({
    ecosystem: 'npm',
    name: '@types/node',
    registry: 'registry.npmjs.org',
  }, { ...config.metadata, allowedPublicScopes: ['@types'] }).allowed, true);
  assert.equal(privacyDecision({
    ecosystem: 'npm',
    name: '@company/tool',
    registry: 'registry.npmjs.org',
  }, { ...config.metadata, privateScopePolicy: 'allow' }).allowed, true);
});

test('dependency metadata caches successful lookups and warns on network failures', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-cache-'));
  let calls = 0;

  const first = reviewPackageSpecs(root, ['left-pad@1.3.0'], {
    fetchReputation: cleanReputation,
    fetchMetadata: (_url, dep) => {
      calls += 1;
      return metadataResponse(dep.name, dep.version);
    },
  });
  const second = reviewPackageSpecs(root, ['left-pad@1.3.0'], {
    fetchReputation: cleanReputation,
    fetchMetadata: () => {
      throw new Error('should use cache');
    },
  });
  const failed = reviewPackageSpecs(fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-fail-')), ['left-pad@1.3.0'], {
    fetchReputation: cleanReputation,
    fetchMetadata: () => ({ ok: false, error: 'registry unavailable' }),
  });

  assert.equal(calls, 1);
  assert.equal(first.ok, true);
  assert.equal(second.dependencies[0].metadata.source, 'cache');
  assert.equal(failed.ok, true);
  assert.equal(failed.findings[0].id, 'dependency-metadata-unavailable');
  assert.equal(failed.findings[0].severity, 'medium');
});

test('dependency metadata blocks release cooldown and security deprecation signals', () => {
  const recent = new Date().toISOString();
  const result = reviewPackageSpecs(fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-risk-')), ['plain-crypto-js@4.2.1'], {
    fetchReputation: cleanReputation,
    fetchMetadata: (_url, dep) => metadataResponse(dep.name, dep.version, {
      publishedAt: recent,
      deprecated: 'malware compromise: do not use',
    }),
  });

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-metadata-release-cooldown'));
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-metadata-security-deprecated'));
});

test('dependency metadata flags reputation and provenance policy signals', () => {
  const recent = new Date().toISOString();
  const result = reviewPackageSpecs(fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-reputation-')), ['fresh-pkg@1.0.0'], {
    config: { metadata: { provenancePolicy: 'block' } },
    fetchReputation: cleanReputation,
    fetchMetadata: (_url, dep) => metadataResponse(dep.name, dep.version, {
      createdAt: recent,
      modifiedAt: recent,
      maintainers: [],
      noProvenance: true,
    }),
  });

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-metadata-new-package'));
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-metadata-no-maintainers'));
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-metadata-missing-provenance'));
});

test('dependency tarball review validates integrity and scans runtime-sensitive code', () => {
  const tgz = tarGz({
    'index.js': "const cp = require('child_process'); fetch(process.env.NPM_TOKEN); cp.exec('whoami');\n",
  });
  const result = reviewPackageSpecs(fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-tarball-')), ['runtime-pkg@1.0.0'], {
    fetchReputation: cleanReputation,
    fetchMetadata: (_url, dep) => metadataResponse(dep.name, dep.version, {
      tarball: 'https://registry.npmjs.org/runtime-pkg/-/runtime-pkg-1.0.0.tgz',
      integrity: integrity(tgz),
    }),
    fetchTarball: () => ({ ok: true, bytes: tgz }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.dependencies[0].tarball.status, 'complete');
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-tarball-runtime-sensitive-code'));
});

test('dependency review compares changed tarball delta against previous version', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-delta-'));
  initRepo(root);
  const oldTgz = tarGz({ 'index.js': 'module.exports = 1;\n' });
  const newTgz = tarGz({
    'index.js': "require('child_process').exec('whoami');\n",
    'binding.node': 'native',
  });
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'delta-app' },
      'node_modules/delta-pkg': {
        version: '1.0.0',
        resolved: 'https://registry.npmjs.org/delta-pkg/-/delta-pkg-1.0.0.tgz',
        integrity: integrity(oldTgz),
      },
    },
  }, null, 2));
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'delta-app' },
      'node_modules/delta-pkg': {
        version: '1.1.0',
        resolved: 'https://registry.npmjs.org/delta-pkg/-/delta-pkg-1.1.0.tgz',
        integrity: integrity(newTgz),
      },
    },
  }, null, 2));

  const result = reviewDependencies(root, {
    fetchReputation: cleanReputation,
    fetchMetadata: (_url, dep) => ({
      ok: true,
      json: {
        name: dep.name,
        'dist-tags': { latest: '1.1.0' },
        maintainers: [{ name: 'reviewer' }],
        time: { created: '2000-01-01T00:00:00.000Z', modified: '2000-01-02T00:00:00.000Z', '1.0.0': '2000-01-01T00:00:00.000Z', '1.1.0': '2000-01-02T00:00:00.000Z' },
        versions: {
          '1.0.0': { dist: { tarball: 'https://registry.npmjs.org/delta-pkg/-/delta-pkg-1.0.0.tgz', integrity: integrity(oldTgz), signatures: [{ keyid: 'test', sig: 'test' }] } },
          '1.1.0': { dist: { tarball: 'https://registry.npmjs.org/delta-pkg/-/delta-pkg-1.1.0.tgz', integrity: integrity(newTgz), signatures: [{ keyid: 'test', sig: 'test' }] } },
        },
      },
    }),
    fetchTarball: (url) => ({ ok: true, bytes: url.includes('1.0.0') ? oldTgz : newTgz }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.dependencies[0].tarball.delta.status, 'complete');
  assert.ok(result.dependencies[0].tarball.delta.addedFiles.some((file) => file.name === 'binding.node'));
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-tarball-delta-added-dangerous-artifact'));
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-tarball-delta-changed-runtime-sensitive-code'));
});

test('dependency reputation blocks OSV advisory matches', () => {
  const result = reviewPackageSpecs(fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-osv-')), ['vuln-pkg@1.0.0'], {
    fetchMetadata: (_url, dep) => metadataResponse(dep.name, dep.version),
    fetchReputation: () => ({ ok: true, json: { vulns: [{ id: 'GHSA-test' }] } }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.dependencies[0].reputation.status, 'complete');
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-reputation-osv-advisory'));
});

test('strict supply-chain mode blocks unavailable medium signals', () => {
  const result = reviewPackageSpecs(fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-strict-')), ['left-pad@1.3.0'], {
    config: { mode: 'strict' },
    fetchMetadata: () => ({ ok: false, error: 'registry offline' }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'dependency-metadata-unavailable');
  assert.equal(result.findings[0].severity, 'medium');
  assert.equal(result.summary.blockedFindings, 1);
});

test('cached reputation failures still warn and block in strict mode', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-rep-cache-'));
  const first = reviewPackageSpecs(root, ['left-pad@1.3.0'], {
    config: { mode: 'strict' },
    fetchMetadata: (_url, dep) => metadataResponse(dep.name, dep.version),
    fetchReputation: () => ({ ok: false, error: 'osv offline' }),
  });
  const second = reviewPackageSpecs(root, ['left-pad@1.3.0'], {
    config: { mode: 'strict' },
    fetchMetadata: (_url, dep) => metadataResponse(dep.name, dep.version),
    fetchReputation: () => {
      throw new Error('should use cached reputation failure');
    },
  });

  assert.equal(first.ok, false);
  assert.equal(second.ok, false);
  assert.ok(second.findings.some((finding) => finding.id === 'dependency-reputation-unavailable'));
});

test('dependency metadata mode off disables registry lookups', () => {
  const result = reviewPackageSpecs(fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-off-')), ['left-pad@1.3.0'], {
    config: { metadata: { mode: 'off' } },
    fetchMetadata: () => {
      throw new Error('metadata lookup should not run');
    },
  });

  assert.equal(result.ok, true);
  assert.equal(result.summary.metadataLookups, 0);
  assert.equal(result.dependencies[0].metadata.status, 'disabled');
});

test('dependency review supports fake registry metadata for integration tests', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-registry-'));
  const result = reviewPackageSpecs(root, ['left-pad@1.3.0'], {
    registryBaseUrl: 'https://registry.npmjs.org',
    config: { metadata: { allowedRegistries: ['registry.npmjs.org'] } },
    fetchReputation: cleanReputation,
    fetchMetadata: (url, dep) => {
      assert.equal(url, 'https://registry.npmjs.org/left-pad');
      return metadataResponse(dep.name, dep.version);
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.dependencies[0].metadata.status, 'complete');
});

test('deps review CLI returns stable json summary', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-deps-review-cli-'));
  initRepo(root);
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'execfence.json'), JSON.stringify({
    supplyChain: { metadata: { enabled: false } },
  }, null, 2));
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'review-app' } } }, null, 2));
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'review-app' },
      'node_modules/left-pad': {
        version: '1.3.0',
        resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
        integrity: 'sha512-left',
      },
    },
  }, null, 2));

  const result = JSON.parse(runCli(root, ['deps', 'review', '--format', 'json']));

  assert.equal(result.ok, true);
  assert.equal(result.summary.reviewed, 1);
  assert.equal(result.dependencies[0].name, 'left-pad');
  assert.equal(result.dependencies[0].metadata.status, 'disabled');
});
