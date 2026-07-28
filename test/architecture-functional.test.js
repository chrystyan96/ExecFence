'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { classifyCommand } = require('../lib/ecosystems');
const { analyzeCoverage } = require('../lib/coverage');
const { validateConfig } = require('../lib/config-validate');
const { depsDiff, dependencyFiles } = require('../lib/deps');
const { parseTarball, reviewDependenciesConcurrent, reviewPackageSpecs } = require('../lib/deps-review');
const { runCi } = require('../lib/ci');
const { diffPolicy } = require('../lib/policy-diff');
const { generateSbom } = require('../lib/sbom');
const { scan } = require('../lib/scanner');
const { sandboxPlan } = require('../lib/sandbox');
const { writeManifest } = require('../lib/manifest');
const { runWithFence } = require('../lib/runtime');
const { isDirectGuarded } = require('../lib/entrypoint-coverage');
const { annotateWorkflowCoverage, workflowRunSteps } = require('../lib/workflow-parser');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function initRepo(root) {
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
}

test('repository config cannot narrow the default security scan', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-floor-'));
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.mkdirSync(path.join(root, 'safe'), { recursive: true });
  fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'execfence.json'), JSON.stringify({
    mode: 'audit',
    roots: ['safe'],
    skipFiles: ['payload.js'],
    blockSeverities: ['low'],
  }));
  fs.writeFileSync(path.join(root, 'bin', 'payload.js'), "global.i='2-30-4';\n");

  const result = scan({ cwd: root });

  assert.equal(result.mode, 'block');
  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.file === 'bin/payload.js'));
  assert.ok(result.config.blockSeverities.includes('critical'));
  assert.ok(result.config.blockSeverities.includes('high'));
});

test('tool-aware parser cannot hide install commands behind value options', () => {
  assert.equal(classifyCommand('npm', ['--prefix', 'workspace', 'install']).installLike, true);
  assert.equal(classifyCommand('pip', ['--index-url', 'https://pypi.org/simple', 'install', 'requests']).installLike, true);
  assert.equal(classifyCommand('go', ['-C', 'service', 'get', 'example.com/mod']).installLike, true);
});

test('workflow coverage only inherits an earlier gate in the same job', () => {
  const steps = annotateWorkflowCoverage(workflowRunSteps(`jobs:
  build:
    steps:
      - name: Test before gate
        run: npm test
      - run: execfence scan
      - run: npm run build
  release:
    steps:
      - run: npm publish
`), isDirectGuarded);

  assert.equal(steps[0].guarded, false);
  assert.equal(steps[2].guarded, true);
  assert.equal(steps[3].guarded, false);
});

test('coverage requires a real ExecFence command invocation', () => {
  assert.equal(isDirectGuarded('echo "execfence scan"'), false);
  assert.equal(isDirectGuarded('printf "execfence run -- npm test"'), false);
  assert.equal(isDirectGuarded('echo ready && execfence scan'), true);

  const steps = annotateWorkflowCoverage(workflowRunSteps(`jobs:
    build:
      steps:
        - name: Fake gate
          run: echo "execfence scan"
        - name: Multiline build
          run: |
            npm test
            npm run build
`), isDirectGuarded);
  assert.equal(steps.length, 2);
  assert.equal(steps[0].guarded, false);
  assert.equal(steps[1].guarded, false);
  assert.equal(steps[1].line, 7);
});

test('coverage discovers nested package scripts and parses VS Code task commands', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-coverage-monorepo-'));
  fs.mkdirSync(path.join(root, 'services', 'api'), { recursive: true });
  fs.mkdirSync(path.join(root, '.vscode'), { recursive: true });
  fs.writeFileSync(path.join(root, 'services', 'api', 'package.json'), JSON.stringify({
    scripts: { build: 'execfence run -- node build.js' },
  }));
  fs.writeFileSync(path.join(root, '.vscode', 'tasks.json'), JSON.stringify({
    tasks: [{ label: 'fake guard', type: 'shell', command: 'echo "execfence scan"' }],
  }));

  const result = analyzeCoverage(root);
  const nested = result.entrypoints.find((entry) => entry.file === 'services/api/package.json' && entry.name === 'build');
  const vscode = result.entrypoints.find((entry) => entry.file === '.vscode/tasks.json');

  assert.equal(nested.covered, true);
  assert.equal(vscode.covered, false);
});

test('allowDegraded makes the effective sandbox mode explicit audit', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-degraded-'));
  const plan = sandboxPlan(root, ['node', '-e', '0'], { mode: 'enforce', allowDegraded: true });

  assert.equal(plan.requestedMode, 'enforce');
  assert.equal(plan.mode, 'audit');
  assert.equal(plan.degradedFrom, 'enforce');
});

test('repository sandbox config cannot authorize degraded enforcement', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-degraded-config-'));
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'sandbox.json'), JSON.stringify({
    mode: 'enforce',
    profile: 'test',
    allowDegraded: true,
    fs: { readAllow: ['.'], writeAllow: ['.'], deny: [], denyNewExecutable: true },
    process: { allow: [], deny: [], superviseChildren: true },
    network: { default: 'deny', allow: [], auditOnly: false },
  }));

  const plan = sandboxPlan(root, ['node', '-e', '0']);
  const validation = validateConfig(root);

  assert.equal(plan.requestedMode, 'enforce');
  assert.equal(plan.mode, 'enforce');
  assert.equal(plan.allowDegraded, false);
  assert.equal(plan.ok, false);
  assert.ok(validation.findings.some((finding) => finding.id === 'sandbox-project-allows-degraded-helper'));
});

test('CI never mutates the explicitly approved execution manifest', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-ci-manifest-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { test: 'execfence run -- node --test' } }, null, 2));
  const approved = writeManifest(root);
  const before = fs.readFileSync(approved.filePath, 'utf8');
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { test: 'execfence run -- node --test', build: 'node build.js' } }, null, 2));

  runCi(root);

  assert.equal(fs.readFileSync(approved.filePath, 'utf8'), before);
});

test('CI rejects a manifest rewritten in the same change as a new entrypoint', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-ci-manifest-poison-'));
  initRepo(root);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { test: 'execfence run -- node --test' } }, null, 2));
  writeManifest(root);
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'approved manifest']);
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    scripts: {
      test: 'execfence run -- node --test',
      publish: 'execfence run -- npm publish',
    },
  }, null, 2));
  writeManifest(root);

  const result = runCi(root, { baseRef: 'HEAD' });

  assert.equal(result.ci.manifestDiff.ok, false);
  assert.equal(result.ci.manifestApprovalRequired, true);
  assert.ok(result.ci.manifestDiff.added.some((entry) => entry.name === 'publish'));
});

test('dependency discovery and diff cover nested and removed monorepo manifests', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-monorepo-'));
  initRepo(root);
  fs.mkdirSync(path.join(root, 'packages', 'api'), { recursive: true });
  fs.writeFileSync(path.join(root, 'packages', 'api', 'requirements.txt'), 'requests==2.31.0\n');
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'baseline']);
  fs.unlinkSync(path.join(root, 'packages', 'api', 'requirements.txt'));

  const filesAtBase = dependencyFiles(root, { ref: 'HEAD' });
  const diff = depsDiff(root);

  assert.ok(filesAtBase.includes('packages/api/requirements.txt'));
  assert.ok(diff.removed.some((dependency) => dependency.name === 'requests'));
});

test('real schemas reject unknown properties and hashless executable allowlists', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-schema-'));
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'execfence.json'), JSON.stringify({
    unknownOption: true,
    allowExecutables: ['bin/tool.exe'],
  }));

  const result = validateConfig(root);

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.id === 'config-schema-validation-error' && /unknownOption/.test(finding.detail)));
  assert.ok(result.findings.some((finding) => finding.id === 'config-allow-executable-without-hash'));
});

test('repository-controlled paths cannot escape the project root', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-path-floor-'));
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'execfence.json'), JSON.stringify({
    reportsDir: '../outside',
    manifest: { path: '../../manifest.json' },
    trustStore: { files: 'C:\\outside\\files.json' },
    deps: { detectRegistryDrift: false },
  }));

  const result = validateConfig(root);

  assert.equal(result.ok, false);
  assert.ok(result.findings.filter((finding) => finding.id === 'config-path-escapes-project').length >= 3);
  assert.ok(result.findings.some((finding) => finding.id === 'config-security-floor-dependency-checks'));
});

test('sandbox project policy cannot broaden a strict profile', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-sandbox-floor-'));
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'sandbox.json'), JSON.stringify({
    mode: 'audit',
    profile: 'strict',
    fs: { readAllow: ['..'], writeAllow: ['.', '../outside'], deny: [] },
    process: { allow: ['node'], deny: [], superviseChildren: false },
    network: { default: 'allow', allow: ['example.com'], auditOnly: false },
  }));

  const plan = sandboxPlan(root, ['node', '-e', '0']);

  assert.deepEqual(plan.fs.writeAllow, []);
  assert.deepEqual(plan.process.allow, []);
  assert.equal(plan.network.default, 'deny');
  assert.deepEqual(plan.network.allow, []);
  assert.equal(plan.process.superviseChildren, true);
  const validation = validateConfig(root);
  assert.ok(validation.findings.some((finding) => finding.id === 'sandbox-security-floor-profile-broadening'));
});

test('ZIP package artifacts are inspected for executable contents', () => {
  const zip = storedZip('binding.node', Buffer.from('native fixture'));
  const entries = parseTarball(zip);

  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, 'binding.node');
  assert.equal(entries[0].kind, 'executable');
});

test('ZIP package inspection rejects oversized expanded entries', () => {
  const zip = storedZip('oversized.js', Buffer.from('small'));
  const centralOffset = 30 + Buffer.byteLength('oversized.js') + Buffer.byteLength('small');
  zip.writeUInt32LE(30 * 1024 * 1024, centralOffset + 24);

  const entries = parseTarball(zip);
  assert.deepEqual(entries, []);
  assert.match(entries.inspectionIssues[0], /expanded-size/);
});

test('SBOM generation includes nested multi-ecosystem components', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-sbom-'));
  fs.mkdirSync(path.join(root, 'services', 'api'), { recursive: true });
  fs.writeFileSync(path.join(root, 'services', 'api', 'requirements.txt'), 'requests==2.32.0\n');
  fs.writeFileSync(path.join(root, 'go.mod'), 'module example.com/app\nrequire example.com/lib v1.2.3\n');

  const cyclonedx = generateSbom(root);
  const spdx = generateSbom(root, { format: 'spdx' });

  assert.ok(cyclonedx.components.some((component) => component.purl === 'pkg:pypi/requests@2.32.0'));
  assert.ok(cyclonedx.components.some((component) => component.purl === 'pkg:golang/example.com%2Flib@v1.2.3'));
  assert.equal(spdx.spdxVersion, 'SPDX-2.3');
});

test('policy diff flags security-sensitive policy changes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-policy-diff-'));
  initRepo(root);
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  const configPath = path.join(root, '.execfence', 'config', 'execfence.json');
  const signaturesPath = path.join(root, '.execfence', 'config', 'signatures.json');
  fs.writeFileSync(configPath, JSON.stringify({ mode: 'block', blockSeverities: ['critical', 'high'] }, null, 2));
  fs.writeFileSync(signaturesPath, JSON.stringify({ exact: ['reviewed-marker'] }, null, 2));
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'policy baseline']);
  fs.writeFileSync(configPath, JSON.stringify({ mode: 'audit', blockSeverities: ['low'] }, null, 2));
  fs.writeFileSync(signaturesPath, JSON.stringify({ exact: [] }, null, 2));

  const result = diffPolicy(root);

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => /mode|blockSeverities/.test(finding.detail)));
  assert.ok(result.findings.some((finding) => finding.id === 'policy-controlled-file-change' && finding.file.endsWith('signatures.json')));
});

test('reputation review remains active when registry metadata is disabled', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-reputation-independent-'));
  let calls = 0;
  const result = reviewPackageSpecs(root, ['left-pad@1.3.0'], {
    config: { metadata: { mode: 'off' }, reputation: { enabled: true, sources: ['osv'] } },
    fetchReputation: () => {
      calls += 1;
      return { ok: true, json: {} };
    },
  });

  assert.equal(calls, 1);
  assert.equal(result.dependencies[0].metadata.status, 'disabled');
  assert.equal(result.dependencies[0].reputation.status, 'complete');
});

test('dependency metadata and tarball fetches stay on allowlisted HTTPS endpoints', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-endpoint-floor-'));
  let fetchedTarball = false;
  const result = reviewPackageSpecs(root, ['safe-pkg@1.0.0'], {
    config: { reputation: { enabled: false } },
    fetchMetadata: () => ({
      ok: true,
      json: {
        name: 'safe-pkg',
        'dist-tags': { latest: '1.0.0' },
        maintainers: [{ name: 'reviewer' }],
        time: { created: '2000-01-01T00:00:00.000Z', modified: '2000-01-01T00:00:00.000Z', '1.0.0': '2000-01-01T00:00:00.000Z' },
        versions: {
          '1.0.0': {
            dist: {
              tarball: 'https://evil.example/safe-pkg.tgz',
              integrity: 'sha512-AA==',
              signatures: [{ keyid: 'reviewed', sig: 'reviewed' }],
            },
          },
        },
      },
    }),
    fetchTarball: () => {
      fetchedTarball = true;
      return { ok: true, bytes: Buffer.alloc(0) };
    },
  });

  assert.equal(fetchedTarball, false);
  assert.ok(result.findings.some((finding) => finding.id === 'dependency-tarball-endpoint-not-allowed'));
});

test('Go proxy metadata uses protocol escaping for uppercase module paths', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-go-proxy-'));
  let requestedUrl = '';
  reviewPackageSpecs(root, ['github.com/Azure/azure-sdk-for-go@v1.2.3'], {
    packageManager: 'go',
    config: { metadata: { tarballReview: { enabled: false } }, reputation: { enabled: false } },
    fetchMetadata: (url) => {
      requestedUrl = url;
      return { ok: true, json: { Version: 'v1.2.3', Time: '2000-01-01T00:00:00Z' } };
    },
  });

  assert.equal(requestedUrl, 'https://proxy.golang.org/github.com/!azure/azure-sdk-for-go/@v/v1.2.3.info');
});

test('runtime timeout terminates a command and records the operational error', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-timeout-'));
  const result = runWithFence([process.execPath, '-e', 'setTimeout(() => {}, 5000)'], {
    cwd: root,
    stdio: 'pipe',
    timeoutMs: 100,
  });

  assert.equal(result.ok, false);
  assert.match(result.runtimeTrace.error, /timed out|ETIMEDOUT/i);
});

test('dependency review supports bounded concurrency and cancellation', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-concurrency-'));
  initRepo(root);
  const lockPath = path.join(root, 'package-lock.json');
  fs.writeFileSync(lockPath, JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'app' } } }, null, 2));
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'baseline']);
  fs.writeFileSync(lockPath, JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'app' },
      'node_modules/alpha': { version: '1.0.0', resolved: 'https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz' },
      'node_modules/beta': { version: '1.0.0', resolved: 'https://registry.npmjs.org/beta/-/beta-1.0.0.tgz' },
    },
  }, null, 2));
  const config = { metadata: { enabled: false }, reputation: { enabled: false } };
  const result = await reviewDependenciesConcurrent(root, { config, concurrency: 2 });
  const controller = new AbortController();
  controller.abort();

  assert.equal(result.summary.reviewed, 2);
  assert.equal(result.summary.concurrency, 2);
  await assert.rejects(
    reviewDependenciesConcurrent(root, { config, concurrency: 2, signal: controller.signal }),
    /cancelled/i,
  );
});

function storedZip(name, content) {
  const nameBytes = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(content.length, 18);
  local.writeUInt32LE(content.length, 22);
  local.writeUInt16LE(nameBytes.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0, 10);
  central.writeUInt32LE(content.length, 20);
  central.writeUInt32LE(content.length, 24);
  central.writeUInt16LE(nameBytes.length, 28);
  central.writeUInt32LE(0, 42);
  const centralOffset = local.length + nameBytes.length + content.length;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length + nameBytes.length, 12);
  end.writeUInt32LE(centralOffset, 16);
  return Buffer.concat([local, nameBytes, content, central, nameBytes, end]);
}
