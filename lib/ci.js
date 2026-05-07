'use strict';

const path = require('node:path');
const { scan } = require('./scanner');
const { depsDiff } = require('./deps');
const { reviewDependencies } = require('./deps-review');
const { analyzeCoverage } = require('./coverage');
const { generateManifest, readManifest, writeManifest, diffManifest } = require('./manifest');
const { packAudit, trustAudit } = require('./supply-chain');
const { validateConfig } = require('./config-validate');

function runCi(cwd = process.cwd(), options = {}) {
  const root = path.resolve(cwd);
  const scanResult = scan({ cwd: root, mode: options.mode || 'block', fullIocScan: options.fullIocScan });
  const previousManifest = readManifest(root);
  const currentManifest = generateManifest(root);
  const manifestDiff = previousManifest
    ? diffManifest(currentManifest, previousManifest)
    : { ok: true, added: [], removed: [], changed: [], riskLevel: 'low', risk: [], bootstrapped: true };
  writeManifest(root, currentManifest);
  const deps = depsDiff(root, { baseRef: options.baseRef || 'HEAD' });
  const depsReview = reviewDependencies(root, { baseRef: options.baseRef || 'HEAD' });
  const coverage = analyzeCoverage(root, { supplyChain: depsReview.config });
  const configValidation = validateConfig(root, { strict: options.strictConfig });
  const pack = packAudit(root);
  const trust = trustAudit(root);
  const operationalFindings = [
    ...findingsFromManifestDiff(manifestDiff),
    ...(deps.findings || []),
    ...(depsReview.findings || []),
    ...findingsFromCoverage(coverage, depsReview.config),
    ...(configValidation.findings || []),
    ...(pack.findings || []),
    ...(trust.findings || []),
  ];
  const findings = [...(scanResult.findings || []), ...operationalFindings];
  const blockSeverities = new Set(scanResult.config?.blockSeverities || ['critical', 'high']);
  const warningSeverities = new Set(scanResult.config?.warnSeverities || ['medium', 'low']);
  const blockedFindings = findings.filter((finding) => blockSeverities.has(finding.severity || 'high'));
  const warningFindings = findings.filter((finding) => !blockedFindings.includes(finding) && warningSeverities.has(finding.severity || 'medium'));

  return {
    cwd: root,
    ok: scanResult.ok && manifestDiff.ok && deps.ok && depsReview.ok && pack.ok && trust.ok && coverage.ok && configValidation.ok && blockedFindings.length === 0,
    mode: 'ci',
    config: scanResult.config,
    configPath: scanResult.configPath,
    baselinePath: scanResult.baselinePath,
    roots: scanResult.roots,
    findings,
    blockedFindings,
    warningFindings,
    suppressedFindings: scanResult.suppressedFindings || [],
    manifest: currentManifest,
    changeRisk: {
      level: highestRisk([manifestDiff.riskLevel, riskFromFindings(findings)]),
      reasons: [
        ...((manifestDiff.risk || []).map((item) => item.reason)),
        ...(deps.findings || []).map((item) => item.detail),
        ...(depsReview.findings || []).map((item) => item.detail),
        ...(pack.findings || []).map((item) => item.detail),
        ...(trust.findings || []).map((item) => item.detail),
      ].filter(Boolean).slice(0, 20),
    },
    ci: {
      scan: summarizeCheck(scanResult),
      manifestDiff,
      deps,
      depsReview,
      coverage,
      configValidation,
      packAudit: pack,
      trustAudit: trust,
    },
  };
}

function findingsFromCoverage(coverage, supplyChainConfig = {}) {
  if (supplyChainConfig.mode !== 'strict') {
    return [];
  }
  return (coverage.uncovered || [])
    .filter((entry) => entry.type === 'package-manager-surface' || /\b(?:npm|pnpm|yarn|bun|pip|pipx|uv|poetry|cargo|go|mvn|mvnw|gradle|gradlew|dotnet|composer|bundle|bundler)\b/.test(entry.command || ''))
    .map((entry) => ({
      id: 'supply-chain-package-manager-surface-uncovered',
      severity: 'high',
      file: entry.file || 'package.json',
      line: 1,
      detail: `Strict supply-chain mode requires ExecFence coverage for ${entry.command || entry.name}.`,
      remediation: entry.fixSuggestion?.command || 'Enable global package-manager shims or wrap this command with execfence run.',
    }));
}

function findingsFromManifestDiff(diff) {
  const findings = [];
  for (const item of diff.risk || []) {
    const entry = item.entrypoint || item.after || {};
    findings.push({
      id: item.reason.includes('changed') ? 'manifest-entrypoint-changed' : 'manifest-new-entrypoint',
      severity: item.severity || 'high',
      file: entry.file || 'manifest',
      line: 1,
      detail: item.reason,
      remediation: entry.guarded
        ? 'Review the new or changed covered entrypoint and update the manifest baseline after approval.'
        : 'Wrap this entrypoint with execfence run or add a reviewed policy exception.',
    });
  }
  return findings;
}

function summarizeCheck(result) {
  return {
    ok: Boolean(result.ok),
    findings: (result.findings || []).length,
    blockedFindings: (result.blockedFindings || []).length,
    warningFindings: (result.warningFindings || []).length,
    suppressedFindings: (result.suppressedFindings || []).length,
  };
}

function riskFromFindings(findings) {
  if (findings.some((finding) => finding.severity === 'critical')) {
    return 'critical';
  }
  if (findings.some((finding) => finding.severity === 'high')) {
    return 'high';
  }
  if (findings.some((finding) => finding.severity === 'medium')) {
    return 'medium';
  }
  return 'low';
}

function highestRisk(values) {
  const order = ['low', 'medium', 'high', 'critical'];
  return values.filter(Boolean).sort((a, b) => order.indexOf(b) - order.indexOf(a))[0] || 'low';
}

module.exports = {
  findingsFromManifestDiff,
  runCi,
};
