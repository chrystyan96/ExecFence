'use strict';

const path = require('node:path');
const { scan } = require('./scanner');
const { depsDiff } = require('./deps');
const { reviewDependencies } = require('./deps-review');
const { analyzeCoverage } = require('./coverage');
const { generateManifest, readManifest, readManifestAtRef, diffManifest } = require('./manifest');
const { packAudit, trustAudit } = require('./supply-chain');
const { validateConfig } = require('./config-validate');
const { evaluateFindings } = require('./decision-engine');
const { diffPolicy } = require('./policy-diff');
const { activeApprovalFor, auditApprovals } = require('./approvals');
const { resolveCiBaseRef } = require('./ci-adapters');

function runCi(cwd = process.cwd(), options = {}) {
  const root = path.resolve(cwd);
  const scanResult = scan({ cwd: root, mode: options.mode || 'block', fullIocScan: options.fullIocScan });
  const configuredBaseRef = scanResult.config?.ci?.baseRef;
  const requestedBaseRef = options.baseRef || (configuredBaseRef && configuredBaseRef !== 'HEAD' ? configuredBaseRef : undefined);
  const baseResolution = resolveCiBaseRef(root, requestedBaseRef);
  const baseRef = baseResolution.ref;
  const previousManifest = readManifestAtRef(root, baseRef) || readManifest(root);
  const currentManifest = generateManifest(root);
  const rawManifestDiff = previousManifest
    ? diffManifest(currentManifest, previousManifest)
    : { ok: true, added: [], removed: [], changed: [], riskLevel: 'low', risk: [], bootstrapped: true };
  const manifestDiff = applyManifestApprovals(root, rawManifestDiff);
  const deps = depsDiff(root, { baseRef });
  const depsReview = reviewDependencies(root, { baseRef });
  const coverage = analyzeCoverage(root, { supplyChain: depsReview.config });
  const configValidation = validateConfig(root, { strict: options.strictConfig });
  const pack = packAudit(root);
  const trust = trustAudit(root);
  const approvals = auditApprovals(root, { cwd: root, environment: 'ci' });
  const policyDiff = diffPolicy(root, { baseRef });
  const signedPolicyApproval = !policyDiff.ok && scanResult.config?.approvals?.requireSignedPolicyChanges
    ? activeApprovalFor(root, 'policy', { policyHash: policyDiff.contentHash }, { cwd: root, environment: 'ci' })
    : null;
  const policyApprovalFindings = !policyDiff.ok && scanResult.config?.approvals?.requireSignedPolicyChanges && !signedPolicyApproval
    ? [{
      id: 'policy-change-missing-signed-approval',
      severity: 'high',
      confidence: 'high',
      file: '.execfence/approvals.json',
      line: 1,
      detail: `Policy change ${policyDiff.contentHash} requires a valid signed policy approval.`,
    }]
    : [];
  const policyDiffAccepted = policyDiff.ok || Boolean(signedPolicyApproval);
  const operationalFindings = [
    ...findingsFromManifestDiff(manifestDiff),
    ...(deps.findings || []),
    ...(depsReview.findings || []),
    ...findingsFromCoverage(coverage, depsReview.config),
    ...(configValidation.findings || []),
    ...(pack.findings || []),
    ...(trust.findings || []),
    ...(approvals.findings || []),
    ...(!signedPolicyApproval ? (policyDiff.findings || []) : []),
    ...policyApprovalFindings,
    ...(!baseResolution.ok ? [{
      id: 'ci-base-ref-unavailable',
      severity: 'high',
      confidence: 'high',
      file: '.git',
      line: 1,
      detail: `${baseResolution.remediation} Candidates: ${baseResolution.candidates.join(', ') || '(none)'}.`,
    }] : []),
  ];
  const findings = [...(scanResult.findings || []), ...operationalFindings];
  const decision = evaluateFindings(findings, {
    mode: scanResult.mode,
    blockSeverities: scanResult.config?.blockSeverities,
    warnSeverities: scanResult.config?.warnSeverities,
  });

  return {
    cwd: root,
    ok: scanResult.ok && manifestDiff.ok && deps.ok && depsReview.ok && pack.ok && trust.ok && approvals.ok && coverage.ok && configValidation.ok && policyDiffAccepted && baseResolution.ok && decision.ok,
    mode: 'ci',
    config: scanResult.config,
    configPath: scanResult.configPath,
    baselinePath: scanResult.baselinePath,
    roots: scanResult.roots,
    findings: decision.findings,
    blockedFindings: decision.blockedFindings,
    warningFindings: decision.warningFindings,
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
        ...(approvals.findings || []).map((item) => item.detail),
      ].filter(Boolean).slice(0, 20),
    },
    ci: {
      scan: summarizeCheck(scanResult),
      manifestDiff,
      manifestApprovalRequired: !manifestDiff.ok,
      deps,
      depsReview,
      coverage,
      configValidation,
      packAudit: pack,
      trustAudit: trust,
      approvalAudit: approvals,
      policyDiff: { ...policyDiff, approved: Boolean(signedPolicyApproval), effectiveOk: policyDiffAccepted },
      signedPolicyApproval: signedPolicyApproval ? signedPolicyApproval.id : null,
      baseRef: baseResolution,
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

function applyManifestApprovals(cwd, diff) {
  const approved = [];
  const added = (diff.added || []).filter((entrypoint) => {
    const approval = activeApprovalFor(cwd, 'manifest-entry', { entrypointId: entrypoint.id }, {
      cwd,
      environment: 'ci',
      command: 'execfence ci',
    });
    if (approval) {
      approved.push({ changeType: 'added', entrypoint, approvalId: approval.id });
      return false;
    }
    return true;
  });
  const changed = (diff.changed || []).filter((change) => {
    const approval = activeApprovalFor(cwd, 'manifest-entry', { entrypointId: change.after?.id }, {
      cwd,
      environment: 'ci',
      command: 'execfence ci',
    });
    if (approval) {
      approved.push({ changeType: 'changed', entrypoint: change.after, approvalId: approval.id });
      return false;
    }
    return true;
  });
  const risk = (diff.risk || []).filter((item) => {
    const id = item.entrypoint?.id || item.after?.id;
    return !approved.some((entry) => entry.entrypoint?.id === id);
  });
  return {
    ...diff,
    ok: added.length === 0 && changed.length === 0,
    added,
    changed,
    risk,
    approvedChanges: approved,
  };
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
  applyManifestApprovals,
  findingsFromManifestDiff,
  runCi,
};
