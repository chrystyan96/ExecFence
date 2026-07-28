'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { reportsDir, resolveProjectPath } = require('./paths');

const policyPacks = {
  baseline: {
    blockSeverities: ['critical', 'high'],
    auditAllPackageScripts: false,
    workflowHardening: true,
    archiveAudit: true,
  },
  web: {
    blockSeverities: ['critical', 'high'],
    auditAllPackageScripts: false,
    workflowHardening: true,
  },
  desktop: {
    blockSeverities: ['critical', 'high', 'medium'],
    auditAllPackageScripts: true,
    workflowHardening: true,
    archiveAudit: true,
  },
  node: {
    blockSeverities: ['critical', 'high'],
    auditAllPackageScripts: true,
    workflowHardening: true,
  },
  go: {
    blockSeverities: ['critical', 'high'],
    workflowHardening: true,
  },
  python: {
    blockSeverities: ['critical', 'high'],
    workflowHardening: true,
  },
  rust: {
    blockSeverities: ['critical', 'high'],
    workflowHardening: true,
    archiveAudit: true,
  },
  agentic: {
    blockSeverities: ['critical', 'high', 'medium'],
    auditAllPackageScripts: true,
    workflowHardening: true,
  },
  strict: {
    blockSeverities: ['critical', 'high', 'medium'],
    auditAllPackageScripts: true,
    workflowHardening: true,
    archiveAudit: true,
  },
};

function applyPolicyPack(config = {}) {
  const name = config.policyPack || 'baseline';
  const custom = config.cwd ? loadCustomPolicyPack(config.cwd, name, config.policy?.customPoliciesDir) : null;
  const pack = custom || policyPacks[name] || policyPacks.baseline;
  const { cwd, ...projectConfig } = config;
  return {
    ...pack,
    ...projectConfig,
    policyPack: name,
    roots: projectConfig.roots || pack.roots,
    blockSeverities: projectConfig.blockSeverities || pack.blockSeverities,
    warnSeverities: projectConfig.warnSeverities || pack.warnSeverities || ['medium', 'low'],
    reportsDir: projectConfig.reportsDir || pack.reportsDir || reportsDir,
    reportsGitignore: projectConfig.reportsGitignore ?? pack.reportsGitignore ?? true,
    analysis: projectConfig.analysis || pack.analysis || {
      webEnrichment: {
        enabled: false,
        maxQueriesPerFinding: 3,
        allowedDomains: [],
      },
    },
  };
}

function resolvePolicy(cwd = process.cwd(), projectConfig = {}, invocation = {}) {
  const effective = applyPolicyPack({ cwd, ...projectConfig });
  const configuredBlocks = effective.blockSeverities || [];
  effective.blockSeverities = invocation.failOn?.length
    ? [...invocation.failOn]
    : Array.from(new Set(['critical', 'high', ...configuredBlocks]));
  effective.warnSeverities = invocation.warnOn?.length
    ? [...invocation.warnOn]
    : (effective.warnSeverities || ['medium', 'low']);
  return {
    config: effective,
    mode: invocation.mode || 'block',
    roots: invocation.roots?.length ? invocation.roots : ['.'],
  };
}

function loadCustomPolicyPack(cwd, name, customPoliciesDir) {
  if (!name || policyPacks[name]) {
    return null;
  }
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(name)) {
    throw new Error(`Invalid custom policy pack name: ${name}`);
  }
  const policiesDir = resolveProjectPath(cwd, customPoliciesDir, '.execfence/config/policies');
  const filePath = resolveProjectPath(cwd, path.relative(path.resolve(cwd), path.join(policiesDir, `${name}.json`)));
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  return { ...parsed, customPolicyPath: filePath };
}

function explainPolicy(cwd = process.cwd(), config = {}) {
  const resolved = resolvePolicy(cwd, config);
  const effective = resolved.config;
  return {
    cwd,
    policyPack: effective.policyPack,
    builtIn: Boolean(policyPacks[effective.policyPack]),
    customPolicyPath: effective.customPolicyPath || null,
    blockSeverities: effective.blockSeverities || [],
    warnSeverities: effective.warnSeverities || [],
    roots: resolved.roots,
    configuredRoots: effective.roots || [],
    mode: resolved.mode,
    configuredMode: config.mode || null,
    manifest: effective.manifest || {},
    requiredOwners: effective.policy?.requiredOwners || {},
    reason: `ExecFence applies ${effective.policyPack} defaults, then project config overrides. Findings in ${JSON.stringify(effective.blockSeverities || [])} block in block mode.`,
  };
}

function testPolicy(cwd = process.cwd(), config = {}) {
  const errors = [];
  const warnings = [];
  const resolved = resolvePolicy(cwd, config);
  const effective = resolved.config;
  for (const severity of effective.blockSeverities || []) {
    if (!['critical', 'high', 'medium', 'low'].includes(severity)) {
      errors.push(`Unknown block severity: ${severity}`);
    }
  }
  for (const severity of effective.warnSeverities || []) {
    if (!['critical', 'high', 'medium', 'low'].includes(severity)) {
      errors.push(`Unknown warn severity: ${severity}`);
    }
  }
  if (config.mode === 'audit') {
    warnings.push('Project mode=audit is ignored by the security floor; only an explicit CLI --mode audit invocation can enable audit mode.');
  }
  const policiesDir = resolveProjectPath(cwd, effective.policy?.customPoliciesDir, '.execfence/config/policies');
  if (fs.existsSync(policiesDir)) {
    for (const file of fs.readdirSync(policiesDir).filter((name) => name.endsWith('.json'))) {
      try {
        const parsed = JSON.parse(fs.readFileSync(path.join(policiesDir, file), 'utf8'));
        if (!Array.isArray(parsed.blockSeverities) && !Array.isArray(parsed.roots)) {
          warnings.push(`${file} does not define roots or blockSeverities.`);
        }
      } catch (error) {
        errors.push(`${file}: ${error.message}`);
      }
    }
  }
  const baselinePath = resolveProjectPath(cwd, effective.baselineFile, '.execfence/config/baseline.json');
  if (fs.existsSync(baselinePath)) {
    try {
      const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
      for (const [index, entry] of (baseline.findings || baseline || []).entries()) {
        for (const key of ['findingId', 'reason', 'owner', 'expiresAt']) {
          if (!entry[key]) {
            errors.push(`baseline entry ${index} missing ${key}`);
          }
        }
      }
    } catch (error) {
      errors.push(`baseline: ${error.message}`);
    }
  }
  return { cwd, ok: errors.length === 0, errors, warnings, effective };
}

function learnPolicyFromReport(cwd = process.cwd(), reportPath) {
  if (!reportPath) throw new Error('Usage: execfence policy learn --report <report.json>');
  const resolved = resolveProjectPath(cwd, reportPath);
  if (!fs.existsSync(resolved)) throw new Error(`Report not found: ${reportPath}`);
  const report = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  const proposals = (report.findings || []).map((finding) => ({
    type: 'finding',
    subject: {
      findingId: finding.id,
      file: finding.file,
      sha256: finding.sha256 || null,
    },
    suggestedScope: {
      branch: report.metadata?.gitBranch || null,
      environment: process.env.CI ? 'ci' : 'local',
    },
    suggestedExpiryDays: ['critical', 'high'].includes(finding.severity) ? 7 : 30,
    requiredSignatures: finding.severity === 'critical' ? 2 : 1,
    rationale: `Proposal only: review ${finding.id} before creating a signed, expiring approval.`,
  }));
  return {
    cwd: path.resolve(cwd),
    reportPath: resolved,
    mode: 'proposal-only',
    wroteFiles: false,
    findings: (report.findings || []).length,
    proposals,
    warning: 'Learning mode never mutates policy, baselines, trust, or approvals.',
  };
}

module.exports = {
  applyPolicyPack,
  explainPolicy,
  loadCustomPolicyPack,
  learnPolicyFromReport,
  policyPacks,
  resolvePolicy,
  testPolicy,
};
