'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { reportsDir } = require('./paths');

const policyPacks = {
  baseline: {
    blockSeverities: ['critical', 'high'],
    auditAllPackageScripts: false,
    workflowHardening: true,
    archiveAudit: true,
  },
  web: {
    roots: ['frontend', 'web', 'app', 'src', 'packages', '.github', '.vscode'],
    blockSeverities: ['critical', 'high'],
    auditAllPackageScripts: false,
    workflowHardening: true,
  },
  desktop: {
    roots: ['desktop', 'src-tauri', 'electron', 'app', 'packages', '.github', '.vscode'],
    blockSeverities: ['critical', 'high', 'medium'],
    auditAllPackageScripts: true,
    workflowHardening: true,
    archiveAudit: true,
  },
  node: {
    roots: ['.', 'packages', 'scripts', '.github', '.vscode'],
    blockSeverities: ['critical', 'high'],
    auditAllPackageScripts: true,
    workflowHardening: true,
  },
  go: {
    roots: ['.', 'backend-go', 'cmd', 'internal', 'pkg', '.github', '.vscode'],
    blockSeverities: ['critical', 'high'],
    workflowHardening: true,
  },
  python: {
    roots: ['.', 'src', 'scripts', 'tests', '.github', '.vscode'],
    blockSeverities: ['critical', 'high'],
    workflowHardening: true,
  },
  rust: {
    roots: ['.', 'src', 'crates', 'src-tauri', '.cargo', '.github', '.vscode'],
    blockSeverities: ['critical', 'high'],
    workflowHardening: true,
    archiveAudit: true,
  },
  agentic: {
    roots: ['.', 'agents', 'mcp', 'tools', 'scripts', '.github', '.vscode'],
    blockSeverities: ['critical', 'high', 'medium'],
    auditAllPackageScripts: true,
    workflowHardening: true,
  },
  strict: {
    roots: ['.'],
    blockSeverities: ['critical', 'high', 'medium'],
    auditAllPackageScripts: true,
    workflowHardening: true,
    archiveAudit: true,
  },
};

function applyPolicyPack(config = {}) {
  const name = config.policyPack || 'baseline';
  const custom = config.cwd ? loadCustomPolicyPack(config.cwd, name) : null;
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

function loadCustomPolicyPack(cwd, name) {
  if (!name || policyPacks[name]) {
    return null;
  }
  const filePath = path.join(cwd, '.execfence', 'config', 'policies', `${name}.json`);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  return { ...parsed, customPolicyPath: filePath };
}

function explainPolicy(cwd = process.cwd(), config = {}) {
  const effective = applyPolicyPack({ cwd, ...config });
  return {
    cwd,
    policyPack: effective.policyPack,
    builtIn: Boolean(policyPacks[effective.policyPack]),
    customPolicyPath: effective.customPolicyPath || null,
    blockSeverities: effective.blockSeverities || [],
    warnSeverities: effective.warnSeverities || [],
    roots: effective.roots || [],
    mode: effective.mode || 'block',
    manifest: effective.manifest || {},
    requiredOwners: effective.requiredOwners || {},
    reason: `ExecFence applies ${effective.policyPack} defaults, then project config overrides. Findings in ${JSON.stringify(effective.blockSeverities || [])} block in block mode.`,
  };
}

function testPolicy(cwd = process.cwd(), config = {}) {
  const errors = [];
  const warnings = [];
  const effective = applyPolicyPack({ cwd, ...config });
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
  const policiesDir = path.join(cwd, '.execfence', 'config', 'policies');
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
  const baselinePath = path.join(cwd, effective.baselineFile || '.execfence/config/baseline.json');
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

module.exports = {
  applyPolicyPack,
  explainPolicy,
  loadCustomPolicyPack,
  policyPacks,
  testPolicy,
};
