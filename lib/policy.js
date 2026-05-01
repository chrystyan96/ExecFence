'use strict';

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
  const pack = policyPacks[name] || policyPacks.baseline;
  return {
    ...pack,
    ...config,
    policyPack: name,
    roots: config.roots || pack.roots,
    blockSeverities: config.blockSeverities || pack.blockSeverities,
    warnSeverities: config.warnSeverities || pack.warnSeverities || ['medium', 'low'],
    reportsDir: config.reportsDir || pack.reportsDir || reportsDir,
    reportsGitignore: config.reportsGitignore ?? pack.reportsGitignore ?? true,
    analysis: config.analysis || pack.analysis || {
      webEnrichment: {
        enabled: false,
        maxQueriesPerFinding: 3,
        allowedDomains: [],
      },
    },
  };
}

module.exports = {
  applyPolicyPack,
  policyPacks,
};
