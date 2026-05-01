'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  baselineFileName,
  configFileName,
  projectDirName,
  reportsDir,
  signaturesFileName,
} = require('./paths');

function loadConfig(cwd = process.cwd(), explicitPath) {
  const configPath = explicitPath ? path.resolve(cwd, explicitPath) : path.join(cwd, configFileName);
  let config = {};
  let loadedConfigPath = null;
  if (fs.existsSync(configPath)) {
    try {
      config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      loadedConfigPath = configPath;
    } catch (error) {
      throw new Error(`Could not parse ${configPath}: ${error.message}`);
    }
  }

  const signaturesPath = config.signaturesFile
    ? path.resolve(cwd, config.signaturesFile)
    : path.join(cwd, signaturesFileName);
  if (fs.existsSync(signaturesPath)) {
    try {
      config.externalSignatures = JSON.parse(fs.readFileSync(signaturesPath, 'utf8'));
      config.signaturesPath = signaturesPath;
    } catch (error) {
      throw new Error(`Could not parse ${signaturesPath}: ${error.message}`);
    }
  }
  return { config, configPath: loadedConfigPath };
}

function createDefaultConfig(cwd = process.cwd(), options = {}) {
  const configPath = path.join(cwd, configFileName);
  if (fs.existsSync(configPath)) {
    return { configPath, changed: false };
  }
  const config = {
    $schema: 'https://raw.githubusercontent.com/chrystyan96/execfence/master/schema/execfence.schema.json',
    policyPack: 'baseline',
    mode: 'block',
    blockSeverities: ['critical', 'high'],
    warnSeverities: ['medium', 'low'],
    roots: ['backend-go', 'backend', 'frontend', 'desktop', 'packages', 'scripts', '.github', '.vscode'],
    ignoreDirs: [],
    skipFiles: [],
    allowExecutables: [],
    extraSignatures: [],
    extraRegexSignatures: [],
    signaturesFile: signaturesFileName,
    baselineFile: baselineFileName,
    sandboxFile: '.execfence/config/sandbox.json',
    reportsDir,
    reportsGitignore: true,
    runtimeTrace: {
      enabled: true,
      postRunScan: true,
      captureGitStatus: true,
      redactEnv: true,
      snapshotFiles: true,
      recordArtifacts: false,
      denyOnNewExecutable: false,
    },
    analysis: {
      webEnrichment: {
        enabled: true,
        automaticForSeverities: ['critical', 'high'],
        maxQueriesPerFinding: 3,
        allowedDomains: [],
        timeoutMs: 4000,
        cacheTtlMs: 86400000,
      },
    },
    manifest: {
      path: '.execfence/manifest.json',
      requireRunWrapper: true,
      blockNewEntrypoints: true,
      sensitiveEntrypoints: ['build', 'test', 'dev', 'start', 'serve', 'watch', 'prepare', 'install', 'postinstall'],
    },
    ci: {
      enabled: true,
      baseRef: 'HEAD',
      checks: ['scan', 'manifest-diff', 'deps-diff', 'pack-audit', 'trust-audit'],
    },
    wire: {
      packageScripts: true,
      workflows: true,
      makefile: true,
      vscodeTasks: true,
    },
    deps: {
      detectRegistryDrift: true,
      detectSuspiciousSources: true,
      detectLifecycleEntries: true,
      detectBinEntries: true,
      detectTyposquatting: true,
    },
    adopt: {
      writeSuggestedBaseline: false,
      blockDuringAdoption: false,
    },
    policy: {
      customPoliciesDir: '.execfence/config/policies',
      requiredOwners: {},
      requireSignedPolicyFiles: false,
    },
    trustStore: {
      files: '.execfence/trust/files.json',
      actions: '.execfence/trust/actions.json',
      registries: '.execfence/trust/registries.json',
      packageScopes: '.execfence/trust/package-scopes.json',
      packageSources: '.execfence/trust/package-sources.json',
    },
    htmlReport: {
      enabled: true,
      includeRuntimeTrace: true,
      includeManifest: true,
    },
    reportRetention: {
      maxReports: 100,
      maxAgeDays: 90,
    },
    reports: {
      retention: {
        maxReports: 100,
        maxAgeDays: 90,
      },
    },
    redaction: {
      redactLocalPaths: true,
      redactEnv: true,
      extraPatterns: [],
    },
    auditAllPackageScripts: false,
  };
  if (!options.dryRun) {
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
  }
  return { configPath, changed: true };
}

module.exports = {
  configFileName,
  projectDirName,
  reportsDir,
  signaturesFileName,
  baselineFileName,
  createDefaultConfig,
  loadConfig,
};
