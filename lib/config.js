'use strict';

const fs = require('node:fs');
const path = require('node:path');

const configFileName = '.security-guardrails.json';
const signaturesFileName = '.security-guardrails.signatures.json';

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
    $schema: 'https://raw.githubusercontent.com/chrystyan96/security-guardrails/master/schema/security-guardrails.schema.json',
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
    signaturesFile: '.security-guardrails.signatures.json',
    baselineFile: '.security-guardrails.baseline.json',
    auditAllPackageScripts: false,
  };
  if (!options.dryRun) {
    fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
  }
  return { configPath, changed: true };
}

module.exports = {
  configFileName,
  signaturesFileName,
  createDefaultConfig,
  loadConfig,
};
