'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { projectDirName } = require('./paths');

const sandboxFileName = `${projectDirName}/config/sandbox.json`;
const helperMetadataFileName = `${projectDirName}/helper/execfence-helper.json`;

const profiles = {
  test: {
    fs: {
      readAllow: ['.'],
      writeAllow: ['.', '.execfence/reports', '.execfence/cache', 'coverage', 'tmp', 'temp'],
      deny: ['.git', '.ssh', '.env', '.env.local'],
      denyNewExecutable: true,
    },
    process: {
      allow: [],
      deny: ['curl', 'wget', 'powershell -enc', 'Invoke-WebRequest', 'bash -c', 'sh -c', 'cmd /c'],
      superviseChildren: true,
    },
    network: {
      default: 'deny',
      allow: ['localhost', '127.0.0.1', '::1'],
      auditOnly: false,
    },
  },
  build: {
    fs: {
      readAllow: ['.'],
      writeAllow: ['dist', 'build', '.next', '.nuxt', '.execfence/reports', '.execfence/cache', 'tmp', 'temp'],
      deny: ['.git', '.ssh', '.env', '.env.local'],
      denyNewExecutable: true,
    },
    process: {
      allow: [],
      deny: ['curl |', 'wget |', 'powershell -enc', 'eval(', 'bash -c', 'sh -c'],
      superviseChildren: true,
    },
    network: {
      default: 'audit',
      allow: [],
      auditOnly: true,
    },
  },
  dev: {
    fs: {
      readAllow: ['.'],
      writeAllow: ['.', '.execfence/reports', '.execfence/cache', 'tmp', 'temp'],
      deny: ['.git', '.ssh', '.env', '.env.local'],
      denyNewExecutable: true,
    },
    process: {
      allow: ['node', 'npm', 'pnpm', 'yarn', 'bun', 'go', 'python', 'cargo'],
      deny: ['powershell -enc', 'Invoke-WebRequest', 'curl |', 'wget |'],
      superviseChildren: true,
    },
    network: {
      default: 'audit',
      allow: ['localhost', '127.0.0.1', '::1'],
      auditOnly: true,
    },
  },
  pack: {
    fs: {
      readAllow: ['.'],
      writeAllow: ['.', 'dist', 'build', '.execfence/reports', '.execfence/cache'],
      deny: ['.git', '.ssh', '.env', '.env.local'],
      denyNewExecutable: true,
    },
    process: {
      allow: ['npm', 'pnpm', 'yarn', 'bun', 'node'],
      deny: ['curl', 'wget', 'powershell', 'bash -c', 'sh -c'],
      superviseChildren: true,
    },
    network: {
      default: 'deny',
      allow: ['registry.npmjs.org'],
      auditOnly: false,
    },
  },
  publish: {
    fs: {
      readAllow: ['.'],
      writeAllow: ['.', 'dist', 'build', '.execfence/reports', '.execfence/cache'],
      deny: ['.git', '.ssh', '.env', '.env.local'],
      denyNewExecutable: true,
    },
    process: {
      allow: ['npm', 'pnpm', 'yarn', 'bun', 'node'],
      deny: ['curl', 'wget', 'powershell', 'bash -c', 'sh -c'],
      superviseChildren: true,
    },
    network: {
      default: 'deny',
      allow: ['registry.npmjs.org'],
      auditOnly: false,
    },
  },
  strict: {
    fs: {
      readAllow: ['.'],
      writeAllow: ['.execfence/reports', '.execfence/cache', 'tmp', 'temp'],
      deny: ['.git', '.ssh', '.env', '.env.local', 'node_modules'],
      denyNewExecutable: true,
    },
    process: {
      allow: [],
      deny: ['curl', 'wget', 'powershell', 'Invoke-WebRequest', 'bash', 'sh', 'cmd', 'python -c', 'node -e'],
      superviseChildren: true,
    },
    network: {
      default: 'deny',
      allow: [],
      auditOnly: false,
    },
  },
};

function defaultSandboxConfig() {
  return mergeProfile({
    $schema: 'https://raw.githubusercontent.com/chrystyan96/execfence/master/schema/execfence-sandbox.schema.json',
    mode: 'audit',
    profile: 'test',
    allowDegraded: false,
    helper: {
      path: helperMetadataFileName,
      requiredForEnforce: true,
    },
  });
}

function sandboxConfigPath(cwd = process.cwd()) {
  return path.join(cwd, sandboxFileName);
}

function helperMetadataPath(cwd = process.cwd(), config = defaultSandboxConfig()) {
  return path.resolve(cwd, config.helper?.path || helperMetadataFileName);
}

function loadSandboxConfig(cwd = process.cwd()) {
  const filePath = sandboxConfigPath(cwd);
  if (!fs.existsSync(filePath)) {
    const config = defaultSandboxConfig();
    return { config, configPath: null, exists: false };
  }
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`Could not parse ${filePath}: ${error.message}`);
  }
  const profileName = parsed.profile || 'test';
  return {
    config: mergeProfile({ ...parsed, profile: profileName }),
    configPath: filePath,
    exists: true,
  };
}

function initSandbox(cwd = process.cwd(), options = {}) {
  const filePath = sandboxConfigPath(cwd);
  const config = defaultSandboxConfig();
  if (options.dryRun) {
    return { ok: true, changed: !fs.existsSync(filePath), configPath: filePath, config };
  }
  if (!fs.existsSync(filePath)) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify(config, null, 2)}\n`);
    return { ok: true, changed: true, configPath: filePath, config };
  }
  return { ok: true, changed: false, configPath: filePath, config: loadSandboxConfig(cwd).config };
}

function sandboxCapabilities(cwd = process.cwd(), options = {}) {
  const { config } = loadSandboxConfig(cwd);
  const helper = helperAudit(cwd, { config });
  const hasHelper = Boolean(helper.ok && helper.installed);
  const filesystem = hasHelper ? 'yes' : 'degraded';
  const processSupervision = hasHelper ? 'yes' : 'degraded';
  const network = hasHelper ? 'yes' : 'no';
  const missingForEnforce = [];
  if (filesystem !== 'yes') {
    missingForEnforce.push('filesystem enforcement helper');
  }
  if (processSupervision !== 'yes') {
    missingForEnforce.push('process tree enforcement helper');
  }
  if (network !== 'yes') {
    missingForEnforce.push('network enforcement helper');
  }
  return {
    ok: true,
    cwd: path.resolve(cwd),
    platform: process.platform,
    arch: process.arch,
    mode: options.mode || config.mode || 'audit',
    profile: options.profile || config.profile || 'test',
    filesystem: {
      enforcement: filesystem,
      detail: hasHelper ? 'Verified helper metadata is available.' : 'Built-in mode can snapshot and rescan files, but cannot block writes before they happen.',
    },
    process: {
      supervision: processSupervision,
      detail: hasHelper ? 'Verified helper metadata is available.' : 'Built-in mode records the root process only and cannot block child processes.',
    },
    network: {
      enforcement: network,
      detail: hasHelper ? 'Verified helper metadata is available.' : 'Built-in mode cannot block outbound network connections.',
    },
    helper,
    missingForEnforce,
  };
}

function sandboxPlan(cwd = process.cwd(), commandArgs = [], options = {}) {
  const loaded = loadSandboxConfig(cwd);
  const requestedMode = options.mode || (options.sandbox ? 'enforce' : loaded.config.mode) || 'audit';
  const profileName = options.profile || loaded.config.profile || 'test';
  const config = mergeProfile({ ...loaded.config, mode: requestedMode, profile: profileName });
  const capabilities = sandboxCapabilities(cwd, { mode: requestedMode, profile: profileName });
  const missingCapabilities = requestedMode === 'enforce' ? capabilities.missingForEnforce : [];
  const allowDegraded = Boolean(options.allowDegraded || config.allowDegraded);
  const ok = requestedMode !== 'enforce' || allowDegraded || missingCapabilities.length === 0;
  const commandText = commandArgs.map(String).join(' ');
  const processDecision = commandDecision(commandText, config.process || {});
  const blockedOperations = [];
  if (!ok) {
    blockedOperations.push({
      domain: 'sandbox',
      operation: 'start command',
      reason: `Sandbox enforce requested but missing: ${missingCapabilities.join(', ')}`,
    });
  }
  if (processDecision.blocked) {
    blockedOperations.push({
      domain: 'process',
      operation: commandText,
      reason: processDecision.reason,
    });
  }
  return {
    ok: ok && (requestedMode !== 'enforce' || !processDecision.blocked),
    cwd: path.resolve(cwd),
    configPath: loaded.configPath,
    mode: requestedMode,
    profile: profileName,
    allowDegraded,
    command: {
      argv: commandArgs,
      display: commandText,
    },
    capabilities,
    fs: {
      readAllow: normalizeList(config.fs?.readAllow),
      writeAllow: normalizeList(config.fs?.writeAllow),
      deny: normalizeList(config.fs?.deny),
      denyNewExecutable: config.fs?.denyNewExecutable !== false,
      missingEnforcement: capabilities.filesystem.enforcement !== 'yes',
    },
    process: {
      allow: normalizeList(config.process?.allow),
      deny: normalizeList(config.process?.deny),
      superviseChildren: config.process?.superviseChildren !== false,
      decision: processDecision,
      missingEnforcement: capabilities.process.supervision !== 'yes',
    },
    network: {
      default: config.network?.default || 'deny',
      allow: normalizeList(config.network?.allow),
      auditOnly: Boolean(config.network?.auditOnly),
      missingEnforcement: capabilities.network.enforcement !== 'yes',
    },
    decisions: planDecisions(config, capabilities, requestedMode),
    blockedOperations,
    missingCapabilities,
  };
}

function sandboxPreflight(cwd = process.cwd(), commandArgs = [], options = {}) {
  const plan = sandboxPlan(cwd, commandArgs, options);
  if (plan.ok) {
    return { ok: true, blocked: false, plan, findings: [] };
  }
  const finding = {
    id: 'sandbox-enforcement-unavailable',
    severity: 'high',
    file: sandboxFileName,
    line: 1,
    detail: plan.blockedOperations.map((item) => item.reason).join(' ') || 'Sandbox policy blocked command execution.',
  };
  return {
    ok: false,
    blocked: true,
    plan,
    findings: [finding],
  };
}

function explainSandbox(cwd = process.cwd(), options = {}) {
  const { config, configPath } = loadSandboxConfig(cwd);
  const capabilities = sandboxCapabilities(cwd, options);
  return {
    ok: true,
    configPath,
    mode: options.mode || config.mode,
    profile: options.profile || config.profile,
    profiles: Object.keys(profiles),
    summary: 'ExecFence V3 sandbox uses audit mode without a helper and blocks enforce mode when required enforcement capabilities are unavailable.',
    enforcement: {
      audit: 'Runs the command, records sandbox policy, and rescans after execution.',
      enforce: 'Requires verified local enforcement capabilities. Without them, ExecFence blocks before execution unless --allow-degraded is explicit.',
    },
    capabilities,
  };
}

function helperAudit(cwd = process.cwd(), options = {}) {
  const config = options.config || loadSandboxConfig(cwd).config;
  const metadataPath = helperMetadataPath(cwd, config);
  if (!fs.existsSync(metadataPath)) {
    return {
      ok: false,
      installed: false,
      metadataPath,
      reason: 'No helper metadata found. CLI base remains usable for scan, ci, run, and sandbox audit mode.',
    };
  }
  let metadata;
  try {
    metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
  } catch (error) {
    return { ok: false, installed: true, metadataPath, reason: `Could not parse helper metadata: ${error.message}` };
  }
  const issues = [];
  if (!metadata.name) issues.push('missing name');
  if (!metadata.version) issues.push('missing version');
  if (metadata.platform && metadata.platform !== process.platform) issues.push(`platform mismatch: ${metadata.platform} != ${process.platform}`);
  if (!/^[a-f0-9]{64}$/i.test(String(metadata.sha256 || ''))) issues.push('missing or invalid sha256');
  if (!metadata.provenance) issues.push('missing provenance');
  let actualSha256 = null;
  if (metadata.path) {
    const helperBinary = path.resolve(path.dirname(metadataPath), metadata.path);
    if (!fs.existsSync(helperBinary)) {
      issues.push('helper binary path does not exist');
    } else {
      actualSha256 = sha256File(helperBinary);
      if (metadata.sha256 && actualSha256 !== String(metadata.sha256).toLowerCase()) {
        issues.push('helper binary hash mismatch');
      }
    }
  }
  return {
    ok: issues.length === 0,
    installed: true,
    metadataPath,
    metadata: {
      name: metadata.name || null,
      version: metadata.version || null,
      platform: metadata.platform || null,
      sha256: metadata.sha256 || null,
      provenance: metadata.provenance || null,
      path: metadata.path || null,
      actualSha256,
    },
    issues,
  };
}

function installHelperMetadata(cwd = process.cwd(), metadataFile) {
  if (!metadataFile) {
    return {
      ok: false,
      installed: false,
      reason: 'ExecFence does not bundle a sandbox helper. Provide verified metadata with --metadata <file>.',
    };
  }
  const source = path.resolve(cwd, metadataFile);
  if (!fs.existsSync(source)) {
    return { ok: false, installed: false, reason: `Metadata file not found: ${source}` };
  }
  const target = helperMetadataPath(cwd);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
  return helperAudit(cwd);
}

function uninstallHelperMetadata(cwd = process.cwd()) {
  const target = helperMetadataPath(cwd);
  if (fs.existsSync(target)) {
    fs.unlinkSync(target);
    return { ok: true, removed: true, metadataPath: target };
  }
  return { ok: true, removed: false, metadataPath: target };
}

function mergeProfile(config) {
  const profile = profiles[config.profile || 'test'] || profiles.test;
  return {
    ...config,
    fs: { ...profile.fs, ...(config.fs || {}) },
    process: { ...profile.process, ...(config.process || {}) },
    network: { ...profile.network, ...(config.network || {}) },
  };
}

function commandDecision(commandText, processPolicy) {
  const deny = normalizeList(processPolicy.deny);
  const lower = commandText.toLowerCase();
  const match = deny.find((item) => lower.includes(String(item).toLowerCase()));
  if (match) {
    return { blocked: true, reason: `Command matches sandbox process deny rule: ${match}` };
  }
  return { blocked: false, reason: 'No process deny rule matched.' };
}

function planDecisions(config, capabilities, mode) {
  return [
    {
      domain: 'filesystem',
      decision: mode === 'enforce' && capabilities.filesystem.enforcement === 'yes' ? 'enforce' : 'audit',
      reason: capabilities.filesystem.detail,
      policy: `writeAllow=${normalizeList(config.fs?.writeAllow).join(',') || '(none)'}`,
    },
    {
      domain: 'process',
      decision: mode === 'enforce' && capabilities.process.supervision === 'yes' ? 'enforce' : 'audit',
      reason: capabilities.process.detail,
      policy: `deny=${normalizeList(config.process?.deny).join(',') || '(none)'}`,
    },
    {
      domain: 'network',
      decision: mode === 'enforce' && capabilities.network.enforcement === 'yes' ? 'enforce' : 'audit',
      reason: capabilities.network.detail,
      policy: `default=${config.network?.default || 'deny'}`,
    },
  ];
}

function normalizeList(value) {
  return Array.isArray(value) ? value : [];
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

module.exports = {
  defaultSandboxConfig,
  explainSandbox,
  helperAudit,
  helperMetadataFileName,
  initSandbox,
  installHelperMetadata,
  loadSandboxConfig,
  profiles,
  sandboxCapabilities,
  sandboxConfigPath,
  sandboxFileName,
  sandboxPlan,
  sandboxPreflight,
  uninstallHelperMetadata,
};
