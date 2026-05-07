'use strict';

const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { projectDirName } = require('./paths');

const sandboxFileName = `${projectDirName}/config/sandbox.json`;
const helperMetadataFileName = `${projectDirName}/helper/execfence-helper.json`;
const helperProtocolVersion = 1;
const requiredHelperCapabilities = ['filesystem', 'sensitiveReads', 'process', 'childProcesses', 'network', 'newExecutables'];
const helperCapabilityAliases = {
  filesystem: ['filesystem', 'filesystemDeny', 'filesystemWriteAllow'],
  sensitiveReads: ['sensitiveReads', 'sensitiveReadDeny'],
  process: ['process', 'processSupervision'],
  childProcesses: ['childProcesses', 'childProcessSupervision'],
  network: ['network', 'networkDeny'],
  newExecutables: ['newExecutables', 'newExecutableDeny', 'artifactAudit'],
};

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
      requiredCapabilities: requiredHelperCapabilities,
      minExecFenceVersion: '5.0.0',
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
  const helperCaps = helper.capabilities || helper.metadata?.capabilities || {};
  const helperVerified = Boolean(helper.ok && helper.installed && helper.selfTest?.ok);
  const filesystem = helperVerified && helperCaps.filesystem?.enforced && helperCaps.sensitiveReads?.enforced && helperCaps.newExecutables?.enforced ? 'yes' : 'degraded';
  const processSupervision = helperVerified && helperCaps.process?.enforced && helperCaps.childProcesses?.enforced ? 'yes' : 'degraded';
  const network = helperVerified && helperCaps.network?.enforced ? 'yes' : 'no';
  const missingForEnforce = [];
  if (filesystem !== 'yes') {
    missingForEnforce.push('filesystem/sensitive-read/new-executable enforcement helper');
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
    helperVerified,
    capabilityProof: helper.capabilityProof || [],
    unsupportedCapabilities: helper.unsupportedCapabilities || requiredHelperCapabilities,
    filesystem: {
      enforcement: filesystem,
      detail: filesystem === 'yes' ? 'Verified helper self-test proved filesystem, sensitive-read, and new executable controls.' : 'No verified helper proof for pre-execution filesystem/sensitive-read containment. Built-in mode can snapshot and rescan, but cannot block reads/writes before they happen.',
    },
    process: {
      supervision: processSupervision,
      detail: processSupervision === 'yes' ? 'Verified helper self-test proved process-tree supervision.' : 'No verified helper proof for process-tree containment. Built-in mode records the root process only.',
    },
    network: {
      enforcement: network,
      detail: network === 'yes' ? 'Verified helper self-test proved outbound network controls.' : 'No verified helper proof for outbound network blocking.',
    },
    helper,
    missingForEnforce,
  };
}

function sandboxPlan(cwd = process.cwd(), commandArgs = [], options = {}) {
  const loaded = loadSandboxConfig(cwd);
  const requestedMode = options.mode || (options.sandbox ? 'enforce' : loaded.config.mode) || 'audit';
  const profileName = options.profile || loaded.config.profile || 'test';
  const baseConfig = !loaded.exists && profileName !== loaded.config.profile
    ? stripProfilePolicy(loaded.config)
    : loaded.config;
  const config = mergeProfile({ ...baseConfig, mode: requestedMode, profile: profileName });
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
    helperVerified: capabilities.helperVerified,
    capabilityProof: capabilities.capabilityProof,
    unsupportedCapabilities: capabilities.unsupportedCapabilities,
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

function stripProfilePolicy(config) {
  const { fs: _fs, process: _process, network: _network, ...rest } = config;
  return rest;
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
    summary: 'ExecFence V5 sandbox uses audit mode without a helper and requires a verified platform helper self-test before enforce mode can execute.',
    enforcement: {
      audit: 'Runs the command, records sandbox policy, and rescans after execution.',
      enforce: 'Requires a verified helper binary, matching SHA-256, successful self-test, and enforced required capabilities. Without them, ExecFence blocks before execution unless --allow-degraded is explicit.',
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
  if (!metadata.schemaVersion) issues.push('missing schemaVersion');
  if (!metadata.name) issues.push('missing name');
  if (!metadata.version) issues.push('missing version');
  if (metadata.platform && metadata.platform !== process.platform) issues.push(`platform mismatch: ${metadata.platform} != ${process.platform}`);
  if (metadata.arch && metadata.arch !== process.arch) issues.push(`arch mismatch: ${metadata.arch} != ${process.arch}`);
  if (!/^[a-f0-9]{64}$/i.test(String(metadata.sha256 || ''))) issues.push('missing or invalid sha256');
  if (!metadata.provenance) issues.push('missing provenance');
  const declaredCapabilities = normalizeHelperCapabilities(metadata.capabilities);
  let actualSha256 = null;
  let helperBinary = null;
  if (!metadata.path) {
    issues.push('helper metadata must include executable path; metadata-only helpers cannot enable enforce mode');
  } else {
    helperBinary = path.resolve(path.dirname(metadataPath), metadata.path);
    if (!fs.existsSync(helperBinary)) {
      issues.push('helper binary path does not exist');
    } else {
      actualSha256 = sha256File(helperBinary);
      if (metadata.sha256 && actualSha256 !== String(metadata.sha256).toLowerCase()) {
        issues.push('helper binary hash mismatch');
      }
    }
  }
  const selfTest = helperBinary && fs.existsSync(helperBinary) ? runHelperSelfTest(helperBinary, cwd, metadata) : null;
  if (!selfTest) {
    issues.push('helper self-test did not run');
  } else {
    if (!selfTest.ok) issues.push(`helper self-test failed: ${selfTest.reason || 'unknown error'}`);
    if (selfTest.protocolVersion && Number(selfTest.protocolVersion) !== helperProtocolVersion) {
      issues.push(`helper protocol mismatch: ${selfTest.protocolVersion} != ${helperProtocolVersion}`);
    }
    if (selfTest.platform && selfTest.platform !== process.platform) issues.push(`self-test platform mismatch: ${selfTest.platform} != ${process.platform}`);
    if (selfTest.arch && selfTest.arch !== process.arch) issues.push(`self-test arch mismatch: ${selfTest.arch} != ${process.arch}`);
    if (selfTest.sha256 && actualSha256 && String(selfTest.sha256).toLowerCase() !== actualSha256) {
      issues.push('self-test binary hash mismatch');
    }
  }
  const capabilities = normalizeHelperCapabilities(selfTest?.capabilities || {});
  const required = Array.isArray(metadata.requiredCapabilities)
    ? metadata.requiredCapabilities
    : [];
  for (const capability of required) {
    if (!capabilities[capability]?.enforced) {
      issues.push(`missing verified helper capability: ${capability}`);
    }
  }
  const unsupportedCapabilities = requiredHelperCapabilities.filter((capability) => !capabilities[capability]?.enforced);
  const capabilityProof = Object.entries(capabilities)
    .filter(([, value]) => value.enforced)
    .map(([name, value]) => ({
      name,
      enforced: true,
      proof: value.proof || selfTest?.selfTestId || 'helper self-test',
    }));
  return {
    ok: issues.length === 0,
    installed: true,
    metadataPath,
    helperVerified: issues.length === 0,
    selfTest,
    capabilityProof,
    unsupportedCapabilities,
    capabilities,
    metadata: {
      schemaVersion: metadata.schemaVersion || null,
      name: metadata.name || null,
      version: metadata.version || null,
      platform: metadata.platform || null,
      arch: metadata.arch || null,
      sha256: metadata.sha256 || null,
      provenance: metadata.provenance || null,
      path: metadata.path || null,
      minExecFenceVersion: metadata.minExecFenceVersion || null,
      declaredCapabilities,
      actualSha256,
      binaryPath: helperBinary,
    },
    issues,
  };
}

function normalizeHelperCapabilities(value = {}) {
  return Object.fromEntries(requiredHelperCapabilities.map((capability) => {
    const aliases = helperCapabilityAliases[capability] || [capability];
    const raw = aliases.map((name) => value[name]).find((item) => item !== undefined);
    if (raw && typeof raw === 'object') {
      return [capability, {
        enforced: Boolean(raw.enforced === undefined ? raw.available : raw.enforced),
        available: Boolean(raw.available === undefined ? raw.enforced : raw.available),
        proof: raw.proof || raw.method || null,
        requiresElevation: Boolean(raw.requiresElevation),
        limitation: raw.limitation || null,
      }];
    }
    return [capability, {
      enforced: Boolean(raw),
      available: Boolean(raw),
      proof: raw ? 'declared boolean capability' : null,
      requiresElevation: false,
      limitation: raw ? null : 'not reported by helper self-test',
    }];
  }));
}

function installHelperMetadata(cwd = process.cwd(), metadataFile, options = {}) {
  if (!metadataFile && !options.binary) {
    return {
      ok: false,
      installed: false,
      reason: 'Provide verified helper metadata with --metadata <file> or a helper binary with --binary <file>.',
    };
  }
  let metadata;
  let sourceDir = cwd;
  if (metadataFile) {
    const source = path.resolve(cwd, metadataFile);
    if (!fs.existsSync(source)) {
      return { ok: false, installed: false, reason: `Metadata file not found: ${source}` };
    }
    sourceDir = path.dirname(source);
    try {
      metadata = JSON.parse(fs.readFileSync(source, 'utf8'));
    } catch (error) {
      return { ok: false, installed: false, reason: `Could not parse helper metadata: ${error.message}` };
    }
  } else {
    const binary = path.resolve(cwd, options.binary);
    if (!fs.existsSync(binary)) {
      return { ok: false, installed: false, reason: `Helper binary not found: ${binary}` };
    }
    metadata = defaultHelperMetadata(binary);
    sourceDir = path.dirname(binary);
  }
  const target = helperMetadataPath(cwd);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  if (metadata.path) {
    const sourceBinary = path.resolve(sourceDir, metadata.path);
    if (fs.existsSync(sourceBinary)) {
      const targetBinary = path.join(path.dirname(target), path.basename(metadata.path));
      fs.copyFileSync(sourceBinary, targetBinary);
      metadata.path = path.basename(targetBinary);
      metadata.sha256 = sha256File(targetBinary);
    }
  }
  fs.writeFileSync(target, `${JSON.stringify(metadata, null, 2)}\n`);
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

function defaultHelperMetadata(binaryPath) {
  const binary = path.resolve(binaryPath);
  return {
    schemaVersion: 1,
    name: 'execfence-helper',
    version: '5.0.0-local',
    platform: process.platform,
    arch: process.arch,
    path: path.basename(binary),
    sha256: sha256File(binary),
    provenance: 'local install-helper --binary',
    minExecFenceVersion: '5.0.0',
    requiredCapabilities: [],
    capabilities: {},
  };
}

function runHelperSelfTest(helperBinary, cwd, metadata) {
  const invocation = helperInvocation(helperBinary, ['self-test']);
  const child = spawnSync(invocation.command, invocation.args, {
    cwd,
    env: {
      ...process.env,
      EXECFENCE_HELPER_EXPECTED_SHA256: String(metadata.sha256 || ''),
    },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 10_000,
  });
  if (child.error) {
    return { ok: false, reason: child.error.message, stderr: child.stderr || '' };
  }
  if (child.status !== 0) {
    return { ok: false, reason: `self-test exited ${child.status}`, stderr: child.stderr || '' };
  }
  try {
    const parsed = JSON.parse(String(child.stdout || '').trim() || '{}');
    return { ...parsed, ok: parsed.ok !== false };
  } catch (error) {
    return { ok: false, reason: `self-test did not return JSON: ${error.message}`, stdout: child.stdout || '', stderr: child.stderr || '' };
  }
}

function runSandboxedCommand(cwd, commandArgs, plan, options = {}) {
  const helper = plan.capabilities?.helper || helperAudit(cwd);
  const helperBinary = helper.metadata?.binaryPath;
  if (!helper.ok || !helperBinary) {
    return {
      status: 126,
      signal: null,
      error: new Error('Verified sandbox helper is unavailable.'),
      helper: { ok: false, reason: helper.reason || helper.issues?.join('; ') || 'helper unavailable' },
      events: [],
    };
  }
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-helper-'));
  const policyPath = path.join(tempDir, 'policy.json');
  const eventsPath = path.join(tempDir, 'events.jsonl');
  const policy = sandboxPolicy(plan, commandArgs);
  fs.writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
  const invocation = helperInvocation(helperBinary, ['run', '--policy', policyPath, '--events', eventsPath, '--', ...commandArgs]);
  const child = spawnSync(invocation.command, invocation.args, {
    cwd,
    shell: false,
    stdio: options.stdio || 'inherit',
    env: process.env,
  });
  const events = readJsonl(eventsPath);
  return {
    status: child.status,
    signal: child.signal,
    error: child.error || null,
    pid: child.pid || null,
    stdout: child.stdout,
    stderr: child.stderr,
    helper: {
      ok: !child.error,
      command: invocation.command,
      args: invocation.args,
      metadataPath: helper.metadataPath,
      binaryPath: helperBinary,
      sha256: helper.metadata?.actualSha256,
      selfTestId: helper.selfTest?.selfTestId || null,
      policyHash: sha256String(JSON.stringify(policy)),
      eventsPath,
    },
    events,
  };
}

function sandboxPolicy(plan, commandArgs) {
  return {
    schemaVersion: 1,
    protocolVersion: helperProtocolVersion,
    mode: plan.mode,
    profile: plan.profile,
    cwd: plan.cwd,
    command: {
      argv: commandArgs,
      display: commandArgs.map(String).join(' '),
    },
    requiredCapabilities: requiredHelperCapabilities,
    fs: plan.fs,
    process: plan.process,
    network: plan.network,
    capabilityProof: plan.capabilityProof || [],
  };
}

function helperInvocation(helperBinary, args) {
  if (/\.js$/i.test(helperBinary)) {
    return { command: process.execPath, args: [helperBinary, ...args] };
  }
  return { command: helperBinary, args };
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) {
    return [];
  }
  return fs.readFileSync(filePath, 'utf8')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return { type: 'parse-error', raw: line };
      }
    });
}

function sha256String(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
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
  runSandboxedCommand,
  sandboxCapabilities,
  sandboxConfigPath,
  sandboxFileName,
  sandboxPlan,
  sandboxPolicy,
  sandboxPreflight,
  uninstallHelperMetadata,
};
