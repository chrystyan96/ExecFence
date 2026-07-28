'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { analyzeCoverage } = require('./coverage');
const { baselineFileName, configFileName, resolveProjectPath, signaturesFileName } = require('./paths');
const { profiles, sandboxCapabilities } = require('./sandbox');
const { validateSchema } = require('./schema-validator');
const { auditApprovals } = require('./approvals');

const configFiles = [
  { id: 'config', file: configFileName, schema: 'execfence.schema.json' },
  { id: 'baseline', file: baselineFileName, schema: 'execfence-baseline.schema.json' },
  { id: 'signatures', file: signaturesFileName, schema: 'execfence-signatures.schema.json' },
  { id: 'sandbox', file: '.execfence/config/sandbox.json', schema: 'execfence-sandbox.schema.json' },
  { id: 'approvals', file: '.execfence/approvals.json', schema: 'execfence-approvals.schema.json' },
  { id: 'approvers', file: '.execfence/trust/approvers.json', schema: 'execfence-approvers.schema.json' },
];

function validateConfig(cwd = process.cwd(), options = {}) {
  const root = path.resolve(cwd);
  const strict = Boolean(options.strict);
  const findings = [];
  const files = [];
  const parsed = {};
  let configuredPaths = {};
  try {
    const mainPath = path.join(root, configFileName);
    configuredPaths = fs.existsSync(mainPath) ? JSON.parse(fs.readFileSync(mainPath, 'utf8')) : {};
  } catch {
    configuredPaths = {};
  }
  const validationFiles = configFiles.map((item) => ({
    ...item,
    file: item.id === 'baseline' ? (configuredPaths.baselineFile || item.file)
      : item.id === 'signatures' ? (configuredPaths.signaturesFile || item.file)
        : item.id === 'sandbox' ? (configuredPaths.sandboxFile || item.file)
          : item.id === 'approvals' ? (configuredPaths.approvals?.path || item.file)
            : item.id === 'approvers' ? (configuredPaths.approvals?.approversPath || item.file)
          : item.file,
  }));

  for (const item of validationFiles) {
    let fullPath;
    try {
      fullPath = resolveProjectPath(root, item.file);
    } catch (error) {
      const file = { id: item.id, file: item.file, exists: false, ok: false };
      add(findings, 'config-path-escapes-project', 'high', item.file, 1, error.message, true);
      files.push(file);
      continue;
    }
    const file = { id: item.id, file: item.file, exists: fs.existsSync(fullPath), ok: true };
    if (!file.exists) {
      files.push(file);
      continue;
    }
    try {
      parsed[item.id] = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
      validateAgainstSchema(item, parsed[item.id], findings);
    } catch (error) {
      file.ok = false;
      add(findings, 'config-json-parse-error', 'high', item.file, 1, `Could not parse JSON: ${error.message}`, true);
      files.push(file);
      continue;
    }
    files.push(file);
  }

  validateMainConfig(root, parsed.config || {}, findings, strict);
  validateBaseline(root, parsed.baseline || {}, findings, strict, parsed.config || {});
  validateSignatures(parsed.config || {}, parsed.signatures || {}, findings);
  validateSandbox(root, parsed.sandbox || {}, findings, strict);
  validatePolicyPacks(root, parsed.config || {}, findings, strict);
  try {
    findings.push(...auditApprovals(root).findings.map((finding) => ({
      ...finding,
      error: ['critical', 'high'].includes(finding.severity),
    })));
  } catch (error) {
    add(findings, 'approval-audit-failed', 'high', configuredPaths.approvals?.path || '.execfence/approvals.json', 1, error.message, true);
  }

  const hasError = findings.some((finding) => finding.error || (strict && finding.strictError));
  return {
    ok: !hasError,
    cwd: root,
    strict,
    files,
    findings: findings.map((finding) => ({
      ...finding,
      error: Boolean(finding.error || (strict && finding.strictError)),
      strictError: undefined,
    })),
    summary: {
      filesChecked: files.filter((file) => file.exists).length,
      errors: findings.filter((finding) => finding.error || (strict && finding.strictError)).length,
      warnings: findings.filter((finding) => !(finding.error || (strict && finding.strictError))).length,
    },
  };
}

function validateMainConfig(cwd, config, findings, strict) {
  const configuredPaths = [
    ['reportsDir', config.reportsDir],
    ['manifest.path', config.manifest?.path],
    ['policy.customPoliciesDir', config.policy?.customPoliciesDir],
    ['approvals.path', config.approvals?.path],
    ['approvals.approversPath', config.approvals?.approversPath],
    ...Object.entries(config.trustStore || {}).map(([name, value]) => [`trustStore.${name}`, value]),
  ];
  for (const [field, value] of configuredPaths) {
    validateConfiguredPath(cwd, value, field, findings, 'execfence.json');
  }
  if (config.policyPack && !/^[a-z0-9][a-z0-9._-]*$/i.test(config.policyPack)) {
    add(findings, 'config-invalid-policy-name', 'high', 'execfence.json', 1, `policyPack contains path separators or unsupported characters: ${config.policyPack}`, true);
  }
  if (config.mode === 'audit') {
    add(findings, 'config-security-floor-mode', 'high', 'execfence.json', 1, 'Project-controlled config cannot downgrade the scanner from block to audit mode; use the explicit CLI --mode audit option for a reviewed invocation.', true);
  }
  const blockSeverities = new Set(asArray(config.blockSeverities));
  if (config.blockSeverities && (!blockSeverities.has('critical') || !blockSeverities.has('high'))) {
    add(findings, 'config-security-floor-severity', 'high', 'execfence.json', 1, 'Project config must keep critical and high findings blocking.', true);
  }
  if (asArray(config.roots).length || asArray(config.ignoreDirs).length || asArray(config.skipFiles).length) {
    add(findings, 'config-security-floor-scan-scope', 'medium', 'execfence.json', 1, 'Repository-controlled roots/ignoreDirs/skipFiles do not narrow the default security scan. Pass explicit CLI paths only for a reviewed partial scan.');
  }
  if (config.workflowHardening === false || config.archiveAudit === false) {
    add(findings, 'config-security-floor-required-audits', 'high', 'execfence.json', 1, 'Workflow hardening and archive audit cannot be disabled by repository-controlled config.', true);
  }
  if (config.runtimeTrace?.enabled === false || config.runtimeTrace?.postRunScan === false || config.runtimeTrace?.snapshotFiles === false || config.runtimeTrace?.redactEnv === false) {
    add(findings, 'config-security-floor-runtime-trace', 'high', 'execfence.json', 1, 'Runtime pre/post scanning, file snapshots, and environment redaction cannot be disabled by repository-controlled config.', true);
  }
  if (config.redaction?.redactLocalPaths === false || config.redaction?.redactEnv === false) {
    add(findings, 'config-security-floor-redaction', 'high', 'execfence.json', 1, 'Repository-controlled config cannot disable local-path or environment redaction.', true);
  }
  if (config.manifest?.requireRunWrapper === false || config.manifest?.blockNewEntrypoints === false) {
    add(findings, 'config-security-floor-manifest', 'high', 'execfence.json', 1, 'Execution wrapper and new-entrypoint manifest checks cannot be disabled by repository-controlled config.', true);
  }
  const mandatoryDependencyChecks = ['detectRegistryDrift', 'detectSuspiciousSources', 'detectLifecycleEntries'];
  const disabledDependencyChecks = mandatoryDependencyChecks.filter((name) => config.deps?.[name] === false);
  if (disabledDependencyChecks.length) {
    add(findings, 'config-security-floor-dependency-checks', 'high', 'execfence.json', 1, `Repository-controlled config cannot disable mandatory dependency checks: ${disabledDependencyChecks.join(', ')}.`, true);
  }
  const requiredCiChecks = ['scan', 'manifest-diff', 'deps-diff', 'coverage', 'config-validate', 'pack-audit', 'trust-audit', 'policy-diff', 'approval-audit'];
  if (config.ci?.enabled === false || (config.ci?.checks && requiredCiChecks.some((check) => !config.ci.checks.includes(check)))) {
    add(findings, 'config-security-floor-ci', 'high', 'execfence.json', 1, `CI security checks cannot be disabled. Required checks: ${requiredCiChecks.join(', ')}.`, true);
  }
  for (const [index, signature] of asArray(config.extraRegexSignatures).entries()) {
    validateRegex(signature, findings, 'execfence.json', `extraRegexSignatures[${index}]`);
  }
  for (const [index, pattern] of asArray(config.redaction?.extraPatterns).entries()) {
    validateRegex(pattern, findings, 'execfence.json', `redaction.extraPatterns[${index}]`);
  }
  for (const [index, allowed] of asArray(config.allowExecutables).entries()) {
    if (typeof allowed === 'string' || !/^[a-f0-9]{64}$/i.test(String(allowed.sha256 || ''))) {
      add(findings, 'config-allow-executable-without-hash', strict ? 'high' : 'medium', 'execfence.json', 1, `allowExecutables[${index}] is not pinned with a SHA-256 hash.`, false, true);
    }
  }
  for (const [index, registry] of asArray(config.supplyChain?.metadata?.allowedRegistries).entries()) {
    const value = String(registry);
    if (/^http:\/\//i.test(value) || /(?:raw\.githubusercontent|gist\.githubusercontent|pastebin|localhost|127\.0\.0\.1)/i.test(value)) {
      add(findings, 'config-suspicious-registry-allowlist', strict ? 'high' : 'medium', 'execfence.json', 1, `supplyChain.metadata.allowedRegistries[${index}] points at a suspicious registry/source: ${value}`, false, true);
    }
  }
  const supplyStrict = config.supplyChain?.mode === 'strict';
  if (supplyStrict) {
    let coverage;
    try {
      coverage = analyzeCoverage(cwd, { config });
    } catch (error) {
      add(findings, 'config-strict-coverage-check-failed', 'high', 'execfence.json', 1, `Could not evaluate strict coverage: ${error.message}`, true);
      return;
    }
    if (!coverage.ok) {
      add(findings, 'config-strict-without-complete-coverage', 'high', 'execfence.json', 1, `Strict supply-chain mode requires complete coverage; ${coverage.summary?.uncovered || coverage.uncovered?.length || 0} entrypoint(s) are uncovered.`, true);
    }
  }
}

function validateAgainstSchema(item, value, findings) {
  const schemaPath = path.join(__dirname, '..', 'schema', item.schema);
  let schema;
  try {
    schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  } catch (error) {
    add(findings, 'config-schema-unavailable', 'high', item.file, 1, `Could not load ${item.schema}: ${error.message}`, true);
    return;
  }
  for (const issue of validateSchema(value, schema)) {
    add(findings, 'config-schema-validation-error', 'high', item.file, 1, `${issue.path} ${issue.message} (${issue.keyword}).`, true);
  }
}

function validateBaseline(cwd, baseline, findings, strict, config = {}) {
  const ownerRules = config.policy?.requiredOwners || {};
  for (const [index, entry] of baselineEntries(baseline).entries()) {
    validateConfiguredPath(cwd, entry.file, `findings[${index}].file`, findings, 'baseline.json');
    if (entry.expiresAt && !validDate(entry.expiresAt)) {
      add(findings, 'baseline-invalid-expiry', 'high', 'baseline.json', 1, `findings[${index}].expiresAt is not a valid date.`, true);
    } else if (entry.expiresAt && new Date(entry.expiresAt).getTime() < Date.now()) {
      add(findings, 'baseline-expired-entry', strict ? 'high' : 'medium', 'baseline.json', 1, `findings[${index}] expired at ${entry.expiresAt}.`, false, true);
    }
    if (!entry.owner || !entry.reason) {
      add(findings, 'baseline-entry-missing-review-metadata', strict ? 'high' : 'medium', 'baseline.json', 1, `findings[${index}] should include owner and reason.`, false, true);
    }
    const allowedOwners = ownerRules[entry.findingId] || ownerRules['*'] || [];
    if (allowedOwners.length && !allowedOwners.includes(entry.owner)) {
      add(findings, 'baseline-owner-not-authorized', 'high', 'baseline.json', 1, `findings[${index}].owner must be one of ${allowedOwners.join(', ')} for ${entry.findingId}.`, true);
    }
  }
}

function validateSignatures(config, signatures, findings) {
  for (const [index, signature] of asArray(signatures.regex || signatures.regexSignatures).entries()) {
    validateRegex(signaturePattern(signature), findings, 'signatures.json', `regex[${index}]`);
  }
  for (const [index, signature] of asArray(config.externalSignatures?.regex || config.externalSignatures?.regexSignatures).entries()) {
    validateRegex(signaturePattern(signature), findings, 'signatures.json', `external regex[${index}]`);
  }
}

function validateSandbox(cwd, sandbox, findings, strict) {
  if (!Object.keys(sandbox).length) {
    return;
  }
  validateConfiguredPath(cwd, sandbox.helper?.path, 'helper.path', findings, 'sandbox.json');
  for (const [field, values] of [['fs.readAllow', sandbox.fs?.readAllow], ['fs.writeAllow', sandbox.fs?.writeAllow]]) {
    for (const [index, value] of asArray(values).entries()) {
      validateConfiguredPath(cwd, value, `${field}[${index}]`, findings, 'sandbox.json');
    }
  }
  const profile = profiles[sandbox.profile || 'test'] || profiles.test;
  const broadening = [
    ...outsideProfilePaths(sandbox.fs?.readAllow, profile.fs.readAllow).map((value) => `fs.readAllow=${value}`),
    ...outsideProfilePaths(sandbox.fs?.writeAllow, profile.fs.writeAllow).map((value) => `fs.writeAllow=${value}`),
    ...asArray(sandbox.process?.allow).filter((value) => !asArray(profile.process.allow).includes(value)).map((value) => `process.allow=${value}`),
    ...asArray(sandbox.network?.allow).filter((value) => !asArray(profile.network.allow).includes(value)).map((value) => `network.allow=${value}`),
  ];
  const networkRank = { allow: 0, audit: 1, deny: 2 };
  if (sandbox.network?.default && networkRank[sandbox.network.default] < networkRank[profile.network.default]) {
    broadening.push(`network.default=${sandbox.network.default}`);
  }
  if (sandbox.fs?.denyNewExecutable === false && profile.fs.denyNewExecutable !== false) broadening.push('fs.denyNewExecutable=false');
  if (sandbox.process?.superviseChildren === false && profile.process.superviseChildren !== false) broadening.push('process.superviseChildren=false');
  if (broadening.length) {
    add(findings, 'sandbox-security-floor-profile-broadening', 'high', 'sandbox.json', 1, `Sandbox config cannot broaden the ${sandbox.profile || 'test'} profile: ${broadening.join(', ')}.`, true);
  }
  if (sandbox.allowDegraded) {
    add(findings, 'sandbox-project-allows-degraded-helper', 'high', 'sandbox.json', 1, 'Repository-controlled sandbox config cannot authorize degraded execution. Local use requires --allow-degraded --degraded-reason <reason>; CI forbids degradation.', true);
  }
  if (sandbox.mode === 'enforce' && sandbox.helper?.requiredForEnforce === false) {
    add(findings, 'sandbox-enforce-without-required-helper', 'high', 'sandbox.json', 1, 'Sandbox enforce mode must require a verified helper; ExecFence does not silently downgrade enforcement.', true);
  }
  if (sandbox.mode === 'enforce') {
    let capabilities;
    try {
      capabilities = sandboxCapabilities(cwd, { mode: 'enforce', profile: sandbox.profile });
    } catch (error) {
      add(findings, 'sandbox-helper-capability-check-failed', 'high', 'sandbox.json', 1, `Could not verify sandbox helper capabilities: ${error.message}`, true);
      return;
    }
    if (!capabilities.helperVerified || capabilities.missingForEnforce.length) {
      add(findings, 'sandbox-enforce-without-verified-helper', 'high', 'sandbox.json', 1, `Sandbox enforce mode requires a verified helper self-test and complete capabilities. Missing: ${capabilities.missingForEnforce.join(', ') || 'helper self-test proof'}.`, true);
    }
  }
}

function validatePolicyPacks(cwd, config, findings, strict) {
  let dir;
  try {
    dir = resolveProjectPath(cwd, config.policy?.customPoliciesDir, '.execfence/config/policies');
  } catch {
    return;
  }
  if (!fs.existsSync(dir)) {
    return;
  }
  for (const file of fs.readdirSync(dir).filter((name) => name.endsWith('.json'))) {
    const relative = path.relative(cwd, path.join(dir, file)).replaceAll(path.sep, '/');
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
    } catch (error) {
      add(findings, 'policy-pack-json-parse-error', 'high', relative, 1, `Could not parse policy pack JSON: ${error.message}`, true);
      continue;
    }
    for (const [index, signature] of asArray(parsed.extraRegexSignatures).entries()) {
      validateRegex(signature, findings, relative, `extraRegexSignatures[${index}]`);
    }
    if (strict && parsed.supplyChain?.mode === 'strict' && parsed.ci?.enabled === false) {
      add(findings, 'policy-pack-strict-without-ci', 'high', relative, 1, 'Strict supply-chain policy packs must keep CI guardrails enabled.', true);
    }
  }
}

function outsideProfilePaths(configured, allowed) {
  const allowedPaths = asArray(allowed).map(normalizePolicyPath).filter(Boolean);
  return asArray(configured).filter((value) => {
    const candidate = normalizePolicyPath(value);
    return !candidate || !allowedPaths.some((base) => base === '.' || candidate === base || candidate.startsWith(`${base}/`));
  });
}

function normalizePolicyPath(value) {
  const text = String(value || '').replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/+$/, '') || '.';
  if (path.isAbsolute(text) || text === '..' || text.startsWith('../') || text.includes('/../')) return null;
  return text;
}

function validateConfiguredPath(cwd, value, field, findings, file) {
  if (value == null || value === '') return;
  try {
    resolveProjectPath(cwd, value);
  } catch (error) {
    add(findings, 'config-path-escapes-project', 'high', file, 1, `${field}: ${error.message}`, true);
  }
}

function validateRegex(pattern, findings, file, field) {
  if (!pattern) {
    add(findings, 'config-invalid-regex-signature', 'high', file, 1, `${field} is empty.`, true);
    return;
  }
  try {
    new RegExp(String(pattern));
  } catch (error) {
    add(findings, 'config-invalid-regex-signature', 'high', file, 1, `${field} is not a valid JavaScript RegExp: ${error.message}`, true);
  }
}

function add(findings, id, severity, file, line, detail, error = false, strictError = false) {
  findings.push({
    id,
    severity,
    file: normalizeConfigFile(file),
    line,
    detail,
    remediation: remediationFor(id),
    threatCategory: 'policy-integrity',
    activationSurface: 'ci',
    error,
    strictError,
  });
}

function normalizeConfigFile(file) {
  const normalized = String(file).replaceAll('\\', '/');
  if (normalized.startsWith('.execfence/') || normalized.includes('/')) return normalized;
  return `.execfence/config/${normalized}`;
}

function remediationFor(id) {
  if (id === 'config-path-escapes-project') return 'Use a path contained within the project root and remove symbolic links that resolve outside it.';
  if (id === 'config-invalid-regex-signature') return 'Fix or remove the invalid regex signature, then re-run execfence config validate.';
  if (id === 'baseline-expired-entry') return 'Remove the expired baseline entry or renew it with current owner, reason, expiry, and hash review.';
  if (id === 'config-allow-executable-without-hash') return 'Replace the allowlist string with an object containing path, sha256, and reason.';
  if (id === 'config-suspicious-registry-allowlist') return 'Use a trusted HTTPS package registry or document the source through a reviewed trust entry.';
  if (id.startsWith('sandbox-')) return 'Keep enforce mode blocked unless a verified helper with required capabilities is installed.';
  if (id === 'config-strict-without-complete-coverage') return 'Run execfence coverage, wire uncovered entrypoints, or enable verified global shims before strict mode.';
  return 'Fix the config issue or add a reviewed, time-bound exception.';
}

function baselineEntries(value) {
  if (Array.isArray(value)) return value;
  return Array.isArray(value.findings) ? value.findings : [];
}

function signaturePattern(value) {
  if (typeof value === 'string') return value;
  return value?.pattern || value?.value || value?.signature || '';
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function validDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value)) && !Number.isNaN(new Date(value).getTime());
}

function formatConfigValidation(result) {
  const lines = [
    `[execfence] config validation: ${result.ok ? 'OK' : 'failed'}`,
    `files checked: ${result.summary.filesChecked}`,
  ];
  for (const finding of result.findings) {
    lines.push(`- [${finding.error ? 'error' : 'warning'}] ${finding.id}: ${finding.detail}`);
    lines.push(`  next: ${finding.remediation}`);
  }
  return lines.join('\n');
}

module.exports = {
  formatConfigValidation,
  validateConfig,
};
