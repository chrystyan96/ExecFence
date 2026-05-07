'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { analyzeCoverage } = require('./coverage');
const { baselineFileName, configFileName, signaturesFileName } = require('./paths');
const { sandboxCapabilities } = require('./sandbox');

const configFiles = [
  { id: 'config', file: configFileName },
  { id: 'baseline', file: baselineFileName },
  { id: 'signatures', file: signaturesFileName },
  { id: 'sandbox', file: '.execfence/config/sandbox.json' },
];

function validateConfig(cwd = process.cwd(), options = {}) {
  const root = path.resolve(cwd);
  const strict = Boolean(options.strict);
  const findings = [];
  const files = [];
  const parsed = {};

  for (const item of configFiles) {
    const fullPath = path.join(root, item.file);
    const file = { id: item.id, file: item.file, exists: fs.existsSync(fullPath), ok: true };
    if (!file.exists) {
      files.push(file);
      continue;
    }
    try {
      parsed[item.id] = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
    } catch (error) {
      file.ok = false;
      add(findings, 'config-json-parse-error', 'high', item.file, 1, `Could not parse JSON: ${error.message}`, true);
      files.push(file);
      continue;
    }
    files.push(file);
  }

  validateMainConfig(root, parsed.config || {}, findings, strict);
  validateBaseline(parsed.baseline || {}, findings, strict);
  validateSignatures(parsed.config || {}, parsed.signatures || {}, findings);
  validateSandbox(root, parsed.sandbox || {}, findings, strict);
  validatePolicyPacks(root, parsed.config || {}, findings, strict);

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

function validateBaseline(baseline, findings, strict) {
  for (const [index, entry] of baselineEntries(baseline).entries()) {
    if (entry.expiresAt && !validDate(entry.expiresAt)) {
      add(findings, 'baseline-invalid-expiry', 'high', 'baseline.json', 1, `findings[${index}].expiresAt is not a valid date.`, true);
    } else if (entry.expiresAt && new Date(entry.expiresAt).getTime() < Date.now()) {
      add(findings, 'baseline-expired-entry', strict ? 'high' : 'medium', 'baseline.json', 1, `findings[${index}] expired at ${entry.expiresAt}.`, false, true);
    }
    if (!entry.owner || !entry.reason) {
      add(findings, 'baseline-entry-missing-review-metadata', strict ? 'high' : 'medium', 'baseline.json', 1, `findings[${index}] should include owner and reason.`, false, true);
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
  if (sandbox.mode === 'enforce' && sandbox.allowDegraded) {
    add(findings, 'sandbox-enforce-allows-degraded-helper', strict ? 'high' : 'medium', 'sandbox.json', 1, 'Sandbox enforce mode should not allow degraded helper behavior without an explicit reviewed exception.', false, true);
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
  const dir = path.resolve(cwd, config.policy?.customPoliciesDir || '.execfence/config/policies');
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
    file: `.execfence/config/${file}`.replace(/\.execfence\/config\/\.execfence\/config\//, '.execfence/config/'),
    line,
    detail,
    remediation: remediationFor(id),
    threatCategory: 'policy-integrity',
    activationSurface: 'ci',
    error,
    strictError,
  });
}

function remediationFor(id) {
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
