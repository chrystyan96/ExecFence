'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { resolveProjectPath } = require('./paths');
const { sha256File } = require('./baseline');
const { loadConfig } = require('./config');

const approvalsFileName = '.execfence/approvals.json';
const approversFileName = '.execfence/trust/approvers.json';
const approvalTypes = new Set(['finding', 'manifest', 'manifest-entry', 'package', 'command', 'policy']);

function approvalStorePath(cwd = process.cwd()) {
  return resolveProjectPath(cwd, loadConfig(cwd).config?.approvals?.path, approvalsFileName);
}

function approverStorePath(cwd = process.cwd()) {
  return resolveProjectPath(cwd, loadConfig(cwd).config?.approvals?.approversPath, approversFileName);
}

function createApproval(cwd = process.cwd(), input = {}) {
  validateApprovalInput(input);
  const store = readStore(approvalStorePath(cwd), { schemaVersion: 1, approvals: [] });
  const createdAt = new Date().toISOString();
  const approval = {
    id: input.id || `appr_${crypto.randomBytes(12).toString('hex')}`,
    type: input.type,
    subject: normalizeSubject(cwd, input.type, input.subject || {}),
    scope: normalizeScope(input.scope || {}),
    reason: String(input.reason),
    owner: String(input.owner),
    createdAt,
    expiresAt: new Date(input.expiresAt).toISOString(),
    requiredSignatures: Math.max(
      boundedInteger(input.requiredSignatures, 1, 20, 1),
      minimumApprovalSignatures(cwd),
    ),
    signatures: [],
  };
  store.approvals = (store.approvals || []).filter((item) => item.id !== approval.id);
  store.approvals.push(approval);
  writeStore(approvalStorePath(cwd), store);
  return { filePath: approvalStorePath(cwd), approval };
}

function addApprover(cwd = process.cwd(), input = {}) {
  for (const field of ['keyId', 'publicKey', 'owner', 'reason', 'expiresAt']) {
    if (!input[field]) throw new Error(`Missing required approver metadata: ${field}`);
  }
  const publicKeyPath = path.resolve(cwd, input.publicKey);
  if (!fs.existsSync(publicKeyPath)) throw new Error(`Public key not found: ${input.publicKey}`);
  const publicKeyPem = fs.readFileSync(publicKeyPath, 'utf8');
  const key = crypto.createPublicKey(publicKeyPem);
  const fingerprint = publicKeyFingerprint(key);
  const store = readStore(approverStorePath(cwd), { schemaVersion: 1, approvers: [] });
  const entry = {
    keyId: String(input.keyId),
    owner: String(input.owner),
    reason: String(input.reason),
    expiresAt: new Date(input.expiresAt).toISOString(),
    algorithm: key.asymmetricKeyType,
    fingerprint,
    publicKeyPem: key.export({ type: 'spki', format: 'pem' }).toString(),
    addedAt: new Date().toISOString(),
  };
  store.approvers = (store.approvers || []).filter((item) => item.keyId !== entry.keyId);
  store.approvers.push(entry);
  writeStore(approverStorePath(cwd), store);
  return { filePath: approverStorePath(cwd), approver: entry };
}

function signApproval(cwd = process.cwd(), id, input = {}) {
  if (!id || !input.keyId || !input.privateKey) {
    throw new Error('Usage: execfence approval sign <id> --key-id <id> --private-key <file>');
  }
  const storePath = approvalStorePath(cwd);
  const store = readStore(storePath, { schemaVersion: 1, approvals: [] });
  const approval = (store.approvals || []).find((item) => item.id === id);
  if (!approval) throw new Error(`Approval not found: ${id}`);
  const trusted = trustedApprovers(cwd).find((item) => item.keyId === input.keyId);
  if (!trusted) throw new Error(`Approver key is not trusted: ${input.keyId}`);
  const privateKeyPath = path.resolve(cwd, input.privateKey);
  if (!fs.existsSync(privateKeyPath)) throw new Error(`Private key not found: ${input.privateKey}`);
  const privateKey = crypto.createPrivateKey({
    key: fs.readFileSync(privateKeyPath, 'utf8'),
    passphrase: input.passphrase,
  });
  const derivedPublic = crypto.createPublicKey(privateKey);
  if (publicKeyFingerprint(derivedPublic) !== trusted.fingerprint) {
    throw new Error(`Private key does not match trusted approver ${input.keyId}`);
  }
  const algorithm = signatureAlgorithm(privateKey);
  const signature = crypto.sign(algorithm, canonicalApprovalBytes(approval), privateKey).toString('base64');
  approval.signatures = (approval.signatures || []).filter((item) => item.keyId !== input.keyId);
  approval.signatures.push({
    keyId: input.keyId,
    fingerprint: trusted.fingerprint,
    algorithm: algorithm || 'intrinsic',
    signedAt: new Date().toISOString(),
    signature,
  });
  writeStore(storePath, store);
  return { filePath: storePath, approvalId: id, keyId: input.keyId, verified: verifyApproval(cwd, approval).ok };
}

function auditApprovals(cwd = process.cwd(), context = {}) {
  const storePath = approvalStorePath(cwd);
  const store = readStore(storePath, { schemaVersion: 1, approvals: [] });
  const approvals = [];
  const findings = [];
  const approvers = trustedApprovers(cwd);
  for (const approver of approvers) {
    if (!approver.keyId || !approver.owner || !approver.reason) {
      findings.push({
        id: 'approver-key-missing-metadata',
        severity: 'high',
        confidence: 'high',
        file: path.relative(cwd, approverStorePath(cwd)).replaceAll(path.sep, '/'),
        line: 1,
        detail: `Trusted approver ${approver.keyId || '(missing keyId)'} lacks owner or reason.`,
      });
      continue;
    }
    if (!Number.isFinite(Date.parse(approver.expiresAt || '')) || Date.parse(approver.expiresAt) <= Date.now()) {
      findings.push({
        id: 'approver-key-expired',
        severity: 'high',
        confidence: 'high',
        file: path.relative(cwd, approverStorePath(cwd)).replaceAll(path.sep, '/'),
        line: 1,
        detail: `Trusted approver ${approver.keyId} is expired or has an invalid expiry.`,
      });
    }
    try {
      const key = crypto.createPublicKey(approver.publicKeyPem);
      if (publicKeyFingerprint(key) !== approver.fingerprint) {
        findings.push({
          id: 'approver-key-fingerprint-mismatch',
          severity: 'high',
          confidence: 'high',
          file: path.relative(cwd, approverStorePath(cwd)).replaceAll(path.sep, '/'),
          line: 1,
          detail: `Trusted approver ${approver.keyId} public-key fingerprint changed.`,
        });
      }
    } catch (error) {
      findings.push({
        id: 'approver-key-invalid',
        severity: 'high',
        confidence: 'high',
        file: path.relative(cwd, approverStorePath(cwd)).replaceAll(path.sep, '/'),
        line: 1,
        detail: `Trusted approver ${approver.keyId} has an invalid public key: ${error.message}`,
      });
    }
  }
  for (const approval of store.approvals || []) {
    const verification = verifyApproval(cwd, approval, context);
    approvals.push({ ...approval, verification });
    for (const issue of verification.issues) {
      findings.push({
        id: issue.id,
        severity: issue.severity,
        confidence: 'high',
        file: approvalsFileName,
        line: 1,
        detail: `Approval ${approval.id}: ${issue.detail}`,
        approvalId: approval.id,
      });
    }
  }
  return {
    cwd: path.resolve(cwd),
    ok: !findings.some((finding) => ['critical', 'high'].includes(finding.severity)),
    filePath: storePath,
    approvals,
    approvers: approvers.map(({ publicKeyPem: _publicKeyPem, ...approver }) => approver),
    findings,
  };
}

function verifyApproval(cwd, approval, context = {}) {
  const issues = [];
  const expiresAt = Date.parse(approval.expiresAt || '');
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    issues.push({ id: 'approval-expired', severity: 'high', detail: `expired or invalid expiresAt ${approval.expiresAt || '(missing)'}.` });
  }
  if (!approvalTypes.has(approval.type)) {
    issues.push({ id: 'approval-invalid-type', severity: 'high', detail: `unsupported type ${approval.type}.` });
  }
  if (!approval.reason || !approval.owner) {
    issues.push({ id: 'approval-missing-review-metadata', severity: 'high', detail: 'owner and reason are mandatory.' });
  }
  const scopeIssue = scopeMismatch(approval.scope || {}, context);
  if (scopeIssue) issues.push({ id: 'approval-scope-mismatch', severity: 'medium', detail: scopeIssue });
  const approvers = new Map(trustedApprovers(cwd).map((entry) => [entry.keyId, entry]));
  const validSigners = new Set();
  for (const signature of approval.signatures || []) {
    const approver = approvers.get(signature.keyId);
    if (!approver) {
      issues.push({ id: 'approval-signature-untrusted', severity: 'high', detail: `signature key ${signature.keyId} is not trusted.` });
      continue;
    }
    if (Date.parse(approver.expiresAt || '') <= Date.now()) {
      issues.push({ id: 'approval-signing-key-expired', severity: 'high', detail: `signing key ${signature.keyId} expired.` });
      continue;
    }
    if (signature.fingerprint !== approver.fingerprint) {
      issues.push({ id: 'approval-signature-key-mismatch', severity: 'high', detail: `signature fingerprint for ${signature.keyId} changed.` });
      continue;
    }
    try {
      const ok = crypto.verify(
        signature.algorithm === 'intrinsic' ? null : (signature.algorithm || signatureAlgorithm(crypto.createPublicKey(approver.publicKeyPem))),
        canonicalApprovalBytes(approval),
        crypto.createPublicKey(approver.publicKeyPem),
        Buffer.from(signature.signature, 'base64'),
      );
      if (ok) validSigners.add(signature.keyId);
      else issues.push({ id: 'approval-signature-invalid', severity: 'high', detail: `signature from ${signature.keyId} is invalid.` });
    } catch (error) {
      issues.push({ id: 'approval-signature-invalid', severity: 'high', detail: `signature from ${signature.keyId} could not be verified: ${error.message}` });
    }
  }
  const required = Math.max(
    boundedInteger(approval.requiredSignatures, 1, 20, 1),
    minimumApprovalSignatures(cwd),
  );
  if (validSigners.size < required) {
    issues.push({
      id: 'approval-signatures-insufficient',
      severity: 'high',
      detail: `requires ${required} distinct trusted signature(s), found ${validSigners.size}.`,
    });
  }
  return {
    ok: issues.length === 0,
    active: issues.length === 0,
    validSigners: Array.from(validSigners),
    requiredSignatures: required,
    issues,
  };
}

function applyApprovals(cwd = process.cwd(), findings = [], context = {}) {
  let store;
  try {
    store = readStore(approvalStorePath(cwd), { schemaVersion: 1, approvals: [] });
  } catch (error) {
    return {
      activeFindings: [...findings, {
        id: 'approval-store-invalid',
        severity: 'high',
        confidence: 'high',
        file: path.relative(cwd, approvalStorePath(cwd)).replaceAll(path.sep, '/'),
        line: 1,
        detail: error.message,
      }],
      approvedFindings: [],
    };
  }
  const active = (store.approvals || [])
    .map((approval) => ({ approval, verification: verifyApproval(cwd, approval, context) }))
    .filter((item) => item.verification.active && item.approval.type === 'finding');
  const remaining = [];
  const approved = [];
  for (const finding of findings) {
    const match = active.find(({ approval }) => approvalMatchesFinding(cwd, approval, finding, context));
    if (match) approved.push({ ...finding, approval: summarizeApproval(match.approval, match.verification) });
    else remaining.push(finding);
  }
  return { activeFindings: remaining, approvedFindings: approved };
}

function approvalMatchesFinding(cwd, approval, finding, context = {}) {
  const subject = approval.subject || {};
  if (subject.findingId && subject.findingId !== finding.id) return false;
  if (subject.file && normalizePath(subject.file) !== normalizePath(finding.file)) return false;
  if (subject.sha256) {
    let filePath;
    try {
      filePath = resolveProjectPath(cwd, finding.file);
    } catch {
      return false;
    }
    if (!fs.existsSync(filePath) || sha256File(filePath) !== subject.sha256) return false;
  }
  return !scopeMismatch(approval.scope || {}, context);
}

function activeApprovalFor(cwd, type, subject = {}, context = {}) {
  let store;
  try {
    store = readStore(approvalStorePath(cwd), { schemaVersion: 1, approvals: [] });
  } catch {
    return null;
  }
  return (store.approvals || []).find((approval) => {
    if (approval.type !== type || !verifyApproval(cwd, approval, context).active) return false;
    return Object.entries(subject).every(([key, value]) => {
      if (value == null) return true;
      return normalizeComparable(approval.subject?.[key]) === normalizeComparable(value);
    });
  }) || null;
}

function trustedApprovers(cwd) {
  const store = readStore(approverStorePath(cwd), { schemaVersion: 1, approvers: [] });
  return store.approvers || [];
}

function canonicalApprovalBytes(approval) {
  const unsigned = {
    id: approval.id,
    type: approval.type,
    subject: approval.subject || {},
    scope: approval.scope || {},
    reason: approval.reason,
    owner: approval.owner,
    createdAt: approval.createdAt,
    expiresAt: approval.expiresAt,
    requiredSignatures: boundedInteger(approval.requiredSignatures, 1, 20, 1),
  };
  return Buffer.from(stableStringify(unsigned));
}

function validateApprovalInput(input) {
  for (const field of ['type', 'reason', 'owner', 'expiresAt']) {
    if (!input[field]) throw new Error(`Missing required approval metadata: ${field}`);
  }
  if (!approvalTypes.has(input.type)) throw new Error(`Unknown approval type: ${input.type}`);
  const expiry = Date.parse(input.expiresAt);
  if (!Number.isFinite(expiry) || expiry <= Date.now()) throw new Error('Approval expiresAt must be a future date/time.');
  if (!input.subject || Object.keys(input.subject).length === 0) throw new Error('Approval requires a narrow subject.');
  if (input.type === 'finding' && (!input.subject.findingId || !input.subject.file)) {
    throw new Error('Finding approvals require findingId and file; a file hash is captured when available.');
  }
  if (input.type === 'package' && !/^@?[^@\s]+(?:\/[^@\s]+)?@[^@\s]+$/.test(String(input.subject.package || ''))) {
    throw new Error('Package approvals require an exact package@version subject.');
  }
  if (input.type === 'manifest' && !/^[a-f0-9]{64}$/i.test(String(input.subject.manifestHash || ''))) {
    throw new Error('Manifest approvals require a 64-character manifestHash.');
  }
  if (input.type === 'manifest-entry' && !input.subject.entrypointId) {
    throw new Error('Manifest-entry approvals require entrypointId.');
  }
  if (input.type === 'command' && !input.subject.command) {
    throw new Error('Command approvals require an exact command subject.');
  }
  if (input.type === 'policy' && !/^[a-f0-9]{64}$/i.test(String(input.subject.policyHash || ''))) {
    throw new Error('Policy approvals require a 64-character policyHash.');
  }
}

function normalizeSubject(cwd, type, subject) {
  const normalized = { ...subject };
  if (normalized.file) normalized.file = normalizePath(normalized.file);
  if (normalized.path) normalized.path = normalizePath(normalized.path);
  if (normalized.sha256) normalized.sha256 = String(normalized.sha256).toLowerCase();
  if (!normalized.sha256 && normalized.file && ['finding', 'manifest-entry', 'policy'].includes(type)) {
    try {
      const filePath = resolveProjectPath(cwd, normalized.file);
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) normalized.sha256 = sha256File(filePath);
    } catch {
      // A missing subject file remains explicit and will not match a different hash later.
    }
  }
  return normalized;
}

function normalizeScope(scope) {
  return {
    branch: scope.branch || null,
    command: scope.command || null,
    commit: scope.commit || null,
    environment: scope.environment || null,
  };
}

function scopeMismatch(scope, context) {
  if (scope.branch && scope.branch !== (context.branch || currentBranch(context.cwd))) return `branch ${scope.branch} does not match current branch.`;
  if (scope.commit && scope.commit !== (context.commit || currentCommit(context.cwd))) return `commit ${scope.commit} does not match current commit.`;
  if (scope.environment && scope.environment !== (context.environment || (process.env.CI ? 'ci' : 'local'))) return `environment ${scope.environment} does not match.`;
  if (scope.command) {
    const command = String(context.command || '');
    let matches = false;
    try {
      matches = new RegExp(scope.command).test(command);
    } catch {
      return `command scope is not a valid regular expression: ${scope.command}.`;
    }
    if (!matches) return `command does not match scope ${scope.command}.`;
  }
  return null;
}

function currentBranch(cwd = process.cwd()) {
  return safeGit(cwd, ['branch', '--show-current']);
}

function currentCommit(cwd = process.cwd()) {
  return safeGit(cwd, ['rev-parse', 'HEAD']);
}

function safeGit(cwd, args) {
  try {
    return execFileSync('git', args, { cwd: cwd || process.cwd(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return '';
  }
}

function summarizeApproval(approval, verification) {
  return {
    id: approval.id,
    owner: approval.owner,
    reason: approval.reason,
    expiresAt: approval.expiresAt,
    validSigners: verification.validSigners,
  };
}

function publicKeyFingerprint(key) {
  const der = key.export({ type: 'spki', format: 'der' });
  return `sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
}

function signatureAlgorithm(key) {
  return ['ed25519', 'ed448'].includes(key.asymmetricKeyType) ? null : 'sha256';
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function readStore(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`Could not parse ${filePath}: ${error.message}`);
  }
}

function writeStore(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function boundedInteger(value, minimum, maximum, fallback) {
  const number = Number(value ?? fallback);
  return Number.isInteger(number) && number >= minimum && number <= maximum ? number : fallback;
}

function minimumApprovalSignatures(cwd) {
  return boundedInteger(loadConfig(cwd).config?.approvals?.minimumSignatures, 1, 20, 1);
}

function normalizePath(value) {
  return String(value || '').replaceAll('\\', '/').replace(/^\.\//, '');
}

function normalizeComparable(value) {
  return typeof value === 'string' ? value.replaceAll('\\', '/').toLowerCase() : JSON.stringify(value);
}

module.exports = {
  activeApprovalFor,
  addApprover,
  approvalStorePath,
  approverStorePath,
  applyApprovals,
  auditApprovals,
  canonicalApprovalBytes,
  createApproval,
  signApproval,
  verifyApproval,
};
