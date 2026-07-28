'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ruleMetadata } = require('./scanner');

const advice = {
  'allowed-executable-hash-mismatch': 'Recompute the SHA-256 only after reviewing the binary source and provenance.',
  'executable-artifact-in-source-tree': 'Move generated binaries out of source folders or allowlist a reviewed binary with a SHA-256 hash.',
  'insecure-lockfile-url': 'Replace HTTP artifact URLs with HTTPS registry URLs and regenerate the lockfile.',
  'lockfile-suspicious-host': 'Verify why a dependency resolves from a paste/raw host before allowing it.',
  'long-obfuscated-javascript-line': 'Treat this as a likely injected loader until a manual deobfuscation proves otherwise.',
  'suspicious-lockfile-url': 'Verify why a dependency resolves from a paste/raw host before allowing it.',
  'suspicious-package-script': 'Remove install-time download/eval/LOLBins behavior or pin it behind a reviewed build step.',
};

function explainFinding(id, options = {}) {
  if (!id) {
    return `Usage: execfence explain <finding-id>\n\nKnown findings:\n${knownFindings()}`;
  }
  const reportFinding = options.reportPath ? findingFromReport(options.cwd || process.cwd(), options.reportPath, id) : null;
  const metadata = ruleMetadata[id];
  if (!metadata && !reportFinding) {
    return `Unknown finding: ${id}\n\nKnown findings:\n${knownFindings()}`;
  }
  const finding = reportFinding || {
    id,
    severity: metadata.severity,
    confidence: 'medium',
    decision: ['critical', 'high'].includes(metadata.severity) ? 'block' : 'review',
    detail: metadata.description,
    remediation: advice[id] || 'Review the artifact provenance and remove the suspicious pattern or add a narrow, documented exception.',
  };
  const explanation = {
    id: finding.id,
    severity: finding.severity || metadata?.severity || 'high',
    confidence: finding.confidence || 'medium',
    decision: finding.decision || 'review',
    enforcement: finding.enforcement || finding.decision || 'review',
    reason: finding.decisionReason || finding.reason || finding.detail || metadata?.description,
    evidence: {
      file: finding.file || null,
      line: finding.line || 1,
      snippet: finding.snippet || null,
      sha256: finding.sha256 || null,
      activationSurface: finding.activationSurface || null,
      threatCategory: finding.threatCategory || null,
    },
    whyItMatters: finding.analysis?.whyItMatters || metadata?.description || finding.detail,
    remediation: finding.remediation || advice[id] || 'Review provenance and use a narrow, expiring, signed approval only when the behavior is expected.',
    approval: finding.approval || null,
  };
  if (options.format === 'json') return JSON.stringify(explanation, null, 2);
  return [
    explanation.id,
    `Decision: ${explanation.decision} (${explanation.enforcement})`,
    `Severity: ${explanation.severity}`,
    `Confidence: ${explanation.confidence}`,
    `Reason: ${explanation.reason}`,
    `Evidence: ${explanation.evidence.file ? `${explanation.evidence.file}:${explanation.evidence.line}` : 'rule metadata only'}`,
    `Why it matters: ${explanation.whyItMatters}`,
    `Review guidance: ${explanation.remediation}`,
    explanation.approval ? `Approval: ${explanation.approval.id} by ${explanation.approval.owner}, expires ${explanation.approval.expiresAt}` : 'Approval: none',
  ].join('\n');
}

function findingFromReport(cwd, reportPath, id) {
  const resolved = path.resolve(cwd, reportPath);
  if (!fs.existsSync(resolved)) throw new Error(`Report not found: ${reportPath}`);
  const report = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  return (report.findings || []).find((finding) => finding.id === id) || null;
}

function knownFindings() {
  return Object.keys(ruleMetadata).sort().map((id) => `- ${id}`).join('\n');
}

module.exports = {
  explainFinding,
};
