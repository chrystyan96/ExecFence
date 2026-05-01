'use strict';

const { ruleMetadata } = require('./scanner');

const advice = {
  'allowed-executable-hash-mismatch': 'Recompute the SHA-256 only after reviewing the binary source and provenance.',
  'executable-artifact-in-source-tree': 'Move generated binaries out of source folders or allowlist a reviewed binary with a SHA-256 hash.',
  'insecure-lockfile-url': 'Replace HTTP artifact URLs with HTTPS registry URLs and regenerate the lockfile.',
  'lockfile-suspicious-host': 'Verify why a dependency resolves from a paste/raw host before allowing it.',
  'long-obfuscated-javascript-line': 'Treat this as a likely injected loader until a manual deobfuscation proves otherwise.',
  'suspicious-lockfile-url': 'Verify why a dependency resolves from a paste/raw host before allowing it.',
  'suspicious-package-script': 'Remove install-time download/eval behavior or pin it behind a reviewed build step.',
};

function explainFinding(id) {
  if (!id) {
    return `Usage: security-guardrails explain <finding-id>\n\nKnown findings:\n${knownFindings()}`;
  }
  const metadata = ruleMetadata[id];
  if (!metadata) {
    return `Unknown finding: ${id}\n\nKnown findings:\n${knownFindings()}`;
  }
  return [
    id,
    `Severity: ${metadata.severity}`,
    `Why it matters: ${metadata.description}`,
    `Review guidance: ${advice[id] || 'Review the artifact provenance and remove the suspicious pattern or add a narrow, documented exception.'}`,
  ].join('\n');
}

function knownFindings() {
  return Object.keys(ruleMetadata).sort().map((id) => `- ${id}`).join('\n');
}

module.exports = {
  explainFinding,
};
