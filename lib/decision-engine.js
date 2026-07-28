'use strict';

const severities = ['critical', 'high', 'medium', 'low'];
const confidences = ['high', 'medium', 'low'];
const decisions = ['block', 'review', 'allow'];

function evaluateFindings(findings = [], policy = {}) {
  const mode = policy.mode || 'block';
  const blockSeverities = new Set(policy.blockSeverities || ['critical', 'high']);
  const warnSeverities = new Set(policy.warnSeverities || ['medium', 'low']);
  const evaluatedFindings = findings.map((finding) => evaluateFinding(finding, {
    mode,
    blockSeverities,
    warnSeverities,
  }));
  const blockedFindings = mode === 'audit'
    ? []
    : evaluatedFindings.filter((finding) => finding.decision === 'block');
  const warningFindings = evaluatedFindings.filter((finding) => (
    finding.decision === 'review' || (mode === 'audit' && finding.decision === 'block')
  ));
  return {
    mode,
    ok: mode === 'audit' || blockedFindings.length === 0,
    findings: evaluatedFindings,
    blockedFindings,
    warningFindings,
    summary: {
      findings: evaluatedFindings.length,
      blocked: blockedFindings.length,
      warnings: warningFindings.length,
      decisions: countBy(evaluatedFindings, 'decision'),
      confidence: countBy(evaluatedFindings, 'confidence'),
    },
  };
}

function evaluateFinding(finding = {}, context = {}) {
  const severity = normalizeSeverity(finding.severity);
  const confidence = normalizeConfidence(finding.confidence || inferConfidence(finding, severity));
  const decision = context.blockSeverities?.has(severity)
    ? 'block'
    : context.warnSeverities?.has(severity) ? 'review' : 'allow';
  return {
    ...finding,
    severity,
    confidence,
    decision,
    enforcement: context.mode === 'audit' && decision === 'block' ? 'reported' : decision,
    decisionReason: finding.decisionReason || decisionReason(decision, severity, confidence, context.mode),
  };
}

function highestSeverity(findings = []) {
  return severities.find((severity) => findings.some((finding) => normalizeSeverity(finding.severity) === severity)) || null;
}

function normalizeSeverity(value) {
  return severities.includes(value) ? value : 'high';
}

function normalizeConfidence(value) {
  return confidences.includes(value) ? value : 'medium';
}

function inferConfidence(finding, severity) {
  const id = String(finding.id || '');
  if (severity === 'critical' || /hash-mismatch|integrity-mismatch|invalid|denied-operation|curl-pipe/.test(id)) {
    return 'high';
  }
  if (/typosquat|similar|reputation|cooldown|large|adjacent|suspicious/.test(id)) {
    return 'medium';
  }
  return severity === 'low' ? 'low' : 'medium';
}

function decisionReason(decision, severity, confidence, mode) {
  const policy = decision === 'block'
    ? `severity ${severity} is inside the blocking policy floor`
    : decision === 'review'
      ? `severity ${severity} requires review`
      : `severity ${severity} is informational under the effective policy`;
  return `${policy}; detection confidence is ${confidence}${mode === 'audit' && decision === 'block' ? '; audit mode reports the block decision without enforcing it' : ''}.`;
}

function countBy(items, key) {
  return items.reduce((counts, item) => {
    const value = item[key] || 'unknown';
    counts[value] = (counts[value] || 0) + 1;
    return counts;
  }, {});
}

module.exports = {
  confidences,
  decisions,
  evaluateFinding,
  evaluateFindings,
  highestSeverity,
  normalizeConfidence,
  normalizeSeverity,
  severities,
};
