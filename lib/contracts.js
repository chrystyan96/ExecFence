'use strict';

const contractVersions = Object.freeze({
  finding: 1,
  report: 3,
  manifest: 2,
  helperProtocol: 1,
  approval: 1,
  sbomCycloneDx: '1.6',
  sbomSpdx: '2.3',
});

function assertFinding(value) {
  if (!value || typeof value !== 'object') throw new TypeError('Finding must be an object.');
  for (const field of ['id', 'severity', 'file', 'detail']) {
    if (!value[field]) throw new TypeError(`Finding is missing ${field}.`);
  }
  if (!['critical', 'high', 'medium', 'low'].includes(value.severity)) throw new TypeError(`Invalid finding severity: ${value.severity}`);
  if (value.confidence && !['high', 'medium', 'low'].includes(value.confidence)) throw new TypeError(`Invalid finding confidence: ${value.confidence}`);
  if (value.decision && !['block', 'review', 'allow'].includes(value.decision)) throw new TypeError(`Invalid finding decision: ${value.decision}`);
  return value;
}

function assertResult(value) {
  if (!value || typeof value !== 'object' || !Array.isArray(value.findings)) throw new TypeError('ExecFence result must contain findings.');
  value.findings.forEach(assertFinding);
  return value;
}

module.exports = {
  assertFinding,
  assertResult,
  contractVersions,
};
