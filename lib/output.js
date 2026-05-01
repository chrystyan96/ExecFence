'use strict';

function formatResult(result, format = 'text') {
  if (format === 'json') {
    return JSON.stringify(result, null, 2);
  }
  if (format === 'sarif') {
    return JSON.stringify(toSarif(result), null, 2);
  }
  return formatFindings(result.findings || [], result);
}

function formatFindings(findings, result = {}) {
  if (findings.length === 0) {
    return '[execfence] OK';
  }
  const blocked = result.mode === 'audit'
    ? []
    : result.blockedFindings || findings.filter((item) => ['critical', 'high'].includes(item.severity || 'high'));
  const blockedKeys = new Set(blocked.map((item) => `${item.id}:${item.file}:${item.line || 1}`));
  const warnings = result.warningFindings || findings.filter((item) => !blockedKeys.has(`${item.id}:${item.file}:${item.line || 1}`));
  return [
    result.mode === 'audit'
      ? '[execfence] Audit findings:'
      : blocked.length > 0 ? '[execfence] Suspicious artifact(s) blocked:' : '[execfence] Suspicious artifact(s) found:',
    ...blocked.map((item) => `- [${item.severity || 'high'}] ${item.id}: ${item.file}:${item.line || 1} - ${item.detail}`),
    ...warnings.map((item) => `- [${item.severity}] ${item.id}: ${item.file}:${item.line || 1} - ${item.detail}`),
  ].join('\n');
}

function toSarif(result) {
  const findings = result.findings || [];
  const rules = new Map();
  for (const finding of findings) {
    if (!rules.has(finding.id)) {
      rules.set(finding.id, {
        id: finding.id,
        name: finding.id,
        shortDescription: { text: finding.id },
        fullDescription: { text: finding.detail || finding.id },
        defaultConfiguration: { level: sarifLevel(finding.severity) },
        help: { text: finding.detail || finding.id },
      });
    }
  }
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'execfence',
            informationUri: 'https://github.com/chrystyan96/execfence',
            rules: Array.from(rules.values()),
          },
        },
        results: findings.map((finding) => ({
          ruleId: finding.id,
          level: sarifLevel(finding.severity),
          message: { text: finding.detail },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                region: { startLine: finding.line || 1 },
              },
            },
          ],
        })),
      },
    ],
  };
}

function sarifLevel(severity) {
  if (severity === 'critical' || severity === 'high') {
    return 'error';
  }
  if (severity === 'medium') {
    return 'warning';
  }
  return 'note';
}

module.exports = {
  formatFindings,
  formatResult,
  toSarif,
};
