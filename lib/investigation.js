'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { reportsDir } = require('./paths');

function listReports(cwd = process.cwd()) {
  const dir = path.join(cwd, reportsDir);
  if (!fs.existsSync(dir)) {
    return [];
  }
  return fs.readdirSync(dir)
    .filter((name) => name.endsWith('.json'))
    .map((name) => {
      const filePath = path.join(dir, name);
      const stat = fs.statSync(filePath);
      return { id: name.replace(/\.json$/, ''), filePath, size: stat.size, mtime: stat.mtime.toISOString() };
    })
    .sort((a, b) => b.mtime.localeCompare(a.mtime));
}

function resolveReport(cwd, idOrPath) {
  if (!idOrPath) {
    const [latest] = listReports(cwd);
    if (!latest) {
      throw new Error('No ExecFence reports found.');
    }
    return latest.filePath;
  }
  const direct = path.resolve(cwd, idOrPath);
  if (fs.existsSync(direct)) {
    return direct;
  }
  const withJson = path.join(cwd, reportsDir, idOrPath.endsWith('.json') ? idOrPath : `${idOrPath}.json`);
  if (fs.existsSync(withJson)) {
    return withJson;
  }
  throw new Error(`Report not found: ${idOrPath}`);
}

function readReport(cwd, idOrPath) {
  const filePath = resolveReport(cwd, idOrPath);
  return { filePath, report: JSON.parse(fs.readFileSync(filePath, 'utf8')) };
}

function diffReports(cwd, left, right) {
  const a = readReport(cwd, left);
  const b = readReport(cwd, right);
  const aKeys = new Set((a.report.findings || []).map(findingKey));
  const bKeys = new Set((b.report.findings || []).map(findingKey));
  return {
    left: a.filePath,
    right: b.filePath,
    addedFindings: (b.report.findings || []).filter((finding) => !aKeys.has(findingKey(finding))),
    removedFindings: (a.report.findings || []).filter((finding) => !bKeys.has(findingKey(finding))),
    summary: {
      leftFindings: (a.report.findings || []).length,
      rightFindings: (b.report.findings || []).length,
    },
  };
}

function htmlReport(cwd, reportPath) {
  const { filePath, report } = readReport(cwd, reportPath);
  const htmlPath = filePath.replace(/\.json$/, '.html');
  const findings = report.findings || [];
  const body = `<!doctype html>
<html>
<head><meta charset="utf-8"><title>ExecFence report</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.4}pre{background:#f6f8fa;padding:1rem;overflow:auto}.finding{border:1px solid #ddd;padding:1rem;margin:1rem 0;border-radius:8px}</style></head>
<body>
<h1>ExecFence report</h1>
<p><strong>Generated:</strong> ${escapeHtml(report.metadata?.generatedAt || '')}</p>
<p><strong>Command:</strong> ${escapeHtml(report.command?.display || report.metadata?.command || '')}</p>
<p><strong>OK:</strong> ${String(report.summary?.ok)}</p>
${findings.map((finding) => `<section class="finding"><h2>${escapeHtml(finding.id)}</h2><p>${escapeHtml(finding.file)}:${finding.line || 1}</p><p>${escapeHtml(finding.reason || finding.detail || '')}</p><pre>${escapeHtml(finding.snippet || '')}</pre></section>`).join('\n')}
</body></html>`;
  fs.writeFileSync(htmlPath, body);
  return { htmlPath };
}

function incidentFromReport(cwd, reportPath) {
  const { filePath, report } = readReport(cwd, reportPath);
  const incidentPath = filePath.replace(/\.json$/, '.incident.md');
  const lines = [
    '# ExecFence Incident Checklist',
    '',
    `Report: ${filePath}`,
    `Generated: ${report.metadata?.generatedAt || ''}`,
    '',
    '- [ ] Preserve the report JSON and suspicious files.',
    '- [ ] Review git blame and recent commits for each finding.',
    '- [ ] Audit CI workflows and local build/test entrypoints.',
    '- [ ] Review lockfiles and package lifecycle scripts.',
    '- [ ] Rotate tokens if build/test may have executed suspicious code.',
    '- [ ] Remove payload or add a narrow reviewed baseline entry with owner, reason, expiry, and hash.',
    '',
    '## Findings',
    ...(report.findings || []).map((finding) => `- ${finding.id}: ${finding.file}:${finding.line || 1} (${finding.severity})`),
    '',
  ];
  fs.writeFileSync(incidentPath, `${lines.join('\n')}\n`);
  return { incidentPath };
}

function prCommentFromReport(report) {
  const findings = report.findings || [];
  return [
    '## ExecFence',
    '',
    `Status: ${report.summary?.ok ? 'OK' : 'Blocked'}`,
    `Findings: ${findings.length}`,
    '',
    ...findings.slice(0, 20).map((finding) => `- **${finding.severity || 'high'}** ${finding.id}: \`${finding.file}:${finding.line || 1}\` - ${finding.remediation || finding.detail || ''}`),
    findings.length > 20 ? `\n_${findings.length - 20} more findings omitted._` : '',
  ].filter(Boolean).join('\n');
}

function findingKey(finding) {
  return `${finding.id}:${finding.file}:${finding.line || 1}`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

module.exports = {
  diffReports,
  htmlReport,
  incidentFromReport,
  listReports,
  prCommentFromReport,
  readReport,
  resolveReport,
};
