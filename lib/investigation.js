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

function latestReport(cwd = process.cwd()) {
  return listReports(cwd)[0] || null;
}

function latestReportSummary(cwd = process.cwd()) {
  const latest = latestReport(cwd);
  if (!latest) {
    return null;
  }
  const { report } = readReport(cwd, latest.filePath);
  return {
    ...latest,
    status: report.blockingSummary?.status || (report.summary?.ok ? 'ok' : 'blocked'),
    blockingSummary: report.blockingSummary || null,
    summary: report.summary || null,
    changeRisk: report.changeRisk || null,
  };
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

function compareReports(cwd, options = {}) {
  const reports = listReports(cwd);
  if (reports.length < 2 && !options.since) {
    throw new Error('Need at least two reports to compare.');
  }
  const right = options.right || reports[0].filePath;
  const left = options.since || options.left || reports[1].filePath;
  return diffReports(cwd, left, right);
}

function htmlReport(cwd, reportPath) {
  const { filePath, report } = readReport(cwd, reportPath);
  const htmlPath = filePath.replace(/\.json$/, '.html');
  const findings = report.findings || [];
  const grouped = groupFindings(findings);
  const body = `<!doctype html>
<html>
<head><meta charset="utf-8"><title>ExecFence report</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.4;color:#161616}pre{background:#f6f8fa;padding:1rem;overflow:auto}.finding{border:1px solid #ddd;padding:1rem;margin:1rem 0;border-radius:8px}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem}.tile{border:1px solid #ddd;padding:.75rem;border-radius:6px}.sev-critical,.sev-high{border-left:4px solid #b42318}.sev-medium{border-left:4px solid #b54708}.sev-low{border-left:4px solid #475467}</style></head>
<body>
<h1>ExecFence report</h1>
<p><strong>Generated:</strong> ${escapeHtml(report.metadata?.generatedAt || '')}</p>
<p><strong>Command:</strong> ${escapeHtml(report.command?.display || report.metadata?.command || '')}</p>
<section class="summary"><div class="tile"><strong>Status</strong><br>${String(report.summary?.ok)}</div><div class="tile"><strong>Findings</strong><br>${findings.length}</div><div class="tile"><strong>Blocked</strong><br>${report.summary?.blockedFindings || 0}</div><div class="tile"><strong>Risk</strong><br>${escapeHtml(report.changeRisk?.level || 'unknown')}</div></section>
${blockingSummaryHtml(report.blockingSummary)}
<h2>Findings by rule</h2>
${Object.entries(grouped).map(([rule, items]) => `<details open><summary>${escapeHtml(rule)} (${items.length})</summary>${items.map((finding) => findingHtml(finding)).join('\n')}</details>`).join('\n')}
<h2>Manifest</h2><pre>${escapeHtml(JSON.stringify(report.manifest?.summary || {}, null, 2))}</pre>
<h2>Runtime trace</h2><pre>${escapeHtml(JSON.stringify(report.runtimeTrace || {}, null, 2))}</pre>
</body></html>`;
  fs.writeFileSync(htmlPath, body);
  return { htmlPath };
}

function markdownReport(cwd, reportPath) {
  const { filePath, report } = readReport(cwd, reportPath);
  const markdownPath = filePath.replace(/\.json$/, '.md');
  const lines = [
    '# ExecFence Report',
    '',
    `Report: ${filePath}`,
    `Generated: ${report.metadata?.generatedAt || ''}`,
    `Status: ${report.summary?.ok ? 'OK' : 'Blocked'}`,
    `Risk: ${report.changeRisk?.level || 'unknown'}`,
    '',
    '## Summary',
    '',
    `- Total findings: ${report.summary?.totalFindings || 0}`,
    `- Blocked findings: ${report.summary?.blockedFindings || 0}`,
    `- Warnings: ${report.summary?.warningFindings || 0}`,
    '',
    '## Blocking Summary',
    '',
    `- Status: ${report.blockingSummary?.status || (report.summary?.ok ? 'ok' : 'blocked')}`,
    `- Why blocked: ${report.blockingSummary?.whyBlocked || 'No blocking findings were detected.'}`,
    `- How it can execute: ${report.blockingSummary?.howItCanExecute || 'No suspicious execution surface was observed.'}`,
    `- Affected ecosystem: ${report.blockingSummary?.affectedEcosystem || 'unknown'}`,
    `- Next action: ${report.blockingSummary?.recommendedNextAction || 'No immediate action required.'}`,
    '',
    '## Findings',
    '',
    ...((report.findings || []).map((finding) => [
      `### ${finding.id}`,
      '',
      `- Severity: ${finding.severity || 'high'}`,
      `- File: ${finding.file}:${finding.line || 1}`,
      `- Reason: ${finding.reason || finding.detail || ''}`,
      `- Next action: ${finding.remediation || ''}`,
      '',
      finding.snippet ? ['```', finding.snippet, '```', ''].join('\n') : '',
    ].filter(Boolean).join('\n'))),
  ];
  fs.writeFileSync(markdownPath, `${lines.join('\n')}\n`);
  return { markdownPath };
}

function incidentFromReport(cwd, reportPath, options = {}) {
  const { filePath, report } = readReport(cwd, reportPath);
  const incidentPath = filePath.replace(/\.json$/, '.incident.md');
  const profile = options.profile || 'general';
  const lines = [
    '# ExecFence Incident Checklist',
    '',
    `Report: ${filePath}`,
    `Generated: ${report.metadata?.generatedAt || ''}`,
    `Profile: ${profile}`,
    '',
    '- [ ] Preserve the report JSON and suspicious files.',
    '- [ ] Review git blame and recent commits for each finding.',
    '- [ ] Audit CI workflows and local build/test entrypoints.',
    '- [ ] Review lockfiles and package lifecycle scripts.',
    '- [ ] Rotate tokens if build/test may have executed suspicious code.',
    '- [ ] Remove payload or add a narrow reviewed baseline entry with owner, reason, expiry, and hash.',
    ...profileChecklist(profile),
    '',
    '## Findings',
    ...(report.findings || []).map((finding) => `- ${finding.id}: ${finding.file}:${finding.line || 1} (${finding.severity})`),
    '',
  ];
  fs.writeFileSync(incidentPath, `${lines.join('\n')}\n`);
  return { incidentPath };
}

function incidentBundle(cwd, reportPath) {
  const { filePath, report } = readReport(cwd, reportPath);
  const id = report.metadata?.reportId || path.basename(filePath, '.json');
  const bundleDir = path.join(cwd, '.execfence', 'incidents', id);
  fs.mkdirSync(bundleDir, { recursive: true });
  const reportCopy = path.join(bundleDir, 'report.json');
  fs.copyFileSync(filePath, reportCopy);
  const html = htmlReport(cwd, filePath);
  fs.copyFileSync(html.htmlPath, path.join(bundleDir, 'report.html'));
  const incident = incidentFromReport(cwd, filePath);
  fs.copyFileSync(incident.incidentPath, path.join(bundleDir, 'checklist.md'));
  if (fs.existsSync(path.join(cwd, '.execfence', 'manifest.json'))) {
    fs.copyFileSync(path.join(cwd, '.execfence', 'manifest.json'), path.join(bundleDir, 'manifest.json'));
  }
  const quarantine = path.join(cwd, '.execfence', 'quarantine', id, 'metadata.json');
  if (fs.existsSync(quarantine)) {
    fs.copyFileSync(quarantine, path.join(bundleDir, 'quarantine-metadata.json'));
  }
  fs.writeFileSync(path.join(bundleDir, 'git-evidence.json'), `${JSON.stringify({
    report: filePath,
    branch: report.metadata?.gitBranch || '',
    commit: report.metadata?.gitCommit || '',
    files: (report.findings || []).map((finding) => ({ file: finding.file, git: finding.git || {} })),
  }, null, 2)}\n`);
  return { bundleDir, files: fs.readdirSync(bundleDir).map((name) => path.join(bundleDir, name)) };
}

function incidentTimeline(cwd, reportPath) {
  const { filePath, report } = readReport(cwd, reportPath);
  const timelinePath = filePath.replace(/\.json$/, '.timeline.md');
  const rows = [];
  rows.push(`- ${report.metadata?.generatedAt || ''}: report generated (${report.summary?.totalFindings || 0} findings)`);
  for (const finding of report.findings || []) {
    rows.push(`- ${finding.file}:${finding.line || 1} ${finding.id} (${finding.severity || 'high'})`);
    if (finding.git?.recentCommits) {
      for (const line of String(finding.git.recentCommits).split(/\r?\n/).filter(Boolean).slice(0, 5)) {
        rows.push(`  - commit: ${line}`);
      }
    }
  }
  fs.writeFileSync(timelinePath, `${['# ExecFence Incident Timeline', '', `Report: ${filePath}`, '', ...rows].join('\n')}\n`);
  return { timelinePath };
}

function riskRegression(cwd, options = {}) {
  const diff = compareReports(cwd, options);
  const severityScore = (finding) => ({ critical: 4, high: 3, medium: 2, low: 1 }[finding.severity || 'high'] || 3);
  const addedScore = diff.addedFindings.reduce((total, finding) => total + severityScore(finding), 0);
  const removedScore = diff.removedFindings.reduce((total, finding) => total + severityScore(finding), 0);
  return {
    ...diff,
    regression: addedScore > removedScore,
    scoreDelta: addedScore - removedScore,
  };
}

function pruneReports(cwd = process.cwd(), options = {}) {
  const maxReports = Number(options.maxReports || options.reportRetention?.maxReports || 0);
  const maxAgeDays = Number(options.maxAgeDays || options.reportRetention?.maxAgeDays || 0);
  const now = Date.now();
  const reports = listReports(cwd);
  const deleted = [];
  for (const [index, report] of reports.entries()) {
    const tooMany = maxReports > 0 && index >= maxReports;
    const tooOld = maxAgeDays > 0 && now - new Date(report.mtime).getTime() > maxAgeDays * 24 * 60 * 60 * 1000;
    if (tooMany || tooOld) {
      fs.unlinkSync(report.filePath);
      deleted.push(report.filePath);
    }
  }
  return { deleted, remaining: listReports(cwd).length };
}

function prCommentFromReport(report) {
  const findings = report.findings || [];
  const grouped = Object.entries(groupFindings(findings)).slice(0, 10);
  const summary = report.blockingSummary || {};
  return [
    '## ExecFence',
    '',
    `Status: ${report.summary?.ok ? 'OK' : 'Blocked'}`,
    `Findings: ${findings.length}`,
    `Risk: ${report.changeRisk?.level || 'unknown'}`,
    `Why blocked: ${summary.whyBlocked || 'No blocking findings were detected.'}`,
    `How it can execute: ${summary.howItCanExecute || 'No suspicious execution surface was observed.'}`,
    `Next: ${summary.recommendedNextAction || 'Re-run `execfence ci` after remediation.'}`,
    '',
    ...grouped.map(([rule, items]) => `- **${highestSeverity(items)}** ${rule} (${items.length})\n  Cause: ${items[0].reason || items[0].detail || ''}\n  Surface: ${items[0].activationSurface || 'run'}; ecosystem: ${items[0].ecosystem || summary.affectedEcosystem || 'unknown'}\n  Next: ${items[0].remediation || 'Review and remove the suspicious behavior or baseline it with owner, reason, expiry, and hash.'}`),
    findings.length > grouped.reduce((total, [, items]) => total + items.length, 0) ? `\n_${findings.length - grouped.reduce((total, [, items]) => total + items.length, 0)} more findings omitted._` : '',
    '',
    'Checklist:',
    '- [ ] Preserve the ExecFence report and suspicious files.',
    '- [ ] Review commits/blame for changed execution surfaces.',
    '- [ ] Re-run `execfence ci` after remediation.',
  ].filter(Boolean).join('\n');
}

function findingKey(finding) {
  return `${finding.id}:${finding.file}:${finding.line || 1}`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function groupFindings(findings) {
  const groups = {};
  for (const finding of findings) {
    const key = finding.id || 'finding';
    groups[key] = groups[key] || [];
    groups[key].push(finding);
  }
  return groups;
}

function findingHtml(finding) {
  return `<section class="finding sev-${escapeHtml(finding.severity || 'high')}"><h3>${escapeHtml(finding.id)}</h3><p><strong>${escapeHtml(finding.severity || 'high')}</strong> ${escapeHtml(finding.file)}:${finding.line || 1}</p><p>${escapeHtml(finding.reason || finding.detail || '')}</p><p>${escapeHtml(finding.remediation || '')}</p><pre>${escapeHtml(finding.snippet || '')}</pre></section>`;
}

function blockingSummaryHtml(summary = {}) {
  return `<h2>Blocking summary</h2><section class="finding"><p><strong>Why blocked:</strong> ${escapeHtml(summary.whyBlocked || 'No blocking findings were detected.')}</p><p><strong>How it can execute:</strong> ${escapeHtml(summary.howItCanExecute || 'No suspicious execution surface was observed.')}</p><p><strong>Affected ecosystem:</strong> ${escapeHtml(summary.affectedEcosystem || 'unknown')}</p><p><strong>Recommended next action:</strong> ${escapeHtml(summary.recommendedNextAction || 'No immediate action required.')}</p></section>`;
}

function highestSeverity(findings) {
  const order = ['critical', 'high', 'medium', 'low'];
  return findings
    .map((finding) => finding.severity || 'high')
    .sort((a, b) => order.indexOf(a) - order.indexOf(b))[0] || 'high';
}

function profileChecklist(profile) {
  const profiles = {
    npm: ['- [ ] Review package scripts, lockfiles, npm tokens, and publish provenance.'],
    go: ['- [ ] Review go.sum changes, generated test binaries, and local toolchain cache behavior.'],
    python: ['- [ ] Review pyproject/setup hooks, uv/poetry lockfiles, and wheel/sdist contents.'],
    rust: ['- [ ] Review build.rs, Cargo.lock source drift, and compiled artifacts.'],
    desktop: ['- [ ] Review Electron/Tauri build hooks, native modules, and bundled archives.'],
    agentic: ['- [ ] Review AGENTS/Claude/Gemini/Copilot instructions and MCP/tool configs.'],
  };
  return profiles[profile] || [];
}

module.exports = {
  compareReports,
  diffReports,
  htmlReport,
  incidentBundle,
  incidentFromReport,
  incidentTimeline,
  latestReport,
  latestReportSummary,
  listReports,
  markdownReport,
  pruneReports,
  prCommentFromReport,
  readReport,
  riskRegression,
  resolveReport,
};
