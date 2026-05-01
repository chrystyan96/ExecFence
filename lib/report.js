'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { sha256File } = require('./baseline');

function writeReport(result, options = {}) {
  const cwd = result.cwd || process.cwd();
  const reportDir = path.resolve(cwd, options.reportDir || 'security-guardrails-report');
  fs.mkdirSync(reportDir, { recursive: true });
  const evidence = {
    generatedAt: new Date().toISOString(),
    command: options.command || 'security-guardrails scan',
    cwd,
    configPath: result.configPath || null,
    mode: result.mode,
    ok: result.ok,
    findings: (result.findings || []).map((finding) => enrichFinding(cwd, finding)),
    suppressedFindings: result.suppressedFindings || [],
  };
  fs.writeFileSync(path.join(reportDir, 'report.json'), `${JSON.stringify(evidence, null, 2)}\n`);
  fs.writeFileSync(path.join(reportDir, 'report.md'), markdownReport(evidence));
  return { reportDir, files: ['report.json', 'report.md'].map((file) => path.join(reportDir, file)) };
}

function enrichFinding(cwd, finding) {
  const filePath = path.join(cwd, finding.file);
  return {
    ...finding,
    sha256: fs.existsSync(filePath) ? sha256File(filePath) : null,
    snippet: fs.existsSync(filePath) ? snippet(filePath, finding.line || 1) : '',
    blame: git(cwd, ['blame', '-L', `${finding.line || 1},${finding.line || 1}`, '--', finding.file]),
    recentCommits: git(cwd, ['log', '--oneline', '-5', '--', finding.file]),
  };
}

function snippet(filePath, line) {
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  const start = Math.max(0, line - 3);
  const end = Math.min(lines.length, line + 2);
  return lines.slice(start, end).map((value, index) => `${start + index + 1}: ${value.slice(0, 240)}`).join('\n');
}

function git(cwd, args) {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return '';
  }
}

function markdownReport(evidence) {
  const lines = [
    '# security-guardrails report',
    '',
    `Generated: ${evidence.generatedAt}`,
    `Mode: ${evidence.mode}`,
    `OK: ${evidence.ok}`,
    '',
  ];
  for (const finding of evidence.findings) {
    lines.push(`## ${finding.id}`);
    lines.push(`- Severity: ${finding.severity}`);
    lines.push(`- File: ${finding.file}:${finding.line || 1}`);
    lines.push(`- SHA-256: ${finding.sha256 || 'n/a'}`);
    lines.push(`- Detail: ${finding.detail}`);
    if (finding.snippet) {
      lines.push('');
      lines.push('```');
      lines.push(finding.snippet);
      lines.push('```');
    }
    lines.push('');
  }
  return `${lines.join('\n').trimEnd()}\n`;
}

module.exports = {
  writeReport,
};
