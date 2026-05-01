'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { baselineFileName } = require('./paths');

function loadBaseline(cwd = process.cwd(), explicitPath) {
  const baselinePath = explicitPath ? path.resolve(cwd, explicitPath) : path.join(cwd, baselineFileName);
  if (!fs.existsSync(baselinePath)) {
    return { baselinePath: null, entries: [] };
  }
  const parsed = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
  return {
    baselinePath,
    entries: Array.isArray(parsed) ? parsed : parsed.findings || [],
  };
}

function applyBaseline(cwd, findings, options = {}) {
  const loaded = loadBaseline(cwd, options.baselinePath);
  if (loaded.entries.length === 0) {
    return { activeFindings: findings, suppressedFindings: [], baselinePath: loaded.baselinePath };
  }
  const activeFindings = [];
  const suppressedFindings = [];
  for (const finding of findings) {
    const match = loaded.entries.find((entry) => baselineMatches(cwd, finding, entry));
    if (match) {
      suppressedFindings.push({ ...finding, baseline: match });
    } else {
      activeFindings.push(finding);
    }
  }
  return { activeFindings, suppressedFindings, baselinePath: loaded.baselinePath };
}

function baselineMatches(cwd, finding, entry) {
  if (entry.expiresAt && new Date(entry.expiresAt).getTime() < Date.now()) {
    return false;
  }
  if ((entry.findingId || entry.id) !== finding.id) {
    return false;
  }
  if (entry.file && entry.file.replaceAll('\\', '/') !== finding.file) {
    return false;
  }
  if (!entry.sha256) {
    return true;
  }
  const filePath = path.join(cwd, finding.file);
  return fs.existsSync(filePath) && sha256File(filePath) === String(entry.sha256).toLowerCase();
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function addBaselineFromReport(cwd = process.cwd(), reportPath, metadata = {}) {
  if (!reportPath) {
    throw new Error('Usage: execfence baseline add --from-report <report.json> --owner <owner> --reason <reason> --expires-at <date>');
  }
  for (const field of ['owner', 'reason', 'expiresAt']) {
    if (!metadata[field]) {
      throw new Error(`Missing required baseline metadata: ${field}`);
    }
  }
  const resolved = path.resolve(cwd, reportPath);
  const report = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  const baselinePath = path.join(cwd, baselineFileName);
  const current = fs.existsSync(baselinePath) ? JSON.parse(fs.readFileSync(baselinePath, 'utf8')) : { findings: [] };
  const findings = Array.isArray(current) ? current : (current.findings || []);
  const added = [];
  for (const finding of report.findings || []) {
    const entry = {
      findingId: finding.id,
      file: finding.file,
      sha256: finding.sha256 || hashForFinding(cwd, finding),
      reason: metadata.reason,
      owner: metadata.owner,
      expiresAt: metadata.expiresAt,
    };
    if (!findings.some((item) => item.findingId === entry.findingId && item.file === entry.file && item.sha256 === entry.sha256)) {
      findings.push(entry);
      added.push(entry);
    }
  }
  fs.mkdirSync(path.dirname(baselinePath), { recursive: true });
  fs.writeFileSync(baselinePath, `${JSON.stringify({ findings }, null, 2)}\n`);
  return { baselinePath, added, total: findings.length };
}

function hashForFinding(cwd, finding) {
  const filePath = path.join(cwd, finding.file || '');
  return fs.existsSync(filePath) && fs.statSync(filePath).isFile() ? sha256File(filePath) : null;
}

module.exports = {
  addBaselineFromReport,
  applyBaseline,
  baselineFileName,
  loadBaseline,
  sha256File,
};
