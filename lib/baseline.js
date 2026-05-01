'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');

const baselineFileName = '.security-guardrails.baseline.json';

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

module.exports = {
  applyBaseline,
  baselineFileName,
  loadBaseline,
  sha256File,
};
