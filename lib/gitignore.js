'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { reportsDir } = require('./paths');

function ensureReportsGitignore(cwd = process.cwd(), config = {}, options = {}) {
  if (config.reportsGitignore === false) {
    return { changed: false, skipped: true, gitignorePath: path.join(cwd, '.gitignore') };
  }
  const gitignorePath = path.join(cwd, '.gitignore');
  const entry = normalizeGitignoreEntry(options.entry || `${config.reportsDir || reportsDir}/`);
  const existing = fs.existsSync(gitignorePath) ? fs.readFileSync(gitignorePath, 'utf8') : '';
  const lines = existing.split(/\r?\n/).map((line) => line.trim());
  if (lines.includes(entry)) {
    return { changed: false, skipped: false, gitignorePath };
  }
  const prefix = existing.trimEnd();
  const next = `${prefix}${prefix ? '\n' : ''}${entry}\n`;
  if (!options.dryRun) {
    fs.writeFileSync(gitignorePath, next);
  }
  return { changed: true, skipped: false, gitignorePath };
}

function normalizeGitignoreEntry(value) {
  return String(value).replaceAll('\\', '/').replace(/^\/+/, '');
}

module.exports = {
  ensureReportsGitignore,
};
