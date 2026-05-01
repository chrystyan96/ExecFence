'use strict';

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { exactSignatures } = require('./signatures');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function changedFiles(cwd = process.cwd(), options = {}) {
  const args = options.staged ? ['diff', '--name-only', '--cached'] : ['diff', '--name-only'];
  const output = git(cwd, args);
  const files = output ? output.split(/\r?\n/).filter(Boolean) : [];
  if (!options.staged) {
    const untracked = git(cwd, ['ls-files', '--others', '--exclude-standard']);
    files.push(...(untracked ? untracked.split(/\r?\n/).filter(Boolean) : []));
  }
  return Array.from(new Set(files)).map((file) => path.resolve(cwd, file));
}

function scanHistory(cwd = process.cwd(), options = {}) {
  if (!options.includeSelf && isExecFencePackage(cwd)) {
    return {
      cwd,
      commitsScanned: 0,
      findings: [],
      ok: true,
      skipped: 'self-package-documents-signatures',
    };
  }
  const signatures = options.signatures || exactSignatures;
  const findings = [];
  const maxCommits = Number(options.maxCommits || 500);
  const commitOutput = git(cwd, ['log', '--all', `--max-count=${maxCommits}`, '--format=%H']);
  const commits = commitOutput ? commitOutput.split(/\r?\n/).filter(Boolean) : [];
  for (const [id, signature] of signatures) {
    let output = '';
    try {
      output = git(cwd, ['log', '--all', `--max-count=${maxCommits}`, '--format=%H %s', '-S', signature]);
    } catch {
      output = '';
    }
    for (const line of output.split(/\r?\n/).filter(Boolean)) {
      const [commit, ...messageParts] = line.split(' ');
      findings.push({
        id: `history-${id}`,
        file: commit,
        line: 1,
        detail: `History contains ${signature} in commit ${commit}${messageParts.length ? ` (${messageParts.join(' ')})` : ''}`,
      });
    }
  }
  return {
    cwd,
    commitsScanned: commits.length,
    findings,
    ok: findings.length === 0,
  };
}

function isExecFencePackage(cwd) {
  const packagePath = path.join(cwd, 'package.json');
  if (!fs.existsSync(packagePath)) {
    return false;
  }
  try {
    return JSON.parse(fs.readFileSync(packagePath, 'utf8')).name === 'execfence';
  } catch {
    return false;
  }
}

module.exports = {
  changedFiles,
  git,
  scanHistory,
};
