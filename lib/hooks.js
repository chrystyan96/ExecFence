'use strict';

const fs = require('node:fs');
const path = require('node:path');

function installGitHook(cwd = process.cwd()) {
  const gitDir = path.join(cwd, '.git');
  if (!fs.existsSync(gitDir)) {
    throw new Error('Cannot install hook: .git directory not found');
  }
  const hooksDir = path.join(gitDir, 'hooks');
  fs.mkdirSync(hooksDir, { recursive: true });
  const hookPath = path.join(hooksDir, 'pre-commit');
  const block = [
    '# execfence:start',
    'npx --yes execfence diff-scan --staged',
    '# execfence:end',
  ].join('\n');
  const existing = fs.existsSync(hookPath) ? fs.readFileSync(hookPath, 'utf8') : '#!/bin/sh\n';
  const pattern = /# execfence:start[\s\S]*?# execfence:end/;
  const next = pattern.test(existing)
    ? existing.replace(pattern, block)
    : `${existing.trimEnd()}\n\n${block}\n`;
  fs.writeFileSync(hookPath, next);
  try {
    fs.chmodSync(hookPath, 0o755);
  } catch {
    // Windows may ignore POSIX mode bits.
  }
  return hookPath;
}

module.exports = {
  installGitHook,
};
