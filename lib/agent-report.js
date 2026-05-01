'use strict';

const path = require('node:path');
const { changedFiles } = require('./git');

function agentReport(cwd = process.cwd(), options = {}) {
  const files = changedFiles(cwd, { staged: options.staged });
  const sensitivePatterns = [
    /package\.json$/,
    /(?:package-lock|pnpm-lock|yarn\.lock|bun\.lock|Cargo\.lock|go\.sum|poetry\.lock|uv\.lock)$/,
    /\.github\/workflows\//,
    /\.vscode\/tasks\.json$/,
    /(?:vite|next|webpack|rollup|tailwind|postcss|eslint)\.config\./,
    /AGENTS\.md|CLAUDE\.md|GEMINI\.md|copilot-instructions\.md|\.clinerules/,
  ];
  const sensitiveChanges = files
    .map((file) => path.relative(cwd, file).replaceAll(path.sep, '/'))
    .filter((file) => sensitivePatterns.some((pattern) => pattern.test(file)));
  return {
    cwd,
    ok: sensitiveChanges.length === 0,
    changedFiles: files.map((file) => path.relative(cwd, file).replaceAll(path.sep, '/')),
    sensitiveChanges,
    findings: sensitiveChanges.map((file) => ({
      id: 'agent-sensitive-surface-changed',
      severity: 'medium',
      file,
      line: 1,
      detail: 'Changed file affects build/dev/test execution or agent behavior.',
    })),
  };
}

module.exports = {
  agentReport,
};
