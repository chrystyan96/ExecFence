'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { changedFiles } = require('./git');
const { packageManagerForFile } = require('./ecosystems');

function agentReport(cwd = process.cwd(), options = {}) {
  const files = changedFiles(cwd, { staged: options.staged });
  const sensitivePatterns = [
    /package\.json$/,
    /(?:package-lock|pnpm-lock|yarn\.lock|bun\.lock|Cargo\.lock|Cargo\.toml|go\.mod|go\.sum|go\.work|poetry\.lock|uv\.lock|requirements.*\.txt|pyproject\.toml|pom\.xml|build\.gradle(?:\.kts)?|packages\.lock\.json|composer\.(?:json|lock)|Gemfile(?:\.lock)?)$/,
    /\.github\/workflows\//,
    /\.vscode\/tasks\.json$/,
    /(?:vite|next|webpack|rollup|tailwind|postcss|eslint)\.config\./,
    /AGENTS\.md|CLAUDE\.md|GEMINI\.md|copilot-instructions\.md|\.clinerules/,
    /(?:^|\/)\.?mcp(?:\/|\.json$)/,
    /\.cursor\/mcp\.json$/,
    /\.continue\/config\.json$/,
    /\.claude\/settings\.json$/,
    /\.gemini\/settings\.json$/,
  ];
  const sensitiveChanges = files
    .map((file) => path.relative(cwd, file).replaceAll(path.sep, '/'))
    .filter((file) => sensitivePatterns.some((pattern) => pattern.test(file)));
  const mcpFindings = auditAgentToolConfigs(cwd, [
    ...new Set([
      ...sensitiveChanges,
      ...candidateAgentToolFiles(cwd),
    ]),
  ]);
  const findings = [
    ...sensitiveChanges.map((file) => ({
      id: 'agent-sensitive-surface-changed',
      severity: 'medium',
      file,
      line: 1,
      detail: 'Changed file affects build/dev/test execution or agent behavior.',
    })),
    ...mcpFindings,
  ];
  const ecosystemImpact = impactByEcosystem(sensitiveChanges);
  return {
    cwd,
    ok: sensitiveChanges.length === 0 && !mcpFindings.some((finding) => ['critical', 'high'].includes(finding.severity)),
    changedFiles: files.map((file) => path.relative(cwd, file).replaceAll(path.sep, '/')),
    sensitiveChanges,
    ecosystemImpact,
    mcpFindings,
    findings,
  };
}

function impactByEcosystem(files) {
  const groups = {};
  for (const file of files) {
    const ecosystem = packageManagerForFile(file, surfaceFallback(file));
    groups[ecosystem] = groups[ecosystem] || { ecosystem, files: [], surfaces: [] };
    groups[ecosystem].files.push(file);
    groups[ecosystem].surfaces.push(surfaceFor(file));
  }
  return Object.values(groups).map((group) => ({
    ecosystem: group.ecosystem,
    files: group.files,
    surfaces: Array.from(new Set(group.surfaces)),
    impact: impactText(group.ecosystem, group.surfaces),
  }));
}

function surfaceFallback(file) {
  if (/\.github\/workflows\//.test(file)) return 'ci';
  if (/AGENTS|CLAUDE|GEMINI|mcp|copilot|\.clinerules/.test(file)) return 'agent';
  return 'execution';
}

function surfaceFor(file) {
  if (/lock|\.sum$|\.mod$|Gemfile|composer|package\.json|pyproject|requirements|Cargo/.test(file)) return 'dependency';
  if (/\.github\/workflows\//.test(file)) return 'ci';
  if (/AGENTS|CLAUDE|GEMINI|mcp|copilot|\.clinerules/.test(file)) return 'agent';
  return 'runtime';
}

function impactText(ecosystem, surfaces) {
  return `${ecosystem} ${Array.from(new Set(surfaces)).join('/')} surface changed; review install, build, test, run, and CI activation before execution.`;
}

function candidateAgentToolFiles(cwd) {
  const direct = [
    'mcp.json',
    '.mcp.json',
    '.cursor/mcp.json',
    '.continue/config.json',
    '.claude/settings.json',
    '.gemini/settings.json',
  ];
  const files = direct.filter((file) => fs.existsSync(path.join(cwd, file)));
  const mcpDir = path.join(cwd, '.mcp');
  if (fs.existsSync(mcpDir)) {
    for (const entry of walk(mcpDir)) {
      files.push(path.relative(cwd, entry).replaceAll(path.sep, '/'));
    }
  }
  return files;
}

function auditAgentToolConfigs(cwd, files) {
  const findings = [];
  for (const file of files) {
    if (!isAgentToolConfig(file)) {
      continue;
    }
    const fullPath = path.join(cwd, file);
    if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
      continue;
    }
    const text = safeRead(fullPath);
    if (!text) {
      continue;
    }
    const lower = text.toLowerCase();
    if (/(disable|skip|ignore|bypass).{0,80}(execfence|security guardrail|security scan)/i.test(text)) {
      findings.push({
        id: 'agent-disable-execfence-instruction',
        severity: 'high',
        file,
        line: lineOf(text, /disable|skip|ignore|bypass/i),
        detail: 'Agent or tool instruction appears to disable, skip, ignore, or bypass ExecFence/security guardrails.',
      });
    }
    if (/(shell|powershell|cmd\.exe|bash|sh|child_process|spawn|execFile|exec\()/i.test(text)) {
      findings.push({
        id: 'agent-mcp-shell-access',
        severity: 'high',
        file,
        line: lineOf(text, /shell|powershell|cmd\.exe|bash|child_process|spawn|execFile|exec\(/i),
        detail: 'MCP/tool config exposes broad shell or process execution capability.',
      });
    }
    if (/(filesystem|file_system|readfile|writefile|fs\.|root\s*[:=]|home\s*[:=]|c:\\\\|\/home\/|\/users\/)/i.test(text)) {
      findings.push({
        id: 'agent-mcp-filesystem-access',
        severity: 'medium',
        file,
        line: lineOf(text, /filesystem|readfile|writefile|fs\./i),
        detail: 'MCP/tool config exposes broad filesystem capability that can affect local project or user files.',
      });
    }
    if (/(browser|fetch|http|https|network|credentials|token|secret)/i.test(lower)) {
      findings.push({
        id: 'agent-mcp-network-or-credential-access',
        severity: 'medium',
        file,
        line: lineOf(text, /browser|fetch|http|network|credentials|token|secret/i),
        detail: 'MCP/tool config references network, browser, or credential access that should be reviewed before CI/strict execution.',
      });
    }
  }
  return findings;
}

function isAgentToolConfig(file) {
  return /(?:^|\/)\.?mcp(?:\/|\.json$)/.test(file) ||
    /\.cursor\/mcp\.json$/.test(file) ||
    /\.continue\/config\.json$/.test(file) ||
    /\.claude\/settings\.json$/.test(file) ||
    /\.gemini\/settings\.json$/.test(file) ||
    /AGENTS\.md|CLAUDE\.md|GEMINI\.md|copilot-instructions\.md|\.clinerules/.test(file);
}

function walk(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walk(fullPath));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

function safeRead(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8').slice(0, 1024 * 1024);
  } catch {
    return '';
  }
}

function lineOf(text, pattern) {
  const lines = text.split(/\r?\n/);
  const index = lines.findIndex((line) => pattern.test(line));
  return index >= 0 ? index + 1 : 1;
}

module.exports = {
  agentReport,
};
