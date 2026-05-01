'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan, formatFindings } = require('./scanner');
const { detectStack, initProject } = require('./init');

function usage() {
  return `security-guardrails

Usage:
  security-guardrails scan [paths...]
  security-guardrails init
  security-guardrails detect
  security-guardrails install-skill [--codex-home <path>]
  security-guardrails print-agents-snippet

Examples:
  npx --yes security-guardrails scan
  npx --yes security-guardrails init
`;
}

async function main(args) {
  const command = args[0] || 'scan';
  if (command === '-h' || command === '--help' || command === 'help') {
    console.log(usage());
    return;
  }
  if (command === 'scan') {
    const result = scan({ roots: args.slice(1) });
    console.log(formatFindings(result.findings));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (command === 'detect') {
    console.log(JSON.stringify(detectStack(process.cwd()), null, 2));
    return;
  }
  if (command === 'init') {
    const result = initProject({ cwd: process.cwd() });
    console.log(`[security-guardrails] detected stack: ${JSON.stringify(result.stack)}`);
    if (result.changes.length === 0) {
      console.log('[security-guardrails] no changes needed');
      return;
    }
    for (const change of result.changes) {
      console.log(`- ${change}`);
    }
    return;
  }
  if (command === 'install-skill') {
    installSkill(args.slice(1));
    return;
  }
  if (command === 'print-agents-snippet') {
    console.log(agentsSnippet());
    return;
  }
  throw new Error(`Unknown command: ${command}\n\n${usage()}`);
}

function installSkill(args) {
  const codexHomeFlag = args.indexOf('--codex-home');
  const codexHome = codexHomeFlag >= 0 && args[codexHomeFlag + 1]
    ? path.resolve(args[codexHomeFlag + 1])
    : path.join(os.homedir(), '.codex');
  const source = path.resolve(__dirname, '..', 'skill', 'security-guardrails', 'SKILL.md');
  const targetDir = path.join(codexHome, 'skills', 'security-guardrails');
  fs.mkdirSync(targetDir, { recursive: true });
  fs.copyFileSync(source, path.join(targetDir, 'SKILL.md'));
  const agentsPath = updateGlobalAgents(codexHome);
  console.log(`[security-guardrails] installed Codex skill at ${targetDir}`);
  console.log(`[security-guardrails] updated global AGENTS.md at ${agentsPath}`);
}

function agentsSnippet() {
  return `<!-- SECURITY-GUARDRAILS:START -->
## Security Guardrails

- For persistent projects that run on the web, build executable code, run CI/CD, or access the user's filesystem, credentials, browser, network, shell, desktop APIs, or local machine, use \`$security-guardrails\` to evaluate the stack and add lightweight malware/supply-chain guardrails unless the user explicitly opts out.

Keyword trigger:
| "security guardrails", "guardrail", "supply-chain guardrails", "malware guardrails" | \`$security-guardrails\` | Read \`~/.codex/skills/security-guardrails/SKILL.md\`, evaluate stack and add malware/supply-chain guardrails |
<!-- SECURITY-GUARDRAILS:END -->
`;
}

function updateGlobalAgents(codexHome) {
  const agentsPath = path.join(codexHome, 'AGENTS.md');
  fs.mkdirSync(codexHome, { recursive: true });
  const snippet = agentsSnippet().trimEnd();
  const start = '<!-- SECURITY-GUARDRAILS:START -->';
  const end = '<!-- SECURITY-GUARDRAILS:END -->';
  const existing = fs.existsSync(agentsPath) ? fs.readFileSync(agentsPath, 'utf8') : '';
  const pattern = new RegExp(`${escapeRegExp(start)}[\\s\\S]*?${escapeRegExp(end)}`);
  if (!pattern.test(existing) && existing.includes('$security-guardrails')) {
    return agentsPath;
  }
  const next = pattern.test(existing)
    ? existing.replace(pattern, snippet)
    : `${existing.trimEnd()}${existing.trim() ? '\n\n' : ''}${snippet}\n`;
  fs.writeFileSync(agentsPath, next.endsWith('\n') ? next : `${next}\n`);
  return agentsPath;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = {
  installSkill,
  main,
  usage,
  agentsSnippet,
  updateGlobalAgents,
};
