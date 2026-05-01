'use strict';

const os = require('node:os');
const path = require('node:path');
const {
  guardrailsRule,
  installAgentRules,
  installCodexSkill,
} = require('./agent-rules');
const { scan, formatFindings } = require('./scanner');
const { detectStack, initProject } = require('./init');

function usage() {
  return `security-guardrails

Usage:
  security-guardrails scan [paths...]
  security-guardrails init
  security-guardrails detect
  security-guardrails install-skill [--codex-home <path>] [--home <path>]
  security-guardrails install-agent-rules [--scope global|project|both] [--home <path>] [--project <path>]
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
  if (command === 'install-agent-rules') {
    installAgentRulesCommand(args.slice(1));
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
  const homeFlag = args.indexOf('--home');
  const codexHome = codexHomeFlag >= 0 && args[codexHomeFlag + 1]
    ? path.resolve(args[codexHomeFlag + 1])
    : path.join(os.homedir(), '.codex');
  const home = homeFlag >= 0 && args[homeFlag + 1] ? path.resolve(args[homeFlag + 1]) : os.homedir();
  const installed = installCodexSkill({ codexHome });
  const rules = installAgentRules({ scope: 'global', home });
  console.log(`[security-guardrails] installed Codex skill at ${installed.skillDir}`);
  console.log(`[security-guardrails] updated Codex AGENTS.md at ${installed.agents.filePath}`);
  for (const rule of rules) {
    console.log(`[security-guardrails] updated agent rules at ${rule.filePath}`);
  }
}

function installAgentRulesCommand(args) {
  const scope = readOption(args, '--scope') || 'global';
  const home = readOption(args, '--home') || os.homedir();
  const project = readOption(args, '--project') || process.cwd();
  const rules = installAgentRules({ scope, home, project });
  for (const rule of rules) {
    console.log(`[security-guardrails] updated agent rules at ${rule.filePath}`);
  }
}

function agentsSnippet() {
  return `${guardrailsRule()}\n`;
}

function updateGlobalAgents(codexHome) {
  return installCodexSkill({ codexHome }).agents.filePath;
}

function readOption(args, name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

module.exports = {
  installSkill,
  main,
  usage,
  agentsSnippet,
  updateGlobalAgents,
};
