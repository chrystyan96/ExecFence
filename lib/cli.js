'use strict';

const os = require('node:os');
const path = require('node:path');
const { execFileSync, execSync } = require('node:child_process');
const {
  guardrailsRule,
  installAgentRules,
  installCodexSkill,
} = require('./agent-rules');
const { scan } = require('./scanner');
const { detectStack, initProject } = require('./init');
const { changedFiles, scanHistory } = require('./git');
const { installGitHook } = require('./hooks');
const { formatFindings, formatResult } = require('./output');
const { explainFinding } = require('./explain');

function usage() {
  return `security-guardrails

Usage:
  security-guardrails scan [paths...]
  security-guardrails scan [--mode block|audit] --ci [--format text|json|sarif] [paths...]
  security-guardrails diff-scan [--staged] [--mode block|audit]
  security-guardrails scan-history [--max-commits <n>] [--format text|json|sarif] [--include-self]
  security-guardrails explain <finding-id>
  security-guardrails init [--preset auto|node|go|tauri|python|rust]
  security-guardrails detect
  security-guardrails install-hooks
  security-guardrails install-skill [--codex-home <path>] [--home <path>]
  security-guardrails install-agent-rules [--scope global|project|both] [--home <path>] [--project <path>]
  security-guardrails publish [--real]
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
    const parsed = parseScanArgs(args.slice(1));
    const result = scan({ roots: parsed.paths, configPath: parsed.configPath, mode: parsed.mode });
    const format = parsed.ci && parsed.format === 'text' ? 'json' : parsed.format;
    console.log(formatResult(result, format));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (command === 'diff-scan') {
    const parsed = parseScanArgs(args.slice(1));
    const staged = args.includes('--staged');
    const files = changedFiles(process.cwd(), { staged });
    if (files.length === 0) {
      console.log('[security-guardrails] OK');
      return;
    }
    const result = scan({ roots: files, mode: parsed.mode });
    console.log(formatFindings(result.findings, result));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (command === 'scan-history') {
    const result = scanHistory(process.cwd(), {
      includeSelf: args.includes('--include-self'),
      maxCommits: readOption(args.slice(1), '--max-commits'),
    });
    console.log(formatResult(result, readOption(args.slice(1), '--format') || 'text'));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (command === 'explain') {
    console.log(explainFinding(args[1]));
    return;
  }
  if (command === 'detect') {
    console.log(JSON.stringify(detectStack(process.cwd()), null, 2));
    return;
  }
  if (command === 'init') {
    const result = initProject({ cwd: process.cwd(), preset: readOption(args.slice(1), '--preset') || 'auto' });
    console.log(`[security-guardrails] detected stack: ${JSON.stringify(result.stack)}`);
    console.log(`[security-guardrails] preset: ${result.preset}`);
    if (result.changes.length === 0) {
      console.log('[security-guardrails] no changes needed');
      return;
    }
    for (const change of result.changes) {
      console.log(`- ${change}`);
    }
    return;
  }
  if (command === 'install-hooks') {
    const hookPath = installGitHook(process.cwd());
    console.log(`[security-guardrails] installed pre-commit hook at ${hookPath}`);
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
  if (command === 'publish') {
    publishPackage({ real: args.includes('--real') });
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

function parseScanArgs(args) {
  const paths = [];
  let format = 'text';
  let configPath;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--ci') {
      continue;
    }
    if (arg === '--format') {
      format = args[index + 1] || 'text';
      index += 1;
      continue;
    }
    if (arg === '--config') {
      configPath = args[index + 1];
      index += 1;
      continue;
    }
    if (arg === '--mode') {
      index += 1;
      continue;
    }
    if (arg === '--staged') {
      continue;
    }
    paths.push(arg);
  }
  return {
    ci: args.includes('--ci'),
    configPath,
    format,
    mode: readOption(args, '--mode'),
    paths,
  };
}

function publishPackage(options = {}) {
  run('npm', ['test']);
  run('npm', ['run', 'scan']);
  run('npm', ['pack', '--dry-run']);
  if (!options.real) {
    console.log('[security-guardrails] publish dry-run complete. Re-run with --real after npm login to publish.');
    return;
  }
  run('npm', ['publish', '--access', 'public', '--provenance']);
}

function run(command, args) {
  console.log(`[security-guardrails] ${command} ${args.join(' ')}`);
  if (process.platform === 'win32') {
    const resolved = resolveWindowsCommand(command);
    const commandLine = `call ${quoteShellArg(resolved)} ${args.map(quoteShellArg).join(' ')}`;
    execSync(commandLine, { shell: process.env.ComSpec || 'cmd.exe', stdio: 'inherit' });
    return;
  }
  execFileSync(command, args, { stdio: 'inherit' });
}

function resolveWindowsCommand(command) {
  try {
    return execSync(`where ${quoteShellArg(`${command}.cmd`)}`, { encoding: 'utf8' })
      .split(/\r?\n/)
      .find(Boolean) || command;
  } catch {
    return command;
  }
}

function quoteShellArg(value) {
  return `"${String(value).replace(/"/g, '""')}"`;
}

module.exports = {
  installSkill,
  main,
  usage,
  agentsSnippet,
  updateGlobalAgents,
};
