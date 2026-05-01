'use strict';

const os = require('node:os');
const path = require('node:path');
const { execFileSync, execSync } = require('node:child_process');
const {
  guardrailsRule,
  installAgentRules,
  installCodexSkill,
  installSkillDefaults,
} = require('./agent-rules');
const { scan } = require('./scanner');
const { detectStack, initProject } = require('./init');
const { changedFiles, scanHistory } = require('./git');
const { installGitHook } = require('./hooks');
const { formatFindings, formatResult } = require('./output');
const { explainFinding } = require('./explain');
const { analyzeCoverage } = require('./coverage');
const { writeReport } = require('./report');
const { runDoctor } = require('./doctor');
const { ensureReportsGitignore } = require('./gitignore');
const { runWithFence } = require('./runtime');
const { runCi } = require('./ci');
const { generateManifest, writeManifest, readManifest, diffManifest } = require('./manifest');
const {
  compareReports,
  diffReports,
  htmlReport,
  incidentBundle,
  incidentFromReport,
  incidentTimeline,
  latestReport,
  listReports,
  pruneReports,
  prCommentFromReport,
  readReport,
} = require('./investigation');
const { enrichFindings } = require('./enrichment');
const { agentReport } = require('./agent-report');
const { lockfileDiff, packAudit, trustAdd, trustAudit } = require('./supply-chain');
const { collectDependencies, depsDiff } = require('./deps');
const { wireProject } = require('./wire');
const { addBaselineFromReport } = require('./baseline');

function usage() {
  return `execfence

Usage:
  execfence run [--record-artifacts] [--deny-on-new-executable] -- <command>
  execfence scan [paths...]
  execfence scan [--mode block|audit] [--fail-on list] [--changed-only] [--report <dir>] --ci [--format text|json|sarif] [paths...]
  execfence diff-scan [--staged] [--mode block|audit] [--fail-on list]
  execfence scan-history [--max-commits <n>] [--format text|json|sarif] [--include-self]
  execfence coverage [--fix-suggestions] [--format text|json]
  execfence wire [--dry-run|--apply]
  execfence ci [--base-ref <ref>]
  execfence deps diff [--base-ref <ref>]
  execfence manifest
  execfence manifest diff
  execfence report [--dir <dir>] [paths...]
  execfence report --html <report.json>
  execfence reports list|latest|show <id>|open <id>|diff <a> <b>|compare [--since <report>]|prune
  execfence incident create|bundle|timeline --from-report <report.json>
  execfence baseline add --from-report <report.json> --owner <owner> --reason <reason> --expires-at <date>
  execfence enrich <report.json>
  execfence pack-audit
  execfence trust add <path> --reason <reason> --owner <owner> --expires-at <date>
  execfence trust audit
  execfence agent-report
  execfence pr-comment --report <report.json>
  execfence doctor
  execfence explain <finding-id>
  execfence init [--preset auto|node|go|tauri|python|rust] [--dry-run]
  execfence detect
  execfence install-hooks
  execfence install-skill [--codex-home <path>] [--home <path>]
  execfence install-agent-rules [--scope global|project|both] [--verify] [--home <path>] [--project <path>]
  execfence publish [--real]
  execfence print-agents-snippet

Examples:
  npx --yes execfence run -- npm test
  npx --yes execfence scan
  npx --yes execfence init
`;
}

async function main(args) {
  const command = args[0] || 'scan';
  if (command === '-h' || command === '--help' || command === 'help') {
    console.log(usage());
    return;
  }
  if (command === 'run') {
    const delimiter = args.indexOf('--');
    const commandArgs = delimiter >= 0 ? args.slice(delimiter + 1) : args.slice(1);
    const result = runWithFence(commandArgs, {
      recordArtifacts: args.includes('--record-artifacts'),
      denyOnNewExecutable: args.includes('--deny-on-new-executable'),
    });
    const report = writeAutomaticReport(result, { command: `execfence ${args.join(' ')}` });
    console.error(`[execfence] runtime report: ${report.filePath}`);
    if (!result.ok) {
      process.exitCode = result.runtimeTrace?.exitCode || 1;
    }
    return;
  }
  if (command === 'scan') {
    const parsed = parseScanArgs(args.slice(1));
    const roots = parsed.changedOnly ? changedFiles(process.cwd()) : parsed.paths;
    const result = scan({
      roots,
      configPath: parsed.configPath,
      mode: parsed.mode,
      failOn: parsed.failOn,
      warnOn: parsed.warnOn,
      fullIocScan: parsed.fullIocScan,
    });
    writeAutomaticReport(result, { reportDir: parsed.reportDir, command: `execfence ${args.join(' ')}` });
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
      writeAutomaticReport({
        cwd: process.cwd(),
        mode: parsed.mode || 'block',
        ok: true,
        findings: [],
        blockedFindings: [],
        warningFindings: [],
        suppressedFindings: [],
        config: {},
        roots: [],
      }, { reportDir: parsed.reportDir, command: `execfence ${args.join(' ')}` });
      console.log('[execfence] OK');
      return;
    }
    const result = scan({ roots: files, mode: parsed.mode, failOn: parsed.failOn, warnOn: parsed.warnOn, fullIocScan: parsed.fullIocScan });
    writeAutomaticReport(result, { reportDir: parsed.reportDir, command: `execfence ${args.join(' ')}` });
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
    writeAutomaticReport(result, { command: `execfence ${args.join(' ')}` });
    console.log(formatResult(result, readOption(args.slice(1), '--format') || 'text'));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (command === 'coverage') {
    const parsed = parseScanArgs(args.slice(1));
    const result = analyzeCoverage(process.cwd());
    console.log(parsed.format === 'json' ? JSON.stringify(result, null, 2) : formatCoverage(result));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (command === 'wire') {
    const result = wireProject(process.cwd(), { dryRun: !args.includes('--apply') });
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (command === 'ci') {
    const result = runCi(process.cwd(), { baseRef: readOption(args.slice(1), '--base-ref'), fullIocScan: args.includes('--full-ioc-scan') });
    writeAutomaticReport(result, { command: `execfence ${args.join(' ')}` });
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (command === 'deps') {
    depsCommand(args.slice(1));
    return;
  }
  if (command === 'manifest') {
    if (args[1] === 'diff') {
      const previous = readManifest(process.cwd());
      const current = generateManifest(process.cwd());
      const result = diffManifest(current, previous);
      writeManifest(process.cwd(), current);
      console.log(JSON.stringify(result, null, 2));
      if (!result.ok) {
        process.exitCode = 1;
      }
      return;
    }
    const manifest = writeManifest(process.cwd());
    console.log(JSON.stringify(manifest, null, 2));
    return;
  }
  if (command === 'report') {
    const htmlInput = readOption(args.slice(1), '--html');
    if (htmlInput) {
      const output = htmlReport(process.cwd(), htmlInput);
      console.log(`[execfence] wrote HTML report to ${output.htmlPath}`);
      return;
    }
    const parsed = parseScanArgs(args.slice(1));
    const result = scan({ roots: parsed.paths, mode: parsed.mode, failOn: parsed.failOn, warnOn: parsed.warnOn, fullIocScan: parsed.fullIocScan });
    writeAutomaticReport(result, { reportDir: parsed.reportDir || readOption(args.slice(1), '--dir'), command: `execfence ${args.join(' ')}`, stdout: true });
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (command === 'reports') {
    reportsCommand(args.slice(1));
    return;
  }
  if (command === 'incident') {
    incidentCommand(args.slice(1));
    return;
  }
  if (command === 'enrich') {
    enrichCommand(args.slice(1));
    return;
  }
  if (command === 'pack-audit') {
    const result = packAudit(process.cwd());
    result.lockfiles = lockfileDiff(process.cwd());
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok || !result.lockfiles.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (command === 'trust') {
    trustCommand(args.slice(1));
    return;
  }
  if (command === 'baseline') {
    baselineCommand(args.slice(1));
    return;
  }
  if (command === 'agent-report') {
    const result = agentReport(process.cwd());
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (command === 'pr-comment') {
    const reportPath = readOption(args.slice(1), '--report');
    if (!reportPath) {
      throw new Error('Usage: execfence pr-comment --report <report.json>');
    }
    const { report } = readReport(process.cwd(), reportPath);
    console.log(prCommentFromReport(report));
    return;
  }
  if (command === 'doctor') {
    const result = runDoctor();
    const reportResult = {
      cwd: process.cwd(),
      mode: 'doctor',
      ok: result.ok,
      findings: result.findings || [],
      blockedFindings: result.ok ? [] : result.findings || [],
      warningFindings: [],
      suppressedFindings: [],
      config: {},
      roots: [result.fixtureDir],
    };
    writeAutomaticReport(reportResult, { command: `execfence ${args.join(' ')}` });
    console.log(JSON.stringify(result, null, 2));
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
    const result = initProject({ cwd: process.cwd(), preset: readOption(args.slice(1), '--preset') || 'auto', dryRun: args.includes('--dry-run') });
    console.log(`[execfence] detected stack: ${JSON.stringify(result.stack)}`);
    console.log(`[execfence] preset: ${result.preset}`);
    if (result.changes.length === 0) {
      console.log('[execfence] no changes needed');
      return;
    }
    for (const change of result.changes) {
      console.log(`- ${change}`);
    }
    return;
  }
  if (command === 'install-hooks') {
    const hookPath = installGitHook(process.cwd());
    console.log(`[execfence] installed pre-commit hook at ${hookPath}`);
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

function reportsCommand(args) {
  const subcommand = args[0] || 'list';
  if (subcommand === 'list') {
    console.log(JSON.stringify(listReports(process.cwd()), null, 2));
    return;
  }
  if (subcommand === 'latest') {
    console.log(JSON.stringify(latestReport(process.cwd()), null, 2));
    return;
  }
  if (subcommand === 'show') {
    const id = args[1];
    if (!id) {
      throw new Error('Usage: execfence reports show <id>');
    }
    console.log(JSON.stringify(readReport(process.cwd(), id).report, null, 2));
    return;
  }
  if (subcommand === 'open') {
    const output = htmlReport(process.cwd(), args[1]);
    console.log(`[execfence] wrote HTML report to ${output.htmlPath}`);
    return;
  }
  if (subcommand === 'diff') {
    if (!args[1] || !args[2]) {
      throw new Error('Usage: execfence reports diff <a> <b>');
    }
    console.log(JSON.stringify(diffReports(process.cwd(), args[1], args[2]), null, 2));
    return;
  }
  if (subcommand === 'compare') {
    console.log(JSON.stringify(compareReports(process.cwd(), { since: readOption(args, '--since') }), null, 2));
    return;
  }
  if (subcommand === 'prune') {
    console.log(JSON.stringify(pruneReports(process.cwd(), {
      maxReports: readOption(args, '--max-reports'),
      maxAgeDays: readOption(args, '--max-age-days'),
    }), null, 2));
    return;
  }
  throw new Error(`Unknown reports subcommand: ${subcommand}`);
}

function incidentCommand(args) {
  const subcommand = args[0] || 'create';
  const reportPath = readOption(args, '--from-report');
  if (!reportPath) {
    throw new Error('Usage: execfence incident create|bundle|timeline --from-report <report.json>');
  }
  if (subcommand === 'create' || subcommand === 'checklist') {
    const output = incidentFromReport(process.cwd(), reportPath, { profile: readOption(args, '--profile') });
    console.log(`[execfence] wrote incident checklist to ${output.incidentPath}`);
    return;
  }
  if (subcommand === 'bundle') {
    const output = incidentBundle(process.cwd(), reportPath);
    console.log(`[execfence] wrote incident bundle to ${output.bundleDir}`);
    return;
  }
  if (subcommand === 'timeline') {
    const output = incidentTimeline(process.cwd(), reportPath);
    console.log(`[execfence] wrote incident timeline to ${output.timelinePath}`);
    return;
  }
  throw new Error(`Unknown incident subcommand: ${subcommand}`);
}

function depsCommand(args) {
  const subcommand = args[0] || 'diff';
  if (subcommand === 'diff') {
    const result = depsDiff(process.cwd(), { baseRef: readOption(args, '--base-ref') || 'HEAD' });
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (subcommand === 'list') {
    console.log(JSON.stringify(collectDependencies(process.cwd()), null, 2));
    return;
  }
  throw new Error('Usage: execfence deps diff [--base-ref <ref>]');
}

function enrichCommand(args) {
  const reportPath = args[0];
  if (!reportPath) {
    throw new Error('Usage: execfence enrich <report.json>');
  }
  const { filePath, report } = readReport(process.cwd(), reportPath);
  const enrichment = enrichFindings(process.cwd(), report.findings || [], report.config || {});
  const enriched = {
    ...report,
    enrichment,
  };
  const output = filePath.replace(/\.json$/i, '.enriched.json');
  require('node:fs').writeFileSync(output, `${JSON.stringify(enriched, null, 2)}\n`);
  console.log(`[execfence] wrote enriched report to ${output}`);
}

function trustCommand(args) {
  const subcommand = args[0];
  if (subcommand === 'add') {
    const file = args[1];
    const result = trustAdd(process.cwd(), file, {
      reason: readOption(args, '--reason'),
      owner: readOption(args, '--owner'),
      expiresAt: readOption(args, '--expires-at'),
      type: readOption(args, '--type'),
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (subcommand === 'audit') {
    const result = trustAudit(process.cwd());
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  throw new Error('Usage: execfence trust add <path> --reason <reason> --owner <owner> --expires-at <date>\n       execfence trust audit');
}

function baselineCommand(args) {
  if (args[0] === 'add') {
    const result = addBaselineFromReport(process.cwd(), readOption(args, '--from-report'), {
      owner: readOption(args, '--owner'),
      reason: readOption(args, '--reason'),
      expiresAt: readOption(args, '--expires-at'),
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  throw new Error('Usage: execfence baseline add --from-report <report.json> --owner <owner> --reason <reason> --expires-at <date>');
}

function installSkill(args) {
  const codexHomeFlag = args.indexOf('--codex-home');
  const homeFlag = args.indexOf('--home');
  const codexHome = codexHomeFlag >= 0 && args[codexHomeFlag + 1]
    ? path.resolve(args[codexHomeFlag + 1])
    : path.join(os.homedir(), '.codex');
  const home = homeFlag >= 0 && args[homeFlag + 1] ? path.resolve(args[homeFlag + 1]) : os.homedir();
  const installed = installCodexSkill({ codexHome });
  const defaults = installSkillDefaults({ home });
  const rules = installAgentRules({ scope: 'global', home });
  console.log(`[execfence] installed Codex skill at ${installed.skillDir}`);
  console.log(`[execfence] installed ExecFence defaults at ${defaults.filePath}`);
  console.log(`[execfence] updated Codex AGENTS.md at ${installed.agents.filePath}`);
  for (const rule of rules) {
    console.log(`[execfence] updated agent rules at ${rule.filePath}`);
  }
}

function writeAutomaticReport(result, options = {}) {
  ensureReportsGitignore(result.cwd || process.cwd(), result.config || {});
  const report = writeReport(result, { reportDir: options.reportDir, command: options.command });
  const retention = result.config?.reports?.retention || result.config?.reportRetention;
  if (retention) {
    pruneReports(result.cwd || process.cwd(), retention);
  }
  result.report = {
    filePath: report.filePath,
    reportDir: report.reportDir,
  };
  const stream = options.stdout ? console.log : console.error;
  stream(`[execfence] wrote report to ${report.filePath}`);
  return report;
}

function installAgentRulesCommand(args) {
  if (args.includes('--verify')) {
    const scope = readOption(args, '--scope') || 'both';
    const home = readOption(args, '--home') || os.homedir();
    const project = readOption(args, '--project') || process.cwd();
    const result = verifyAgentRules({ scope, home, project });
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  const scope = readOption(args, '--scope') || 'global';
  const home = readOption(args, '--home') || os.homedir();
  const project = readOption(args, '--project') || process.cwd();
  const rules = installAgentRules({ scope, home, project });
  for (const rule of rules) {
    console.log(`[execfence] updated agent rules at ${rule.filePath}`);
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
  let reportDir;
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
    if (arg === '--fail-on' || arg === '--warn-on' || arg === '--report' || arg === '--dir') {
      if (arg === '--report' || arg === '--dir') {
        reportDir = args[index + 1];
      }
      index += 1;
      continue;
    }
    if (arg === '--staged') {
      continue;
    }
    if (arg === '--changed-only' || arg === '--full-ioc-scan') {
      continue;
    }
    paths.push(arg);
  }
  return {
    ci: args.includes('--ci'),
    configPath,
    format,
    changedOnly: args.includes('--changed-only'),
    failOn: splitList(readOption(args, '--fail-on')),
    fullIocScan: args.includes('--full-ioc-scan'),
    mode: readOption(args, '--mode'),
    paths,
    reportDir,
    warnOn: splitList(readOption(args, '--warn-on')),
  };
}

function splitList(value) {
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : undefined;
}

function formatCoverage(result) {
  if (result.ok) {
    return '[execfence] coverage OK';
  }
  return [
    '[execfence] unguarded execution entrypoint(s):',
    ...result.uncovered.map((entry) => `- ${entry.type}: ${entry.file} ${entry.name} -> ${entry.command}${entry.fixSuggestion ? `\n  fix: ${entry.fixSuggestion.command}` : ''}`),
  ].join('\n');
}

function verifyAgentRules(options = {}) {
  const home = options.home || os.homedir();
  const project = options.project || process.cwd();
  const globalTargets = [
    path.join(home, '.codex', 'AGENTS.md'),
    path.join(home, '.claude', 'CLAUDE.md'),
    path.join(home, '.gemini', 'GEMINI.md'),
  ];
  const projectTargets = [
    path.join(project, 'AGENTS.md'),
    path.join(project, 'CLAUDE.md'),
    path.join(project, 'GEMINI.md'),
    path.join(project, '.cursor', 'rules', 'execfence.mdc'),
    path.join(project, '.github', 'copilot-instructions.md'),
    path.join(project, '.continue', 'rules', 'execfence.md'),
    path.join(project, '.windsurf', 'rules', 'execfence.md'),
    path.join(project, '.aider', 'execfence.md'),
    path.join(project, '.roo', 'rules', 'execfence.md'),
    path.join(project, '.clinerules'),
  ];
  const targets = [
    ...(['global', 'both'].includes(options.scope) ? globalTargets : []),
    ...(['project', 'both'].includes(options.scope) ? projectTargets : []),
  ];
  const files = targets.map((filePath) => ({
    filePath,
    exists: require('node:fs').existsSync(filePath),
    hasRule: require('node:fs').existsSync(filePath) && /execfence|EXECFENCE:START/.test(require('node:fs').readFileSync(filePath, 'utf8')),
  }));
  return { ok: files.every((file) => file.exists && file.hasRule), files };
}

function publishPackage(options = {}) {
  run('node', ['bin/execfence.js', 'run', '--', 'npm', 'test']);
  run('node', ['bin/execfence.js', 'ci']);
  run('node', ['bin/execfence.js', 'pack-audit']);
  run('npm', ['pack', '--dry-run']);
  if (!options.real) {
    console.log('[execfence] publish dry-run complete. Re-run with --real after npm login to publish.');
    return;
  }
  run('npm', ['publish', '--access', 'public', '--provenance']);
}

function run(command, args) {
  console.log(`[execfence] ${command} ${args.join(' ')}`);
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
    return execFileSync('where', [`${command}.cmd`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
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
