'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { sha256File } = require('./baseline');
const { reportsDir: defaultReportsDir } = require('./paths');
const { ruleMetadata } = require('./scanner');
const { enrichFindings } = require('./enrichment');
const { generateManifest } = require('./manifest');

const packageJson = require('../package.json');

function writeReport(result, options = {}) {
  const cwd = result.cwd || process.cwd();
  const reportDir = path.resolve(cwd, options.reportDir || result.config?.reportsDir || defaultReportsDir);
  fs.mkdirSync(reportDir, { recursive: true });
  const generatedAt = new Date().toISOString();
  const filePath = uniqueReportPath(reportDir, `${projectName(cwd)}_${safeTimestamp(generatedAt)}`);
  const enrichedFindings = (result.findings || []).map((finding) => enrichFinding(cwd, finding));
  const enrichment = result.enrichment || enrichFindings(cwd, enrichedFindings, result.config || {});
  const reportId = path.basename(filePath, '.json');
  const evidence = {
    metadata: {
      schemaVersion: 2,
      reportId,
      generatedAt,
      tool: 'ExecFence',
      packageName: packageJson.name,
      packageVersion: packageJson.version,
      cwd,
      projectName: projectName(cwd),
      gitBranch: git(cwd, ['branch', '--show-current']),
      gitCommit: git(cwd, ['rev-parse', 'HEAD']),
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      hostname: options.includeHostname === false ? undefined : os.hostname(),
    },
    command: result.command || {
      display: options.command || 'execfence scan',
      argv: options.command ? options.command.split(/\s+/) : ['execfence', 'scan'],
    },
    runtimeTrace: result.runtimeTrace || null,
    config: {
      configPath: result.configPath || null,
      baselinePath: result.baselinePath || null,
      policyPack: result.config?.policyPack || null,
      mode: result.mode || null,
      blockSeverities: result.config?.blockSeverities || [],
      warnSeverities: result.config?.warnSeverities || [],
      roots: result.roots || [],
      reportsDir: path.relative(cwd, reportDir).replaceAll(path.sep, '/') || '.',
      analysis: result.config?.analysis || {},
    },
    summary: {
      ok: Boolean(result.ok),
      totalFindings: (result.findings || []).length,
      blockedFindings: (result.blockedFindings || []).length,
      warningFindings: (result.warningFindings || []).length,
      suppressedFindings: (result.suppressedFindings || []).length,
    },
    manifest: result.manifest || safeManifest(cwd),
    changeRisk: result.changeRisk || changeRiskFor(result),
    findings: enrichedFindings,
    enrichment,
    recommendedActions: recommendedActions(enrichedFindings, result),
    suppressedFindings: result.suppressedFindings || [],
  };
  fs.writeFileSync(filePath, `${JSON.stringify(stripUndefined(evidence), null, 2)}\n`);
  writeQuarantineMetadata(cwd, reportId, evidence);
  return { reportDir, filePath, files: [filePath], evidence };
}

function enrichFinding(cwd, finding) {
  const filePath = path.join(cwd, finding.file);
  const metadata = ruleMetadata[finding.id] || {};
  const findingSnippet = fs.existsSync(filePath) ? snippet(filePath, finding.line || 1) : '';
  return {
    ...finding,
    column: finding.column || null,
    symbol: fs.existsSync(filePath) ? inferSymbol(filePath, finding.line || 1) : null,
    sha256: fs.existsSync(filePath) ? sha256File(filePath) : null,
    snippet: findingSnippet,
    rule: {
      id: finding.id,
      severity: finding.severity || metadata.severity || 'high',
      description: metadata.description || finding.detail,
    },
    reason: finding.detail,
    remediation: remediationFor(finding.id),
    confidence: confidenceFor(finding.id),
    git: {
      blame: git(cwd, ['blame', '-L', `${finding.line || 1},${finding.line || 1}`, '--', finding.file]),
      recentCommits: git(cwd, ['log', '--oneline', '-5', '--', finding.file]),
      status: git(cwd, ['status', '--short', '--', finding.file]),
    },
    analysis: {
      local: localAnalysis(finding, metadata),
      whyItMatters: whyItMatters(finding.id),
      exactNextAction: remediationFor(finding.id),
    },
    research: {
      queries: researchQueries(finding, metadata),
      webEnrichment: [],
    },
  };
}

function snippet(filePath, line) {
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  const start = Math.max(0, line - 3);
  const end = Math.min(lines.length, line + 2);
  return lines.slice(start, end).map((value, index) => `${start + index + 1}: ${value.slice(0, 240)}`).join('\n');
}

function git(cwd, args) {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return '';
  }
}

function inferSymbol(filePath, line) {
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  for (let index = Math.min(line - 1, lines.length - 1); index >= 0 && index >= line - 40; index -= 1) {
    const value = lines[index];
    const match = value.match(/\b(?:class|function|def|func|struct|interface)\s+([A-Za-z0-9_$]+)/) ||
      value.match(/\b([A-Za-z0-9_$]+)\s*[:=]\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>)/);
    if (match) {
      return { name: match[1], line: index + 1 };
    }
  }
  return null;
}

function projectName(cwd) {
  const packagePath = path.join(cwd, 'package.json');
  if (fs.existsSync(packagePath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
      if (parsed.name) {
        return sanitizeName(parsed.name);
      }
    } catch {
      // Fall back to the directory name.
    }
  }
  return sanitizeName(path.basename(cwd));
}

function sanitizeName(value) {
  return String(value).replace(/^@/, '').replace(/[\\/:*?"<>|@\s]+/g, '-').replace(/^-+|-+$/g, '') || 'project';
}

function safeTimestamp(value) {
  return value.replace(/[:.]/g, '-');
}

function uniqueReportPath(reportDir, baseName) {
  let candidate = path.join(reportDir, `${baseName}.json`);
  let index = 2;
  while (fs.existsSync(candidate)) {
    candidate = path.join(reportDir, `${baseName}_${index}.json`);
    index += 1;
  }
  return candidate;
}

function localAnalysis(finding, metadata = {}) {
  const description = metadata.description || finding.detail || 'ExecFence found a suspicious pattern.';
  return `${description} The finding is in ${finding.file}:${finding.line || 1}. Review this path before running build, dev, test, or CI commands because it may execute during normal project workflows.`;
}

function researchQueries(finding, metadata = {}) {
  return Array.from(new Set([
    `ExecFence ${finding.id}`,
    `${finding.id} ${finding.file}`,
    metadata.description ? `${finding.id} ${metadata.description}` : finding.detail,
  ].filter(Boolean))).slice(0, 3);
}

function whyItMatters(id) {
  if (/workflow/.test(id)) {
    return 'This can run in CI with repository credentials, package publishing access, or write permissions.';
  }
  if (/lockfile|dependency|package/.test(id)) {
    return 'This can alter code that runs during install, build, test, pack, or publish.';
  }
  if (/executable|archive|artifact|runtime/.test(id)) {
    return 'Binary/archive artifacts can hide payloads that are harder to review than source code.';
  }
  if (/vscode|task|entrypoint|manifest/.test(id)) {
    return 'Execution entrypoints are where injected code becomes active during normal development.';
  }
  return 'The finding is in code or config that may execute as part of development or CI workflows.';
}

function remediationFor(id) {
  const advice = {
    'allowed-executable-hash-mismatch': 'Review the executable provenance. Update the allowlist hash only after confirming the binary is expected.',
    'archive-artifact-in-source-tree': 'Move generated archives out of source/build-input folders or document why the archive must be committed.',
    'executable-artifact-in-source-tree': 'Move executables out of source/build-input folders or allowlist a reviewed artifact with SHA-256.',
    'insecure-lockfile-url': 'Regenerate the lockfile using HTTPS registry URLs.',
    'lockfile-suspicious-host': 'Verify why the dependency resolves from a paste/raw host and replace it with a trusted registry source.',
    'long-obfuscated-javascript-line': 'Treat as likely injected loader code until manual deobfuscation proves otherwise.',
    'suspicious-lockfile-url': 'Verify the lockfile source and regenerate from trusted package metadata.',
    'suspicious-package-script': 'Remove install-time download/eval behavior or move it behind a reviewed build step.',
    'workflow-curl-pipe-shell': 'Replace curl/wget pipe-to-shell with a pinned, verified action or checksum-verified script.',
    'workflow-publish-without-provenance': 'Use npm Trusted Publishing or npm publish --provenance.',
    'workflow-pull-request-target': 'Avoid pull_request_target for untrusted PR code unless permissions and checkout behavior are tightly constrained.',
    'workflow-unpinned-action': 'Pin GitHub Actions to full commit SHAs.',
    'workflow-write-all-permissions': 'Use least-privilege workflow permissions instead of write-all.',
  };
  return advice[id] || 'Review the artifact provenance, remove the suspicious pattern, or add a narrow reviewed exception.';
}

function confidenceFor(id) {
  if (id.includes('void-dokkaebi') || id === 'long-obfuscated-javascript-line') {
    return 'high';
  }
  if (id.includes('workflow') || id.includes('lockfile')) {
    return 'medium';
  }
  return 'medium';
}

function stripUndefined(value) {
  return JSON.parse(JSON.stringify(value));
}

function changeRiskFor(result) {
  const blocked = result.blockedFindings || [];
  if (blocked.some((finding) => finding.severity === 'critical')) {
    return { level: 'critical', reasons: ['critical finding present'] };
  }
  if (blocked.length > 0) {
    return { level: 'high', reasons: ['blocked finding present'] };
  }
  if ((result.warningFindings || []).length > 0) {
    return { level: 'medium', reasons: ['warning finding present'] };
  }
  return { level: 'low', reasons: [] };
}

function recommendedActions(findings, result) {
  const actions = [];
  if ((result.blockedFindings || []).length > 0 || findings.some((finding) => ['critical', 'high'].includes(finding.severity || 'high'))) {
    actions.push('Do not run build, dev, test, or CI commands until the blocked findings are reviewed.');
    actions.push('Preserve the report and suspicious files before cleanup.');
  }
  if (findings.some((finding) => /workflow/.test(finding.id))) {
    actions.push('Audit GitHub Actions permissions, triggers, and pinned actions.');
  }
  if (findings.some((finding) => /lockfile|package/.test(finding.id))) {
    actions.push('Regenerate lockfiles from trusted registries and review lifecycle scripts.');
  }
  if (actions.length === 0) {
    actions.push('No immediate action required.');
  }
  return actions;
}

function writeQuarantineMetadata(cwd, reportId, evidence) {
  if (!evidence.findings?.length) {
    return;
  }
  const quarantinePath = path.join(cwd, '.execfence', 'quarantine', reportId, 'metadata.json');
  fs.mkdirSync(path.dirname(quarantinePath), { recursive: true });
  fs.writeFileSync(quarantinePath, `${JSON.stringify({
    reportId,
    createdAt: evidence.metadata.generatedAt,
    findings: evidence.findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      file: finding.file,
      line: finding.line,
      sha256: finding.sha256,
      snippet: finding.snippet,
    })),
  }, null, 2)}\n`);
}

function safeManifest(cwd) {
  try {
    return generateManifest(cwd);
  } catch {
    return null;
  }
}

module.exports = {
  projectName,
  enrichFinding,
  writeReport,
};
