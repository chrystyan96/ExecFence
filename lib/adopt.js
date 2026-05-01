'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { scan } = require('./scanner');
const { analyzeCoverage } = require('./coverage');
const { depsDiff } = require('./deps');
const { packAudit } = require('./supply-chain');
const { wireProject } = require('./wire');
const { baselineFileName } = require('./paths');
const { sha256File } = require('./baseline');

function adoptProject(cwd = process.cwd(), options = {}) {
  const root = path.resolve(cwd);
  const scanResult = scan({ cwd: root, mode: 'audit', fullIocScan: options.fullIocScan });
  const coverage = analyzeCoverage(root);
  const deps = depsDiff(root, { baseRef: options.baseRef || 'HEAD' });
  const pack = packAudit(root);
  const wiring = wireProject(root, { dryRun: true });
  const suggestedBaseline = suggestedBaselineFor(root, scanResult.findings || []);
  const remediationPlan = remediationPlanFor({ findings: scanResult.findings || [], coverage, deps, pack, wiring });
  const output = {
    cwd: root,
    ok: true,
    mode: 'adopt',
    config: scanResult.config,
    configPath: scanResult.configPath,
    baselinePath: scanResult.baselinePath,
    roots: scanResult.roots,
    findings: scanResult.findings || [],
    blockedFindings: [],
    warningFindings: scanResult.findings || [],
    suppressedFindings: scanResult.suppressedFindings || [],
    coverage,
    deps,
    packAudit: pack,
    wiring,
    suggestedBaseline,
    remediationPlan,
    changeRisk: {
      level: (scanResult.findings || []).some((finding) => ['critical', 'high'].includes(finding.severity || 'high')) ? 'medium' : 'low',
      reasons: remediationPlan.slice(0, 10).map((item) => item.action),
    },
  };
  if (options.writeSuggestedBaseline) {
    const filePath = path.join(root, baselineFileName.replace(/baseline\.json$/, 'baseline.suggested.json'));
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify({ findings: suggestedBaseline }, null, 2)}\n`);
    output.suggestedBaselinePath = filePath;
  }
  return output;
}

function suggestedBaselineFor(cwd, findings) {
  return findings.map((finding) => {
    const filePath = path.join(cwd, finding.file || '');
    return {
      findingId: finding.id,
      file: finding.file,
      sha256: fs.existsSync(filePath) && fs.statSync(filePath).isFile() ? sha256File(filePath) : null,
      reason: 'Suggested by execfence adopt; review before copying into baseline.json.',
      owner: 'TODO',
      expiresAt: 'TODO',
    };
  });
}

function remediationPlanFor(input) {
  const plan = [];
  for (const finding of input.findings) {
    plan.push({
      priority: ['critical', 'high'].includes(finding.severity || 'high') ? 'high' : 'medium',
      file: finding.file,
      findingId: finding.id,
      action: finding.remediation || `Review ${finding.id} in ${finding.file}:${finding.line || 1}.`,
      whyItMatters: whyItMatters(finding.id),
    });
  }
  for (const entry of input.coverage.uncovered || []) {
    plan.push({
      priority: 'medium',
      file: entry.file,
      action: `Protect ${entry.type} ${entry.name} with ${entry.fixSuggestion?.command || 'execfence run -- <command>'}.`,
      whyItMatters: 'Unprotected execution entrypoints can run injected code before ExecFence has a chance to block.',
    });
  }
  for (const finding of input.deps.findings || []) {
    plan.push({
      priority: finding.severity || 'medium',
      file: finding.file,
      findingId: finding.id,
      action: finding.detail,
      whyItMatters: 'Dependency source changes and lifecycle/bin entries can execute code during install, build, or test.',
    });
  }
  for (const finding of input.pack.findings || []) {
    plan.push({
      priority: finding.severity || 'medium',
      file: finding.file,
      findingId: finding.id,
      action: finding.detail,
      whyItMatters: 'Package contents are what downstream users receive; suspicious packed files increase supply-chain blast radius.',
    });
  }
  for (const change of input.wiring.changes || []) {
    plan.push({
      priority: 'low',
      file: change.file,
      action: `Apply wiring suggestion for ${change.name}: ${change.after}.`,
      whyItMatters: 'Using execfence run consistently lowers the chance that local or CI commands bypass the preflight gate.',
    });
  }
  return plan;
}

function whyItMatters(id) {
  if (/workflow/.test(id)) {
    return 'CI workflows often run with repository tokens and publish privileges.';
  }
  if (/lockfile|dependency|package/.test(id)) {
    return 'Dependency and package changes can execute before application code starts.';
  }
  if (/executable|archive|artifact/.test(id)) {
    return 'Committed executable artifacts can bypass code review and run during build/dev/test.';
  }
  return 'Suspicious code in execution surfaces can run during normal development commands.';
}

module.exports = {
  adoptProject,
  remediationPlanFor,
  suggestedBaselineFor,
};
