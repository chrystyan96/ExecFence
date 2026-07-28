'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { toSarif } = require('./output');
const { resolveProjectPath } = require('./paths');

function resolveCiBaseRef(cwd = process.cwd(), requested) {
  const candidates = Array.from(new Set([
    requested,
    process.env.GITHUB_BASE_REF && `origin/${process.env.GITHUB_BASE_REF}`,
    process.env.GITHUB_BASE_REF,
    process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME && `origin/${process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME}`,
    process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME,
    process.env.SYSTEM_PULLREQUEST_TARGETBRANCH,
    'HEAD',
  ].filter(Boolean)));
  for (const candidate of candidates) {
    if (gitObjectExists(cwd, candidate)) {
      const explicitFallback = Boolean(requested && candidate !== requested);
      return {
        ok: !explicitFallback,
        requested: requested || null,
        ref: candidate,
        source: candidate === requested ? 'explicit' : candidate === 'HEAD' ? 'fallback' : 'ci-environment',
        degraded: explicitFallback,
        shallow: isShallowRepository(cwd),
        candidates,
        remediation: explicitFallback
          ? `Requested base ref ${requested} is unavailable. Fetch it before running ExecFence (for GitHub Actions use actions/checkout with fetch-depth: 0).`
          : null,
      };
    }
  }
  return {
    ok: false,
    requested: requested || null,
    ref: 'HEAD',
    source: 'unavailable',
    shallow: isShallowRepository(cwd),
    candidates,
    remediation: 'Fetch the pull-request base commit before running ExecFence (for GitHub Actions use actions/checkout with fetch-depth: 0).',
  };
}

function writeCiArtifacts(cwd, result, options = {}) {
  const written = [];
  if (options.sarif) {
    const sarifPath = resolveProjectPath(cwd, options.sarif);
    fs.mkdirSync(path.dirname(sarifPath), { recursive: true });
    fs.writeFileSync(sarifPath, `${JSON.stringify(toSarif(result), null, 2)}\n`);
    written.push({ format: 'sarif', filePath: sarifPath });
  }
  if (options.summary) {
    const summaryPath = resolveProjectPath(cwd, options.summary);
    fs.mkdirSync(path.dirname(summaryPath), { recursive: true });
    fs.writeFileSync(summaryPath, `${githubStepSummary(result)}\n`);
    written.push({ format: 'markdown', filePath: summaryPath });
  }
  return written;
}

function githubAnnotations(result) {
  return (result.findings || []).map((finding) => {
    const level = finding.decision === 'block' ? 'error' : finding.decision === 'review' ? 'warning' : 'notice';
    const properties = [
      finding.file ? `file=${escapeAnnotationProperty(finding.file)}` : null,
      `line=${Math.max(1, Number(finding.line || 1))}`,
      `title=${escapeAnnotationProperty(`ExecFence ${finding.id}`)}`,
    ].filter(Boolean).join(',');
    return `::${level} ${properties}::${escapeAnnotationMessage(finding.detail || finding.id)}`;
  });
}

function githubStepSummary(result) {
  const summary = result.ci || {};
  const rows = [
    ['Scan', summary.scan?.ok],
    ['Manifest diff', summary.manifestDiff?.ok],
    ['Dependency diff', summary.deps?.ok],
    ['Dependency review', summary.depsReview?.ok],
    ['Coverage', summary.coverage?.ok],
    ['Configuration', summary.configValidation?.ok],
    ['Package audit', summary.packAudit?.ok],
    ['Trust audit', summary.trustAudit?.ok],
    ['Approval audit', summary.approvalAudit?.ok],
    ['Policy diff', summary.policyDiff?.ok],
  ];
  return [
    '# ExecFence CI',
    '',
    `Overall result: **${result.ok ? 'passed' : 'blocked'}**`,
    '',
    '| Check | Result |',
    '| --- | --- |',
    ...rows.map(([name, ok]) => `| ${name} | ${ok === true ? 'pass' : ok === false ? 'blocked' : 'not run'} |`),
    '',
    `Findings: ${(result.findings || []).length}; blocking: ${(result.blockedFindings || []).length}; review: ${(result.warningFindings || []).length}.`,
  ].join('\n');
}

function gitObjectExists(cwd, ref) {
  try {
    execFileSync('git', ['rev-parse', '--verify', `${ref}^{commit}`], {
      cwd,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return true;
  } catch {
    return false;
  }
}

function isShallowRepository(cwd) {
  try {
    return execFileSync('git', ['rev-parse', '--is-shallow-repository'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim() === 'true';
  } catch {
    return false;
  }
}

function escapeAnnotationProperty(value) {
  return String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A').replace(/:/g, '%3A').replace(/,/g, '%2C');
}

function escapeAnnotationMessage(value) {
  return String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

module.exports = {
  githubAnnotations,
  githubStepSummary,
  resolveCiBaseRef,
  writeCiArtifacts,
};
