'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const canonicalBootstrapSha256 = '898394cefcaf35070df3aeb798e3e85a108d45571401637688da00961893c766';
const compromisedBlobs = new Set([
  '36c1da196eba1b8beede56b0fad6c3b6761d0859',
  '958e3bb065073aa3809d2fa22c10357de5feb27e',
  '931a69575c030e29bf9432dcbef99a3d06773493',
  '5bac424e0df156a86d3f9355e51b7f3faa1374d3',
  'bb853231dad9dd893203ab9c0d8d44d8e0f57ff0',
]);
const entrypoints = ['bin/execfence.js', 'lib/cli.js'];

function git(cwd, args, options = {}) {
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: options.encoding || 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    if (options.allowFailure) return null;
    const detail = String(error.stderr || error.message || '').trim();
    throw new Error(`git ${args.join(' ')} failed${detail ? `: ${detail}` : ''}`);
  }
}

function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function normalize(content) {
  return String(content).replace(/\r\n/g, '\n');
}

function inspectEntrypoint(file, content, context, blob = null) {
  const findings = [];
  const normalized = normalize(content);
  const lines = normalized.split('\n');
  const longestLine = Math.max(0, ...lines.map((line) => line.length));

  if (blob && compromisedBlobs.has(blob)) {
    findings.push(`${context}: ${file} uses known compromised blob ${blob}.`);
  }
  if (longestLine > 1_000) {
    findings.push(`${context}: ${file} contains an unauditable ${longestLine}-character line.`);
  }

  if (file === 'bin/execfence.js') {
    if (Buffer.byteLength(normalized) > 1_000) {
      findings.push(`${context}: the executable bootstrap exceeds 1,000 bytes.`);
    }
    if (sha256(normalized) !== canonicalBootstrapSha256) {
      findings.push(`${context}: the executable bootstrap differs from the reviewed canonical wrapper.`);
    }
  }

  if (file === 'lib/cli.js') {
    const exportsOffset = normalized.lastIndexOf('module.exports');
    if (exportsOffset < 0 || normalized.length - exportsOffset > 1_000 || !normalized.trimEnd().endsWith('};')) {
      findings.push(`${context}: CLI source continues beyond its reviewed exports boundary.`);
    }
    const riskyFragments = [
      ['windows', 'Hide'].join(''),
      ['detach', 'ed'].join(''),
      ['runIn', 'ThisContext'].join(''),
      ['global', '.i='].join(''),
    ];
    for (const fragment of riskyFragments) {
      if (normalized.includes(fragment)) {
        findings.push(`${context}: CLI source contains prohibited bootstrap fragment ${JSON.stringify(fragment)}.`);
      }
    }
  }

  return findings;
}

function inspectWorktree(cwd) {
  const findings = [];
  for (const file of entrypoints) {
    const fullPath = path.join(cwd, file);
    if (!fs.existsSync(fullPath)) {
      findings.push(`worktree: missing required entrypoint ${file}.`);
      continue;
    }
    findings.push(...inspectEntrypoint(file, fs.readFileSync(fullPath, 'utf8'), 'worktree'));
  }
  return findings;
}

function inspectHistory(cwd) {
  const findings = [];
  if (git(cwd, ['rev-parse', '--is-shallow-repository']).trim() === 'true') {
    return ['history: repository is shallow; fetch the complete history before integrity verification.'];
  }

  const commits = git(cwd, ['rev-list', 'HEAD']).trim().split(/\r?\n/).filter(Boolean);
  const inspectedBlobs = new Set();
  for (const commit of commits) {
    for (const file of entrypoints) {
      const blob = git(cwd, ['rev-parse', '--verify', `${commit}:${file}`], { allowFailure: true })?.trim();
      if (!blob || inspectedBlobs.has(`${file}:${blob}`)) continue;
      inspectedBlobs.add(`${file}:${blob}`);
      const content = git(cwd, ['cat-file', 'blob', blob]);
      findings.push(...inspectEntrypoint(file, content, `history ${commit}`, blob));
    }
  }
  return findings;
}

function verifySourceIntegrity(cwd = root, options = {}) {
  const includeHistory = options.history !== false;
  const findings = [
    ...inspectWorktree(cwd),
    ...(includeHistory ? inspectHistory(cwd) : []),
  ];
  return {
    ok: findings.length === 0,
    cwd: path.resolve(cwd),
    historyChecked: includeHistory,
    findings,
  };
}

if (require.main === module) {
  const result = verifySourceIntegrity(root, {
    history: !process.argv.includes('--worktree-only'),
  });
  if (!result.ok) {
    console.error('[source-integrity] FAILED');
    for (const finding of result.findings) console.error(`- ${finding}`);
    process.exitCode = 1;
  } else {
    console.log(`[source-integrity] OK (${result.historyChecked ? 'worktree + history' : 'worktree'})`);
  }
}

module.exports = {
  canonicalBootstrapSha256,
  compromisedBlobs,
  inspectEntrypoint,
  verifySourceIntegrity,
};
