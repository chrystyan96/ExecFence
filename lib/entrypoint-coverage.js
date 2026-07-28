'use strict';

function coverageFor(entry, options = {}) {
  const command = String(entry.command || '');
  const directGuarded = Boolean(entry.directGuarded ?? entry.guarded ?? isDirectGuarded(command));
  const inheritedGuard = Boolean(entry.inheritedGuarded || entry.fileGuarded || entry.prehookGuarded);
  const globalGuard = Boolean(entry.globalGuarded || options.npmGuardActive);
  const covered = Boolean(entry.covered ?? (directGuarded || inheritedGuard || globalGuard));
  const coverageSource = entry.coverageSource || sourceFor({ directGuarded, inheritedGuard, globalGuard, entry });
  return {
    ...entry,
    directGuarded,
    covered,
    guarded: entry.guarded ?? covered,
    coverageSource,
    coverageReason: entry.coverageReason || reasonFor(coverageSource, entry),
    guard: entry.guard || (directGuarded ? 'execfence-run' : coverageSource || null),
  };
}

function isDirectGuarded(command) {
  return execFenceInvocationModes(command).length > 0;
}

function execFenceInvocationModes(command) {
  const modes = [];
  for (const rawSegment of shellCommandSegments(command)) {
    const segment = stripCommandPrefix(rawSegment);
    const match = segment.match(/^(?:(?:npx\s+(?:--yes\s+)?)?(?:execfence(?:\.js)?|(?:\.?[\\/])?node_modules[\\/]\.bin[\\/]execfence)|node\s+(?:\.?[\\/])?bin[\\/]execfence\.js)\s+(run|scan|ci)\b/i)
      || segment.match(/^npm\s+run\s+execfence:(scan|ci)\b/i)
      || segment.match(/^node\s+(?:\.?[\\/])?scripts[\\/]verify-source-integrity\.cjs\b/i)
      || segment.match(/^(?:npm|pnpm|yarn|bun)\s+run\s+(integrity:source)\b/i);
    if (match) modes.push((match[1] || 'integrity').toLowerCase());
  }
  return modes;
}

function invokedNpmScripts(command) {
  const scripts = [];
  for (const rawSegment of shellCommandSegments(command)) {
    const segment = stripCommandPrefix(rawSegment);
    const match = segment.match(/^(?:npm|pnpm|yarn|bun)\s+(?:run(?:-script)?\s+)?([A-Za-z0-9:_.-]+)\b/i);
    if (match && !['run', 'run-script'].includes(match[1])) scripts.push(match[1]);
  }
  return scripts;
}

function shellCommandSegments(command) {
  const text = String(command || '');
  const segments = [];
  let current = '';
  let quote = null;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === '\\' && quote !== "'") {
      current += char;
      escaped = true;
      continue;
    }
    if (quote) {
      current += char;
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      current += char;
      continue;
    }
    const pair = text.slice(index, index + 2);
    if (pair === '&&' || pair === '||') {
      if (current.trim()) segments.push(current.trim());
      current = '';
      index += 1;
      continue;
    }
    if (char === ';' || char === '\n' || char === '\r' || char === '|') {
      if (current.trim()) segments.push(current.trim());
      current = '';
      continue;
    }
    current += char;
  }
  if (current.trim()) segments.push(current.trim());
  return segments;
}

function stripCommandPrefix(segment) {
  let value = String(segment || '').trim().replace(/^[(&]\s*/, '');
  value = value.replace(/^(?:sudo\s+|command\s+|env\s+)+/i, '');
  while (/^[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S+)\s+/.test(value)) {
    value = value.replace(/^[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S+)\s+/, '');
  }
  return value.trim();
}

function sourceFor(input) {
  if (input.directGuarded) return 'direct-execfence';
  if (input.entry.prehookGuarded) return 'package-prehook';
  if (input.entry.fileGuarded) return 'workflow-level-execfence';
  if (input.entry.inheritedGuarded) return 'inherited-guard';
  if (input.globalGuard) return 'global-package-manager-guard';
  return null;
}

function reasonFor(source, entry) {
  if (source === 'direct-execfence') return 'The entrypoint command invokes ExecFence directly.';
  if (source === 'package-prehook') return 'A package prehook runs ExecFence before this script.';
  if (source === 'workflow-level-execfence') return 'The workflow contains an ExecFence gate that covers package-manager execution in the same workflow.';
  if (source === 'inherited-guard') return 'A parent or wrapper entrypoint applies ExecFence before this command can run.';
  if (source === 'global-package-manager-guard') return 'The current PATH resolves package-manager commands through ExecFence shims.';
  return 'No ExecFence coverage was detected for this entrypoint.';
}

function summarizeCoverage(entrypoints = []) {
  return {
    total: entrypoints.length,
    sensitive: entrypoints.filter((entry) => entry.sensitive).length,
    directGuarded: entrypoints.filter((entry) => entry.directGuarded).length,
    covered: entrypoints.filter((entry) => entry.covered).length,
    uncovered: entrypoints.filter((entry) => !entry.covered).length,
    guarded: entrypoints.filter((entry) => entry.directGuarded).length,
  };
}

module.exports = {
  coverageFor,
  execFenceInvocationModes,
  invokedNpmScripts,
  isDirectGuarded,
  shellCommandSegments,
  summarizeCoverage,
};
