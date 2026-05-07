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
  return /(?:^|\s)(?:npx\s+--yes\s+)?execfence(?:\.js)?\s+(?:run|scan|ci)\b|(?:^|\s)node\s+bin[\\/]+execfence\.js\s+(?:run|scan|ci)\b|execfence:(?:scan|ci)\b|npm\s+run\s+execfence:(?:scan|ci)\b/.test(String(command));
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
  isDirectGuarded,
  summarizeCoverage,
};
