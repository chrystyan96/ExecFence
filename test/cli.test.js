'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { execFileSync } = require('node:child_process');
const { installSkill, main, updateGlobalAgents } = require('../lib/cli');
const { explainFinding } = require('../lib/explain');
const {
  installAgentRules,
  installGlobalAgentRules,
  installProjectAgentRules,
} = require('../lib/agent-rules');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

test('installSkill copies Codex skill and updates global agent files', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-codex-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-home-'));

  installSkill(['--codex-home', codexHome, '--home', home]);

  const skillPath = path.join(codexHome, 'skills', 'execfence', 'SKILL.md');
  assert.equal(fs.existsSync(skillPath), true);
  assert.equal(fs.existsSync(path.join(codexHome, 'skills', 'execfence', 'defaults.json')), true);
  assert.equal(fs.existsSync(path.join(home, '.agents', 'skills', 'execfence', 'defaults.json')), true);
  const agents = fs.readFileSync(path.join(codexHome, 'AGENTS.md'), 'utf8');
  assert.match(agents, /EXECFENCE:START/);
  assert.equal(fs.existsSync(path.join(home, '.claude', 'CLAUDE.md')), true);
  assert.equal(fs.existsSync(path.join(home, '.gemini', 'GEMINI.md')), true);
});

test('installGlobalAgentRules is idempotent', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-agents-'));
  const codexAgents = path.join(home, '.codex', 'AGENTS.md');
  fs.mkdirSync(path.dirname(codexAgents), { recursive: true });
  fs.writeFileSync(codexAgents, '# Existing\n\nKeep this.\n');

  installGlobalAgentRules({ home });
  installGlobalAgentRules({ home });

  const agents = fs.readFileSync(codexAgents, 'utf8');
  assert.equal((agents.match(/EXECFENCE:START/g) || []).length, 1);
  assert.match(agents, /# Existing/);
  assert.match(agents, /Keep this\./);
});

test('installGlobalAgentRules does not duplicate an existing manual guardrails rule', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-existing-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-home-existing-'));
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
  fs.writeFileSync(path.join(home, '.codex', 'AGENTS.md'), '- Use `execfence` for persistent projects.\n');

  installGlobalAgentRules({ home });

  const agents = fs.readFileSync(path.join(home, '.codex', 'AGENTS.md'), 'utf8');
  assert.equal((agents.match(/execfence/g) || []).length, 1);
  assert.equal((agents.match(/EXECFENCE:START/g) || []).length, 0);
  assert.equal(fs.existsSync(path.join(codexHome, 'AGENTS.md')), false);
});

test('installProjectAgentRules writes common agent instruction files', () => {
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-project-'));

  installProjectAgentRules({ project });

  assert.equal(fs.existsSync(path.join(project, 'AGENTS.md')), true);
  assert.equal(fs.existsSync(path.join(project, 'CLAUDE.md')), true);
  assert.equal(fs.existsSync(path.join(project, 'GEMINI.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.cursor', 'rules', 'execfence.mdc')), true);
  assert.equal(fs.existsSync(path.join(project, '.github', 'copilot-instructions.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.continue', 'rules', 'execfence.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.windsurf', 'rules', 'execfence.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.aider', 'execfence.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.roo', 'rules', 'execfence.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.clinerules')), true);
});

test('installAgentRules supports both global and project scopes', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-both-home-'));
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-both-project-'));

  const results = installAgentRules({ scope: 'both', home, project });

  assert.ok(results.length >= 7);
  assert.equal(fs.existsSync(path.join(home, '.claude', 'CLAUDE.md')), true);
  assert.equal(fs.existsSync(path.join(project, 'CLAUDE.md')), true);
});

test('explainFinding describes known finding ids', () => {
  const output = explainFinding('suspicious-package-script');

  assert.match(output, /Severity: high/);
  assert.match(output, /Lifecycle scripts/);
});

test('install-agent-rules verify reports missing project rules', async () => {
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-verify-'));
  const originalCwd = process.cwd();
  const originalExitCode = process.exitCode;
  const originalLog = console.log;
  process.chdir(project);
  process.exitCode = 0;
  console.log = () => {};
  try {
    await main(['install-agent-rules', '--verify', '--scope', 'project']);
    assert.equal(process.exitCode, 1);
  } finally {
    console.log = originalLog;
    process.chdir(originalCwd);
    process.exitCode = originalExitCode;
  }
});

test('scan command always writes a timestamped report and gitignore entry', async () => {
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-cli-scan-'));
  fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'cli-scan-app' }, null, 2));
  fs.writeFileSync(path.join(project, 'tailwind.config.js'), "global.i='2-30-4';\n");
  const originalCwd = process.cwd();
  const originalExitCode = process.exitCode;
  const originalLog = console.log;
  const originalError = console.error;
  process.chdir(project);
  process.exitCode = 0;
  console.log = () => {};
  console.error = () => {};
  try {
    await main(['scan', '--mode', 'audit', 'tailwind.config.js']);
    const reports = fs.readdirSync(path.join(project, '.execfence', 'reports'));
    assert.equal(reports.length, 1);
    assert.match(reports[0], /^cli-scan-app_\d{4}-\d{2}-\d{2}T.*\.json$/);
    assert.match(fs.readFileSync(path.join(project, '.gitignore'), 'utf8'), /\.execfence\/reports\//);
  } finally {
    console.log = originalLog;
    console.error = originalError;
    process.chdir(originalCwd);
    process.exitCode = originalExitCode;
  }
});

test('diff-scan, scan-history, and doctor commands write reports', async () => {
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-cli-reports-'));
  git(project, ['init']);
  git(project, ['config', 'user.email', 'test@example.com']);
  git(project, ['config', 'user.name', 'Test']);
  fs.writeFileSync(path.join(project, 'tailwind.config.js'), "global.i='2-30-4';\n");
  git(project, ['add', '.']);
  git(project, ['commit', '-m', 'bad']);
  const originalCwd = process.cwd();
  const originalExitCode = process.exitCode;
  const originalLog = console.log;
  const originalError = console.error;
  process.chdir(project);
  process.exitCode = 0;
  console.log = () => {};
  console.error = () => {};
  try {
    await main(['diff-scan']);
    await main(['scan-history', '--max-commits', '5']);
    await main(['doctor']);
    const reports = fs.readdirSync(path.join(project, '.execfence', 'reports')).filter((name) => name.endsWith('.json'));
    assert.equal(reports.length, 3);
  } finally {
    console.log = originalLog;
    console.error = originalError;
    process.chdir(originalCwd);
    process.exitCode = originalExitCode;
  }
});
