'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { installSkill, updateGlobalAgents } = require('../lib/cli');
const { explainFinding } = require('../lib/explain');
const {
  installAgentRules,
  installGlobalAgentRules,
  installProjectAgentRules,
} = require('../lib/agent-rules');

test('installSkill copies Codex skill and updates global agent files', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-codex-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-home-'));

  installSkill(['--codex-home', codexHome, '--home', home]);

  const skillPath = path.join(codexHome, 'skills', 'security-guardrails', 'SKILL.md');
  assert.equal(fs.existsSync(skillPath), true);
  const agents = fs.readFileSync(path.join(codexHome, 'AGENTS.md'), 'utf8');
  assert.match(agents, /SECURITY-GUARDRAILS:START/);
  assert.equal(fs.existsSync(path.join(home, '.claude', 'CLAUDE.md')), true);
  assert.equal(fs.existsSync(path.join(home, '.gemini', 'GEMINI.md')), true);
});

test('installGlobalAgentRules is idempotent', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-agents-'));
  const codexAgents = path.join(home, '.codex', 'AGENTS.md');
  fs.mkdirSync(path.dirname(codexAgents), { recursive: true });
  fs.writeFileSync(codexAgents, '# Existing\n\nKeep this.\n');

  installGlobalAgentRules({ home });
  installGlobalAgentRules({ home });

  const agents = fs.readFileSync(codexAgents, 'utf8');
  assert.equal((agents.match(/SECURITY-GUARDRAILS:START/g) || []).length, 1);
  assert.match(agents, /# Existing/);
  assert.match(agents, /Keep this\./);
});

test('installGlobalAgentRules does not duplicate an existing manual guardrails rule', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-existing-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-home-existing-'));
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
  fs.writeFileSync(path.join(home, '.codex', 'AGENTS.md'), '- Use `security-guardrails` for persistent projects.\n');

  installGlobalAgentRules({ home });

  const agents = fs.readFileSync(path.join(home, '.codex', 'AGENTS.md'), 'utf8');
  assert.equal((agents.match(/security-guardrails/g) || []).length, 1);
  assert.equal((agents.match(/SECURITY-GUARDRAILS:START/g) || []).length, 0);
  assert.equal(fs.existsSync(path.join(codexHome, 'AGENTS.md')), false);
});

test('installProjectAgentRules writes common agent instruction files', () => {
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-project-'));

  installProjectAgentRules({ project });

  assert.equal(fs.existsSync(path.join(project, 'AGENTS.md')), true);
  assert.equal(fs.existsSync(path.join(project, 'CLAUDE.md')), true);
  assert.equal(fs.existsSync(path.join(project, 'GEMINI.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.cursor', 'rules', 'security-guardrails.mdc')), true);
  assert.equal(fs.existsSync(path.join(project, '.github', 'copilot-instructions.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.continue', 'rules', 'security-guardrails.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.windsurf', 'rules', 'security-guardrails.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.aider', 'security-guardrails.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.roo', 'rules', 'security-guardrails.md')), true);
  assert.equal(fs.existsSync(path.join(project, '.clinerules')), true);
});

test('installAgentRules supports both global and project scopes', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-both-home-'));
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-both-project-'));

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
