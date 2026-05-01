'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { installSkill, updateGlobalAgents } = require('../lib/cli');

test('installSkill copies skill and updates AGENTS.md', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-codex-'));

  installSkill(['--codex-home', codexHome]);

  const skillPath = path.join(codexHome, 'skills', 'security-guardrails', 'SKILL.md');
  const agentsPath = path.join(codexHome, 'AGENTS.md');
  assert.equal(fs.existsSync(skillPath), true);
  const agents = fs.readFileSync(agentsPath, 'utf8');
  assert.match(agents, /SECURITY-GUARDRAILS:START/);
  assert.match(agents, /\$security-guardrails/);
});

test('updateGlobalAgents is idempotent', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-agents-'));
  fs.writeFileSync(path.join(codexHome, 'AGENTS.md'), '# Existing\n\nKeep this.\n');

  updateGlobalAgents(codexHome);
  updateGlobalAgents(codexHome);

  const agents = fs.readFileSync(path.join(codexHome, 'AGENTS.md'), 'utf8');
  assert.equal((agents.match(/SECURITY-GUARDRAILS:START/g) || []).length, 1);
  assert.match(agents, /# Existing/);
  assert.match(agents, /Keep this\./);
});

test('updateGlobalAgents does not duplicate an existing manual guardrails rule', () => {
  const codexHome = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-existing-'));
  fs.writeFileSync(path.join(codexHome, 'AGENTS.md'), '- Use `$security-guardrails` for persistent projects.\n');

  updateGlobalAgents(codexHome);

  const agents = fs.readFileSync(path.join(codexHome, 'AGENTS.md'), 'utf8');
  assert.equal((agents.match(/\$security-guardrails/g) || []).length, 1);
  assert.equal((agents.match(/SECURITY-GUARDRAILS:START/g) || []).length, 0);
});
