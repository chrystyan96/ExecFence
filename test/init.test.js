'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { detectStack, initProject } = require('../lib/init');

test('detectStack identifies node and github actions', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-detect-'));
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), '{"scripts":{}}\n');

  const stack = detectStack(root);

  assert.equal(stack.node, true);
  assert.equal(stack.githubActions, true);
});

test('initProject adds npm guard script and prepends existing hooks', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-init-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ scripts: { prebuild: 'npm test' } }, null, 2));

  const result = initProject({ cwd: root });
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

  assert.ok(result.changes.length >= 2);
  assert.equal(pkg.scripts['security:guardrails'], 'security-guardrails scan');
  assert.equal(pkg.scripts.prebuild, 'npm run security:guardrails && npm test');
});
