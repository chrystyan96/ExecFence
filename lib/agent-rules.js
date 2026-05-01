'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const startMarker = '<!-- SECURITY-GUARDRAILS:START -->';
const endMarker = '<!-- SECURITY-GUARDRAILS:END -->';

function guardrailsRule() {
  return `${startMarker}
## Security Guardrails

For persistent projects that run on the web, build executable code, run CI/CD, or access the user's filesystem, credentials, browser, network, shell, desktop APIs, or local machine:

- Evaluate the project stack and execution surfaces before or during the first build/test setup.
- Add lightweight malware and supply-chain guardrails unless the user explicitly opts out.
- Prefer \`npx --yes security-guardrails init --preset auto\` when Node is available; otherwise create equivalent local checks.
- Ensure normal dev/build/test commands run the guardrail before executing project code.
- Block known injected JavaScript loader IoCs, suspicious executable configs, autostart tasks, and unexpected binaries in source/build-input folders.
- Use \`scan --mode audit\` for first adoption and \`scan --mode block\` for enforced CI. Allow committed executables only with path plus SHA-256 when possible.
- Keep false positives low by ignoring dependency/build/cache folders such as \`.git\`, \`node_modules\`, \`dist\`, \`build\`, \`target\`, \`target-*\`, \`bin\`, and test output directories.

Agent trigger language:
- "security guardrails", "guardrail", "supply-chain guardrails", "malware guardrails"

Codex skill:
- If Codex skills are available, use \`$security-guardrails\`.
${endMarker}`;
}

function cursorRule() {
  return `---
description: Add malware and supply-chain guardrails for persistent projects
alwaysApply: true
---

${guardrailsRule()}
`;
}

function updateMarkedFile(filePath, snippet = guardrailsRule()) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
  const pattern = new RegExp(`${escapeRegExp(startMarker)}[\\s\\S]*?${escapeRegExp(endMarker)}`);
  if (!pattern.test(existing) && existing.includes('security-guardrails')) {
    return { filePath, changed: false };
  }
  const next = pattern.test(existing)
    ? existing.replace(pattern, snippet)
    : `${existing.trimEnd()}${existing.trim() ? '\n\n' : ''}${snippet}\n`;
  fs.writeFileSync(filePath, next.endsWith('\n') ? next : `${next}\n`);
  return { filePath, changed: next !== existing };
}

function installCodexSkill(options = {}) {
  const codexHome = path.resolve(options.codexHome || path.join(os.homedir(), '.codex'));
  const source = path.resolve(__dirname, '..', 'skill', 'security-guardrails', 'SKILL.md');
  const targetDir = path.join(codexHome, 'skills', 'security-guardrails');
  fs.mkdirSync(targetDir, { recursive: true });
  fs.copyFileSync(source, path.join(targetDir, 'SKILL.md'));
  const agents = updateMarkedFile(path.join(codexHome, 'AGENTS.md'));
  return { codexHome, skillDir: targetDir, agents };
}

function installGlobalAgentRules(options = {}) {
  const home = path.resolve(options.home || os.homedir());
  const results = [];
  results.push(updateMarkedFile(path.join(home, '.codex', 'AGENTS.md')));
  results.push(updateMarkedFile(path.join(home, '.claude', 'CLAUDE.md')));
  results.push(updateMarkedFile(path.join(home, '.gemini', 'GEMINI.md')));
  return results;
}

function installProjectAgentRules(options = {}) {
  const project = path.resolve(options.project || process.cwd());
  const results = [];
  results.push(updateMarkedFile(path.join(project, 'AGENTS.md')));
  results.push(updateMarkedFile(path.join(project, 'CLAUDE.md')));
  results.push(updateMarkedFile(path.join(project, 'GEMINI.md')));
  results.push(updateMarkedFile(path.join(project, '.github', 'copilot-instructions.md')));
  results.push(updateMarkedFile(path.join(project, '.continue', 'rules', 'security-guardrails.md')));
  results.push(updateMarkedFile(path.join(project, '.windsurf', 'rules', 'security-guardrails.md')));
  results.push(updateMarkedFile(path.join(project, '.aider', 'security-guardrails.md')));
  results.push(updateMarkedFile(path.join(project, '.roo', 'rules', 'security-guardrails.md')));
  results.push(updateMarkedFile(path.join(project, '.clinerules')));
  const cursorPath = path.join(project, '.cursor', 'rules', 'security-guardrails.mdc');
  fs.mkdirSync(path.dirname(cursorPath), { recursive: true });
  const existing = fs.existsSync(cursorPath) ? fs.readFileSync(cursorPath, 'utf8') : '';
  const next = cursorRule();
  if (existing !== next) {
    fs.writeFileSync(cursorPath, next);
    results.push({ filePath: cursorPath, changed: true });
  } else {
    results.push({ filePath: cursorPath, changed: false });
  }
  return results;
}

function installAgentRules(options = {}) {
  const scope = options.scope || 'global';
  const results = [];
  if (scope === 'global' || scope === 'both') {
    results.push(...installGlobalAgentRules(options));
  }
  if (scope === 'project' || scope === 'both') {
    results.push(...installProjectAgentRules(options));
  }
  if (!['global', 'project', 'both'].includes(scope)) {
    throw new Error(`Unknown scope: ${scope}`);
  }
  return results;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = {
  cursorRule,
  endMarker,
  guardrailsRule,
  installAgentRules,
  installCodexSkill,
  installGlobalAgentRules,
  installProjectAgentRules,
  startMarker,
  updateMarkedFile,
};
