'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { scan } = require('../lib/scanner');

test('scan passes on a clean project', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-clean-'));
  fs.mkdirSync(path.join(root, 'frontend'), { recursive: true });
  fs.writeFileSync(path.join(root, 'frontend', 'tailwind.config.js'), 'module.exports = { plugins: [] };\n');

  const result = scan({ cwd: root, roots: ['frontend'] });

  assert.equal(result.ok, true);
  assert.deepEqual(result.findings, []);
});

test('scan blocks the known injected loader marker', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-bad-'));
  fs.mkdirSync(path.join(root, 'frontend'), { recursive: true });
  fs.writeFileSync(path.join(root, 'frontend', 'tailwind.config.js'), "module.exports = {};\nglobal.i='2-30-4';\n");

  const result = scan({ cwd: root, roots: ['frontend'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'void-dokkaebi-loader-marker');
});

test('scan ignores build output directories', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-ignore-'));
  fs.mkdirSync(path.join(root, 'desktop', 'src-tauri', 'target-release-codex'), { recursive: true });
  fs.writeFileSync(path.join(root, 'desktop', 'src-tauri', 'target-release-codex', 'app.exe'), 'binary');

  const result = scan({ cwd: root, roots: ['desktop'] });

  assert.equal(result.ok, true);
});

test('scan blocks vscode folder-open autostart', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'security-guardrails-vscode-'));
  fs.mkdirSync(path.join(root, '.vscode'), { recursive: true });
  fs.writeFileSync(path.join(root, '.vscode', 'tasks.json'), '{"runOn":"folderOpen"}\n');

  const result = scan({ cwd: root, roots: ['.vscode'] });

  assert.equal(result.ok, false);
  assert.equal(result.findings[0].id, 'vscode-folder-open-autostart');
});
