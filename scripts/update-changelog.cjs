'use strict';

const fs = require('node:fs');
const { execFileSync } = require('node:child_process');

const version = JSON.parse(fs.readFileSync('package.json', 'utf8')).version;
const tag = `v${version}`;
let previousTag = '';
try {
  previousTag = execFileSync('git', ['describe', '--tags', '--abbrev=0'], { encoding: 'utf8' }).trim();
} catch {
  previousTag = '';
}

const range = previousTag ? `${previousTag}..HEAD` : 'HEAD';
const log = execFileSync('git', ['log', '--pretty=format:- %s (%h)', range], { encoding: 'utf8' }).trim();
const date = new Date().toISOString().slice(0, 10);
const entry = [`## ${tag} - ${date}`, '', log || '- Initial release.', ''].join('\n');
const existing = fs.existsSync('CHANGELOG.md') ? fs.readFileSync('CHANGELOG.md', 'utf8').trimEnd() : '# Changelog\n';
const next = existing.includes(`## ${tag} - `) ? existing : `${existing}\n\n${entry}`;
fs.writeFileSync('CHANGELOG.md', `${next.trimEnd()}\n`);
