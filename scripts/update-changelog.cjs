'use strict';

const fs = require('node:fs');
const { execFileSync } = require('node:child_process');

const args = new Set(process.argv.slice(2));
if (args.has('--help') || args.has('-h')) {
  process.stdout.write(`Usage: node scripts/update-changelog.cjs [--dry-run]\n\n`);
  process.stdout.write('Append a changelog section for the current package.json version using git commit subjects since the latest tag.\n');
  process.stdout.write('\nOptions:\n');
  process.stdout.write('  --dry-run   Print the generated section without modifying CHANGELOG.md\n');
  process.exit(0);
}

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
if (args.has('--dry-run')) {
  process.stdout.write(`${entry.trimEnd()}\n`);
} else {
  fs.writeFileSync('CHANGELOG.md', `${next.trimEnd()}\n`);
}
