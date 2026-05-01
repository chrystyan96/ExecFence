'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('./scanner');

function runDoctor() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-doctor-'));
  try {
    const marker = ['global', ".i='", '2-30-4', "';"].join('');
    fs.writeFileSync(path.join(root, 'tailwind.config.js'), `module.exports = {};\n${marker}\n`);
    const result = scan({ cwd: root, roots: ['tailwind.config.js'] });
    return {
      ok: !result.ok && result.findings.some((finding) => finding.id === 'void-dokkaebi-loader-marker'),
      fixtureDir: root,
      findings: result.findings,
    };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

module.exports = {
  runDoctor,
};
