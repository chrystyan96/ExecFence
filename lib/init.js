'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createDefaultConfig } = require('./config');

function initProject(options = {}) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const changes = [];
  const stack = detectStack(cwd);
  const preset = options.preset || 'auto';
  const dryRun = Boolean(options.dryRun);
  const config = createDefaultConfig(cwd, { dryRun });
  if (config.changed) {
    changes.push('.security-guardrails.json: added');
  }

  const packagePath = path.join(cwd, 'package.json');
  if (fs.existsSync(packagePath)) {
    const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    pkg.scripts = pkg.scripts || {};
    if (!pkg.scripts['security:guardrails']) {
      pkg.scripts['security:guardrails'] = 'security-guardrails scan';
      changes.push('package.json: added security:guardrails');
    }
    const hooks = ['prestart', 'prebuild', 'pretest', 'prewatch'];
    for (const hook of hooks) {
      if (pkg.scripts[hook] && !pkg.scripts[hook].includes('security:guardrails')) {
        pkg.scripts[hook] = `npm run security:guardrails && ${pkg.scripts[hook]}`;
        changes.push(`package.json: prepended ${hook}`);
      }
    }
    if (!dryRun) {
      fs.writeFileSync(packagePath, `${JSON.stringify(pkg, null, 2)}\n`);
    }
  }

  const makefilePath = path.join(cwd, 'Makefile');
  if (fs.existsSync(makefilePath) || preset === 'go') {
    if (!fs.existsSync(makefilePath)) {
      if (!dryRun) {
        fs.writeFileSync(makefilePath, `.PHONY: guard build test test-race vet

build:
\tgo build ./...

test:
\tgo test ./...

test-race:
\tgo test -race ./...

vet:
\tgo vet ./...
`);
      }
      changes.push('Makefile: added');
    }
    let makefile = fs.existsSync(makefilePath) ? fs.readFileSync(makefilePath, 'utf8') : `.PHONY: guard build test test-race vet

build:
\tgo build ./...

test:
\tgo test ./...

test-race:
\tgo test -race ./...

vet:
\tgo vet ./...
`;
    if (!makefile.includes('\nguard:') && !makefile.startsWith('guard:')) {
      makefile = makefile.replace(/(\.PHONY:[^\r\n]*)/, (line) => line.includes(' guard') ? line : `${line} guard`);
      makefile += '\n\nguard:\n\tnpx --yes security-guardrails scan\n';
      changes.push('Makefile: added guard target');
    }
    for (const target of ['build', 'test', 'test-race', 'vet']) {
      makefile = makefile.replace(new RegExp(`^${target}:\\s*$`, 'm'), `${target}: guard`);
    }
    if (!dryRun) {
      fs.writeFileSync(makefilePath, makefile);
    }
  }

  const githubWorkflowDir = path.join(cwd, '.github', 'workflows');
  if (fs.existsSync(githubWorkflowDir)) {
    const workflowPath = path.join(githubWorkflowDir, 'security-guardrails.yml');
    if (!fs.existsSync(workflowPath)) {
      if (!dryRun) {
        fs.writeFileSync(workflowPath, githubWorkflow());
      }
      changes.push('.github/workflows/security-guardrails.yml: added');
    }
  }

  if ((preset === 'python' || (preset === 'auto' && stack.python)) && fs.existsSync(path.join(cwd, 'pyproject.toml'))) {
    changes.push(...ensurePytestGuard(cwd, { dryRun }));
  }

  return { cwd, preset, stack, changes };
}

function detectStack(cwd) {
  const packagePath = path.join(cwd, 'package.json');
  const pkg = fs.existsSync(packagePath) ? readPackage(packagePath) : {};
  return {
    node: fs.existsSync(path.join(cwd, 'package.json')),
    npm: fs.existsSync(path.join(cwd, 'package-lock.json')),
    pnpm: fs.existsSync(path.join(cwd, 'pnpm-lock.yaml')),
    yarn: fs.existsSync(path.join(cwd, 'yarn.lock')),
    bun: fs.existsSync(path.join(cwd, 'bun.lock')) || fs.existsSync(path.join(cwd, 'bun.lockb')),
    go: fs.existsSync(path.join(cwd, 'go.mod')) || fs.existsSync(path.join(cwd, 'backend-go', 'go.mod')),
    rust: fs.existsSync(path.join(cwd, 'Cargo.toml')) || fs.existsSync(path.join(cwd, 'src-tauri', 'Cargo.toml')),
    tauri: fs.existsSync(path.join(cwd, 'src-tauri', 'Cargo.toml')) || Boolean(pkg.dependencies?.['@tauri-apps/api'] || pkg.devDependencies?.['@tauri-apps/cli']),
    electron: Boolean(pkg.dependencies?.electron || pkg.devDependencies?.electron),
    python: fs.existsSync(path.join(cwd, 'pyproject.toml')) || fs.existsSync(path.join(cwd, 'setup.py')),
    vscodeExtension: fs.existsSync(path.join(cwd, '.vscode', 'launch.json')) || Boolean(pkg.engines?.vscode),
    mcp: Boolean(pkg.dependencies?.['@modelcontextprotocol/sdk'] || pkg.devDependencies?.['@modelcontextprotocol/sdk']) || fs.existsSync(path.join(cwd, 'mcp.json')),
    githubActions: fs.existsSync(path.join(cwd, '.github', 'workflows')),
  };
}

function readPackage(packagePath) {
  try {
    return JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  } catch {
    return {};
  }
}

function githubWorkflow() {
  return `name: Security Guardrails

on:
  pull_request:
  push:
    branches: [main, master]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx --yes security-guardrails scan
`;
}

function ensurePytestGuard(cwd, options = {}) {
  const testDir = path.join(cwd, 'tests');
  const testPath = path.join(testDir, 'test_security_guardrails.py');
  if (fs.existsSync(testPath)) {
    return [];
  }
  if (!options.dryRun) {
    fs.mkdirSync(testDir, { recursive: true });
    fs.writeFileSync(testPath, `import shutil
import subprocess


def test_security_guardrails_scan_passes():
    executable = shutil.which("security-guardrails")
    command = [executable, "scan"] if executable else ["npx", "--yes", "security-guardrails", "scan"]
    subprocess.run(command, check=True)
`);
  }
  return ['tests/test_security_guardrails.py: added'];
}

module.exports = {
  detectStack,
  initProject,
  githubWorkflow,
};
