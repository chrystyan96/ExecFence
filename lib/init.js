'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { baselineFileName, createDefaultConfig, loadConfig, reportsDir, signaturesFileName } = require('./config');
const { ensureReportsGitignore } = require('./gitignore');
const { initSandbox } = require('./sandbox');

function initProject(options = {}) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const changes = [];
  const stack = detectStack(cwd);
  const preset = options.preset || 'auto';
  const dryRun = Boolean(options.dryRun);
  const config = createDefaultConfig(cwd, { dryRun });
  if (config.changed) {
    changes.push('.execfence/config/execfence.json: added');
  }
  changes.push(...ensureConfigSupportFiles(cwd, { dryRun }));
  const sandbox = initSandbox(cwd, { dryRun });
  if (sandbox.changed) {
    changes.push('.execfence/config/sandbox.json: added');
  }
  if (!dryRun) {
    fs.mkdirSync(path.join(cwd, reportsDir), { recursive: true });
  }
  changes.push('.execfence/reports/: ensured');
  const gitignoreConfig = loadConfig(cwd).config;
  const gitignore = ensureReportsGitignore(cwd, gitignoreConfig, { dryRun });
  if (gitignore.changed) {
    changes.push('.gitignore: ignored .execfence/reports/');
  }

  const packagePath = path.join(cwd, 'package.json');
  if (fs.existsSync(packagePath)) {
    const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    pkg.scripts = pkg.scripts || {};
    if (!pkg.scripts['execfence:scan']) {
      pkg.scripts['execfence:scan'] = 'execfence scan';
      changes.push('package.json: added execfence:scan');
    }
    if (pkg.scripts.test && !pkg.scripts.test.includes('execfence run')) {
      pkg.scripts.test = `execfence run -- ${pkg.scripts.test}`;
      changes.push('package.json: wrapped test with execfence run');
    }
    if (pkg.scripts.build && !pkg.scripts.build.includes('execfence run')) {
      pkg.scripts.build = `execfence run -- ${pkg.scripts.build}`;
      changes.push('package.json: wrapped build with execfence run');
    }
    const hooks = ['prestart', 'prebuild', 'pretest', 'prewatch'];
    for (const hook of hooks) {
      if (pkg.scripts[hook] && !pkg.scripts[hook].includes('execfence:scan')) {
        pkg.scripts[hook] = `npm run execfence:scan && ${pkg.scripts[hook]}`;
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
      makefile += '\n\nguard:\n\tnpx --yes execfence scan\n';
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
    const workflowPath = path.join(githubWorkflowDir, 'execfence.yml');
    if (!fs.existsSync(workflowPath)) {
      if (!dryRun) {
        fs.writeFileSync(workflowPath, githubWorkflow());
      }
      changes.push('.github/workflows/execfence.yml: added');
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
    jvm: fs.existsSync(path.join(cwd, 'pom.xml')) || fs.existsSync(path.join(cwd, 'build.gradle')) || fs.existsSync(path.join(cwd, 'build.gradle.kts')),
    dotnet: fs.readdirSync(cwd).some((file) => /\.csproj$/i.test(file)) || fs.existsSync(path.join(cwd, 'packages.lock.json')),
    php: fs.existsSync(path.join(cwd, 'composer.json')) || fs.existsSync(path.join(cwd, 'composer.lock')),
    ruby: fs.existsSync(path.join(cwd, 'Gemfile')) || fs.existsSync(path.join(cwd, 'Gemfile.lock')),
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

function ensureConfigSupportFiles(cwd, options = {}) {
  const files = [
    {
      path: path.join(cwd, signaturesFileName),
      contents: {
        $schema: 'https://raw.githubusercontent.com/chrystyan96/execfence/master/schema/execfence-signatures.schema.json',
        exact: [],
        regex: [],
      },
      change: '.execfence/config/signatures.json: added',
    },
    {
      path: path.join(cwd, baselineFileName),
      contents: {
        $schema: 'https://raw.githubusercontent.com/chrystyan96/execfence/master/schema/execfence-baseline.schema.json',
        findings: [],
      },
      change: '.execfence/config/baseline.json: added',
    },
  ];
  const changes = [];
  for (const file of files) {
    if (fs.existsSync(file.path)) {
      continue;
    }
    if (!options.dryRun) {
      fs.mkdirSync(path.dirname(file.path), { recursive: true });
      fs.writeFileSync(file.path, `${JSON.stringify(file.contents, null, 2)}\n`);
    }
    changes.push(file.change);
  }
  return changes;
}

function githubWorkflow() {
  return `name: ExecFence

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
      - run: npx --yes execfence ci
      - run: npx --yes execfence run -- npm test
`;
}

function ensurePytestGuard(cwd, options = {}) {
  const testDir = path.join(cwd, 'tests');
  const testPath = path.join(testDir, 'test_execfence.py');
  if (fs.existsSync(testPath)) {
    return [];
  }
  if (!options.dryRun) {
    fs.mkdirSync(testDir, { recursive: true });
    fs.writeFileSync(testPath, `import shutil
import subprocess


def test_execfence_scan_passes():
    executable = shutil.which("execfence")
    command = [executable, "run", "--", "python", "-m", "pytest"] if executable else ["npx", "--yes", "execfence", "run", "--", "python", "-m", "pytest"]
    subprocess.run(command, check=True)
`);
  }
  return ['tests/test_execfence.py: added'];
}

module.exports = {
  detectStack,
  ensureConfigSupportFiles,
  initProject,
  githubWorkflow,
};
