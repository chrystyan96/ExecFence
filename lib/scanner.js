'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const { loadConfig } = require('./config');
const { applyBaseline } = require('./baseline');
const { applyPolicyPack } = require('./policy');
const { exactSignatures, regexSignatures } = require('./signatures');
const { lockfileNames } = require('./ecosystems');

const defaultRoots = ['backend-go', 'backend', 'frontend', 'desktop', 'packages', 'scripts', '.github', '.vscode'];
const defaultIgnoredDirectories = new Set([
  '.angular',
  '.git',
  '.execfence',
  '.next',
  '.nuxt',
  '.omx',
  '.pytest_cache',
  '.turbo',
  'bin',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'out',
  'playwright-report',
  'target',
  'test-results',
  'vendor',
  'visual-checks',
]);
const defaultSkippedFileNames = new Set([
  'security-malware-guard.cjs',
  'execfence.js',
  'malware_guard_test.go',
]);
const executableExtensions = new Set(['.bat', '.cmd', '.com', '.dll', '.exe', '.scr', '.vbs', '.wsf']);
const archiveExtensions = new Set(['.asar', '.tar', '.tgz', '.zip']);
const maxTextFileBytes = 5 * 1024 * 1024;
const lockfileTextNames = new Set([
  ...lockfileNames(),
  'bun.lock',
  'bun.lockb',
  'Cargo.lock',
  'go.sum',
  'pnpm-lock.yaml',
  'poetry.lock',
  'uv.lock',
  'yarn.lock',
]);

const ruleMetadata = {
  'allowed-executable-hash-mismatch': { severity: 'high', description: 'An executable allowlist entry matched the path but not the expected SHA-256 hash.' },
  'executable-artifact-in-source-tree': { severity: 'high', description: 'Executable artifacts in source/build-input folders can run attacker-controlled code.' },
  'insecure-lockfile-url': { severity: 'high', description: 'Lockfiles resolving artifacts over HTTP allow network tampering.' },
  'lockfile-suspicious-host': { severity: 'medium', description: 'Lockfiles resolving from paste/raw hosts should be reviewed before build.' },
  'long-obfuscated-javascript-line': { severity: 'critical', description: 'Very long JavaScript lines with loader markers are common in injected payloads.' },
  'suspicious-lockfile-url': { severity: 'medium', description: 'Lockfiles resolving from paste/raw hosts should be reviewed before build.' },
  'suspicious-package-script': { severity: 'high', description: 'Lifecycle scripts that download, evaluate, or launch native script hosts run during install/build.' },
  'suspicious-python-build-script': { severity: 'high', description: 'Python setup/build scripts can execute code during package build or install.' },
  'suspicious-rust-build-script': { severity: 'high', description: 'Rust build.rs scripts execute during cargo build/test and can launch processes.' },
  'suspicious-go-generate': { severity: 'high', description: 'go generate directives execute arbitrary commands from source comments.' },
  'suspicious-jvm-build-source': { severity: 'high', description: 'Maven/Gradle build files can pull plugins or artifacts from suspicious repositories and execute build logic.' },
  'suspicious-nuget-source': { severity: 'high', description: 'NuGet restore sources outside trusted HTTPS feeds can affect build and test inputs.' },
  'suspicious-composer-script': { severity: 'high', description: 'Composer scripts can execute shell/PHP commands during install/update or run-script.' },
  'suspicious-bundler-source': { severity: 'high', description: 'Bundler git/path gems can bypass registry review and execute during install/runtime.' },
  'credential-sensitive-reference': { severity: 'medium', description: 'Credential, token, SSH, environment, or package-manager auth paths should be reviewed before execution.' },
  'credential-exfiltration-risk': { severity: 'high', description: 'Credential references combined with process, shell, download, or network behavior can exfiltrate secrets.' },
  'config-invalid-regex-signature': { severity: 'high', description: 'Configured regex signatures must compile before scans can rely on them.' },
  'workflow-curl-pipe-shell': { severity: 'high', description: 'CI workflows that pipe downloaded content to a shell can execute attacker-controlled code.' },
  'workflow-publish-without-provenance': { severity: 'high', description: 'npm publish in CI should use provenance or trusted publishing.' },
  'workflow-pull-request-target': { severity: 'medium', description: 'pull_request_target can expose privileged tokens to untrusted pull request code.' },
  'workflow-unpinned-action': { severity: 'medium', description: 'GitHub Actions pinned only to tags can be retagged upstream.' },
  'workflow-write-all-permissions': { severity: 'medium', description: 'write-all grants broad write permissions to the workflow token.' },
  'archive-artifact-in-source-tree': { severity: 'medium', description: 'Committed archives in source/build-input folders can hide executable payloads.' },
};

function scan(options = {}) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const loaded = loadConfig(cwd, options.configPath);
  const config = applyPolicyPack({ cwd, ...loaded.config, ...(options.config || {}) });
  if (options.failOn?.length) {
    config.blockSeverities = options.failOn;
  }
  if (options.warnOn?.length) {
    config.warnSeverities = options.warnOn;
  }
  const roots = normalizeRoots(cwd, options.roots || config.roots);
  const selfPackage = isExecFencePackage(cwd) && !options.fullIocScan;
  const mode = options.mode || config.mode || 'block';
  if (!['audit', 'block'].includes(mode)) {
    throw new Error(`Invalid execfence mode: ${mode}`);
  }
  const blockSeverities = new Set(config.blockSeverities || ['critical', 'high']);
  const warnSeverities = new Set(config.warnSeverities || ['medium', 'low']);
  const findings = [];

  for (const root of roots) {
    walk(root, cwd, findings, { ...options, config, selfPackage });
  }

  const baseline = applyBaseline(cwd, findings, { baselinePath: options.baselinePath || config.baselineFile });
  const activeFindings = baseline.activeFindings;
  const blockedFindings = activeFindings.filter((item) => mode !== 'audit' && blockSeverities.has(item.severity || 'high'));
  const warningFindings = activeFindings.filter((item) => !blockedFindings.includes(item) && warnSeverities.has(item.severity || 'high'));
  return {
    cwd,
    configPath: loaded.configPath,
    baselinePath: baseline.baselinePath,
    config,
    mode,
    roots,
    findings: activeFindings,
    suppressedFindings: baseline.suppressedFindings,
    blockedFindings,
    warningFindings,
    ok: mode === 'audit' || blockedFindings.length === 0,
  };
}

function normalizeRoots(cwd, roots) {
  const requested = roots && roots.length > 0 ? roots : defaultRoots;
  const resolved = [];
  for (const root of requested) {
    const fullPath = path.resolve(cwd, root);
    if (fs.existsSync(fullPath)) {
      resolved.push(fullPath);
    }
  }
  if (resolved.length === 0) {
    resolved.push(cwd);
  }
  return resolved;
}

function walk(root, cwd, findings, options) {
  if (!fs.existsSync(root)) {
    return;
  }
  const stat = fs.statSync(root);
  if (stat.isFile()) {
    scanFile(root, cwd, findings, options);
    return;
  }

  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (isIgnoredDirectory(entry.name, options)) {
        continue;
      }
      walk(fullPath, cwd, findings, options);
      continue;
    }
    if (entry.isFile()) {
      scanFile(fullPath, cwd, findings, options);
    }
  }
}

function scanFile(filePath, cwd, findings, options) {
  const baseName = path.basename(filePath);
  const skipFiles = new Set([...(options.config?.skipFiles || []), ...(options.skipFiles || [])]);
  if (defaultSkippedFileNames.has(baseName) || skipFiles.has(baseName)) {
    return;
  }
  if (options.selfPackage && isSelfPackageFixture(cwd, filePath)) {
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  if (archiveExtensions.has(ext) && options.config?.archiveAudit !== false) {
    findings.push(finding('archive-artifact-in-source-tree', cwd, filePath, 1, `Archive artifact with ${ext} extension should not be committed in source/build inputs.`));
    return;
  }
  if (executableExtensions.has(ext)) {
    const allowed = executableAllowStatus(cwd, filePath, options.config);
    if (allowed.ok) {
      return;
    }
    if (allowed.reason === 'hash-mismatch') {
      findings.push(finding('allowed-executable-hash-mismatch', cwd, filePath, 1, `Executable hash ${allowed.actual} does not match allowlist SHA-256 ${allowed.expected}.`));
      return;
    }
    findings.push(finding('executable-artifact-in-source-tree', cwd, filePath, 1, `Executable artifact with ${ext} extension is not allowed in source/build inputs.`));
    return;
  }

  const stat = fs.statSync(filePath);
  if (stat.size > maxTextFileBytes) {
    return;
  }

  const buffer = fs.readFileSync(filePath);
  if (buffer.includes(0)) {
    return;
  }

  const content = buffer.toString('utf8');
  const configuredExactSignatures = [
    ...exactSignatures,
    ...(options.config?.extraSignatures || []).map((signature, index) => [`config-extra-signature-${index + 1}`, signature]),
    ...normalizeExternalExactSignatures(options.config?.externalSignatures),
  ];
  let configuredRegexSignatures = [...regexSignatures];
  try {
    configuredRegexSignatures = [
      ...configuredRegexSignatures,
      ...(options.config?.extraRegexSignatures || []).map((signature, index) => [`config-extra-regex-${index + 1}`, new RegExp(signature)]),
      ...normalizeExternalRegexSignatures(options.config?.externalSignatures),
    ];
  } catch (error) {
    findings.push(finding('config-invalid-regex-signature', cwd, filePath, 1, `Invalid configured regex signature: ${error.message}`));
  }
  for (const [id, signature] of configuredExactSignatures) {
    const index = content.indexOf(signature);
    if (index >= 0) {
      findings.push(finding(id, cwd, filePath, lineNumberFor(content, index), `Matched ${signature}`));
    }
  }

  for (const [id, pattern] of configuredRegexSignatures) {
    const match = pattern.exec(content);
    if (match?.index >= 0) {
      findings.push(finding(id, cwd, filePath, lineNumberFor(content, match.index), `Matched ${pattern}`));
    }
  }

  if (baseName === 'package.json') {
    auditPackageScripts(cwd, filePath, content, findings, options.config);
  }
  if (baseName === 'setup.py' || baseName === 'pyproject.toml') {
    auditPythonBuild(cwd, filePath, content, findings);
  }
  if (baseName === 'build.rs') {
    auditRustBuild(cwd, filePath, content, findings);
  }
  if (baseName.endsWith('.go')) {
    auditGoGenerate(cwd, filePath, content, findings);
  }
  if (baseName === 'composer.json') {
    auditComposerScripts(cwd, filePath, content, findings);
  }
  if (baseName === 'build.gradle' || baseName === 'build.gradle.kts' || baseName === 'pom.xml') {
    auditJvmBuild(cwd, filePath, content, findings);
  }
  if (baseName === 'packages.lock.json' || /\.csproj$/i.test(baseName) || /^nuget\.config$/i.test(baseName)) {
    auditNugetSources(cwd, filePath, content, findings);
  }
  if (baseName === 'Gemfile' || baseName === 'Gemfile.lock') {
    auditBundlerSources(cwd, filePath, content, findings);
  }
  if (/\.ya?ml$/i.test(baseName) && path.relative(cwd, filePath).replaceAll(path.sep, '/').startsWith('.github/workflows/')) {
    auditGithubWorkflow(cwd, filePath, content, findings, options.config);
  }
  if (baseName === 'package-lock.json' || baseName === 'npm-shrinkwrap.json') {
    auditNpmLockfile(cwd, filePath, content, findings);
  }
  if (lockfileTextNames.has(baseName)) {
    auditTextLockfile(cwd, filePath, content, findings);
  }

  const lines = content.split(/\r?\n/);
  lines.forEach((line, index) => {
    if (line.length < 2000) {
      return;
    }
    if (/String\.fromCharCode\(127\)|global\[[^\]]+\]\s*=\s*require|var\s+_\$_[A-Za-z0-9_]+/.test(line)) {
      findings.push(finding('long-obfuscated-javascript-line', cwd, filePath, index + 1, 'Very long line contains obfuscated JavaScript loader markers.'));
    }
  });
}

function auditPythonBuild(cwd, filePath, content, findings) {
  if (/(?:subprocess|os\.system|eval\s*\(|exec\s*\(|curl|wget|Invoke-WebRequest|powershell|bash\s+-c|sh\s+-c)/i.test(content)) {
    findings.push(finding('suspicious-python-build-script', cwd, filePath, lineNumberFor(content, content.search(/subprocess|os\.system|eval\s*\(|exec\s*\(|curl|wget|Invoke-WebRequest|powershell|bash\s+-c|sh\s+-c/i)), 'Python build/install metadata executes process, shell, download, or dynamic code behavior.'));
  }
}

function auditRustBuild(cwd, filePath, content, findings) {
  if (/(?:Command::new|std::process|curl|wget|powershell|bash|sh\s+-c|include_bytes!|OUT_DIR)/i.test(content)) {
    findings.push(finding('suspicious-rust-build-script', cwd, filePath, lineNumberFor(content, content.search(/Command::new|std::process|curl|wget|powershell|bash|sh\s+-c|include_bytes!|OUT_DIR/i)), 'Rust build.rs executes process, shell, download, embedded artifact, or generated-output behavior.'));
  }
}

function auditGoGenerate(cwd, filePath, content, findings) {
  for (const match of content.matchAll(/\/\/go:generate\s+([^\r\n]+)/g)) {
    const command = match[1];
    if (/(?:curl|wget|powershell|bash|sh|cmd|go\s+run|python|node|npm|npx)/i.test(command)) {
      findings.push(finding('suspicious-go-generate', cwd, filePath, lineNumberFor(content, match.index || 0), `go generate directive executes high-risk command: ${command}`));
    }
  }
}

function auditComposerScripts(cwd, filePath, content, findings) {
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return;
  }
  for (const [name, command] of Object.entries(parsed.scripts || {})) {
    const text = Array.isArray(command) ? command.join(' && ') : String(command);
    if (/(?:curl|wget|powershell|bash|sh\s+-c|php\s+-r|eval|base64_decode|proc_open|shell_exec)/i.test(text)) {
      findings.push(finding('suspicious-composer-script', cwd, filePath, lineNumberFor(content, content.indexOf(`"${name}"`)), `Composer script "${name}" executes risky behavior: ${text}`));
    }
  }
}

function auditJvmBuild(cwd, filePath, content, findings) {
  for (const match of content.matchAll(/https?:\/\/[^\s"'<>]+/gi)) {
    if (/^http:\/\//i.test(match[0]) || /(?:raw\.githubusercontent|gist\.githubusercontent|pastebin|jitpack\.io)/i.test(match[0])) {
      findings.push(finding('suspicious-jvm-build-source', cwd, filePath, lineNumberFor(content, match.index || 0), `JVM build references suspicious repository/plugin source: ${match[0]}`));
    }
  }
  const risky = content.search(/(?:exec\s*\{|Exec\b|ProcessBuilder|Runtime\.getRuntime|curl|wget|powershell|bash\s+-c|sh\s+-c)/i);
  if (risky >= 0) {
    findings.push(finding('suspicious-jvm-build-source', cwd, filePath, lineNumberFor(content, risky), 'JVM build file includes process, shell, or download behavior that can execute during build/test.'));
  }
}

function auditNugetSources(cwd, filePath, content, findings) {
  for (const match of content.matchAll(/https?:\/\/[^\s"'<>]+|(?:\.\.\/|file:|[A-Za-z]:\\)[^\s"'<>]*/gi)) {
    const value = match[0];
    if (/^http:\/\//i.test(value) || /(?:raw\.githubusercontent|gist\.githubusercontent|pastebin)/i.test(value) || /(?:\.\.\/|file:|[A-Za-z]:\\)/.test(value)) {
      findings.push(finding('suspicious-nuget-source', cwd, filePath, lineNumberFor(content, match.index || 0), `NuGet restore/build source should be reviewed: ${value}`));
    }
  }
}

function auditBundlerSources(cwd, filePath, content, findings) {
  for (const match of content.matchAll(/(?:git:\s*['"][^'"]+|path:\s*['"][^'"]+|https?:\/\/[^\s"'<>]+)/gi)) {
    const value = match[0];
    if (/git:|path:|^http:\/\//i.test(value) || /(?:raw\.githubusercontent|gist\.githubusercontent|pastebin)/i.test(value)) {
      findings.push(finding('suspicious-bundler-source', cwd, filePath, lineNumberFor(content, match.index || 0), `Bundler dependency source bypasses normal registry review: ${value}`));
    }
  }
}

function auditGithubWorkflow(cwd, filePath, content, findings, config = {}) {
  if (config.workflowHardening === false) {
    return;
  }
  const pullRequestTarget = content.search(/\bpull_request_target\b/i);
  if (pullRequestTarget >= 0) {
    findings.push(finding('workflow-pull-request-target', cwd, filePath, lineNumberFor(content, pullRequestTarget), 'Workflow uses pull_request_target.'));
  }
  if (/\bpermissions\s*:\s*write-all\b/i.test(content)) {
    findings.push(finding('workflow-write-all-permissions', cwd, filePath, lineNumberFor(content, content.search(/\bpermissions\s*:\s*write-all\b/i)), 'Workflow grants write-all permissions.'));
  }
  for (const match of content.matchAll(/uses:\s*([^\s#]+)@([^\s#]+)/g)) {
    if (!/^[a-f0-9]{40}$/i.test(match[2])) {
      findings.push(finding('workflow-unpinned-action', cwd, filePath, lineNumberFor(content, match.index || 0), `Action ${match[1]} is pinned to ${match[2]} instead of a full commit SHA.`));
    }
  }
  for (const match of content.matchAll(/(?:curl|wget)[^|\r\n]*\|\s*(?:bash|sh|pwsh|powershell)/gi)) {
    findings.push(finding('workflow-curl-pipe-shell', cwd, filePath, lineNumberFor(content, match.index || 0), `Workflow pipes downloaded content to a shell: ${match[0]}`));
  }
  for (const match of content.matchAll(/npm\s+publish(?![^\r\n]*--provenance)/gi)) {
    findings.push(finding('workflow-publish-without-provenance', cwd, filePath, lineNumberFor(content, match.index || 0), 'Workflow runs npm publish without --provenance.'));
  }
}

function isExecFencePackage(cwd) {
  const packagePath = path.join(cwd, 'package.json');
  if (!fs.existsSync(packagePath)) {
    return false;
  }
  try {
    return JSON.parse(fs.readFileSync(packagePath, 'utf8')).name === 'execfence';
  } catch {
    return false;
  }
}

function isSelfPackageFixture(cwd, filePath) {
  const rel = path.relative(cwd, filePath).replaceAll(path.sep, '/');
  return rel === 'README.md' ||
    rel === 'lib/signatures.js' ||
    rel === 'skill/execfence/SKILL.md' ||
    rel.startsWith('test/');
}

function isIgnoredDirectory(name, options = {}) {
  if (defaultIgnoredDirectories.has(name) || name.startsWith('target-')) {
    return true;
  }
  return Boolean((options.config?.ignoreDirs || []).includes(name) || (options.ignoreDirs || []).includes(name));
}

function lineNumberFor(content, index) {
  return content.slice(0, index).split(/\r?\n/).length;
}

function finding(id, cwd, filePath, line, detail, severity) {
  const metadata = ruleMetadata[id] || {};
  return {
    id,
    severity: severity || metadata.severity || 'high',
    file: path.relative(cwd, filePath).replaceAll(path.sep, '/'),
    line,
    detail,
    threatCategory: threatCategoryFor(id, detail),
    activationSurface: activationSurfaceFor(id, filePath, detail),
  };
}

function threatCategoryFor(id, detail = '') {
  if (/credential|token|secret|npmrc|env|ssh/i.test(`${id} ${detail}`)) return 'credential-access';
  if (/download|curl|wget|pipe|powershell|shell|process|generate|script/i.test(`${id} ${detail}`)) return 'code-execution';
  if (/lockfile|dependency|registry|package|tarball/i.test(id)) return 'supply-chain';
  if (/workflow|agent|mcp/i.test(id)) return 'privileged-automation';
  if (/executable|archive|artifact/i.test(id)) return 'binary-artifact';
  return 'suspicious-execution-surface';
}

function activationSurfaceFor(id, filePath, detail = '') {
  const file = filePath.replaceAll(path.sep, '/');
  if (/go:generate|go generate/i.test(`${id} ${detail}`)) return 'generate';
  if (/postinstall|preinstall|install|prepare|setup\.py|build\.rs|composer/i.test(`${file} ${detail}`)) return 'install';
  if (/workflow|\.github\/workflows/i.test(file)) return 'ci';
  if (/\b(?:publish|pack)\b/i.test(`${id} ${detail}`)) return 'publish';
  if (/test|pytest|cargo test|go test/i.test(`${file} ${detail}`)) return 'test';
  if (/build|gradle|mvn|dotnet/i.test(`${file} ${detail}`)) return 'build';
  if (/agent|mcp|AGENTS|CLAUDE|GEMINI/i.test(file)) return 'agent';
  return 'run';
}

function formatFindings(findings) {
  if (findings.length === 0) {
    return '[execfence] OK';
  }
  return [
    '[execfence] Suspicious artifact(s) blocked:',
    ...findings.map((item) => `- ${item.id}: ${item.file}:${item.line} - ${item.detail}`),
  ].join('\n');
}

function executableAllowStatus(cwd, filePath, config = {}) {
  const rel = path.relative(cwd, filePath).replaceAll(path.sep, '/');
  for (const allowed of config.allowExecutables || []) {
    if (typeof allowed === 'string') {
      if (rel === allowed || rel.endsWith(`/${allowed}`)) {
        return { ok: true };
      }
      continue;
    }
    const allowedPath = allowed.path || allowed.file;
    if (!allowedPath || (rel !== allowedPath && !rel.endsWith(`/${allowedPath}`))) {
      continue;
    }
    if (!allowed.sha256) {
      return { ok: true };
    }
    const actual = sha256File(filePath);
    if (actual === String(allowed.sha256).toLowerCase()) {
      return { ok: true };
    }
    return { ok: false, reason: 'hash-mismatch', actual, expected: String(allowed.sha256).toLowerCase() };
  }
  return { ok: false };
}

function auditPackageScripts(cwd, filePath, content, findings, config = {}) {
  let pkg;
  try {
    pkg = JSON.parse(content);
  } catch {
    return;
  }
  const scripts = pkg.scripts || {};
  const lifecycleScripts = new Set(['preinstall', 'install', 'postinstall', 'prepare']);
  const suspicious = [
    /\b(?:curl|wget)\b/i,
    /\bpowershell\b|\bInvoke-WebRequest\b|\biwr\b/i,
    /\bnode\s+-e\b/i,
    /\beval\s*\(/i,
    /\b(?:base64|atob|certutil)\b/i,
    /\b(?:bash|sh)\s+-c\b/i,
    /\bchild_process\b/i,
    /\b(?:bitsadmin|mshta|rundll32|regsvr32)\b/i,
    /\bStart-BitsTransfer\b/i,
  ];
  const credentialSensitive = /\.(?:npmrc|env)\b|SSH_AUTH_SOCK|GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY|AWS_SECRET|AZURE_|GOOGLE_APPLICATION_CREDENTIALS|id_rsa|\.ssh|credential(?:s)?|keychain|wincred|pass\.show|security\s+find-generic-password/i;
  const processOrNetwork = /\b(?:curl|wget|Invoke-WebRequest|iwr|powershell|bash|sh|node\s+-e|eval|child_process|bitsadmin|mshta|rundll32|regsvr32|fetch|https?:\/\/)\b/i;
  for (const [name, command] of Object.entries(scripts)) {
    if (!config.auditAllPackageScripts && !lifecycleScripts.has(name)) {
      continue;
    }
    for (const pattern of suspicious) {
      if (pattern.test(String(command))) {
        findings.push(finding(
          'suspicious-package-script',
          cwd,
          filePath,
          lineNumberFor(content, content.indexOf(`"${name}"`)),
          `Suspicious package script "${name}" matches ${pattern}: ${command}`,
        ));
      }
    }
    if (credentialSensitive.test(String(command))) {
      findings.push(finding(
        processOrNetwork.test(String(command)) ? 'credential-exfiltration-risk' : 'credential-sensitive-reference',
        cwd,
        filePath,
        lineNumberFor(content, content.indexOf(`"${name}"`)),
        `Package script "${name}" references credential-sensitive material: ${command}`,
      ));
    }
  }
}

function auditNpmLockfile(cwd, filePath, content, findings) {
  let lockfile;
  try {
    lockfile = JSON.parse(content);
  } catch {
    return;
  }
  const packages = lockfile.packages || {};
  for (const [name, entry] of Object.entries(packages)) {
    const resolved = String(entry?.resolved || '');
    if (resolved.startsWith('http://')) {
      findings.push(finding('insecure-lockfile-url', cwd, filePath, lineNumberFor(content, content.indexOf(resolved)), `Package ${name || '<root>'} resolves over insecure HTTP: ${resolved}`));
    }
    if (/pastebin\.com|gist\.githubusercontent\.com|raw\.githubusercontent\.com/i.test(resolved)) {
      findings.push(finding('suspicious-lockfile-url', cwd, filePath, lineNumberFor(content, content.indexOf(resolved)), `Package ${name || '<root>'} resolves from a suspicious host: ${resolved}`));
    }
  }
}

function auditTextLockfile(cwd, filePath, content, findings) {
  const insecure = /http:\/\/[^\s"'<>]+/gi;
  const suspicious = /https?:\/\/[^\s"'<>]*(?:pastebin\.com|gist\.githubusercontent\.com|raw\.githubusercontent\.com)[^\s"'<>]*/gi;
  for (const pattern of [insecure, suspicious]) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const id = match[0].startsWith('http://') ? 'insecure-lockfile-url' : 'lockfile-suspicious-host';
      findings.push(finding(id, cwd, filePath, lineNumberFor(content, match.index), `Lockfile contains ${match[0]}`));
    }
  }
}

function normalizeExternalExactSignatures(external = {}) {
  return normalizeExternalSignatures(external.exact || external.exactSignatures || []);
}

function normalizeExternalRegexSignatures(external = {}) {
  return normalizeExternalSignatures(external.regex || external.regexSignatures || [], { regex: true });
}

function normalizeExternalSignatures(entries, options = {}) {
  return (entries || []).map((entry, index) => {
    if (typeof entry === 'string') {
      return [options.regex ? `external-regex-signature-${index + 1}` : `external-exact-signature-${index + 1}`, options.regex ? new RegExp(entry) : entry];
    }
    const id = entry.id || (options.regex ? `external-regex-signature-${index + 1}` : `external-exact-signature-${index + 1}`);
    const value = entry.value || entry.signature || entry.pattern;
    return [id, options.regex ? new RegExp(value) : value];
  }).filter(([, value]) => value);
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

module.exports = {
  defaultRoots,
  ruleMetadata,
  scan,
  formatFindings,
};
