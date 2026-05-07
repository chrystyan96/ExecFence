const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const helperDir = path.join(root, 'helper');
const cacheDir = path.join(root, '.execfence', 'cache');
const workDir = path.join(cacheDir, 'helper-smoke-work');
const binary = path.join(cacheDir, process.platform === 'win32' ? 'execfence-helper-smoke.exe' : 'execfence-helper-smoke');

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || root,
    encoding: 'utf8',
    shell: false,
    ...options,
  });
  if (options.allowFailure) {
    return result;
  }
  if (result.status !== 0) {
    process.stderr.write(result.stdout || '');
    process.stderr.write(result.stderr || '');
    throw new Error(`${command} ${args.join(' ')} failed with exit ${result.status}`);
  }
  return result;
}

function readJson(output) {
  try {
    return JSON.parse(output);
  } catch (error) {
    throw new Error(`failed to parse helper JSON output: ${error.message}\n${output}`);
  }
}

function readJsonLines(file) {
  return fs.readFileSync(file, 'utf8')
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function nodePlatform() {
  return process.platform;
}

function nodeArch() {
  return process.arch;
}

fs.mkdirSync(cacheDir, { recursive: true });
fs.rmSync(workDir, { recursive: true, force: true });
fs.mkdirSync(workDir, { recursive: true });

run('go', ['test', './...'], { cwd: helperDir });
run('go', ['build', '-o', binary, './cmd/execfence-helper'], { cwd: helperDir });

const selfTest = readJson(run(binary, ['self-test']).stdout);
const sha256 = crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex');

assert.strictEqual(selfTest.ok, true, 'self-test must report ok:true');
assert.strictEqual(selfTest.name, 'execfence-helper');
assert.strictEqual(selfTest.version, '5.0.0');
assert.strictEqual(selfTest.platform, nodePlatform());
assert.strictEqual(selfTest.arch, nodeArch());
assert.strictEqual(selfTest.sha256, sha256);

for (const capability of ['process', 'childProcesses', 'newExecutables']) {
  assert.strictEqual(selfTest.capabilities[capability]?.enforced, true, `${capability} must be enforced`);
}
for (const capability of ['filesystem', 'sensitiveReads', 'network']) {
  assert.strictEqual(selfTest.capabilities[capability]?.enforced, false, `${capability} must not be over-claimed`);
  assert.ok(selfTest.capabilities[capability]?.limitation, `${capability} must explain its limitation`);
}

const passPolicy = path.join(workDir, 'pass-policy.json');
const passEvents = path.join(workDir, 'pass-events.jsonl');
fs.writeFileSync(passPolicy, JSON.stringify({
  schemaVersion: 1,
  protocolVersion: 1,
  mode: 'enforce',
  profile: 'strict',
  cwd: workDir,
  requiredCapabilities: ['process', 'childProcesses', 'newExecutables'],
  command: { argv: [process.execPath, '-e', "console.log('helper-smoke-ok')"], display: 'node helper smoke pass' },
  fs: { deny: [], denyNewExecutable: true },
  process: { deny: [] },
  network: { default: 'allow', allow: [] },
}, null, 2));

run(binary, ['run', '--policy', passPolicy, '--events', passEvents, '--', process.execPath, '-e', "console.log('helper-smoke-ok')"]);
const passLog = readJsonLines(passEvents);
assert.ok(passLog.some((event) => event.type === 'spawn'), 'helper run must emit spawn event');
assert.ok(passLog.some((event) => event.type === 'exit' && event.exitCode === 0), 'helper run must emit clean exit event');

const denyPolicy = path.join(workDir, 'deny-policy.json');
const denyEvents = path.join(workDir, 'deny-events.jsonl');
const createdExecutable = path.join(workDir, process.platform === 'win32' ? 'created.exe' : 'created.sh');
fs.writeFileSync(denyPolicy, JSON.stringify({
  schemaVersion: 1,
  protocolVersion: 1,
  mode: 'enforce',
  profile: 'strict',
  cwd: workDir,
  requiredCapabilities: ['process', 'childProcesses', 'newExecutables'],
  command: { argv: [process.execPath, '-e', ''], display: 'node helper smoke deny' },
  fs: { deny: [], denyNewExecutable: true },
  process: { deny: [] },
  network: { default: 'allow', allow: [] },
}, null, 2));

const denyScript = `require('node:fs').writeFileSync(${JSON.stringify(createdExecutable)}, 'smoke')`;
const denyRun = run(binary, ['run', '--policy', denyPolicy, '--events', denyEvents, '--', process.execPath, '-e', denyScript], { allowFailure: true });
assert.strictEqual(denyRun.status, 126, 'new executable artifact must be denied');
const denyLog = readJsonLines(denyEvents);
assert.ok(denyLog.some((event) => event.type === 'deny' && event.surface === 'filesystem'), 'deny run must emit filesystem deny event');

console.log(`helper smoke passed on ${selfTest.platform}/${selfTest.arch}`);
