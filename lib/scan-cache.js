'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const packageJson = require('../package.json');

const cacheDirName = 'execfence-scan-cache-v1';

function createScanCache(cwd, rules, config = {}, options = {}) {
  const enabled = options.enabled !== false && config.performance?.scanCache !== false;
  const projectIdentity = sha256(Buffer.from(path.resolve(cwd).toLowerCase()));
  const filePath = path.join(os.tmpdir(), cacheDirName, `${projectIdentity}.json`);
  const policyHash = fingerprintPolicy(rules, config);
  const maxEntries = bounded(config.performance?.scanCacheMaxEntries, 100, 100000, 10000);
  const store = enabled ? readCache(filePath) : { schemaVersion: 1, entries: {} };
  let dirty = false;
  return {
    enabled,
    filePath,
    policyHash,
    get(file, bytes) {
      if (!enabled) return null;
      const contentHash = sha256(bytes);
      const key = cacheKey(cwd, file, contentHash, policyHash);
      const entry = store.entries?.[key];
      if (!entry || entry.contentHash !== contentHash || entry.policyHash !== policyHash || entry.toolVersion !== packageJson.version) return null;
      entry.lastUsedAt = new Date().toISOString();
      dirty = true;
      return (entry.findings || []).map((finding) => ({ ...finding }));
    },
    set(file, bytes, findings) {
      if (!enabled) return;
      const contentHash = sha256(bytes);
      const key = cacheKey(cwd, file, contentHash, policyHash);
      store.entries ||= {};
      store.entries[key] = {
        contentHash,
        policyHash,
        toolVersion: packageJson.version,
        findings: findings.map((finding) => ({ ...finding })),
        cachedAt: new Date().toISOString(),
        lastUsedAt: new Date().toISOString(),
      };
      dirty = true;
    },
    flush() {
      if (!enabled || !dirty) return;
      const entries = Object.entries(store.entries || {})
        .sort(([, left], [, right]) => Date.parse(right.lastUsedAt || right.cachedAt || 0) - Date.parse(left.lastUsedAt || left.cachedAt || 0))
        .slice(0, maxEntries);
      const output = { schemaVersion: 1, policyHash, entries: Object.fromEntries(entries) };
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, `${JSON.stringify(output)}\n`);
      dirty = false;
    },
  };
}

function fingerprintPolicy(rules, config) {
  const relevant = {
    exact: (rules.exact || []).map(([id, value]) => [id, value]),
    regex: (rules.regex || []).map(([id, value]) => [id, String(value)]),
    auditAllPackageScripts: Boolean(config.auditAllPackageScripts),
    workflowHardening: config.workflowHardening !== false,
    archiveAudit: config.archiveAudit !== false,
    deps: config.deps || {},
  };
  return sha256(Buffer.from(stableStringify(relevant)));
}

function cacheKey(cwd, file, contentHash, policyHash) {
  const relative = path.relative(cwd, file).replaceAll(path.sep, '/');
  return sha256(Buffer.from(`${relative}\0${contentHash}\0${policyHash}`));
}

function readCache(filePath) {
  if (!fs.existsSync(filePath)) return { schemaVersion: 1, entries: {} };
  try {
    const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return value.schemaVersion === 1 && value.entries ? value : { schemaVersion: 1, entries: {} };
  } catch {
    return { schemaVersion: 1, entries: {} };
  }
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function bounded(value, minimum, maximum, fallback) {
  const number = Number(value ?? fallback);
  return Number.isInteger(number) && number >= minimum && number <= maximum ? number : fallback;
}

module.exports = {
  createScanCache,
  fingerprintPolicy,
};
