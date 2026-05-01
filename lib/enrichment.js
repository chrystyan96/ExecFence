'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { projectDirName } = require('./paths');

const cacheDir = path.join(projectDirName, 'cache', 'enrichment');

function enrichFindings(cwd, findings = [], config = {}) {
  const blocked = findings.filter((finding) => ['critical', 'high'].includes(finding.severity || 'high'));
  if (blocked.length === 0) {
    return { status: 'skipped', sources: [], results: [], errors: [] };
  }
  const timeoutMs = Number(config.enrichment?.timeoutMs || config.analysis?.webEnrichment?.timeoutMs || 2500);
  const ttlMs = Number(config.enrichment?.cacheTtlMs || 24 * 60 * 60 * 1000);
  const results = [];
  const errors = [];
  for (const finding of blocked) {
    const indicators = indicatorsFor(finding);
    const cached = readCache(cwd, finding, ttlMs);
    if (cached) {
      results.push({ findingId: finding.id, status: 'cached', indicators, sources: cached.sources || [] });
      continue;
    }
    const sources = [];
    for (const pkg of indicators.packages) {
      const npm = fetchJson(`https://registry.npmjs.org/${encodeURIComponent(pkg)}`, { timeoutMs });
      sources.push(sourceResult('npm', `https://registry.npmjs.org/${pkg}`, npm.ok ? 'complete' : 'failed', npm.ok ? summarizeNpm(npm.json) : npm.error));
      const osv = postJson('https://api.osv.dev/v1/query', { package: { name: pkg, ecosystem: 'npm' } }, { timeoutMs });
      sources.push(sourceResult('osv', 'https://api.osv.dev/v1/query', osv.ok ? 'complete' : 'failed', osv.ok ? summarizeOsv(osv.json) : osv.error));
    }
    for (const domain of indicators.domains) {
      sources.push(sourceResult('web-query', domain, 'queued', `Search reputable sources for ${domain}`));
    }
    if (sources.length === 0) {
      sources.push(sourceResult('web-query', finding.id, 'queued', `Search public reporting for ${finding.id}`));
    }
    const item = { findingId: finding.id, status: sourceStatus(sources), indicators, sources };
    writeCache(cwd, finding, item);
    results.push(item);
    errors.push(...sources.filter((source) => source.status === 'failed').map((source) => `${source.name}: ${source.summary}`));
  }
  return {
    status: errors.length === 0 ? 'complete' : results.length > 0 ? 'partial' : 'failed',
    sources: ['npm', 'osv', 'github-advisory-manual', 'cisa-kev-manual', 'web-query'],
    results,
    errors,
  };
}

function indicatorsFor(finding) {
  const text = `${finding.file || ''} ${finding.detail || ''}`;
  const domains = Array.from(new Set((text.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi) || [])
    .filter((value) => !value.endsWith('.js') && !value.endsWith('.json'))));
  const packages = [];
  const packageMatch = text.match(/Package\s+([^/\s'"]+)/i);
  if (packageMatch && packageMatch[1] !== '<root>') {
    packages.push(packageMatch[1]);
  }
  return {
    domains,
    packages: Array.from(new Set(packages)),
    hashes: Array.from(new Set(text.match(/\b[A-Fa-f0-9]{64}\b/g) || [])),
    ruleIds: [finding.id].filter(Boolean),
  };
}

function fetchJson(url, options = {}) {
  return runFetch({ url, timeoutMs: options.timeoutMs });
}

function postJson(url, body, options = {}) {
  return runFetch({ url, method: 'POST', body, timeoutMs: options.timeoutMs });
}

function runFetch(request) {
  const script = `
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), ${Number(request.timeoutMs || 2500)});
fetch(${JSON.stringify(request.url)}, {
  method: ${JSON.stringify(request.method || 'GET')},
  headers: ${JSON.stringify(request.body ? { 'content-type': 'application/json' } : {})},
  body: ${request.body ? JSON.stringify(JSON.stringify(request.body)) : 'undefined'},
  signal: controller.signal
}).then(async (response) => {
  clearTimeout(timeout);
  const text = await response.text();
  console.log(JSON.stringify({ ok: response.ok, status: response.status, json: text ? JSON.parse(text) : null }));
}).catch((error) => {
  clearTimeout(timeout);
  console.log(JSON.stringify({ ok: false, error: error.message }));
});
`;
  try {
    const output = require('node:child_process').execFileSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: (request.timeoutMs || 2500) + 1000 });
    return JSON.parse(output);
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function summarizeNpm(json) {
  if (!json) {
    return 'No npm metadata returned.';
  }
  return `npm package ${json.name || 'unknown'} latest=${json['dist-tags']?.latest || 'unknown'} versions=${Object.keys(json.versions || {}).length}`;
}

function summarizeOsv(json) {
  const count = Array.isArray(json?.vulns) ? json.vulns.length : 0;
  return `OSV vulnerabilities: ${count}`;
}

function sourceResult(name, url, status, summary) {
  return { name, url, status, summary: String(summary || '') };
}

function sourceStatus(sources) {
  if (sources.every((source) => source.status === 'complete' || source.status === 'queued')) {
    return 'complete';
  }
  if (sources.some((source) => source.status === 'complete' || source.status === 'queued')) {
    return 'partial';
  }
  return 'failed';
}

function cachePath(cwd, finding) {
  const id = `${finding.id}-${Buffer.from(`${finding.file || ''}:${finding.detail || ''}`).toString('base64url').slice(0, 32)}.json`;
  return path.join(cwd, cacheDir, id);
}

function readCache(cwd, finding, ttlMs) {
  const filePath = cachePath(cwd, finding);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const stat = fs.statSync(filePath);
  if (Date.now() - stat.mtimeMs > ttlMs) {
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function writeCache(cwd, finding, item) {
  const filePath = cachePath(cwd, finding);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(item, null, 2)}\n`);
}

module.exports = {
  enrichFindings,
  indicatorsFor,
};
