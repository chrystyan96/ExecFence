'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const zlib = require('node:zlib');
const { loadConfig } = require('./config');
const { collectDependencies, depsDiff } = require('./deps');

const cacheDir = path.join('.execfence', 'cache', 'supply-chain-metadata');

const defaultSupplyChain = {
  metadata: {
    enabled: true,
    mode: 'guarded',
    allowedRegistries: ['registry.npmjs.org'],
    allowedPublicScopes: [],
    releaseCooldownHours: 48,
    maxPackagesPerRun: 20,
    timeoutMs: 2500,
    cacheTtlMs: 86400000,
    networkFailure: 'warn',
    privateScopePolicy: 'skip',
    packageAgeMinimumDays: 7,
    packageModifiedCooldownHours: 24,
    provenancePolicy: 'warn',
    requireIntegrity: true,
    tarballReview: {
      enabled: true,
      maxBytes: 5242880,
      networkFailure: 'warn',
    },
  },
};

function reviewDependencies(cwd = process.cwd(), options = {}) {
  const root = path.resolve(cwd);
  const config = effectiveSupplyChainConfig(root, options.config);
  const packageManager = options.packageManager || 'auto';
  const baseRef = options.baseRef || 'HEAD';
  const current = collectDependencies(root);
  const previous = collectDependencies(root, { ref: baseRef });
  const diff = depsDiff(root, { baseRef });
  const changedItems = reviewItemsFromDiff(diff, { packageManager });
  return reviewItems(root, changedItems, { ...options, baseRef, config, current, previous, diff, packageManager });
}

function reviewPackageSpecs(cwd = process.cwd(), specs = [], options = {}) {
  const root = path.resolve(cwd);
  const config = effectiveSupplyChainConfig(root, options.config);
  const items = specs
    .map((spec) => dependencyFromSpec(spec))
    .filter(Boolean)
    .map((dependency) => ({ changeType: 'explicit', dependency }));
  return reviewItems(root, items, { ...options, config, current: null, previous: null, diff: null, packageManager: options.packageManager || 'auto' });
}

function reviewItems(cwd, items, options = {}) {
  const config = options.config || effectiveSupplyChainConfig(cwd);
  const metadataConfig = normalizeMetadataConfig(config.metadata || defaultSupplyChain.metadata);
  const findings = [];
  const reviewed = [];
  let metadataLookups = 0;
  let metadataSkipped = 0;

  for (const item of items) {
    const dependency = item.dependency;
    const review = {
      changeType: item.changeType,
      packageManager: packageManagerFor(dependency.lockfile, options.packageManager),
      lockfile: dependency.lockfile || null,
      name: dependency.name,
      version: dependency.version || '',
      registry: dependency.registry || 'registry.npmjs.org',
      source: dependency.source || '',
      integrity: dependency.metadata?.integrity || '',
      lifecycle: Boolean(dependency.metadata?.hasInstallScript),
      bin: Boolean(dependency.metadata?.bin),
      metadata: { status: metadataEnabled(metadataConfig) ? 'pending' : 'disabled' },
      tarball: { status: metadataEnabled(metadataConfig) && tarballReviewEnabled(metadataConfig) ? 'pending' : 'disabled' },
      privacy: { status: 'allowed', reason: '' },
      findings: [],
      recommendedActions: [],
    };
    const privacy = privacyDecision(dependency, metadataConfig);
    review.privacy = privacy;
    if (!metadataEnabled(metadataConfig)) {
      review.metadata = { status: 'disabled' };
      review.tarball = { status: 'disabled' };
    } else if (!privacy.allowed) {
      metadataSkipped += 1;
      review.metadata = { status: 'skipped' };
      review.tarball = { status: 'skipped' };
      review.recommendedActions.push(privacy.action);
    } else if (metadataLookups >= Number(metadataConfig.maxPackagesPerRun || 20)) {
      metadataSkipped += 1;
      review.metadata = { status: 'skipped', reason: 'metadata lookup budget exhausted' };
      review.tarball = { status: 'skipped', reason: 'metadata lookup budget exhausted' };
      review.recommendedActions.push('Increase supplyChain.metadata.maxPackagesPerRun or review remaining packages manually.');
    } else {
      metadataLookups += 1;
      const metadata = fetchPackageMetadata(cwd, dependency, metadataConfig, options);
      review.metadata = metadata.summary;
      review.tarball = metadata.tarball || review.tarball;
      for (const finding of metadata.findings) {
        const enriched = { ...finding, dependency };
        findings.push(enriched);
        review.findings.push(enriched);
      }
      review.recommendedActions.push(...metadata.recommendedActions);
    }
    reviewed.push(review);
  }

  return {
    cwd,
    ok: !findings.some((finding) => blocksReview(finding, metadataConfig)),
    baseRef: options.baseRef || 'HEAD',
    packageManager: options.packageManager || 'auto',
    summary: {
      reviewed: reviewed.length,
      metadataLookups,
      metadataSkipped,
      findings: findings.length,
      blockedFindings: findings.filter((finding) => blocksReview(finding, metadataConfig)).length,
      warningFindings: findings.filter((finding) => !blocksReview(finding, metadataConfig)).length,
    },
    config: { metadata: metadataConfig },
    dependencies: reviewed,
    findings,
    diff: options.diff || null,
  };
}

function reviewItemsFromDiff(diff, options = {}) {
  const items = [];
  for (const dep of diff.added || []) {
    if (includePackageManager(dep, options.packageManager)) {
      items.push({ changeType: 'added', dependency: dep });
    }
  }
  for (const change of diff.changed || []) {
    if (includePackageManager(change.after, options.packageManager)) {
      items.push({ changeType: 'changed', dependency: change.after });
    }
  }
  return items;
}

function fetchPackageMetadata(cwd, dependency, metadataConfig, options = {}) {
  const registryBaseUrl = registryBaseUrlFor(dependency, metadataConfig, options);
  const url = `${registryBaseUrl.replace(/\/$/, '')}/${encodeURIComponent(dependency.name).replace(/^%40/, '@')}`;
  const cached = readCache(cwd, dependency, metadataConfig);
  if (cached) {
    return metadataAnalysis(dependency, cached.json, { source: 'cache', url, metadataConfig });
  }
  const response = options.fetchMetadata
    ? options.fetchMetadata(url, dependency)
    : fetchJsonSync(url, { timeoutMs: metadataConfig.timeoutMs });
  if (!response.ok) {
    const severity = metadataConfig.networkFailure === 'block' ? 'high' : 'medium';
    return {
      summary: { status: 'unavailable', url, reason: response.error || `HTTP ${response.status || 'unknown'}` },
      findings: [{
        id: 'dependency-metadata-unavailable',
        severity,
        file: dependency.lockfile || 'package.json',
        line: 1,
        detail: `Package metadata unavailable for ${dependency.name}: ${response.error || response.status || 'unknown error'}`,
      }],
      recommendedActions: ['Review the package manually or rerun when the registry is reachable.'],
    };
  }
  writeCache(cwd, dependency, response.json);
  return metadataAnalysis(dependency, response.json, { source: 'network', url, metadataConfig, cwd, options });
}

function metadataAnalysis(dependency, json, options = {}) {
  const metadataConfig = options.metadataConfig || defaultSupplyChain.metadata;
  const latest = json?.['dist-tags']?.latest || '';
  const version = dependency.version || latest;
  const versionInfo = json?.versions?.[version] || {};
  const publishedAt = json?.time?.[version] || null;
  const createdAt = json?.time?.created || null;
  const modifiedAt = json?.time?.modified || null;
  const maintainers = Array.isArray(json?.maintainers) ? json.maintainers : [];
  const dist = versionInfo.dist || {};
  const findings = [];
  const recommendedActions = [];
  const summary = {
    status: 'complete',
    source: options.source,
    url: options.url,
    packageName: json?.name || dependency.name,
    requestedVersion: dependency.version || '',
    resolvedVersion: version,
    latest,
    publishedAt,
    packageCreatedAt: createdAt,
    packageModifiedAt: modifiedAt,
    maintainerCount: maintainers.length,
    deprecated: versionInfo.deprecated || '',
    provenance: Boolean(dist.attestations || dist.signatures),
    tarball: dist.tarball || '',
    integrity: dist.integrity || '',
  };

  if (versionInfo.deprecated) {
    const securitySignal = /malware|security|compromis|vulnerab|hijack|phish|token|credential/i.test(String(versionInfo.deprecated));
    findings.push({
      id: securitySignal ? 'dependency-metadata-security-deprecated' : 'dependency-metadata-deprecated',
      severity: securitySignal ? 'high' : 'medium',
      file: dependency.lockfile || 'package.json',
      line: 1,
      detail: `${dependency.name}@${version} is deprecated: ${versionInfo.deprecated}`,
    });
    recommendedActions.push(`Avoid ${dependency.name}@${version}; choose a reviewed non-deprecated version.`);
  }

  if (publishedAt) {
    const ageHours = (Date.now() - new Date(publishedAt).getTime()) / 3600000;
    summary.releaseAgeHours = Math.max(0, Math.round(ageHours * 10) / 10);
    if (ageHours >= 0 && ageHours < Number(metadataConfig.releaseCooldownHours || 0)) {
      findings.push({
        id: 'dependency-metadata-release-cooldown',
        severity: 'high',
        file: dependency.lockfile || 'package.json',
        line: 1,
        detail: `${dependency.name}@${version} was published ${summary.releaseAgeHours}h ago, inside the ${metadataConfig.releaseCooldownHours}h cooldown window.`,
      });
      recommendedActions.push(`Wait for the ${metadataConfig.releaseCooldownHours}h cooldown or require explicit owner review before installing ${dependency.name}@${version}.`);
    }
  }

  if (createdAt) {
    const ageDays = (Date.now() - new Date(createdAt).getTime()) / 86400000;
    summary.packageAgeDays = Math.max(0, Math.round(ageDays * 10) / 10);
    if (ageDays >= 0 && ageDays < Number(metadataConfig.packageAgeMinimumDays || 0)) {
      findings.push({
        id: 'dependency-metadata-new-package',
        severity: 'medium',
        file: dependency.lockfile || 'package.json',
        line: 1,
        detail: `${dependency.name} package was created ${summary.packageAgeDays}d ago, inside the ${metadataConfig.packageAgeMinimumDays}d package-age review window.`,
      });
      recommendedActions.push(`Require owner review before adopting newly created package ${dependency.name}.`);
    }
  }

  if (modifiedAt) {
    const modifiedAgeHours = (Date.now() - new Date(modifiedAt).getTime()) / 3600000;
    summary.packageModifiedAgeHours = Math.max(0, Math.round(modifiedAgeHours * 10) / 10);
    if (modifiedAgeHours >= 0 && modifiedAgeHours < Number(metadataConfig.packageModifiedCooldownHours || 0)) {
      findings.push({
        id: 'dependency-metadata-recent-package-modification',
        severity: 'medium',
        file: dependency.lockfile || 'package.json',
        line: 1,
        detail: `${dependency.name} package metadata changed ${summary.packageModifiedAgeHours}h ago, inside the ${metadataConfig.packageModifiedCooldownHours}h metadata cooldown window.`,
      });
      recommendedActions.push(`Review recent package metadata changes before accepting ${dependency.name}@${version}.`);
    }
  }

  if (maintainers.length === 0) {
    findings.push({
      id: 'dependency-metadata-no-maintainers',
      severity: 'medium',
      file: dependency.lockfile || 'package.json',
      line: 1,
      detail: `${dependency.name} registry metadata does not list maintainers.`,
    });
    recommendedActions.push(`Review maintainer/package ownership for ${dependency.name}.`);
  }

  if (metadataConfig.requireIntegrity !== false && !dependency.metadata?.integrity && !dist.integrity) {
    findings.push({
      id: 'dependency-metadata-missing-integrity',
      severity: 'medium',
      file: dependency.lockfile || 'package.json',
      line: 1,
      detail: `${dependency.name}@${version} has no lockfile or registry integrity value available to ExecFence.`,
    });
    recommendedActions.push(`Regenerate the lockfile with integrity metadata before accepting ${dependency.name}@${version}.`);
  }

  if (!summary.provenance && metadataConfig.provenancePolicy && metadataConfig.provenancePolicy !== 'off') {
    findings.push({
      id: 'dependency-metadata-missing-provenance',
      severity: metadataConfig.provenancePolicy === 'block' ? 'high' : 'medium',
      file: dependency.lockfile || 'package.json',
      line: 1,
      detail: `${dependency.name}@${version} registry metadata does not expose provenance/signature attestations.`,
    });
    recommendedActions.push(`Require provenance review or a documented exception for ${dependency.name}@${version}.`);
  }

  if (!versionInfo.dist) {
    findings.push({
      id: 'dependency-metadata-version-missing',
      severity: 'medium',
      file: dependency.lockfile || 'package.json',
      line: 1,
      detail: `Registry metadata did not include ${dependency.name}@${version}.`,
    });
    recommendedActions.push('Verify the lockfile version against the registry and package manager cache.');
  }

  if (recommendedActions.length === 0) {
    recommendedActions.push('No metadata risk signals found for this changed dependency.');
  }
  const tarball = tarballReview(options.cwd, dependency, {
    metadataConfig,
    url: dist.tarball || '',
    integrity: dependency.metadata?.integrity || dist.integrity || '',
    options: options.options || {},
  });
  findings.push(...tarball.findings);
  recommendedActions.push(...tarball.recommendedActions);
  return { summary, findings, recommendedActions, tarball: tarball.summary };
}

function tarballReview(cwd, dependency, options = {}) {
  const metadataConfig = options.metadataConfig || defaultSupplyChain.metadata;
  const tarballConfig = normalizeTarballConfig(metadataConfig.tarballReview);
  if (!tarballReviewEnabled(metadataConfig)) {
    return { summary: { status: 'disabled' }, findings: [], recommendedActions: [] };
  }
  if (!options.url) {
    return { summary: { status: 'skipped', reason: 'missing tarball url' }, findings: [], recommendedActions: ['Review package contents manually because registry metadata did not include a tarball URL.'] };
  }
  const response = options.options.fetchTarball
    ? options.options.fetchTarball(options.url, dependency)
    : fetchBufferSync(options.url, { timeoutMs: metadataConfig.timeoutMs, maxBytes: tarballConfig.maxBytes });
  if (!response.ok) {
    const severity = tarballConfig.networkFailure === 'block' ? 'high' : 'medium';
    return {
      summary: { status: 'unavailable', url: options.url, reason: response.error || `HTTP ${response.status || 'unknown'}` },
      findings: [{
        id: 'dependency-tarball-unavailable',
        severity,
        file: dependency.lockfile || 'package.json',
        line: 1,
        detail: `Package tarball unavailable for ${dependency.name}: ${response.error || response.status || 'unknown error'}`,
      }],
      recommendedActions: ['Review the package tarball manually or rerun when the registry is reachable.'],
    };
  }
  const bytes = Buffer.isBuffer(response.bytes) ? response.bytes : Buffer.from(response.bytes || '', response.encoding || 'base64');
  const findings = [];
  const recommendedActions = [];
  const integrity = verifyIntegrity(bytes, options.integrity);
  if (integrity.status === 'mismatch') {
    findings.push({
      id: 'dependency-tarball-integrity-mismatch',
      severity: 'high',
      file: dependency.lockfile || 'package.json',
      line: 1,
      detail: `${dependency.name} tarball integrity mismatch: expected ${integrity.expected}, got ${integrity.actual}.`,
    });
    recommendedActions.push(`Do not install ${dependency.name}; regenerate lockfile only after verifying the registry artifact.`);
  }
  const entries = parseTarball(bytes);
  const audit = auditTarballEntries(dependency, entries);
  findings.push(...audit.findings);
  recommendedActions.push(...audit.recommendedActions);
  if (recommendedActions.length === 0) {
    recommendedActions.push('No tarball content risk signals found for this changed dependency.');
  }
  return {
    summary: {
      status: 'complete',
      url: options.url,
      bytes: bytes.length,
      files: entries.length,
      integrity,
    },
    findings,
    recommendedActions,
  };
}

function auditTarballEntries(dependency, entries) {
  const findings = [];
  const recommendedActions = [];
  for (const entry of entries) {
    const ext = path.extname(entry.name).toLowerCase();
    if (/\b(?:\.exe|\.dll|\.scr|\.bat|\.cmd|\.vbs|\.wsf|\.asar)$/i.test(ext)) {
      findings.push(tarballFinding('dependency-tarball-dangerous-artifact', 'high', dependency, entry, `Package tarball includes dangerous artifact ${entry.name}.`));
    } else if (/\b(?:\.node|\.so|\.dylib|\.ps1|\.sh|\.jar)$/i.test(ext)) {
      findings.push(tarballFinding('dependency-tarball-executable-adjacent-artifact', 'medium', dependency, entry, `Package tarball includes executable-adjacent artifact ${entry.name}.`));
    }
    if (entry.content && isCodeLikeTarballFile(entry.name)) {
      const content = entry.content;
      if (isObfuscated(content)) {
        findings.push(tarballFinding('dependency-tarball-obfuscated-code', 'high', dependency, entry, `Package tarball includes obfuscation-like code in ${entry.name}.`));
      }
      if (/(?:child_process|spawn\s*\(|execFile\s*\(|exec\s*\(|https?\.request|fetch\s*\(|XMLHttpRequest|process\.env|\.npmrc|SSH_AUTH_SOCK|GITHUB_TOKEN|NPM_TOKEN)/i.test(content)) {
        findings.push(tarballFinding('dependency-tarball-runtime-sensitive-code', 'high', dependency, entry, `Package tarball code references process/network/credential-sensitive APIs in ${entry.name}.`));
      }
    }
  }
  if (findings.length > 0) {
    recommendedActions.push(`Review ${dependency.name} tarball contents before install, bundle, or runtime import.`);
  }
  return { findings, recommendedActions };
}

function tarballFinding(id, severity, dependency, entry, detail) {
  return {
    id,
    severity,
    file: `${dependency.lockfile || 'package.json'}:${entry.name}`,
    line: 1,
    detail,
  };
}

function privacyDecision(dependency, metadataConfig = defaultSupplyChain.metadata) {
  if (dependency.ecosystem !== 'npm') {
    return { allowed: false, status: 'skipped', reason: 'non-npm ecosystem', action: 'No npm registry lookup is needed for this ecosystem.' };
  }
  const registry = dependency.registry || 'registry.npmjs.org';
  if (!allowedRegistry(registry, metadataConfig)) {
    return {
      allowed: false,
      status: 'skipped',
      reason: `registry ${registry || 'unknown'} is not allowlisted`,
      action: 'Add the registry to supplyChain.metadata.allowedRegistries only if package names may be sent there.',
    };
  }
  const scope = dependency.name.startsWith('@') ? dependency.name.split('/')[0] : '';
  if (scope && metadataConfig.privateScopePolicy !== 'allow' && !(metadataConfig.allowedPublicScopes || []).includes(scope)) {
    return {
      allowed: false,
      status: 'skipped',
      reason: `scoped package ${scope} is private-safe by default`,
      action: `Add ${scope} to supplyChain.metadata.allowedPublicScopes if it is public and safe to query.`,
    };
  }
  return { allowed: true, status: 'allowed', reason: '' };
}

function allowedRegistry(registry, metadataConfig = defaultSupplyChain.metadata) {
  const allowed = metadataConfig.allowedRegistries || ['registry.npmjs.org'];
  return allowed.some((item) => normalizeRegistry(item) === normalizeRegistry(registry));
}

function registryBaseUrlFor(dependency, metadataConfig, options = {}) {
  if (options.registryBaseUrl) {
    return options.registryBaseUrl;
  }
  const registry = dependency.registry || 'registry.npmjs.org';
  return /^https?:\/\//i.test(registry) ? registry : `https://${registry}`;
}

function readCache(cwd, dependency, metadataConfig = defaultSupplyChain.metadata) {
  const filePath = cachePath(cwd, dependency);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const ttl = Number(metadataConfig.cacheTtlMs ?? 86400000);
  if (ttl >= 0 && Date.now() - fs.statSync(filePath).mtimeMs > ttl) {
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function writeCache(cwd, dependency, json) {
  const filePath = cachePath(cwd, dependency);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify({ json, cachedAt: new Date().toISOString() }, null, 2)}\n`);
}

function cachePath(cwd, dependency) {
  const safeName = dependency.name.replace(/[^A-Za-z0-9._-]+/g, '_');
  const version = (dependency.version || 'latest').replace(/[^A-Za-z0-9._-]+/g, '_');
  return path.join(cwd, cacheDir, `${safeName}-${version}.json`);
}

function syncPromise(promise) {
  const { execFileSync } = require('node:child_process');
  const script = `
const http = require('node:http');
const https = require('node:https');
const url = ${JSON.stringify(promise.url)};
const timeoutMs = ${Number(promise.timeoutMs || 2500)};
const client = url.startsWith('https:') ? https : http;
const req = client.get(url, { timeout: timeoutMs, headers: { accept: 'application/json', 'user-agent': 'execfence' } }, (res) => {
  let body = '';
  res.setEncoding('utf8');
  res.on('data', (chunk) => body += chunk);
  res.on('end', () => {
    try {
      console.log(JSON.stringify({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, json: body ? JSON.parse(body) : null }));
    } catch (error) {
      console.log(JSON.stringify({ ok: false, status: res.statusCode, error: error.message }));
    }
  });
});
req.on('timeout', () => req.destroy(new Error('metadata request timed out')));
req.on('error', (error) => console.log(JSON.stringify({ ok: false, error: error.message })));
`;
  try {
    return JSON.parse(execFileSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: Number(promise.timeoutMs || 2500) + 1000 }));
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function fetchBufferSync(url, options = {}) {
  const { execFileSync } = require('node:child_process');
  const script = `
const http = require('node:http');
const https = require('node:https');
const url = ${JSON.stringify(url)};
const timeoutMs = ${Number(options.timeoutMs || 2500)};
const maxBytes = ${Number(options.maxBytes || 5242880)};
const client = url.startsWith('https:') ? https : http;
const req = client.get(url, { timeout: timeoutMs, headers: { accept: 'application/octet-stream', 'user-agent': 'execfence' } }, (res) => {
  const chunks = [];
  let size = 0;
  res.on('data', (chunk) => {
    size += chunk.length;
    if (size > maxBytes) {
      req.destroy(new Error('tarball response too large'));
      return;
    }
    chunks.push(chunk);
  });
  res.on('end', () => {
    const body = Buffer.concat(chunks);
    console.log(JSON.stringify({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, bytes: body.toString('base64'), encoding: 'base64' }));
  });
});
req.on('timeout', () => req.destroy(new Error('tarball request timed out')));
req.on('error', (error) => console.log(JSON.stringify({ ok: false, error: error.message })));
`;
  try {
    return JSON.parse(execFileSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: Number(options.timeoutMs || 2500) + 1000 }));
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function effectiveSupplyChainConfig(cwd, override = {}) {
  const loaded = loadConfig(cwd).config || {};
  return mergeSupplyChain(defaultSupplyChain, loaded.supplyChain || {}, override || {});
}

function mergeSupplyChain(...items) {
  return items.reduce((acc, item) => ({
    ...acc,
    ...item,
    metadata: {
      ...(acc.metadata || {}),
      ...(item.metadata || {}),
      tarballReview: {
        ...(acc.metadata?.tarballReview || {}),
        ...(item.metadata?.tarballReview || {}),
      },
    },
  }), {});
}

function normalizeMetadataConfig(metadataConfig) {
  return {
    ...defaultSupplyChain.metadata,
    ...(metadataConfig || {}),
  };
}

function metadataEnabled(metadataConfig) {
  return metadataConfig.enabled !== false && metadataConfig.mode !== 'off';
}

function normalizeTarballConfig(tarballConfig) {
  return {
    ...defaultSupplyChain.metadata.tarballReview,
    ...(tarballConfig || {}),
  };
}

function tarballReviewEnabled(metadataConfig) {
  return metadataEnabled(metadataConfig) && normalizeTarballConfig(metadataConfig.tarballReview).enabled !== false;
}

function blocksReview(finding, metadataConfig) {
  if ((metadataConfig.mode || 'guarded') === 'audit') {
    return false;
  }
  return ['critical', 'high'].includes(finding.severity);
}

function includePackageManager(dep, filter = 'auto') {
  if (!filter || filter === 'auto') {
    return ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'].includes(dep.lockfile);
  }
  return packageManagerFor(dep.lockfile) === filter;
}

function packageManagerFor(lockfile, fallback = 'auto') {
  if (lockfile === 'package-lock.json') return 'npm';
  if (lockfile === 'pnpm-lock.yaml') return 'pnpm';
  if (lockfile === 'yarn.lock') return 'yarn';
  return fallback || 'auto';
}

function dependencyFromSpec(spec) {
  if (!spec || spec.startsWith('-') || /^https?:|^git[+:]|^file:|^[./~]/.test(spec)) {
    return null;
  }
  const withoutAlias = spec.includes('@npm:') ? spec.split('@npm:').pop() : spec;
  const match = withoutAlias.startsWith('@')
    ? withoutAlias.match(/^(@[^/]+\/[^@]+)(?:@(.+))?$/)
    : withoutAlias.match(/^([^@]+)(?:@(.+))?$/);
  if (!match) {
    return null;
  }
  return {
    ecosystem: 'npm',
    name: match[1],
    version: match[2] || '',
    source: 'https://registry.npmjs.org',
    registry: 'registry.npmjs.org',
    lockfile: '',
    metadata: {},
  };
}

function normalizeRegistry(value) {
  return String(value || '')
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .toLowerCase();
}

function formatReviewText(result) {
  const lines = [
    `[execfence] dependency review: ${result.summary.reviewed} changed package(s), ${result.summary.findings} finding(s)`,
    `[execfence] metadata: ${result.summary.metadataLookups} lookup(s), ${result.summary.metadataSkipped} skipped`,
  ];
  for (const dep of result.dependencies) {
    lines.push(`- ${dep.changeType} ${dep.name}@${dep.version || dep.metadata.resolvedVersion || 'unknown'} (${dep.packageManager}, ${dep.lockfile || 'explicit'})`);
    if (dep.privacy.status !== 'allowed') {
      lines.push(`  privacy: ${dep.privacy.reason}`);
    }
    if (dep.metadata.status && dep.metadata.status !== 'complete') {
      lines.push(`  metadata: ${dep.metadata.status}${dep.metadata.reason ? ` (${dep.metadata.reason})` : ''}`);
    }
    if (dep.tarball?.status && dep.tarball.status !== 'complete') {
      lines.push(`  tarball: ${dep.tarball.status}${dep.tarball.reason ? ` (${dep.tarball.reason})` : ''}`);
    }
    for (const finding of dep.findings) {
      lines.push(`  [${finding.severity}] ${finding.id}: ${finding.detail}`);
    }
    for (const action of dep.recommendedActions.slice(0, 2)) {
      lines.push(`  action: ${action}`);
    }
  }
  if (result.dependencies.length === 0) {
    lines.push('- no npm/pnpm/yarn dependency changes found');
  }
  return lines.join('\n');
}

function fetchJsonSync(url, options = {}) {
  return syncPromise({ url, timeoutMs: options.timeoutMs });
}

function parseTarball(bytes) {
  let data = bytes;
  try {
    data = zlib.gunzipSync(bytes);
  } catch {
    data = bytes;
  }
  const entries = [];
  for (let offset = 0; offset + 512 <= data.length;) {
    const header = data.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      break;
    }
    const name = tarString(header, 0, 100);
    const prefix = tarString(header, 345, 155);
    const sizeText = tarString(header, 124, 12).trim();
    const size = Number.parseInt(sizeText.replace(/\0/g, '').trim() || '0', 8) || 0;
    const type = tarString(header, 156, 1) || '0';
    offset += 512;
    const contentBytes = data.subarray(offset, offset + size);
    const fullName = [prefix, name].filter(Boolean).join('/');
    if (fullName && (type === '0' || type === '')) {
      entries.push({
        name: fullName.replace(/^package\//, ''),
        size,
        content: size <= 200000 && !contentBytes.includes(0) ? contentBytes.toString('utf8') : '',
      });
    }
    offset += Math.ceil(size / 512) * 512;
  }
  return entries;
}

function tarString(buffer, start, length) {
  return buffer.subarray(start, start + length).toString('utf8').replace(/\0.*$/, '').trim();
}

function verifyIntegrity(bytes, expected) {
  if (!expected) {
    return { status: 'missing' };
  }
  const match = String(expected).match(/^(sha(?:256|384|512))-([A-Za-z0-9+/=]+)$/);
  if (!match) {
    return { status: 'unsupported', expected };
  }
  const algorithm = match[1];
  const actualDigest = crypto.createHash(algorithm).update(bytes).digest('base64');
  const actual = `${algorithm}-${actualDigest}`;
  return actual === expected ? { status: 'match', expected, actual } : { status: 'mismatch', expected, actual };
}

function isCodeLikeTarballFile(name) {
  return /\.(?:cjs|js|jsx|mjs|ts|tsx)$/i.test(name) || /^bin\//.test(name);
}

function isObfuscated(content) {
  const hasLoaderPrimitive = /eval\s*\(|Function\s*\(|fromCharCode|atob\s*\(/i.test(content);
  const hasEncodedBlob = /\\x[0-9a-f]{2}|[A-Za-z0-9+/]{800,}={0,2}/i.test(content);
  const hasLongCodeLine = content.split(/\r?\n/).some((line) => line.length > 2000 && /[;{}()[\]]/.test(line));
  return hasLoaderPrimitive && (hasEncodedBlob || hasLongCodeLine);
}

module.exports = {
  defaultSupplyChain,
  dependencyFromSpec,
  effectiveSupplyChainConfig,
  formatReviewText,
  packageManagerFor,
  privacyDecision,
  reviewDependencies,
  reviewPackageSpecs,
  fetchJsonSync,
  parseTarball,
};
