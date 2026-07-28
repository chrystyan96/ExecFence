'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { collectDependencies } = require('./deps');

function generateSbom(cwd = process.cwd(), options = {}) {
  const root = path.resolve(cwd);
  const inventory = collectDependencies(root, { packageManager: options.packageManager || 'auto' });
  const format = options.format || 'cyclonedx';
  if (format === 'spdx') return spdxDocument(root, inventory);
  if (format !== 'cyclonedx') throw new Error(`Unsupported SBOM format: ${format}`);
  return cyclonedxDocument(root, inventory);
}

function writeSbom(cwd = process.cwd(), options = {}) {
  const document = generateSbom(cwd, options);
  const filePath = path.resolve(cwd, options.output);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(document, null, 2)}\n`);
  return { filePath, document };
}

function cyclonedxDocument(cwd, inventory) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${stableUuid(cwd, inventory.dependencies)}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'ExecFence' }] },
      component: { type: 'application', name: path.basename(cwd), 'bom-ref': 'project:root' },
    },
    components: inventory.dependencies.map((dependency) => ({
      type: 'library',
      'bom-ref': componentRef(dependency),
      group: dependency.name.startsWith('@') ? dependency.name.split('/')[0].slice(1) : undefined,
      name: dependency.name.startsWith('@') ? dependency.name.split('/').slice(1).join('/') : dependency.name,
      version: dependency.version || undefined,
      purl: purl(dependency),
      properties: [
        { name: 'execfence:ecosystem', value: dependency.ecosystem },
        { name: 'execfence:lockfile', value: dependency.lockfile || '' },
        { name: 'execfence:registry', value: dependency.registry || '' },
        { name: 'execfence:source', value: dependency.source || '' },
      ],
    })),
  };
}

function spdxDocument(cwd, inventory) {
  const namespaceHash = crypto.createHash('sha256').update(cwd).digest('hex').slice(0, 24);
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${path.basename(cwd)}-sbom`,
    documentNamespace: `https://execfence.local/spdx/${namespaceHash}`,
    creationInfo: {
      created: new Date().toISOString(),
      creators: ['Tool: ExecFence'],
    },
    packages: inventory.dependencies.map((dependency, index) => ({
      SPDXID: `SPDXRef-Package-${index + 1}`,
      name: dependency.name,
      versionInfo: dependency.version || 'NOASSERTION',
      downloadLocation: dependency.source || 'NOASSERTION',
      filesAnalyzed: false,
      supplier: 'NOASSERTION',
      externalRefs: purl(dependency) ? [{
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: purl(dependency),
      }] : [],
      comment: `ecosystem=${dependency.ecosystem}; lockfile=${dependency.lockfile || ''}; registry=${dependency.registry || ''}`,
    })),
  };
}

function componentRef(dependency) {
  return `pkg:${dependency.ecosystem}:${dependency.name}@${dependency.version || 'unknown'}:${dependency.lockfile || 'explicit'}`;
}

function purl(dependency) {
  const types = {
    npm: 'npm', python: 'pypi', cargo: 'cargo', go: 'golang',
    maven: 'maven', gradle: 'maven', nuget: 'nuget', composer: 'composer', bundler: 'gem',
  };
  const type = types[dependency.ecosystem];
  if (!type || !dependency.name) return null;
  const name = dependency.name.split(':').map(encodeURIComponent).join('/');
  return `pkg:${type}/${name}${dependency.version ? `@${encodeURIComponent(dependency.version)}` : ''}`;
}

function stableUuid(cwd, dependencies) {
  const hex = crypto.createHash('sha256').update(JSON.stringify({
    cwd: path.basename(cwd),
    dependencies: dependencies.map((dependency) => componentRef(dependency)),
  })).digest('hex').slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

module.exports = {
  generateSbom,
  writeSbom,
};
