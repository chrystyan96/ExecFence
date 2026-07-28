'use strict';

const { scan } = require('./scanner');
const { runWithFence } = require('./runtime');
const { runCi } = require('./ci');
const { evaluateFinding, evaluateFindings } = require('./decision-engine');
const { reviewDependencies, reviewDependenciesConcurrent, comparePackageVersions } = require('./deps-review');
const { generateManifest, diffManifest, manifestHash } = require('./manifest');
const { generateSbom } = require('./sbom');
const { sandboxCapabilities, sandboxPlan } = require('./sandbox');
const { createApproval, signApproval, auditApprovals, verifyApproval } = require('./approvals');
const { assertFinding, assertResult, contractVersions } = require('./contracts');

module.exports = Object.freeze({
  approvals: Object.freeze({ audit: auditApprovals, create: createApproval, sign: signApproval, verify: verifyApproval }),
  contracts: Object.freeze({ assertFinding, assertResult, versions: contractVersions }),
  decide: evaluateFindings,
  decideFinding: evaluateFinding,
  dependencies: Object.freeze({ compareVersions: comparePackageVersions, review: reviewDependencies, reviewConcurrent: reviewDependenciesConcurrent }),
  manifest: Object.freeze({ diff: diffManifest, generate: generateManifest, hash: manifestHash }),
  run: runWithFence,
  runCi,
  sandbox: Object.freeze({ capabilities: sandboxCapabilities, plan: sandboxPlan }),
  sbom: generateSbom,
  scan,
});
