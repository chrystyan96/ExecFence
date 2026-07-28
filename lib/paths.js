'use strict';

const fs = require('node:fs');
const path = require('node:path');

const projectDirName = '.execfence';
const configDirName = 'config';
const reportsDirName = 'reports';
const configFileName = `${projectDirName}/${configDirName}/execfence.json`;
const signaturesFileName = `${projectDirName}/${configDirName}/signatures.json`;
const baselineFileName = `${projectDirName}/${configDirName}/baseline.json`;
const reportsDir = `${projectDirName}/${reportsDirName}`;

function projectPath(cwd, relativePath) {
  return path.join(cwd, relativePath);
}

function resolveProjectPath(cwd, configuredPath, fallback = '.') {
  const root = path.resolve(cwd);
  const value = configuredPath == null || configuredPath === '' ? fallback : String(configuredPath);
  if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value)) {
    throw new Error(`Configured path must be relative to the project root: ${value}`);
  }
  const candidate = path.resolve(root, value);
  if (!isWithin(root, candidate)) {
    throw new Error(`Configured path escapes project root: ${value}`);
  }

  const realRoot = realPath(root);
  let existing = candidate;
  while (!fs.existsSync(existing)) {
    const parent = path.dirname(existing);
    if (parent === existing) break;
    existing = parent;
  }
  const realExisting = realPath(existing);
  const resolvedThroughLinks = path.resolve(realExisting, path.relative(existing, candidate));
  if (!isWithin(realRoot, resolvedThroughLinks)) {
    throw new Error(`Configured path escapes project root through a symbolic link: ${value}`);
  }
  return candidate;
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
}

function realPath(value) {
  try {
    return fs.realpathSync.native(value);
  } catch {
    return path.resolve(value);
  }
}

module.exports = {
  baselineFileName,
  configDirName,
  configFileName,
  projectDirName,
  projectPath,
  resolveProjectPath,
  reportsDir,
  reportsDirName,
  signaturesFileName,
};
