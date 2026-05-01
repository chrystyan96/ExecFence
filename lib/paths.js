'use strict';

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

module.exports = {
  baselineFileName,
  configDirName,
  configFileName,
  projectDirName,
  projectPath,
  reportsDir,
  reportsDirName,
  signaturesFileName,
};
