'use strict';

const { parentPort, workerData } = require('node:worker_threads');
const { reviewItems } = require('./deps-review');

try {
  const result = reviewItems(workerData.cwd, [workerData.item], workerData.context);
  parentPort.postMessage({ ok: true, result });
} catch (error) {
  parentPort.postMessage({ ok: false, error: error.stack || error.message });
} finally {
  parentPort.close();
}
