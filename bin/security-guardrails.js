#!/usr/bin/env node

const { main } = require('../lib/cli');

main(process.argv.slice(2)).catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
