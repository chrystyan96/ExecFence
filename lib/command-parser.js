'use strict';

const valueOptions = {
  npm: new Set(['--cache', '--cpu', '--include', '--install-strategy', '--libc', '--omit', '--os', '--prefix', '--registry', '--scope', '--tag', '--userconfig', '--workspace', '-w']),
  npx: new Set(['--cache', '--call', '-c', '--package', '-p', '--prefix', '--registry', '--userconfig']),
  pnpm: new Set(['--config-dir', '--dir', '-C', '--filter', '-F', '--global-dir', '--registry', '--store-dir', '--workspace-dir']),
  yarn: new Set(['--cache-folder', '--cwd', '--modules-folder', '--mutex', '--network-timeout', '--registry', '--use-yarnrc']),
  bun: new Set(['--backend', '--cache-dir', '--cwd', '--filter', '--registry']),
  pip: new Set(['--cache-dir', '--cert', '--client-cert', '--constraint', '-c', '--find-links', '-f', '--index-url', '-i', '--proxy', '--requirement', '-r', '--retries', '--timeout', '--trusted-host']),
  pipx: new Set(['--index-url', '--pip-args', '--python', '--suffix']),
  uv: new Set(['--cache-dir', '--config-file', '--directory', '--index', '--index-url', '--project', '--python', '--resolution']),
  poetry: new Set(['--directory', '-C', '--project', '-P', '--source']),
  cargo: new Set(['--branch', '--color', '--config', '--git', '--manifest-path', '--path', '--registry', '--rev', '--tag', '--target', '--target-dir', '--version']),
  go: new Set(['-C', '-mod', '-modfile', '-overlay', '-p', '-pkgdir', '-tags']),
  mvn: new Set(['-f', '--file', '-P', '--activate-profiles', '-s', '--settings', '-t', '--toolchains']),
  gradle: new Set(['-b', '--build-file', '-c', '--settings-file', '-g', '--gradle-user-home', '-p', '--project-dir']),
  dotnet: new Set(['--arch', '--configuration', '-c', '--framework', '-f', '--os', '--project', '--runtime', '-r']),
  composer: new Set(['--dir', '-d', '--repository', '--working-dir']),
  bundle: new Set(['--gemfile', '--path', '--without', '--with']),
};

const commandAliases = {
  pip3: 'pip',
  yarnpkg: 'yarn',
  bunx: 'npx',
  mvnw: 'mvn',
  gradlew: 'gradle',
  bundler: 'bundle',
};

function parseToolCommand(tool, args = [], knownCommands = []) {
  const normalizedTool = commandAliases[String(tool || '').toLowerCase()] || String(tool || '').toLowerCase();
  const known = new Set(knownCommands);
  const optionsWithValues = valueOptions[normalizedTool] || new Set();
  let fallback = null;

  for (let index = 0; index < args.length; index += 1) {
    const arg = String(args[index] || '');
    if (!arg || arg === '--') {
      continue;
    }
    if (known.has(arg)) {
      return { command: arg, commandIndex: index, ambiguous: false };
    }
    if (arg.startsWith('-')) {
      const option = arg.split('=')[0];
      if (!arg.includes('=') && optionsWithValues.has(option)) {
        index += 1;
      }
      continue;
    }
    fallback ||= { command: arg, commandIndex: index, ambiguous: true };
  }

  return fallback || { command: 'install', commandIndex: -1, ambiguous: true };
}

function argumentsAfterCommand(parsed, args = []) {
  return parsed.commandIndex >= 0 ? args.slice(parsed.commandIndex + 1) : [];
}

function optionTakesValue(tool, option) {
  const normalizedTool = commandAliases[String(tool || '').toLowerCase()] || String(tool || '').toLowerCase();
  return (valueOptions[normalizedTool] || new Set()).has(String(option || '').split('=')[0]);
}

module.exports = {
  argumentsAfterCommand,
  optionTakesValue,
  parseToolCommand,
};
