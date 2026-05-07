'use strict';

const fs = require('node:fs');
const path = require('node:path');

const sensitiveLifecycleScripts = new Set(['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack', 'prepublishOnly']);

function wireProject(cwd = process.cwd(), options = {}) {
  const dryRun = options.dryRun !== false;
  const changes = [];
  wirePackageJson(cwd, changes, { dryRun });
  wireWorkflows(cwd, changes, { dryRun });
  wireMakefile(cwd, changes, { dryRun });
  wireVscodeTasks(cwd, changes, { dryRun });
  return { cwd, dryRun, ok: true, changes };
}

function wirePackageJson(cwd, changes, options) {
  const filePath = path.join(cwd, 'package.json');
  if (!fs.existsSync(filePath)) {
    return;
  }
  const pkg = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const scripts = pkg.scripts || {};
  let changed = false;
  for (const name of ['test', 'build', 'dev', 'start', 'pack', 'publish', 'preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack', 'prepublishOnly']) {
    if (scripts[name] && shouldWrapPackageScript(name, scripts[name])) {
      changes.push(change('package-json-script', 'package.json', name, scripts[name], `execfence run -- ${scripts[name]}`));
      scripts[name] = `execfence run -- ${scripts[name]}`;
      changed = true;
    }
  }
  if (!scripts['execfence:ci']) {
    scripts['execfence:ci'] = 'execfence ci';
    changes.push(change('package-json-script', 'package.json', 'execfence:ci', null, scripts['execfence:ci']));
    changed = true;
  }
  if (changed && !options.dryRun) {
    pkg.scripts = scripts;
    fs.writeFileSync(filePath, `${JSON.stringify(pkg, null, 2)}\n`);
  }
}

function wireWorkflows(cwd, changes, options) {
  const dir = path.join(cwd, '.github', 'workflows');
  if (!fs.existsSync(dir)) {
    return;
  }
  for (const name of fs.readdirSync(dir).filter((file) => /\.ya?ml$/i.test(file))) {
    const filePath = path.join(dir, name);
    const rel = path.join('.github', 'workflows', name).replaceAll(path.sep, '/');
    const original = fs.readFileSync(filePath, 'utf8');
    const next = original.replace(/^(\s*-\s*run:\s*)((?:npm\s+(?:test|run\s+build|run\s+dev|run\s+start|pack|publish)\b|pnpm\s+(?:test|run\s+build|run\s+dev|pack|publish)\b|yarn\s+(?:test|build|dev|pack|publish)\b|bun\s+(?:test|run\s+build|run\s+dev)\b|pipx?\s+(?:install|run)\b|uv\s+(?:add|sync|run|pip)\b|poetry\s+(?:add|install|update|run)\b|go\s+(?:get|install|mod|work|run|build|test|generate|vet)\b|cargo\s+(?:add|install|update|fetch|build|test|run|check)\b|mvnw?\s+|gradlew?\s+|dotnet\s+(?:add|restore|build|test|run|pack)\b|composer\s+(?:require|install|update|run-script|exec|test)\b|bundle(?:r)?\s+(?:add|install|update|exec|test)\b|python\s+-m\s+(?:pytest|build)\b|python\s+setup\.py\b|pytest\b|make\s+(?:test|build|dev|pack|publish)\b).*)$/gm, (full, prefix, command) => {
      if (!shouldWrap(command)) {
        return full;
      }
      changes.push(change('workflow-run', rel, command, command, `execfence run -- ${command}`));
      return `${prefix}execfence run -- ${command}`;
    });
    if (next !== original && !options.dryRun) {
      fs.writeFileSync(filePath, next);
    }
  }
}

function wireMakefile(cwd, changes, options) {
  const filePath = path.join(cwd, 'Makefile');
  if (!fs.existsSync(filePath)) {
    return;
  }
  const original = fs.readFileSync(filePath, 'utf8');
  let next = original;
  if (!/^guard:/m.test(next)) {
    next = `${next.trimEnd()}\n\nguard:\n\texecfence scan\n`;
    changes.push(change('make-target', 'Makefile', 'guard', null, 'execfence scan'));
  }
  next = next.replace(/^(build|test|dev|run|pack|publish):([^\r\n]*)$/gm, (full, target, deps) => {
    if (/\bguard\b/.test(deps)) {
      return full;
    }
    changes.push(change('make-target', 'Makefile', target, full, `${target}: guard${deps}`));
    return `${target}: guard${deps}`;
  });
  if (next !== original && !options.dryRun) {
    fs.writeFileSync(filePath, next.endsWith('\n') ? next : `${next}\n`);
  }
}

function wireVscodeTasks(cwd, changes, options) {
  const filePath = path.join(cwd, '.vscode', 'tasks.json');
  if (!fs.existsSync(filePath)) {
    return;
  }
  const original = fs.readFileSync(filePath, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(original);
  } catch {
    return;
  }
  let changed = false;
  for (const task of parsed.tasks || []) {
    if (typeof task.command === 'string' && shouldWrap(task.command)) {
      changes.push(change('vscode-task', '.vscode/tasks.json', task.label || task.command, task.command, `execfence run -- ${task.command}`));
      task.command = `execfence run -- ${task.command}`;
      changed = true;
    }
  }
  if (changed && !options.dryRun) {
    fs.writeFileSync(filePath, `${JSON.stringify(parsed, null, 2)}\n`);
  }
}

function shouldWrap(command = '') {
  const text = String(command);
  return !/execfence\s+run|execfence:ci|execfence\s+ci/.test(text) &&
    /\b(?:npm\s+(?:test|run\s+build|run\s+dev|run\s+start|pack|publish|install|add|ci)|pnpm\s+(?:test|run\s+build|run\s+dev|pack|publish|install|add)|yarn\s+(?:test|build|dev|pack|publish|install|add)|bun\s+(?:test|run\s+build|run\s+dev|install|add)|pipx?\s+(?:install|run)|uv\s+(?:add|sync|run|pip)|poetry\s+(?:add|install|update|run)|node\b|go\s+(?:get|install|mod|work|run|build|test|generate|vet)|cargo\s+(?:add|install|update|fetch|build|test|run|check)|mvnw?\b|gradlew?\b|dotnet\s+(?:add|restore|build|test|run|pack)|composer\s+(?:require|install|update|run-script|exec|test)|bundle(?:r)?\s+(?:add|install|update|exec|test)|python\s+-m\s+(?:pytest|build)|python\s+setup\.py|pytest\b|make\s+(?:test|build|dev|pack|publish)|vite\b|next\b|webpack\b|tauri\b|curl\b|wget\b|powershell\b|bash\b|sh\b)/.test(text);
}

function shouldWrapPackageScript(name, command = '') {
  const text = String(command);
  if (/execfence\s+run|execfence:ci|execfence\s+ci/.test(text)) {
    return false;
  }
  return sensitiveLifecycleScripts.has(name) || shouldWrap(text);
}

function change(type, file, name, before, after) {
  return { type, file, name, before, after };
}

module.exports = {
  wireProject,
};
