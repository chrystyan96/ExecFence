'use strict';

function parseVscodeTasks(content = '') {
  try {
    const parsed = JSON.parse(String(content));
    return (parsed.tasks || []).map((task, index) => ({
      name: task.label || task.taskName || `task-${index + 1}`,
      command: commandText(task),
      autoRun: task.runOptions?.runOn === 'folderOpen',
    })).filter((task) => task.command);
  } catch {
    const commands = [];
    const pattern = /"command"\s*:\s*("(?:\\.|[^"\\])*")/g;
    let match;
    while ((match = pattern.exec(String(content)))) {
      try {
        commands.push({
          name: `task-${commands.length + 1}`,
          command: JSON.parse(match[1]),
          autoRun: /"runOn"\s*:\s*"folderOpen"/i.test(String(content)),
        });
      } catch {
        // Ignore malformed string fragments; config validation/scanning reports invalid task files.
      }
    }
    return commands;
  }
}

function commandText(task = {}) {
  const command = typeof task.command === 'string' ? task.command : '';
  const args = Array.isArray(task.args) ? task.args.map(shellArgument) : [];
  return [command, ...args].filter(Boolean).join(' ');
}

function shellArgument(value) {
  const text = String(value);
  return /\s/.test(text) ? JSON.stringify(text) : text;
}

module.exports = {
  parseVscodeTasks,
};
