'use strict';

const { execFenceInvocationModes } = require('./entrypoint-coverage');

function workflowRunSteps(content = '') {
  const lines = String(content).split(/\r?\n/);
  const steps = [];
  let inJobs = false;
  let jobsIndent = -1;
  let jobIndent = -1;
  let currentJob = null;
  let stepsIndent = -1;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const indent = leadingSpaces(line);
    if (/^\s*jobs\s*:\s*(?:#.*)?$/.test(line)) {
      inJobs = true;
      jobsIndent = indent;
      jobIndent = -1;
      continue;
    }
    if (!inJobs) continue;
    if (line.trim() && indent <= jobsIndent && !/^\s*#/.test(line)) {
      inJobs = false;
      currentJob = null;
      stepsIndent = -1;
      continue;
    }
    const jobMatch = line.match(/^(\s*)([A-Za-z0-9_.-]+)\s*:\s*(?:#.*)?$/);
    if (jobMatch && indent > jobsIndent && (jobIndent < 0 || indent === jobIndent) && jobMatch[2] !== 'steps') {
      jobIndent = indent;
      currentJob = jobMatch[2];
      stepsIndent = -1;
      continue;
    }
    if (currentJob && /^\s*steps\s*:\s*(?:#.*)?$/.test(line) && indent > jobIndent) {
      stepsIndent = indent;
      continue;
    }
    if (stepsIndent >= 0 && line.trim() && indent <= stepsIndent) {
      stepsIndent = -1;
    }
    const runMatch = line.match(/^(\s*)(?:-\s*)?run\s*:\s*(.*)$/);
    if (!currentJob || stepsIndent < 0 || !runMatch || indent <= stepsIndent) continue;
    const runLine = index + 1;
    let command = runMatch[2].trim();
    if (/^[|>][+-]?$/.test(command)) {
      const runIndent = runMatch[1].length;
      const block = [];
      for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
        const candidate = lines[cursor];
        if (candidate.trim() && leadingSpaces(candidate) <= runIndent) break;
        block.push(candidate.slice(Math.min(candidate.length, runIndent + 2)));
        index = cursor;
      }
      command = block.join('\n').trim();
    }
    steps.push({ job: currentJob, command, line: runLine, order: steps.filter((step) => step.job === currentJob).length });
  }
  return steps;
}

function annotateWorkflowCoverage(steps, isDirectGuarded) {
  const gateByJob = new Map();
  return steps.map((step) => {
    const directGuarded = isDirectGuarded(step.command);
    const inheritedGuarded = Boolean(gateByJob.get(step.job));
    const result = {
      ...step,
      directGuarded,
      fileGuarded: !directGuarded && inheritedGuarded,
      guarded: directGuarded || inheritedGuarded,
    };
    if (isWorkflowGate(step.command)) {
      gateByJob.set(step.job, true);
    }
    return result;
  });
}

function isWorkflowGate(command = '') {
  return execFenceInvocationModes(command).some((mode) => mode === 'scan' || mode === 'ci');
}

function leadingSpaces(value) {
  return (String(value).match(/^\s*/) || [''])[0].replace(/\t/g, '  ').length;
}

module.exports = {
  annotateWorkflowCoverage,
  isWorkflowGate,
  workflowRunSteps,
};
