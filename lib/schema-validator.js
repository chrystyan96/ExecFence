'use strict';

function validateSchema(value, schema, options = {}) {
  const errors = [];
  validateNode(value, schema, options.rootSchema || schema, options.path || '$', errors);
  return errors;
}

function validateNode(value, schema, rootSchema, currentPath, errors) {
  if (!schema || typeof schema !== 'object') return;
  if (schema.$ref) {
    const resolved = resolveRef(rootSchema, schema.$ref);
    if (!resolved) {
      push(errors, currentPath, '$ref', `cannot resolve ${schema.$ref}`);
      return;
    }
    validateNode(value, resolved, rootSchema, currentPath, errors);
    return;
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((candidate) => branchMatches(value, candidate, rootSchema, currentPath)).length;
    if (matches !== 1) push(errors, currentPath, 'oneOf', `must match exactly one schema (matched ${matches})`);
    return;
  }
  if (schema.anyOf) {
    const matches = schema.anyOf.some((candidate) => branchMatches(value, candidate, rootSchema, currentPath));
    if (!matches) push(errors, currentPath, 'anyOf', 'must match at least one schema');
    return;
  }
  if (Object.prototype.hasOwnProperty.call(schema, 'const') && !deepEqual(value, schema.const)) {
    push(errors, currentPath, 'const', `must equal ${JSON.stringify(schema.const)}`);
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((item) => deepEqual(value, item))) {
    push(errors, currentPath, 'enum', `must be one of ${schema.enum.map((item) => JSON.stringify(item)).join(', ')}`);
  }
  if (schema.type && !matchesType(value, schema.type)) {
    push(errors, currentPath, 'type', `must be ${Array.isArray(schema.type) ? schema.type.join(' or ') : schema.type}`);
    return;
  }
  if (typeof value === 'string') {
    if (Number.isInteger(schema.minLength) && value.length < schema.minLength) {
      push(errors, currentPath, 'minLength', `must contain at least ${schema.minLength} character(s)`);
    }
    if (schema.pattern) {
      try {
        if (!new RegExp(schema.pattern).test(value)) push(errors, currentPath, 'pattern', `must match ${schema.pattern}`);
      } catch {
        push(errors, currentPath, 'pattern', `schema contains invalid pattern ${schema.pattern}`);
      }
    }
    if (schema.format === 'date' && !validDate(value)) {
      push(errors, currentPath, 'format', 'must be a valid YYYY-MM-DD date');
    }
    if (schema.format === 'date-time' && !validDateTime(value)) {
      push(errors, currentPath, 'format', 'must be a valid ISO 8601 date-time');
    }
  }
  if (typeof value === 'number') {
    if (Number.isFinite(schema.minimum) && value < schema.minimum) {
      push(errors, currentPath, 'minimum', `must be >= ${schema.minimum}`);
    }
    if (Number.isFinite(schema.maximum) && value > schema.maximum) {
      push(errors, currentPath, 'maximum', `must be <= ${schema.maximum}`);
    }
  }
  if (Array.isArray(value)) {
    if (schema.uniqueItems) {
      const identities = value.map((item) => JSON.stringify(item));
      if (new Set(identities).size !== identities.length) push(errors, currentPath, 'uniqueItems', 'must not contain duplicates');
    }
    if (schema.items) {
      value.forEach((item, index) => validateNode(item, schema.items, rootSchema, `${currentPath}[${index}]`, errors));
    }
  }
  if (isObject(value)) {
    for (const required of schema.required || []) {
      if (!Object.prototype.hasOwnProperty.call(value, required)) {
        push(errors, `${currentPath}.${required}`, 'required', 'is required');
      }
    }
    const properties = schema.properties || {};
    for (const [key, item] of Object.entries(value)) {
      if (properties[key]) {
        validateNode(item, properties[key], rootSchema, `${currentPath}.${key}`, errors);
      } else if (schema.additionalProperties === false) {
        push(errors, `${currentPath}.${key}`, 'additionalProperties', 'is not allowed');
      } else if (isObject(schema.additionalProperties)) {
        validateNode(item, schema.additionalProperties, rootSchema, `${currentPath}.${key}`, errors);
      }
    }
  }
}

function branchMatches(value, schema, rootSchema, currentPath) {
  const branchErrors = [];
  validateNode(value, schema, rootSchema, currentPath, branchErrors);
  return branchErrors.length === 0;
}

function resolveRef(rootSchema, ref) {
  if (!ref.startsWith('#/')) return null;
  return ref.slice(2).split('/').reduce((value, segment) => value?.[segment.replace(/~1/g, '/').replace(/~0/g, '~')], rootSchema);
}

function matchesType(value, expected) {
  const types = Array.isArray(expected) ? expected : [expected];
  return types.some((type) => {
    if (type === 'null') return value === null;
    if (type === 'array') return Array.isArray(value);
    if (type === 'object') return isObject(value);
    if (type === 'integer') return Number.isInteger(value);
    if (type === 'number') return typeof value === 'number' && Number.isFinite(value);
    return typeof value === type;
  });
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function validDateTime(value) {
  if (typeof value !== 'string' || !/[Tt]/.test(value) || !/(?:Z|[+-]\d{2}:\d{2})$/i.test(value)) return false;
  return Number.isFinite(Date.parse(value));
}

function deepEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function push(errors, path, keyword, message) {
  errors.push({ path, keyword, message });
}

module.exports = {
  validateSchema,
};
