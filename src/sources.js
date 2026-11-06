'use strict';

// Reads the texts to screen from where the inputs point: fields of the event payload, and files.
// The texts are never passed as inputs or env values, because the runner prints those in the
// step's log before any script could mask them.

const fs = require('node:fs');
const path = require('node:path');
const { ConfigError, FORBIDDEN_SEGMENTS } = require('./inputs');

// A file larger than this is refused rather than half read.
const MAX_FILE_BYTES = 10_000_000;

// Walks a dot path through the payload's own fields only. Returns undefined when a segment is
// missing.
function resolveField(payload, field) {
  let value = payload;
  for (const segment of field.split('.')) {
    if (FORBIDDEN_SEGMENTS.has(segment)) throw new ConfigError('payload-fields must not walk into a prototype.');
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, segment)) return undefined;
    value = value[segment];
  }
  return value;
}

function isInside(directory, file) {
  const relative = path.relative(directory, file);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function readFile(directory, { name, file }) {
  const resolved = path.resolve(directory, file);
  if (!isInside(directory, resolved)) throw new ConfigError(`files: the path of ${name} is outside files-directory.`);
  let real;
  try {
    real = fs.realpathSync(resolved);
  } catch {
    throw new ConfigError(`files: ${name} does not exist.`);
  }
  // Checked again after following symbolic links.
  if (!isInside(directory, real)) throw new ConfigError(`files: the path of ${name} is outside files-directory.`);
  const stat = fs.statSync(real);
  if (!stat.isFile()) throw new ConfigError(`files: ${name} is not a regular file.`);
  if (stat.size > MAX_FILE_BYTES) throw new ConfigError(`files: ${name} is larger than ${MAX_FILE_BYTES} bytes.`);
  return fs.readFileSync(real, 'utf8');
}

// Returns the texts to screen, and the names that were empty or missing.
function collectTexts(inputs, payload) {
  const texts = [];
  const empty = [];
  const missing = [];
  const add = (name, text) => {
    if (text === null || text.trim() === '') empty.push(name);
    else texts.push({ name, text });
  };

  for (const field of inputs.payloadFields) {
    const value = resolveField(payload ?? {}, field);
    if (value === undefined) missing.push(field);
    else if (value === null || typeof value === 'string') add(field, value);
    else throw new ConfigError(`The payload field ${field} is not a string.`);
  }

  // A misspelled path, e.g. pull_request.bdy, is missing from every payload, so without
  // require-fields it would only ever be skipped, and the run look clean.
  if (inputs.requireFields && missing.length > 0) {
    throw new ConfigError(`payload-fields names paths that are not in the event payload: ${missing.join(', ')}. Check their spelling, or set require-fields to false.`);
  }

  if (inputs.files.length > 0) {
    let directory;
    try {
      directory = fs.realpathSync(inputs.filesDirectory);
    } catch {
      throw new ConfigError('files-directory does not exist.');
    }
    for (const entry of inputs.files) add(entry.name, readFile(directory, entry));
  }
  return { texts, empty, missing };
}

module.exports = { collectTexts, resolveField, MAX_FILE_BYTES };
