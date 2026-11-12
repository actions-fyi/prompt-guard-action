'use strict';

const path = require('node:path');

// Reads and validates the action's inputs. action.yml passes every input through the step's env,
// never by interpolating it into the script, so these values are data, not code.
//
// The texts themselves never pass through an input: the runner prints every input and env value
// of a step in its log. Inputs only say where the texts are, in the event payload or in files,
// and sources.js reads them.
//
// Error messages name the input that is wrong, never its value: the API key and the Access values
// are secrets.

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

const ENV = {
  address: 'PROMPT_GUARD_ADDRESS',
  apiKey: 'PROMPT_GUARD_API_KEY',
  accessClientId: 'PROMPT_GUARD_ACCESS_CLIENT_ID',
  accessClientSecret: 'PROMPT_GUARD_ACCESS_CLIENT_SECRET',
  payloadFields: 'PROMPT_GUARD_PAYLOAD_FIELDS',
  files: 'PROMPT_GUARD_FILES',
  filesDirectory: 'PROMPT_GUARD_FILES_DIRECTORY',
  threshold: 'PROMPT_GUARD_THRESHOLD',
  mode: 'PROMPT_GUARD_MODE',
  dryRun: 'PROMPT_GUARD_DRY_RUN',
  notify: 'PROMPT_GUARD_NOTIFY',
  label: 'PROMPT_GUARD_LABEL',
  marker: 'PROMPT_GUARD_MARKER',
  maliciousLabel: 'PROMPT_GUARD_MALICIOUS_LABEL',
  botLogin: 'PROMPT_GUARD_BOT_LOGIN',
  requireText: 'PROMPT_GUARD_REQUIRE_TEXT',
  requireFields: 'PROMPT_GUARD_REQUIRE_FIELDS',
  allowInsecureAddress: 'PROMPT_GUARD_ALLOW_INSECURE_ADDRESS',
};

// The env names that hold secrets, masked before anything else runs.
const SECRET_ENV = [ENV.apiKey, ENV.accessClientId, ENV.accessClientSecret];

// Text names end up in outputs, logs and comments, so they are kept to a plain identifier.
const NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
// A dot path into the event payload, e.g. pull_request.body. It is also the text's name.
const PAYLOAD_FIELD = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$/;
// Segments that would walk into an object's prototype instead of its own fields.
const FORBIDDEN_SEGMENTS = new Set(['__proto__', 'prototype', 'constructor']);
// A user (@octocat) or a team (@org/team). The @ is optional in the input.
const HANDLE = /^@?([A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99})?)$/;
// Labels are free text on GitHub, but a short single line keeps them out of markup trouble.
const LABEL = /^[^\r\n`<>]{1,50}$/;
// A user or app login, e.g. github-actions[bot] or my-app[bot].
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$/;
// The marker must stay one invisible HTML comment, on one line. Its text has no < or >, so it
// can neither end the comment early (with --> or --!>, or as <!--> and <!--->) nor open a tag.
const MARKER_OPEN = '<!--';
const MARKER_CLOSE = '-->';
const MARKER_FORBIDDEN = /[\r\n<>]/;
function isMarker(value) {
  return (
    value.length <= 200 &&
    value.startsWith(MARKER_OPEN) &&
    value.endsWith(MARKER_CLOSE) &&
    value.length >= MARKER_OPEN.length + MARKER_CLOSE.length &&
    !MARKER_FORBIDDEN.test(value.slice(MARKER_OPEN.length, -MARKER_CLOSE.length))
  );
}

function read(env, key) {
  return (env[key] ?? '').trim();
}

function parseBoolean(value, name) {
  if (['true', 'True', 'TRUE'].includes(value)) return true;
  if (['false', 'False', 'FALSE'].includes(value)) return false;
  throw new ConfigError(`${name} must be true or false.`);
}

// The API key and the Access values go to this address, so it must be https unless the caller
// accepts sending them in the clear, e.g. to a TEI on the runner's own network.
function parseAddress(value, allowInsecure) {
  if (!value) throw new ConfigError('address is required: the base URL of the TEI service.');
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError('address must be an absolute https:// URL.');
  }
  if (url.protocol === 'http:' && !allowInsecure) {
    throw new ConfigError('address must be an https:// URL. Set allow-insecure-address to true to send the credentials over plain http.');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ConfigError('address must be an absolute https:// URL.');
  }
  if (url.username || url.password) {
    throw new ConfigError('address must not contain credentials; use api-key instead.');
  }
  if (url.search || url.hash) {
    throw new ConfigError('address must not have a query or a fragment.');
  }
  return url.href.endsWith('/') ? url.href : `${url.href}/`;
}

function parsePayloadFields(value) {
  const fields = [];
  for (const field of value.split(/[\s,]+/).filter(Boolean)) {
    if (field.length > 100 || !PAYLOAD_FIELD.test(field)) {
      throw new ConfigError(
        'payload-fields must list dot paths into the event payload, e.g. pull_request.title, of letters, digits and "_".',
      );
    }
    if (field.split('.').some((segment) => FORBIDDEN_SEGMENTS.has(segment))) {
      throw new ConfigError('payload-fields must not contain the segments __proto__, prototype or constructor.');
    }
    if (!fields.includes(field)) fields.push(field);
  }
  return fields;
}

function parseFiles(value) {
  const files = [];
  for (const line of value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)) {
    const separator = line.indexOf('=');
    const name = separator > 0 ? line.slice(0, separator).trim() : '';
    const file = separator > 0 ? line.slice(separator + 1).trim() : '';
    if (!NAME.test(name) || !file || file.includes('\0')) {
      throw new ConfigError(
        'files must hold one name=path pair per line. Names start with a letter or digit and hold only letters, digits, ".", "_" and "-", at most 64 characters.',
      );
    }
    if (files.some((f) => f.name === name)) throw new ConfigError(`files names ${name} twice.`);
    files.push({ name, file });
  }
  return files;
}

function parseThreshold(value) {
  if (!/^(?:0|1|0?\.\d+|1\.0*)$/.test(value)) {
    throw new ConfigError('threshold must be a number between 0 and 1, e.g. 0.5.');
  }
  const threshold = Number(value);
  if (!(threshold > 0 && threshold <= 1)) {
    throw new ConfigError('threshold must be greater than 0 and at most 1.');
  }
  return threshold;
}

function parseNotify(value) {
  if (!value) return [];
  const handles = [];
  for (const part of value.split(/[\s,]+/).filter(Boolean)) {
    const match = HANDLE.exec(part);
    if (!match) {
      throw new ConfigError('notify must list GitHub handles, e.g. @octocat or @org/moderators, separated by spaces or commas.');
    }
    const handle = `@${match[1]}`;
    if (!handles.includes(handle)) handles.push(handle);
  }
  return handles;
}

function parseSources(env) {
  const payloadFields = parsePayloadFields(read(env, ENV.payloadFields));
  const files = parseFiles(env[ENV.files] ?? '');
  if (payloadFields.length === 0 && files.length === 0) {
    throw new ConfigError('Nothing to screen: set payload-fields, files, or both.');
  }
  const filesDirectory = read(env, ENV.filesDirectory) || read(env, 'GITHUB_WORKSPACE');
  if (files.length > 0 && !(filesDirectory && path.isAbsolute(filesDirectory))) {
    throw new ConfigError('files-directory must be an absolute path; it defaults to GITHUB_WORKSPACE.');
  }
  const names = [...payloadFields, ...files.map((f) => f.name)];
  const duplicate = names.find((name, i) => names.indexOf(name) !== i);
  if (duplicate) throw new ConfigError(`${duplicate} is named in both payload-fields and files.`);
  return { payloadFields, files, filesDirectory };
}

function parseInputs(env = process.env) {
  const accessClientId = read(env, ENV.accessClientId);
  const accessClientSecret = read(env, ENV.accessClientSecret);
  if (Boolean(accessClientId) !== Boolean(accessClientSecret)) {
    throw new ConfigError(
      `Only ${accessClientId ? 'access-client-id' : 'access-client-secret'} is set. ` +
        'Set both access-client-id and access-client-secret to pass Cloudflare Access, or neither when there is no Access gate.',
    );
  }

  const mode = read(env, ENV.mode) || 'audit';
  if (mode !== 'audit' && mode !== 'block') throw new ConfigError('mode must be audit or block.');

  const label = read(env, ENV.label);
  if (label && !LABEL.test(label)) {
    throw new ConfigError('label must be a single line of at most 50 characters without `, < or >.');
  }
  // The issue lookup passes the label as listForRepo's labels parameter, which GitHub splits at
  // commas, so a label with a comma would never find its own issue.
  if (label.includes(',')) throw new ConfigError('label must not contain a comma.');

  const marker = read(env, ENV.marker) || '<!-- prompt-guard -->';
  if (!isMarker(marker)) {
    throw new ConfigError('marker must be a one-line HTML comment without < or > inside, e.g. <!-- prompt-guard -->.');
  }

  const maliciousLabel = read(env, ENV.maliciousLabel) || 'MALICIOUS';
  if (!LABEL.test(maliciousLabel)) throw new ConfigError('malicious-label must be a short single line.');

  const botLogin = read(env, ENV.botLogin) || 'github-actions[bot]';
  if (!LOGIN.test(botLogin)) throw new ConfigError('bot-login must be a GitHub login, e.g. github-actions[bot].');

  const allowInsecureAddress = parseBoolean(read(env, ENV.allowInsecureAddress) || 'false', 'allow-insecure-address');

  return {
    address: parseAddress(read(env, ENV.address), allowInsecureAddress),
    allowInsecureAddress,
    requireText: parseBoolean(read(env, ENV.requireText) || 'true', 'require-text'),
    requireFields: parseBoolean(read(env, ENV.requireFields) || 'true', 'require-fields'),
    apiKey: read(env, ENV.apiKey),
    accessClientId,
    accessClientSecret,
    ...parseSources(env),
    threshold: parseThreshold(read(env, ENV.threshold) || '0.5'),
    mode,
    dryRun: parseBoolean(read(env, ENV.dryRun) || 'false', 'dry-run'),
    notify: parseNotify(read(env, ENV.notify)),
    label,
    marker,
    maliciousLabel,
    botLogin,
  };
}

module.exports = { ConfigError, ENV, SECRET_ENV, FORBIDDEN_SEGMENTS, parseInputs };
