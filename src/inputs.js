'use strict';

// Reads and validates the action's inputs. action.yml passes every input through the step's env,
// never by interpolating it into the script, so these values are data, not code.
//
// Error messages name the input that is wrong, never its value: the texts are untrusted, and the
// API key and the Access values are secrets.

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
  texts: 'PROMPT_GUARD_TEXTS',
  threshold: 'PROMPT_GUARD_THRESHOLD',
  mode: 'PROMPT_GUARD_MODE',
  dryRun: 'PROMPT_GUARD_DRY_RUN',
  notify: 'PROMPT_GUARD_NOTIFY',
  label: 'PROMPT_GUARD_LABEL',
  marker: 'PROMPT_GUARD_MARKER',
  maliciousLabel: 'PROMPT_GUARD_MALICIOUS_LABEL',
};

// The env names that hold secrets, masked before anything else runs.
const SECRET_ENV = [ENV.apiKey, ENV.accessClientId, ENV.accessClientSecret];

// Text names end up in outputs, logs and comments, so they are kept to a plain identifier.
const NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
// A user (@octocat) or a team (@org/team). The @ is optional in the input.
const HANDLE = /^@?([A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99})?)$/;
// Labels are free text on GitHub, but a short single line keeps them out of markup trouble.
const LABEL = /^[^\r\n`<>]{1,50}$/;
// The marker must stay an invisible HTML comment, on one line.
const MARKER = /^<!--[^\r\n]*-->$/;

function read(env, key) {
  return (env[key] ?? '').trim();
}

function parseBoolean(value, name) {
  if (['true', 'True', 'TRUE'].includes(value)) return true;
  if (['false', 'False', 'FALSE'].includes(value)) return false;
  throw new ConfigError(`${name} must be true or false.`);
}

function parseAddress(value) {
  if (!value) throw new ConfigError('address is required: the base URL of the TEI service.');
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError('address must be an absolute http:// or https:// URL.');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ConfigError('address must be an absolute http:// or https:// URL.');
  }
  if (url.username || url.password) {
    throw new ConfigError('address must not contain credentials; use api-key instead.');
  }
  if (url.search || url.hash) {
    throw new ConfigError('address must not have a query or a fragment.');
  }
  return url.href.endsWith('/') ? url.href : `${url.href}/`;
}

function parseTexts(value) {
  if (!value) throw new ConfigError('texts is required: a JSON object mapping names to texts.');
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    // JSON.parse's own message quotes part of the input, which is untrusted text.
    throw new ConfigError('texts must be a JSON object mapping names to texts, but it is not valid JSON.');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ConfigError('texts must be a JSON object mapping names to texts.');
  }
  const texts = [];
  const skipped = [];
  for (const [name, text] of Object.entries(parsed)) {
    if (!NAME.test(name)) {
      throw new ConfigError(
        'Each name in texts must start with a letter or digit and hold only letters, digits, ".", "_" and "-", at most 64 characters.',
      );
    }
    // A missing field, e.g. the body of a pull request without a description, arrives as null.
    if (text === null || (typeof text === 'string' && text.trim() === '')) {
      skipped.push(name);
    } else if (typeof text === 'string') {
      texts.push({ name, text });
    } else {
      throw new ConfigError(`texts.${name} must be a string or null.`);
    }
  }
  return { texts, skipped };
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

  const marker = read(env, ENV.marker) || '<!-- prompt-guard -->';
  if (!MARKER.test(marker)) throw new ConfigError('marker must be a one-line HTML comment, e.g. <!-- prompt-guard -->.');

  const maliciousLabel = read(env, ENV.maliciousLabel) || 'MALICIOUS';
  if (!LABEL.test(maliciousLabel)) throw new ConfigError('malicious-label must be a short single line.');

  return {
    address: parseAddress(read(env, ENV.address)),
    apiKey: read(env, ENV.apiKey),
    accessClientId,
    accessClientSecret,
    ...parseTexts(env[ENV.texts] ?? ''),
    threshold: parseThreshold(read(env, ENV.threshold) || '0.5'),
    mode,
    dryRun: parseBoolean(read(env, ENV.dryRun) || 'false', 'dry-run'),
    notify: parseNotify(read(env, ENV.notify)),
    label,
    marker,
    maliciousLabel,
  };
}

module.exports = { ConfigError, ENV, SECRET_ENV, parseInputs };
