'use strict';

// Runs the Check Configuration script of _shared.yml, as written in the file, with bash the way
// GitHub runs it, so the tests check the script that actually guards vault-action's headers.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function stepScript(workflow, stepName) {
  const lines = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', workflow), 'utf8').split('\n');
  const step = lines.findIndex((line) => line.trim() === `- name: ${stepName}`);
  assert.ok(step >= 0, `no step ${stepName}`);
  const run = lines.findIndex((line, i) => i > step && line.trim() === 'run: |');
  const indent = lines[run].search(/\S/) + 2;
  const body = [];
  for (let i = run + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() !== '' && line.search(/\S/) < indent) break;
    body.push(line.slice(indent));
  }
  return body.join('\n');
}

const script = stepScript('_shared.yml', 'Check Configuration');

function check(env) {
  const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', script], {
    env: { PATH: process.env.PATH, HAS_ARTIFACT: 'false', HAS_FILES: 'false', ...env },
    encoding: 'utf8',
  });
  return { status: result.status, output: result.stdout + result.stderr };
}

test('valid or absent secrets pass', () => {
  assert.equal(check({}).status, 0);
  const all = check({
    PROMPT_GUARD_CLIENT_ID: '0123abcd.access',
    CF_ACCESS_CLIENT_ID: 'f00d-cafe_01.access',
    CF_ACCESS_CLIENT_SECRET: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  });
  assert.equal(all.status, 0, all.output);
  assert.equal(all.output, '');
});

for (const [name, value] of [
  ['CF_ACCESS_CLIENT_ID', 'x\nhost: evil.example'],
  ['CF_ACCESS_CLIENT_SECRET', 'y\r\nhost: evil.example'],
  ['CF_ACCESS_CLIENT_ID', 'id:with-colon'],
  ['CF_ACCESS_CLIENT_SECRET', 'with space'],
  ['PROMPT_GUARD_CLIENT_ID', 'abc\n'],
  ['PROMPT_GUARD_CLIENT_ID', 'Authorization: Bearer x'],
]) {
  test(`${name} with ${JSON.stringify(value)} fails, naming the secret but not the value`, () => {
    const env = { CF_ACCESS_CLIENT_ID: 'id.access', CF_ACCESS_CLIENT_SECRET: 'secret', [name]: value };
    const result = check(env);
    assert.equal(result.status, 1);
    assert.match(result.output, new RegExp(`::error::The secret ${name} may only hold letters, digits`));
    for (const part of value.split(/[\s:]+/).filter((p) => p.length > 2)) {
      assert.ok(!result.output.includes(part), `the output holds "${part}"`);
    }
  });
}

test('only one OpenBao Access value fails', () => {
  for (const env of [{ CF_ACCESS_CLIENT_ID: 'id' }, { CF_ACCESS_CLIENT_SECRET: 'secret' }]) {
    const result = check(env);
    assert.equal(result.status, 1);
    assert.match(result.output, /Only one of CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET is set/);
  }
});

test('artifact and files must be set together', () => {
  assert.equal(check({ HAS_ARTIFACT: 'true', HAS_FILES: 'true' }).status, 0);
  assert.match(check({ HAS_ARTIFACT: 'true' }).output, /Set artifact and files together/);
  assert.match(check({ HAS_FILES: 'true' }).output, /Set artifact and files together/);
});

test('the secrets reach the script through env only, never interpolated into it', () => {
  assert.doesNotMatch(script, /\$\{\{/);
});
