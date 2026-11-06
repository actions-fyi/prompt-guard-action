'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { TRIGGER, tokenize, mockTei, filler, noSleep } = require('./helpers');
const { createClient, parseInfo, batches, segmentText, cutWindows, scoreText, TeiError } = require('../src/tei');

const info = { maxInputLength: 512, maxClientBatchSize: 32, labels: ['BENIGN', 'MALICIOUS'] };
const client = (tei) => createClient({ address: 'https://tei.example.test/', apiKey: 'k', fetch: tei.fetch, sleep: noSleep });

test('cutWindows cuts at token boundaries by UTF-8 byte offsets, with the overlap', () => {
  const words = filler(1200);
  const text = words.join(' ');
  const windows = cutWindows(text, tokenize(text), 510, 64);
  assert.equal(windows.length, 3);
  // Window n starts at word 446 * n, and holds 510 words, the last one fewer.
  windows.forEach((window, n) => {
    const expected = words.slice(446 * n, 446 * n + 510);
    assert.deepEqual(window.split(' '), expected);
  });
});

test('cutWindows never splits a multi-byte character', () => {
  const text = '日本語 😀😀 ñ';
  const tokens = [
    { special: false, start: 1, stop: 8, text: undefined }, // starts and ends inside 日 and 語
    { special: false, start: 11, stop: 16, text: undefined },
  ];
  const [window] = cutWindows(text, tokens, 10, 2);
  assert.equal(window, '日本語 😀😀');
});

test('cutWindows rejects offsets that do not match the token text', () => {
  const text = 'héllo world';
  // Character offsets instead of byte offsets put "world" one byte early.
  const tokens = [
    { special: false, start: 0, stop: 5, text: 'héllo' },
    { special: false, start: 6, stop: 11, text: 'world' },
  ];
  assert.throws(() => cutWindows(text, tokens, 10, 2), TeiError);
});

test('segmentText splits by code points with overlap and keeps short texts whole', () => {
  assert.deepEqual(segmentText('short', 10, 2), ['short']);
  const text = '😀'.repeat(25);
  const segments = segmentText(text, 10, 2);
  assert.deepEqual(segments.map((s) => Array.from(s).length), [10, 10, 9]);
  assert.ok(segments.every((s) => s.isWellFormed()));
});

test('batches respects the count and the byte budget', () => {
  assert.deepEqual(batches([1, 2, 3, 4, 5], 2).map((b) => b.length), [2, 2, 1]);
  assert.deepEqual(batches(['aaaa', 'bbbb', 'cccc'], 32, 13).map((b) => b.length), [2, 1]);
});

test('parseInfo reads the limits and checks the label', () => {
  const data = {
    model_type: { classifier: { id2label: { 0: 'BENIGN', 1: 'MALICIOUS' } } },
    max_input_length: 512,
    max_client_batch_size: 32,
  };
  assert.deepEqual(parseInfo(data, 'MALICIOUS'), { maxInputLength: 512, maxClientBatchSize: 32, labels: ['BENIGN', 'MALICIOUS'] });
  assert.throws(() => parseInfo(data, 'INJECTION'), /no label "INJECTION"/);
  assert.throws(() => parseInfo({ ...data, model_type: { embedding: {} } }, 'MALICIOUS'), /not a sequence classifier/);
  assert.throws(() => parseInfo({ ...data, max_input_length: '512' }, 'MALICIOUS'), /max_input_length/);
});

test('a short benign text is one window and scores low', async () => {
  const tei = mockTei();
  const result = await scoreText(client(tei), info, 'What is the capital of France?', 'MALICIOUS');
  assert.equal(result.windows, 1);
  assert.ok(result.score < 0.01);
});

test('an injection beyond token 512 is scored, without truncation', async () => {
  const tei = mockTei();
  const words = filler(2000);
  words.splice(1500, 0, TRIGGER);
  const result = await scoreText(client(tei), info, words.join(' '), 'MALICIOUS');
  assert.ok(result.score > 0.99);
  assert.ok(result.windows >= 4);
  for (const call of tei.calls.filter((c) => c.path === '/predict')) {
    assert.equal(call.body.truncate, false);
    for (const [input] of call.body.inputs) assert.ok(tokenize(input).length <= 512);
  }
});

test('an injection spanning a window boundary is seen whole by the next window', async () => {
  const tei = mockTei();
  const words = filler(900);
  // Window 1 holds words 0-509 and window 2 starts at word 446; the four words of the trigger
  // sit at 508-511, so window 1 only has half of it.
  words.splice(508, 0, ...TRIGGER.split(' '));
  const result = await scoreText(client(tei), info, words.join(' '), 'MALICIOUS');
  assert.ok(result.score > 0.99);
  const inputs = tei.calls.filter((c) => c.path === '/predict').flatMap((c) => c.body.inputs.map(([input]) => input));
  assert.ok(inputs[0].endsWith('IGNORE ALL'), 'the first window holds only part of the trigger');
  assert.ok(inputs[1].includes(TRIGGER));
});

test('more than 32 windows are predicted in batches of at most max_client_batch_size', async () => {
  const tei = mockTei();
  const words = filler(446 * 40);
  words.push(TRIGGER);
  const result = await scoreText(client(tei), info, words.join(' '), 'MALICIOUS');
  assert.ok(result.windows > 32);
  assert.ok(result.score > 0.99);
  const predicts = tei.calls.filter((c) => c.path === '/predict');
  assert.ok(predicts.length >= 2);
  assert.ok(predicts.every((c) => c.body.inputs.length <= 32));
  assert.equal(predicts.reduce((n, c) => n + c.body.inputs.length, 0), result.windows);
  assert.ok(tei.calls.filter((c) => c.path === '/tokenize').every((c) => c.body.inputs.length <= 32));
});

test('a window that re-tokenizes too long is split until it fits', async () => {
  const tei = mockTei({ splitFirstWord: true });
  const words = Array.from({ length: 1200 }, (_, i) => `internationalization${i}`);
  words.splice(1100, 0, TRIGGER);
  const result = await scoreText(client(tei), info, words.join(' '), 'MALICIOUS');
  assert.ok(result.score > 0.99);
  // The mock answers 413 to any /predict input over the limit, so reaching here means all fit.
  assert.ok(result.windows > 3);
});

test('texts over TEI character limit are segmented before /tokenize', async () => {
  const tei = mockTei({ maxInputLength: 64 });
  const small = { ...info, maxInputLength: 64 };
  // 64 * 200 = 12,800 characters per segment.
  const words = filler(5000);
  words.push(TRIGGER);
  const text = words.join(' ');
  const result = await scoreText(client(tei), small, text, 'MALICIOUS');
  assert.ok(result.score > 0.99);
  const first = tei.calls.find((c) => c.path === '/tokenize');
  assert.ok(first.body.inputs.length > 1);
  assert.ok(first.body.inputs.every((s) => Array.from(s).length <= 64 * 200));
});

test('a request that times out is aborted, retried twice, then a TeiError', async () => {
  let attempts = 0;
  const fetch = (url, init) =>
    new Promise((resolve, reject) => {
      attempts++;
      init.signal.addEventListener('abort', () => reject(init.signal.reason));
    });
  const slow = createClient({ address: 'https://tei.example.test/', fetch, sleep: noSleep, timeoutMs: 20 });
  // AbortSignal.timeout doesn't keep the event loop alive on its own.
  const keepAlive = setInterval(() => {}, 5);
  try {
    await assert.rejects(slow.info(), (error) => error instanceof TeiError && /could not be reached \(TimeoutError\)/.test(error.message));
  } finally {
    clearInterval(keepAlive);
  }
  assert.equal(attempts, 3);
});
