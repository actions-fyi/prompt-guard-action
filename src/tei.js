'use strict';

// A client for Hugging Face text-embeddings-inference (TEI), and the chunking that lets a
// classifier with a short context score a long text.
//
// TEI doesn't chunk: /predict rejects an input longer than max_input_length tokens unless
// truncation is on, and truncation would hide whatever comes after the limit. So each text is
// tokenized with /tokenize, cut into overlapping windows at token boundaries, and every window is
// scored. A text scores as high as its worst window.
//
// Every failure throws a TeiError, and the caller turns it into the verdict error: a response
// this client doesn't understand never counts as clean. Messages name the endpoint and the
// status, never a request or response body, since both hold the untrusted text.

class TeiError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TeiError';
  }
}

// Tokens shared by neighbouring windows, so an injection that spans a cut is seen whole by one
// of them.
const OVERLAP_TOKENS = 64;
// TEI rejects an input of more than max_input_length * 250 characters before it tokenizes it
// (MAX_CHAR_MULTIPLIER in core/src/tokenization.rs). Longer texts are first cut into segments
// of at most max_input_length * 200 characters, which overlap by this many characters.
const SEGMENT_CHARS_PER_TOKEN = 200;
const SEGMENT_OVERLAP_CHARS = 4096;
// TEI's default --payload-limit is 2,000,000 bytes; batches stay well below it.
const MAX_BATCH_BYTES = 1_000_000;
// How often a window that re-tokenizes too long is split again before giving up.
const MAX_SPLITS = 3;
const RETRYABLE = new Set([429, 502, 503, 504]);

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const ACCESS_HINT =
  'That is how Cloudflare Access (or another gate in front of TEI) rejects a request: check access-client-id and access-client-secret.';

function createClient({
  address,
  apiKey,
  accessClientId,
  accessClientSecret,
  fetch = globalThis.fetch,
  sleep = defaultSleep,
  timeoutMs = 60_000,
  retries = 2,
}) {
  const headers = { Accept: 'application/json' };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
  if (accessClientId && accessClientSecret) {
    headers['CF-Access-Client-Id'] = accessClientId;
    headers['CF-Access-Client-Secret'] = accessClientSecret;
  }

  async function request(method, path, body) {
    const url = new URL(path, address);
    const init = {
      method,
      headers: body === undefined ? headers : { ...headers, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      // A redirect is never followed: it would carry the headers elsewhere, and it is what an
      // Access gate answers when it rejects a request.
      redirect: 'manual',
    };
    for (let attempt = 0; ; attempt++) {
      let response;
      try {
        response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
      } catch (error) {
        if (attempt < retries) {
          await sleep(1000 * 2 ** attempt);
          continue;
        }
        const reason = error?.cause?.code || error?.name || 'network error';
        throw new TeiError(`/${path} could not be reached (${reason}).`);
      }

      const status = response.status;
      if (response.type === 'opaqueredirect' || (status >= 300 && status < 400)) {
        throw new TeiError(`/${path} answered with a redirect (HTTP ${status}). ${ACCESS_HINT}`);
      }
      const text = await response.text();
      const contentType = response.headers.get('content-type') || '';
      if (/\btext\/html\b/i.test(contentType) || /^\s*</.test(text)) {
        throw new TeiError(`/${path} answered with an HTML page (HTTP ${status}), not JSON, most likely a login page. ${ACCESS_HINT}`);
      }
      if (status === 401 || status === 403) {
        throw new TeiError(
          `/${path} refused the request (HTTP ${status}): check api-key` +
            (headers['CF-Access-Client-Id'] ? ', access-client-id and access-client-secret.' : '.'),
        );
      }
      if (RETRYABLE.has(status) && attempt < retries) {
        await sleep(1000 * 2 ** attempt);
        continue;
      }
      if (status < 200 || status >= 300) {
        // TEI's ErrorResponse is {error, error_type}. Only the type is reported: the message of
        // a tokenizer error could echo the input.
        let errorType = '';
        try {
          const parsed = JSON.parse(text);
          if (isObject(parsed) && typeof parsed.error_type === 'string' && /^[a-z_]{1,32}$/.test(parsed.error_type)) {
            errorType = `, ${parsed.error_type}`;
          }
        } catch {
          // Not JSON; the status says enough.
        }
        throw new TeiError(`/${path} failed (HTTP ${status}${errorType}).`);
      }
      try {
        return JSON.parse(text);
      } catch {
        throw new TeiError(`/${path} answered with a body that is not JSON (HTTP ${status}).`);
      }
    }
  }

  return {
    info: () => request('GET', 'info'),
    // add_special_tokens is TEI's default; it is set so the special tokens can be counted.
    tokenize: (inputs) => request('POST', 'tokenize', { inputs, add_special_tokens: true }),
    // Each input is wrapped in a one-element array: TEI reads a flat array of two strings as one
    // sentence pair, not as a batch of two. truncate is set because TEI would otherwise fall back
    // to the server's --auto-truncate.
    predict: (inputs) =>
      request('POST', 'predict', { inputs: inputs.map((input) => [input]), truncate: false, raw_scores: false }),
  };
}

// Reads the limits and labels from GET /info.
function parseInfo(data, maliciousLabel) {
  if (!isObject(data)) throw new TeiError('/info answered with JSON that is not an object.');
  const classifier = isObject(data.model_type) ? data.model_type.classifier : undefined;
  if (!isObject(classifier) || !isObject(classifier.id2label)) {
    throw new TeiError('/info says the served model is not a sequence classifier.');
  }
  const labels = Object.values(classifier.id2label).filter((label) => typeof label === 'string');
  if (!labels.includes(maliciousLabel)) {
    throw new TeiError(
      `The model has no label "${maliciousLabel}"; its labels are ${labels.map((l) => `"${l}"`).join(', ') || 'none'}. Set malicious-label to one of them.`,
    );
  }
  const maxInputLength = data.max_input_length;
  const maxClientBatchSize = data.max_client_batch_size;
  if (!Number.isInteger(maxInputLength) || maxInputLength < 16) {
    throw new TeiError('/info has no usable max_input_length.');
  }
  if (!Number.isInteger(maxClientBatchSize) || maxClientBatchSize < 1) {
    throw new TeiError('/info has no usable max_client_batch_size.');
  }
  return { maxInputLength, maxClientBatchSize, labels };
}

// Splits items into batches of at most maxCount items and about maxBytes of JSON.
function batches(items, maxCount, maxBytes = MAX_BATCH_BYTES) {
  const out = [];
  let current = [];
  let bytes = 0;
  for (const item of items) {
    const size = Buffer.byteLength(JSON.stringify(item));
    if (current.length > 0 && (current.length >= maxCount || bytes + size > maxBytes)) {
      out.push(current);
      current = [];
      bytes = 0;
    }
    current.push(item);
    bytes += size;
  }
  if (current.length > 0) out.push(current);
  return out;
}

// Cuts a text into segments short enough for /tokenize, by code points, as TEI counts them.
function segmentText(text, maxChars, overlapChars) {
  const chars = Array.from(text);
  if (chars.length <= maxChars) return [text];
  const step = maxChars - overlapChars;
  const segments = [];
  for (let first = 0; ; first += step) {
    segments.push(chars.slice(first, first + maxChars).join(''));
    if (first + maxChars >= chars.length) break;
  }
  return segments;
}

function checkTokenLists(result, count) {
  if (!Array.isArray(result) || result.length !== count) {
    throw new TeiError('/tokenize answered with an unexpected shape: expected one token list per input.');
  }
  for (const tokens of result) {
    if (!Array.isArray(tokens)) throw new TeiError('/tokenize answered with an unexpected shape: a token list is not an array.');
    for (const token of tokens) {
      if (!isObject(token) || typeof token.special !== 'boolean') {
        throw new TeiError('/tokenize answered with a token that has no special flag.');
      }
      if (!token.special && !(Number.isInteger(token.start) && Number.isInteger(token.stop) && token.start >= 0 && token.stop >= token.start)) {
        throw new TeiError('/tokenize answered with a token that has no start and stop offsets.');
      }
    }
  }
}

async function tokenizeAll(client, info, texts) {
  const results = [];
  for (const batch of batches(texts, info.maxClientBatchSize)) {
    const result = await client.tokenize(batch);
    checkTokenLists(result, batch.length);
    results.push(...result);
  }
  return results;
}

// TEI's start and stop are byte offsets into the UTF-8 text (into_tokens in
// core/src/tokenization.rs), not character offsets. A cut is moved off a UTF-8 continuation
// byte so that it never splits a character.
function cutWindows(text, tokens, size, overlap) {
  const bytes = Buffer.from(text, 'utf8');
  const content = tokens.filter((token) => !token.special);
  if (content.length === 0) return [text];
  for (const token of content) {
    if (token.stop > bytes.length) throw new TeiError('/tokenize answered with offsets outside the text.');
    // TEI derives a token's text from the same offsets, so they must agree. If they don't, this
    // TEI reports offsets in another unit, and cutting by them could leave text unscored.
    if (typeof token.text === 'string') {
      const slice = bytes.subarray(token.start, token.stop).toString('utf8');
      if (slice !== token.text && !slice.includes('�') && !token.text.includes('�')) {
        throw new TeiError('/tokenize answered with offsets that do not match the token text; this TEI version may count offsets differently.');
      }
    }
  }
  const stride = Math.max(1, size - overlap);
  const windows = [];
  for (let first = 0; ; first += stride) {
    const slice = content.slice(first, first + size);
    let start = Math.min(...slice.map((token) => token.start));
    let stop = Math.max(...slice.map((token) => token.stop));
    while (start > 0 && (bytes[start] & 0xc0) === 0x80) start--;
    while (stop < bytes.length && (bytes[stop] & 0xc0) === 0x80) stop++;
    windows.push(bytes.subarray(start, stop).toString('utf8'));
    if (first + size >= content.length) break;
  }
  return windows;
}

// A window can tokenize to a few more tokens on its own than it had in context, at the cut. Each
// window is tokenized again, and one that is still too long is split in two.
async function fitWindows(client, info, windows, depth = 0) {
  const results = await tokenizeAll(client, info, windows);
  const fitting = [];
  const split = [];
  windows.forEach((window, i) => {
    const tokens = results[i];
    if (tokens.length <= info.maxInputLength) {
      fitting.push(window);
    } else {
      const half = Math.ceil(tokens.filter((token) => !token.special).length / 2);
      const overlap = Math.min(OVERLAP_TOKENS, Math.floor(half / 2));
      split.push(...cutWindows(window, tokens, half + overlap, overlap));
    }
  });
  if (split.length > 0) {
    if (depth >= MAX_SPLITS) throw new TeiError('A window still has too many tokens after splitting it.');
    fitting.push(...(await fitWindows(client, info, split, depth + 1)));
  }
  return fitting;
}

async function predictAll(client, info, windows, maliciousLabel) {
  const scores = [];
  for (const batch of batches(windows, info.maxClientBatchSize)) {
    const result = await client.predict(batch);
    // A batch answers with one array of {score, label} per input (PredictResponse::Batch).
    if (!Array.isArray(result) || result.length !== batch.length || !result.every(Array.isArray)) {
      throw new TeiError('/predict answered with an unexpected shape: expected one list of predictions per input.');
    }
    for (const predictions of result) {
      const match = predictions.find((prediction) => isObject(prediction) && prediction.label === maliciousLabel);
      if (!match || typeof match.score !== 'number' || !Number.isFinite(match.score) || match.score < 0 || match.score > 1) {
        throw new TeiError(`/predict answered without a "${maliciousLabel}" score between 0 and 1.`);
      }
      scores.push(match.score);
    }
  }
  return scores;
}

// Scores one text: the highest score of the label across all of its windows.
async function scoreText(client, info, text, maliciousLabel) {
  // Lone surrogates can't be encoded as UTF-8, and TEI's JSON parser rejects them.
  const wellFormed = text.toWellFormed();
  const segments = segmentText(
    wellFormed,
    info.maxInputLength * SEGMENT_CHARS_PER_TOKEN,
    Math.min(SEGMENT_OVERLAP_CHARS, Math.floor((info.maxInputLength * SEGMENT_CHARS_PER_TOKEN) / 4)),
  );
  const segmentTokens = await tokenizeAll(client, info, segments);
  const cut = [];
  segments.forEach((segment, i) => {
    const tokens = segmentTokens[i];
    const specials = tokens.filter((token) => token.special).length;
    const size = info.maxInputLength - specials;
    if (size < 8) throw new TeiError('max_input_length leaves no room for text next to the special tokens.');
    cut.push(...cutWindows(segment, tokens, size, Math.min(OVERLAP_TOKENS, Math.floor(size / 4))));
  });
  const windows = await fitWindows(client, info, cut);
  const scores = await predictAll(client, info, windows, maliciousLabel);
  return { score: Math.max(...scores), windows: windows.length };
}

module.exports = {
  TeiError,
  OVERLAP_TOKENS,
  createClient,
  parseInfo,
  batches,
  segmentText,
  cutWindows,
  fitWindows,
  predictAll,
  scoreText,
};
