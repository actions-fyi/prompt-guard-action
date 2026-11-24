'use strict';

// The entry point, called by actions/github-script with its github (Octokit), context and core.
//
// The verdict is clean only when every text was scored and none reached the threshold. Anything
// that keeps a text from being scored, a configuration error or a TEI response this action
// doesn't understand, gives the verdict error and fails the step, in every mode. With
// escalate-on-error, a TEI error also escalates: it is the error the author of a text can cause.
// A configuration error is the workflow's, and the failed step is enough.

const { ConfigError, SECRET_ENV, parseInputs, thresholdFor } = require('./inputs');
const { collectTexts } = require('./sources');
const { TeiError, createClient, parseInfo, scoreText } = require('./tei');
const { decide, formatScore } = require('./verdict');
const { EscalationError, escalate, escalateError } = require('./escalate');

function setOutputs(core, outputs) {
  core.setOutput('verdict', outputs.verdict);
  core.setOutput('scores', JSON.stringify(outputs.scores));
  core.setOutput('flagged', JSON.stringify(outputs.flagged));
  core.setOutput('would-escalate', String(outputs.wouldEscalate));
  core.setOutput('escalated', String(outputs.escalated));
}

// Only the messages of this action's own errors are shown: they never hold the texts. Any other
// error could, e.g. one that quotes a response body, so only its name is shown.
function explain(error) {
  if (error instanceof ConfigError || error instanceof TeiError || error instanceof EscalationError) {
    return error.message;
  }
  return `An unexpected ${error?.name || 'error'} occurred.`;
}

module.exports = async function main({ github, context, core, env = process.env, fetch = globalThis.fetch, sleep }) {
  // Before anything can log or send them.
  for (const key of SECRET_ENV) {
    const value = (env[key] ?? '').trim();
    if (value) core.setSecret(value);
  }

  const outputs = { verdict: 'error', scores: {}, flagged: [], wouldEscalate: false, escalated: false };
  let inputs;
  let texts = [];
  try {
    inputs = parseInputs(env);
    if (inputs.address.startsWith('http:')) {
      core.warning('address is plain http, so the API key and the Access values are sent unencrypted.');
    }
    const collected = collectTexts(inputs, context.payload);
    texts = collected.texts;
    const { empty, missing } = collected;
    for (const name of empty) core.info(`${name}: empty, skipped.`);
    for (const name of missing) core.warning(`${name}: not in the event payload, skipped.`);
    if (texts.length === 0) {
      const reasons = [
        empty.length > 0 ? `empty: ${empty.join(', ')}` : '',
        missing.length > 0 ? `missing from the event payload: ${missing.join(', ')}` : '',
      ].filter(Boolean);
      const message = `Nothing was screened (${reasons.join('; ')}).`;
      if (inputs.requireText) throw new ConfigError(`${message} Set require-text to false if that is expected.`);
      core.warning(message);
    }

    if (texts.length > 0) {
      const client = createClient({ ...inputs, fetch, sleep });
      const info = parseInfo(await client.info(), inputs.maliciousLabel);
      for (const { name, text } of texts) {
        const { score, windows } = await scoreText(client, info, text, inputs.maliciousLabel);
        outputs.scores[name] = score;
        core.info(`${name}: ${formatScore(score)} (${windows} ${windows === 1 ? 'window' : 'windows'}).`);
      }
    }
  } catch (error) {
    outputs.scores = {};
    let escalationError;
    if (error instanceof TeiError && inputs?.escalateOnError) {
      outputs.wouldEscalate = true;
      if (inputs.dryRun) {
        core.notice('Dry run: Prompt Guard would escalate the error, but makes no changes on GitHub.');
      } else {
        try {
          await escalateError({ github, context, core, inputs, names: texts.map((t) => t.name) });
          outputs.escalated = true;
        } catch (escalation) {
          escalationError = escalation;
        }
      }
    }
    setOutputs(core, outputs);
    core.setFailed(`Prompt Guard could not screen the texts, so they must be treated as unsafe. ${explain(error)}`);
    if (escalationError) core.setFailed(explain(escalationError));
    return outputs.verdict;
  }

  const { verdict, flagged } = decide(outputs.scores, (name) => thresholdFor(inputs, name));
  Object.assign(outputs, { verdict, flagged, wouldEscalate: verdict === 'flagged' });

  let escalationError;
  if (verdict === 'flagged') {
    if (inputs.dryRun) {
      core.notice('Dry run: Prompt Guard would escalate, but makes no changes on GitHub.');
    } else {
      try {
        await escalate({ github, context, core, inputs, scores: outputs.scores, flagged });
        outputs.escalated = true;
      } catch (error) {
        escalationError = error;
      }
    }
  }
  setOutputs(core, outputs);

  const summary = flagged
    .map((name) => `${name} (${formatScore(outputs.scores[name])}, threshold ${thresholdFor(inputs, name)})`)
    .join(', ');
  if (verdict === 'flagged' && inputs.mode === 'block') {
    core.setFailed(`Prompt Guard flagged ${summary}.`);
  } else if (verdict === 'flagged') {
    core.warning(`Prompt Guard flagged ${summary} (audit mode, not blocking).`);
  } else {
    core.info(`Prompt Guard found nothing at or above the threshold of ${inputs.threshold}, or ${inputs.titleThreshold} for titles.`);
  }
  if (escalationError) core.setFailed(explain(escalationError));
  return outputs.verdict;
};
