'use strict';

// The entry point, called by actions/github-script with its github (Octokit), context and core.
//
// The verdict is clean only when every text was scored and none reached the threshold. Anything
// that keeps a text from being scored, a configuration error or a TEI response this action
// doesn't understand, gives the verdict error and fails the step, in every mode.

const { ConfigError, SECRET_ENV, parseInputs } = require('./inputs');
const { TeiError, createClient, parseInfo, scoreText } = require('./tei');
const { decide, formatScore } = require('./verdict');
const { EscalationError, escalate } = require('./escalate');

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
  try {
    inputs = parseInputs(env);
    for (const name of inputs.skipped) core.info(`${name}: empty, skipped.`);

    if (inputs.texts.length > 0) {
      const client = createClient({ ...inputs, fetch, sleep });
      const info = parseInfo(await client.info(), inputs.maliciousLabel);
      for (const { name, text } of inputs.texts) {
        const { score, windows } = await scoreText(client, info, text, inputs.maliciousLabel);
        outputs.scores[name] = score;
        core.info(`${name}: ${formatScore(score)} (${windows} ${windows === 1 ? 'window' : 'windows'}).`);
      }
    }
  } catch (error) {
    outputs.scores = {};
    setOutputs(core, outputs);
    core.setFailed(`Prompt Guard could not screen the texts, so they must be treated as unsafe. ${explain(error)}`);
    return outputs.verdict;
  }

  const { verdict, flagged } = decide(outputs.scores, inputs.threshold);
  Object.assign(outputs, { verdict, flagged, wouldEscalate: verdict === 'flagged' });

  let escalationError;
  if (verdict === 'flagged') {
    if (inputs.dryRun) {
      core.notice('Dry run: Prompt Guard would escalate, but makes no changes on GitHub.');
    } else {
      try {
        await escalate({ github, context, inputs, scores: outputs.scores, flagged });
        outputs.escalated = true;
      } catch (error) {
        escalationError = error;
      }
    }
  }
  setOutputs(core, outputs);

  const summary = flagged.map((name) => `${name} (${formatScore(outputs.scores[name])})`).join(', ');
  if (verdict === 'flagged' && inputs.mode === 'block') {
    core.setFailed(`Prompt Guard flagged ${summary} at a threshold of ${inputs.threshold}.`);
  } else if (verdict === 'flagged') {
    core.warning(`Prompt Guard flagged ${summary} at a threshold of ${inputs.threshold} (audit mode, not blocking).`);
  } else {
    core.info(`Prompt Guard found nothing at or above the threshold of ${inputs.threshold}.`);
  }
  if (escalationError) core.setFailed(explain(escalationError));
  return outputs.verdict;
};
