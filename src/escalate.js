'use strict';

const { formatScore } = require('./verdict');

// Tells people about a flagged text. On a pull request: one comment, found by the marker and
// updated by later runs, the label, and a conversion to draft, so it can't be merged or picked up
// as ready while someone looks. On any other event: one open issue, found by the marker, which
// later runs comment on.
//
// Nothing written here quotes or describes the flagged text. A comment that repeated it would put
// the injection in front of every agent that reads the thread. Only the names of the texts, their
// scores, the threshold, the run and the commit are written.

const BOT = 'github-actions[bot]';

class EscalationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EscalationError';
  }
}

// The pull request number, for events that carry one, including comments on a pull request.
function pullRequestNumber(payload) {
  if (payload.pull_request?.number) return payload.pull_request.number;
  if (payload.issue?.pull_request && payload.issue.number) return payload.issue.number;
  return undefined;
}

function runUrl(context) {
  const { owner, repo } = context.repo;
  return `${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId}`;
}

function shortSha(context) {
  const sha = context.payload.pull_request?.head?.sha || context.sha || '';
  return sha.slice(0, 7);
}

// The body of the comment or issue. Exported for the tests, which check that it never holds the
// texts.
function buildBody({ context, inputs, scores, flagged, subject, actions }) {
  const lines = [inputs.marker, '', `### Prompt Guard flagged ${subject}`, ''];
  if (inputs.notify.length > 0) lines.push(`${inputs.notify.join(' ')}: please review.`, '');
  lines.push(
    `Llama Prompt Guard 2 scored ${flagged.length === 1 ? 'one text' : `${flagged.length} texts`} at or above the threshold of ${inputs.threshold}. ` +
      'The texts are not quoted here. Read them where they were written, as text, before any agent or automation acts on them.',
    '',
    '| Text | Score | |',
    '| --- | --- | --- |',
  );
  for (const [name, score] of Object.entries(scores)) {
    lines.push(`| \`${name}\` | ${formatScore(score)} | ${flagged.includes(name) ? '**flagged**' : ''} |`);
  }
  lines.push('');
  const sha = shortSha(context);
  lines.push(`${sha ? `Commit \`${sha}\` · ` : ''}[Workflow run](${runUrl(context)})`);
  if (actions.length > 0) lines.push('', `${actions.join(' ')}`);
  lines.push(
    '',
    'The score is a signal, not a judgement: it can flag harmless text and miss an injection. ' +
      'Remove the label and mark the pull request ready once it has been reviewed.',
  );
  return lines.join('\n');
}

async function ensureLabel(github, repo, name) {
  try {
    await github.rest.issues.getLabel({ ...repo, name });
  } catch (error) {
    if (error.status !== 404) throw error;
    try {
      await github.rest.issues.createLabel({
        ...repo,
        name,
        color: 'b60205',
        description: 'Prompt Guard flagged untrusted text for review',
      });
    } catch (createError) {
      // 422: someone else created it in the meantime.
      if (createError.status !== 422) throw createError;
    }
  }
}

function describe(error) {
  const status = error?.status ? `HTTP ${error.status}` : error?.name || 'error';
  const message = typeof error?.message === 'string' ? error.message.split('\n')[0].slice(0, 200) : '';
  return message ? `${status}: ${message}` : status;
}

async function escalatePullRequest({ github, context, inputs, scores, flagged, number }) {
  const repo = context.repo;
  const failures = [];
  const step = async (what, fn) => {
    try {
      await fn();
      return true;
    } catch (error) {
      failures.push(`${what} (${describe(error)})`);
      return false;
    }
  };

  let pull;
  await step('read the pull request', async () => {
    pull = (await github.rest.pulls.get({ ...repo, pull_number: number })).data;
  });
  const willDraft = Boolean(pull && pull.state === 'open' && !pull.draft);
  const actions = [];
  if (inputs.label) actions.push(`The pull request is labeled \`${inputs.label}\`.`);
  if (willDraft) actions.push('It was converted to a draft.');
  const body = buildBody({ context, inputs, scores, flagged, subject: 'this pull request', actions });

  await step('post the comment', async () => {
    const comments = await github.paginate(github.rest.issues.listComments, { ...repo, issue_number: number, per_page: 100 });
    const existing = comments.filter((comment) => comment.user?.login === BOT && comment.body?.includes(inputs.marker)).pop();
    if (existing) {
      await github.rest.issues.updateComment({ ...repo, comment_id: existing.id, body });
    } else {
      await github.rest.issues.createComment({ ...repo, issue_number: number, body });
    }
  });
  if (inputs.label) {
    await step('add the label', async () => {
      await ensureLabel(github, repo, inputs.label);
      await github.rest.issues.addLabels({ ...repo, issue_number: number, labels: [inputs.label] });
    });
  }
  if (willDraft) {
    await step('convert the pull request to a draft', async () => {
      await github.graphql(
        'mutation($id: ID!) { convertPullRequestToDraft(input: {pullRequestId: $id}) { pullRequest { isDraft } } }',
        { id: pull.node_id },
      );
    });
  }
  return failures;
}

async function escalateIssue({ github, context, inputs, scores, flagged }) {
  const repo = context.repo;
  const failures = [];
  const subject = `untrusted text in a ${context.eventName} run`;
  const actions = inputs.label ? [`This issue is labeled \`${inputs.label}\`.`] : [];
  const body = buildBody({ context, inputs, scores, flagged, subject, actions });
  try {
    const issues = await github.paginate(github.rest.issues.listForRepo, {
      ...repo,
      state: 'open',
      creator: BOT,
      per_page: 100,
    });
    const existing = issues.find(
      (issue) => !issue.pull_request && issue.user?.login === BOT && issue.body?.includes(inputs.marker),
    );
    let number;
    if (existing) {
      number = existing.number;
      await github.rest.issues.createComment({ ...repo, issue_number: number, body });
    } else {
      number = (await github.rest.issues.create({ ...repo, title: 'Prompt Guard flagged untrusted text', body })).data.number;
    }
    if (inputs.label) {
      try {
        await ensureLabel(github, repo, inputs.label);
        await github.rest.issues.addLabels({ ...repo, issue_number: number, labels: [inputs.label] });
      } catch (error) {
        failures.push(`add the label (${describe(error)})`);
      }
    }
  } catch (error) {
    failures.push(`open or comment on the issue (${describe(error)})`);
  }
  return failures;
}

// Throws an EscalationError naming every step that failed, after trying all of them.
async function escalate({ github, context, inputs, scores, flagged }) {
  const number = pullRequestNumber(context.payload);
  const failures = number
    ? await escalatePullRequest({ github, context, inputs, scores, flagged, number })
    : await escalateIssue({ github, context, inputs, scores, flagged });
  if (failures.length > 0) {
    throw new EscalationError(`Prompt Guard could not ${failures.join(', ')}.`);
  }
}

module.exports = { EscalationError, buildBody, escalate, pullRequestNumber };
