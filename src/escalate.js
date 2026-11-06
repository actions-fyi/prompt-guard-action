'use strict';

const { formatScore } = require('./verdict');

// Tells people about a flagged text. On a pull request: the label, a conversion to draft, so it
// isn't merged or picked up as ready while someone looks, and one comment, found by the marker and
// updated by later runs. On any other event: one open issue, found by its label and the marker,
// which later runs comment on.
//
// The comment or the issue is the escalation: if it can't be posted, escalate throws and the step
// fails. The label and the draft are best effort, since a GITHUB_TOKEN may not be allowed to
// convert a pull request to a draft. They are tried first, so that the comment says what actually
// happened.
//
// Nothing written here quotes or describes the flagged text. A comment that repeated it would put
// the injection in front of every agent that reads the thread. Only the names of the texts, their
// scores, the threshold, the run and the commit are written.

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
      (subject === 'this pull request'
        ? 'Remove the label and mark the pull request ready once it has been reviewed.'
        : 'Close this issue once the texts have been reviewed.'),
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

const DRAFT_MUTATION =
  'mutation($id: ID!) { convertPullRequestToDraft(input: {pullRequestId: $id}) { pullRequest { isDraft } } }';

async function escalatePullRequest({ github, context, core, inputs, scores, flagged, number }) {
  const repo = context.repo;
  const notes = [];

  // The event's copy may be stale, or absent for a comment on a pull request.
  let pull;
  try {
    pull = (await github.rest.pulls.get({ ...repo, pull_number: number })).data;
  } catch (error) {
    core.warning(`Prompt Guard could not read pull request #${number} (${describe(error)}), so it uses the event's copy.`);
    pull = context.payload.pull_request?.number === number ? context.payload.pull_request : undefined;
  }

  if (inputs.label) {
    try {
      await ensureLabel(github, repo, inputs.label);
      await github.rest.issues.addLabels({ ...repo, issue_number: number, labels: [inputs.label] });
      notes.push(`The pull request is labeled \`${inputs.label}\`.`);
    } catch (error) {
      core.warning(`Prompt Guard could not add the label (${describe(error)}).`);
      notes.push(`The label \`${inputs.label}\` could not be added.`);
    }
  }

  if (pull?.draft === true) {
    notes.push('It is already a draft.');
  } else if (pull && pull.state !== 'open') {
    // A closed pull request can't be converted, and needn't be.
  } else if (pull?.node_id) {
    try {
      await github.graphql(DRAFT_MUTATION, { id: pull.node_id });
      notes.push('It was converted to a draft.');
    } catch (error) {
      core.warning(`Prompt Guard could not convert the pull request to a draft (${describe(error)}).`);
      notes.push('It could not be converted to a draft.');
    }
  } else {
    notes.push('It could not be converted to a draft.');
  }

  const body = buildBody({ context, inputs, scores, flagged, subject: 'this pull request', actions: notes });
  try {
    const comments = await github.paginate(github.rest.issues.listComments, { ...repo, issue_number: number, per_page: 100 });
    const existing = comments
      .filter((comment) => comment.user?.login === inputs.botLogin && comment.body?.includes(inputs.marker))
      .pop();
    if (existing) {
      await github.rest.issues.updateComment({ ...repo, comment_id: existing.id, body });
    } else {
      await github.rest.issues.createComment({ ...repo, issue_number: number, body });
    }
  } catch (error) {
    throw new EscalationError(`Prompt Guard could not post the comment on pull request #${number} (${describe(error)}).`);
  }
}

async function escalateIssue({ github, context, core, inputs, scores, flagged }) {
  const repo = context.repo;
  const subject = `untrusted text in a ${context.eventName} run`;
  const body = buildBody({ context, inputs, scores, flagged, subject, actions: [] });

  if (inputs.label) {
    try {
      await ensureLabel(github, repo, inputs.label);
    } catch (error) {
      core.warning(`Prompt Guard could not create the label (${describe(error)}).`);
    }
  }

  // Found by the label, which every issue it opens carries, rather than by its creator, which
  // depends on the token. Without a label, by the creator.
  let existing;
  try {
    const issues = await github.paginate(github.rest.issues.listForRepo, {
      ...repo,
      state: 'open',
      ...(inputs.label ? { labels: inputs.label } : { creator: inputs.botLogin }),
      per_page: 100,
    });
    existing = issues.find(
      (issue) => !issue.pull_request && issue.user?.login === inputs.botLogin && issue.body?.includes(inputs.marker),
    );
  } catch (error) {
    throw new EscalationError(`Prompt Guard could not look for its open issue (${describe(error)}).`);
  }

  if (existing) {
    try {
      await github.rest.issues.createComment({ ...repo, issue_number: existing.number, body });
    } catch (error) {
      throw new EscalationError(`Prompt Guard could not comment on issue #${existing.number} (${describe(error)}).`);
    }
    return;
  }

  let issue;
  try {
    issue = (
      await github.rest.issues.create({
        ...repo,
        title: 'Prompt Guard flagged untrusted text',
        body,
        ...(inputs.label ? { labels: [inputs.label] } : {}),
      })
    ).data;
  } catch (error) {
    throw new EscalationError(`Prompt Guard could not open an issue (${describe(error)}).`);
  }
  // GitHub drops the labels of a new issue silently when the token may not set them. The next run
  // finds the issue by its label, so it is added again if it is missing.
  const labeled = (issue.labels ?? []).some((label) => (typeof label === 'string' ? label : label?.name) === inputs.label);
  if (inputs.label && !labeled) {
    try {
      await github.rest.issues.addLabels({ ...repo, issue_number: issue.number, labels: [inputs.label] });
    } catch (error) {
      core.warning(`Prompt Guard could not label issue #${issue.number} (${describe(error)}), so the next run opens another.`);
    }
  }
}

// Throws an EscalationError when the comment or the issue could not be posted.
async function escalate({ github, context, core, inputs, scores, flagged }) {
  const number = pullRequestNumber(context.payload);
  if (number) await escalatePullRequest({ github, context, core, inputs, scores, flagged, number });
  else await escalateIssue({ github, context, core, inputs, scores, flagged });
}

module.exports = { EscalationError, buildBody, escalate, pullRequestNumber };
