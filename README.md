# prompt-guard-action

GitHub Action that detects prompt injection and intrusion attempts.

It screens untrusted text, such as a pull request's title and body or an earlier bot comment,
before an agent like Claude reads it. The classifier is Meta's
[Llama Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M), served by
Hugging Face [text-embeddings-inference](https://github.com/huggingface/text-embeddings-inference)
(TEI). You run TEI; the action only needs its address and credentials.

- [Usage](#usage)
- [Inputs](#inputs) and [outputs](#outputs)
- [Permissions](#permissions)
- [Audit, block and dry run](#audit-block-and-dry-run)
- [Escalation](#escalation)
- [How long texts are scored](#how-long-texts-are-scored)
- [The reusable workflow, with OpenBao and Cloudflare Access](#the-reusable-workflow-with-openbao-and-cloudflare-access)
- [Threat model](#threat-model)
- [Development](#development)

## Usage

```yaml
permissions: {}

jobs:
  screen:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      issues: write
    outputs:
      verdict: ${{ steps.guard.outputs.verdict }}
    steps:
      - id: guard
        uses: actions-fyi/prompt-guard-action@v1
        with:
          address: https://prompt-guard.example.com
          api-key: ${{ secrets.PROMPT_GUARD_API_KEY }}
          texts: >-
            {"title": ${{ toJSON(github.event.pull_request.title) }},
            "body": ${{ toJSON(github.event.pull_request.body) }}}
          notify: "@my-org/moderators"

  review:
    needs: screen
    # Only a clean verdict lets the agent read the texts.
    if: needs.screen.outputs.verdict == 'clean'
    # ...
```

`toJSON` turns each field into a JSON string, quotes and newlines escaped, so `texts` is valid JSON
whatever the text holds. A pull request without a description has a `null` body, which is
skipped.

Gate on `verdict == 'clean'`, never on `verdict != 'flagged'`: the verdict is `error` when a text
couldn't be scored, and empty when the step failed before it could screen anything.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `address` | required | The base URL of the TEI service. A path prefix is kept, e.g. `https://gateway.example.com/tei`. |
| `api-key` | `""` | TEI's API key (`--api-key`), sent as `Authorization: Bearer`. |
| `access-client-id` | `""` | The client ID of a Cloudflare Access service token, sent as `CF-Access-Client-Id`. |
| `access-client-secret` | `""` | Its client secret, sent as `CF-Access-Client-Secret`. Set both Access values or neither; one alone is a configuration error, and nothing is sent. |
| `texts` | required | A JSON object mapping a name to a text. Names are letters, digits, `.`, `_` and `-`, at most 64 characters. Empty and `null` texts are skipped. |
| `threshold` | `0.5` | A text whose score is at or above this is flagged. |
| `mode` | `audit` | `audit` or `block`; see [below](#audit-block-and-dry-run). |
| `dry-run` | `false` | Scan and set every output, but make no changes on GitHub. |
| `notify` | `""` | Handles to mention when escalating, e.g. `@my-org/moderators @octocat`. |
| `label` | `prompt-guard:flagged` | The label for a flagged pull request or the escalation issue. Empty adds none. |
| `marker` | `<!-- prompt-guard -->` | The hidden HTML comment that identifies this action's comment or issue. Use a different one per workflow if several screen the same pull request. |
| `malicious-label` | `MALICIOUS` | The model's label whose score is compared with the threshold. It must be one of the labels in TEI's `/info`. |
| `github-token` | `${{ github.token }}` | The token for escalation. |

Every input reaches the script through the environment, never by interpolation into the script,
so a text can't become code.

## Outputs

| Output | Description |
| --- | --- |
| `verdict` | `clean`, `flagged` or `error`. |
| `scores` | A JSON object mapping each screened name to its highest score, e.g. `{"title":0.0004,"body":0.9996}`. |
| `flagged` | A JSON array of the flagged names. |
| `would-escalate` | `true` when a text was flagged, so the action escalates unless it's a dry run. |
| `escalated` | `true` when the escalation was made in full. |

## Permissions

| Permission | Why |
| --- | --- |
| `contents: read` | The minimum for the job. |
| `pull-requests: write` | Label a flagged pull request and convert it to a draft. |
| `issues: write` | Comment on the pull request, or open and comment on the escalation issue. |

A dry run makes no GitHub API calls, so it needs none of them. The token of a `pull_request` run
from a fork is read-only, so escalation fails there; see [Escalation](#escalation).

## Audit, block and dry run

- **audit** (default): a flagged text sets the outputs, escalates and logs a warning, but the step
  passes. Use it to learn how the model scores your traffic before anything depends on it.
- **block**: the same, and the step fails, which fails the job.
- **dry-run**: scans and sets every output, `would-escalate` included, but makes no comment, label,
  draft or issue, and no GitHub API call at all. `escalated` stays `false`. In block mode the step
  still fails on a flagged text.

Independent of the mode, the step fails with the verdict `error` whenever a text couldn't be
scored. It fails closed:

- an invalid input, or only one of the two Access values;
- TEI unreachable, or answering with any non-2xx status (429, 502, 503 and 504 are retried twice);
- a 401 or 403: the API key or the Access token was refused;
- a redirect, or an HTML page instead of JSON, which is how Cloudflare Access turns away a request
  without a valid service token; the message says so;
- a body that isn't JSON, or JSON of an unexpected shape;
- a model without `malicious-label`, or a prediction without a score for it.

## Escalation

Only when a text is flagged and it's not a dry run.

- **Events with a pull request** (`pull_request`, `pull_request_target`, reviews, and comments on
  a pull request): one comment, found by `marker` among `github-actions[bot]`'s comments and
  updated by later runs, mentioning `notify`; the `label`, created if missing; and a conversion to
  a draft (GraphQL `convertPullRequestToDraft`), so it isn't merged or picked up as ready while
  someone looks.
- **Other events**: one open issue by `github-actions[bot]` with the marker, labeled. Later runs
  comment on it while it's open, mentioning `notify`.

The comment and the issue never quote the flagged text: they list the names, scores, threshold,
commit and a link to the run, nothing else. Close the issue, or remove the label and mark the pull
request ready, once someone has looked. The action never un-flags anything itself.

If any of these steps fails, the others are still tried, `escalated` is `false`, and the step
fails, also in audit mode: a flag nobody hears about is no use.

## How long texts are scored

TEI doesn't chunk. Prompt Guard 2 reads 512 tokens, and TEI rejects longer input unless it
truncates, which would hide anything after the cut. So the action:

1. reads `max_input_length`, `max_client_batch_size` and the model's labels from `GET /info`;
2. tokenizes each text with `POST /tokenize` and counts the special tokens the model adds;
3. cuts the text into windows of `max_input_length` minus the special tokens, at token boundaries,
   overlapping by 64 tokens, so an injection that spans a cut is whole in one window;
4. tokenizes each window again, and splits any that grew past the limit on its own;
5. scores the windows with `POST /predict` in batches of at most `max_client_batch_size`, with
   `truncate: false`;
6. takes the highest `malicious-label` score of a text's windows as its score.

Texts longer than TEI accepts for tokenizing (`max_input_length × 250` characters) are first cut
into overlapping segments.

## The reusable workflow, with OpenBao and Cloudflare Access

[`.github/workflows/_shared.yml`](.github/workflows/_shared.yml) wraps the action for a
deployment that keeps its secrets in [OpenBao](https://openbao.org) and has Cloudflare Access in
front of TEI:

```yaml
jobs:
  screen:
    permissions:
      id-token: write
      contents: read
      pull-requests: write
      issues: write
    uses: actions-fyi/prompt-guard-action/.github/workflows/_shared.yml@v1
    secrets:
      PROMPT_GUARD_CLIENT_ID: ${{ secrets.PROMPT_GUARD_CLIENT_ID }}
    with:
      texts: >-
        {"title": ${{ toJSON(github.event.pull_request.title) }},
        "body": ${{ toJSON(github.event.pull_request.body) }}}
```

It logs in to OpenBao with the job's OIDC token
([hashicorp/vault-action](https://github.com/hashicorp/vault-action)), reads TEI's API key and,
when `PROMPT_GUARD_CLIENT_ID` is set, the Access client secret, and passes them straight to the
action. They never reach a job output, the environment or a file.

- **Configuration variables**: `PROMPT_GUARD_ADDRESS` (TEI) and `SECRETS_ADDRESS` (OpenBao), the
  defaults of the inputs `address` and `secrets-address`.
- **OpenBao**: a JWT auth method at `github-actions` with the issuer
  `https://token.actions.githubusercontent.com`, and a role `prompt-guard` with
  `bound_audiences` set to the OpenBao URL (or the `jwt-audience` input) and `bound_claims` on
  `job_workflow_ref`:
  `actions-fyi/prompt-guard-action/.github/workflows/_shared.yml@refs/heads/main`,
  `…@refs/heads/gh-readonly-queue/main/*` and `…@refs/tags/v*`. Binding the role to this file,
  rather than to the callers, lets any repository call it while only this file's reviewed refs get
  the secrets. Its policy reads `ci/data/prompt-guard-api` (key `api_key`) and
  `ci/data/prompt-guard-access` (key `client_secret`); the inputs `api-key-secret` and
  `access-secret` change these.
- **Access in front of TEI**: a service token whose client ID is the GitHub secret
  `PROMPT_GUARD_CLIENT_ID` and whose client secret is in OpenBao. Neither store alone holds a
  working token. Leave `PROMPT_GUARD_CLIENT_ID` unset where TEI has no Access gate, e.g. for
  internal runners.
- **Access in front of OpenBao**, if any: the secrets `CF_ACCESS_CLIENT_ID` and
  `CF_ACCESS_CLIENT_SECRET`, sent to OpenBao only when both are set.

## Threat model

- **A signal, not a boundary.** A classifier misses some injections and flags some harmless text.
  Use the verdict to keep obvious attacks away from an agent and to get a person to look, but
  design the agent's permissions as if an injection got through: least privilege, no secrets in
  reach, and its output screened before it's posted.
- **Never echo the text.** Nothing the action writes, its outputs, logs, comments, issues or
  error messages, quotes the texts. Repeating an injection in a comment would put it in front of
  every agent that reads the thread. Error messages from TEI are reduced to their status and type
  for the same reason.
- **Fail closed.** Anything short of a complete, well-formed answer for every window is the
  verdict `error` and a failed step, in every mode, never `clean`.
- **Trust the workflow, not the text.** The names in `texts`, `notify`, `label` and `marker` come
  from the calling workflow and are validated; the texts are only ever sent to TEI.

Known limits: content that the tokenizer can't represent, e.g. unknown characters, reaches the
model as unknown tokens. Inputs are passed through the environment, where Linux limits a single
variable to 128 KiB, so `texts` must stay below that; a larger value fails the step.

## Development

The action is plain CommonJS run by
[actions/github-script](https://github.com/actions/github-script): Node built-ins and what
github-script provides, no npm dependencies, no build and no `dist/`.

```sh
node --test test/*.test.js
```

The tests mock `fetch` with a fake TEI that enforces TEI's limits, and mock Octokit. The live
test, [`test.yml`](.github/workflows/test.yml), runs the reusable workflow against the real
service in a dry run, on pushes to `main`, in the merge queue and on demand.
