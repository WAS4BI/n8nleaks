# n8nleaks

[![CI](https://github.com/WAS4BI/n8nleaks/actions/workflows/ci.yml/badge.svg)](https://github.com/WAS4BI/n8nleaks/actions/workflows/ci.yml)

Find secrets and personal data in exported n8n workflows before they reach git.

## Why

n8n workflows are JSON, so sooner or later they go into git. Moving every
credential into n8n's credential store or `$vars` does not make an export safe
by itself:

- **Pinned data is exported with the workflow.** Pin a webhook test run and the
  export carries the headers the caller sent, `Authorization` included, plus
  whatever was in the body. Delete it from the file and it comes back on the
  next export, because the pin is still on the canvas.
- **Anything typed into a node is in the export.** A header row, a JSON body
  kept as a string, a query string, a line in a Code node, or a half
  expression like `=Bearer abc123{{ ... }}`.
- **Some tokens are only base64.** `eyJ1c2VyIjogImphbmUuZG9lQGFjbWUudGVzdCJ9`
  looks random and is `{"user": "jane.doe@acme.test"}`. Anyone can make one.

General secret scanners look for key formats and random-looking strings.
n8nleaks knows where n8n keeps things. Use it next to one of those, not
instead of one.

## What it finds

| Rule | Severity | Finds |
|---|---|---|
| `pinned-secret` | error | A credential in pinned data, such as the auth header a webhook caller sent |
| `literal-auth-header` | error | A header like `Authorization` or `x-api-key` with a typed-in value |
| `literal-secret` | error | A field like `password`, `token` or `api_key` with a typed-in value, in parameters, JSON bodies, query strings or Code nodes |
| `known-key-format` | error | GitHub, Slack, AWS, Google, OpenAI, Anthropic, Stripe, SendGrid, Telegram and JWT tokens, private keys, passwords in URLs, and Slack, Google Chat and Discord webhook URLs |
| `pinned-data` | warning | Any pinned data, since it is usually a real record |
| `encoded-identity` | warning | Base64 that decodes to an identity, like `{"user": "..."}` |
| `email-address` | warning | Email addresses, apart from `example.com` and a few others |

References are fine: `={{ $vars.TOKEN }}`, `$env`, `$secrets`, credentials,
`${...}` in Code nodes, and placeholders like `YOUR_API_KEY` are not reported.

## Install

Needs Python 3.11 or newer. No dependencies.

```bash
pipx install git+https://github.com/WAS4BI/n8nleaks
```

## Use

```bash
n8nleaks                          # every workflow under the current folder
n8nleaks workflows/ "My flow.json"
n8nleaks --format json > leaks.json
```

It reads single workflows, the list that `n8n export:workflow --all` writes,
and pages from the n8n API. Any other JSON is skipped, so running it over a
whole repository is fine.

```
examples/leaky-workflow.json  (workflow "Sync Orders")
  24  error    literal-secret       node "Log In to ERP" parameters.jsonBody > password: Wi...(11 chars)
  41  error    literal-auth-header  node "Get Customer" parameters.headerParameters.parameters[0].value (Authorization): Bearer 9f8e...(32 chars)
  55  error    known-key-format     node "Sign Upload" parameters.jsCode: AKIA...(20 chars)  [AWS access key id, code line 2]
  66  warning  email-address        node "Tell Sales" parameters.toEmail: ja***@acme.test
  78  warning  pinned-data          pinned data of "New Order"
  84  error    pinned-secret        pinned data of "New Order" [0].json.headers.authorization: eyJ1...(40 chars)  [base64 of JSON with user]
  91  warning  email-address        pinned data of "New Order" [0].json.body.contactEmail: ma***@acme.test

How to fix:
  pinned-secret        Unpin the node on the canvas, or pin a made-up payload, then export again. ...
  literal-auth-header  Use an n8n credential, or reference the value with $vars or $env.
  ...

4 errors and 3 warnings in 1 of 1 workflow (1 file).
```

Values are redacted, because CI logs are often public. `--no-redact` prints
them in full.

The exit code is 1 when something at or above `--fail-on` (default `error`)
is found, 0 when not, and 2 for bad arguments or config.

## pre-commit

```yaml
repos:
  - repo: https://github.com/WAS4BI/n8nleaks
    rev: v0.1.0
    hooks:
      - id: n8nleaks
```

## GitHub Actions

```yaml
- uses: actions/checkout@v7
- uses: WAS4BI/n8nleaks@v0.1.0
  with:
    paths: |
      workflows/production
      workflows/development
```

Findings show up as annotations on the pull request.

| Input | Default | |
|---|---|---|
| `paths` | `.` | Files or folders, one per line |
| `fail-on` | `error` | `error` or `warning` |
| `format` | `github` | `github`, `text` or `json` |
| `python-version` | `3.13` | Only used to run n8nleaks, your other steps are not affected |

## Configuration

In `.n8nleaks.toml`, or under `[tool.n8nleaks]` in `pyproject.toml`:

```toml
fail-on = "warning"
disable = ["pinned-data"]
allow-emails = ["*@mycompany.com"]
allow-values = ["^sandbox_"]        # regexes, matched against the value found
exclude = ["tests/fixtures/*"]      # globs, relative paths with forward slashes
```

`--fail-on` and `--disable` on the command line take precedence.
`n8nleaks --list-rules` lists every rule.

## Ignoring a node

Write `n8nleaks:ignore` in the node's notes (node settings, Notes) to skip it,
pinned data included. To skip only some rules:
`n8nleaks:ignore email-address, pinned-data`. The note travels with the
workflow, so the reason stays next to the node it is about.

## What it does not do

- **It does not change your files.** Most fixes belong on the canvas, or the
  next export brings the problem back.
- **It cannot prove a workflow is clean.** It works on names and patterns, so
  expect the odd false alarm and the odd miss.
- **It only sees the export.** Credentials stored in n8n and execution data
  are not in the file, so they are not checked.

## License

MIT
