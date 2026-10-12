"""
Every rule n8nleaks knows, and the patterns behind them.

The rule list is the one place the ids, severities and fix hints live, so
--list-rules, the hints printed after a scan and the README table all agree.
The detection itself is in scan.py.
"""

import re
from dataclasses import dataclass

ERROR, WARNING = "error", "warning"
SEVERITY_RANK = {WARNING: 1, ERROR: 2}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    summary: str
    fix: str


RULES = {rule.id: rule for rule in [
    Rule("pinned-secret", ERROR,
         "Pinned data holds a credential, such as the auth header a webhook caller sent.",
         "Unpin the node on the canvas, or pin a made-up payload, then export again. "
         "Editing the file is not enough: the pin is still on the canvas and comes back on the next export."),
    Rule("literal-auth-header", ERROR,
         "A header like Authorization or x-api-key has a typed-in value.",
         "Use an n8n credential, or reference the value with $vars or $env."),
    Rule("literal-secret", ERROR,
         "A field like password, token or api_key has a typed-in value, in parameters, a JSON body or a Code node.",
         "Use an n8n credential, or reference the value with $vars or $env."),
    Rule("known-key-format", ERROR,
         "A value matches a known key or token format (GitHub, Slack, AWS, Google, OpenAI, Stripe, webhook URLs...).",
         "If this file was ever committed or shared, revoke the key. Then use a credential or $vars instead."),
    Rule("pinned-data", WARNING,
         "A node has pinned data. It is exported with the workflow and is often a real record.",
         "Unpin it, or pin made-up data, before exporting."),
    Rule("encoded-identity", WARNING,
         "A value is base64 of an identity, like {\"user\": \"someone@company.com\"}.",
         "Base64 is not encryption: anyone who reads it can decode it and make their own. "
         "Use a random token kept in a credential."),
    Rule("email-address", WARNING,
         "An email address.",
         "Make sure it belongs in a file you share. If it does, add it to allow-emails in the config."),
]}


# Names of headers and fields that hold credentials. Matched against the
# header or key name, never the value.
SENSITIVE_NAME = re.compile(r"""
      authori[sz]ation | ^auth$ | [-_]auth$ | ^x-auth | authtoken | auth[-_]token
    | token | secret | passw | ^pwd$ | ^pass$ | cookie | ^session$ | session[-_]?id
    | api[-_]?key
    | (access|secret|private|subscription|functions|license|app|master)[-_]?key
""", re.IGNORECASE | re.VERBOSE)
# A bare "key" is left out on purpose: it is nearly always the label half of
# a {key, value} row, like a Google Chat card parameter.

# ...unless the name says it is about the credential rather than the
# credential itself: token_type, token_url, password_field, expires_in,
# SecretId (an AWS Secrets Manager secret's name), AuthorizationDate.
NOT_SENSITIVE = re.compile(
    r"(type|url|uri|endpoint|name|expires?|expires[-_]?in|expiry|ttl|field|"
    r"header|path|method|mode|length|count|enabled|location|label|hint|"
    r"arn|date|time|timestamp|(?<!session)(?<!session[-_])ids?)$",
    re.IGNORECASE,
)

PASSWORD_NAME = re.compile(r"^(pass|password|passwd|pwd)$", re.IGNORECASE)

# Header names that mean "this is auth" even outside a headers block, for
# example Authorization set inside a Code node.
HEADER_NAME = re.compile(r"^(proxy-)?authori[sz]ation$|^cookie$|^x-", re.IGNORECASE)

# Values that stand in for a secret rather than being one.
PLACEHOLDER = re.compile(r"""^(
      x{3,} | \*{3,} | \.{3,} | <[^>]*> | \[[^\]]*\]
    | your[-_ ].* | changeme | change[-_ ]me | placeholder | redacted | dummy
    | secret | password | token | test | null | none | undefined | true | false
)$""", re.IGNORECASE | re.VERBOSE)

# Anything in a value that means it is looked up at runtime, not typed in.
REFERENCE = re.compile(r"\{\{|\$\{|\$vars|\$env|\$secrets|process\.env|os\.environ")

# "Bearer abc" -> "abc", and a bare "Bearer" -> "". Applied before deciding
# whether a value is literal.
AUTH_SCHEME = re.compile(r"^(bearer|basic|token|bot|apikey|key|digest)(\s+|$)", re.IGNORECASE)

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")

DEFAULT_ALLOWED_EMAILS = [
    "*@example.com", "*@example.org", "*@example.net", "*@*.example.com",
    "git@*", "*@users.noreply.github.com",
]

# Keys in a decoded base64 JSON object that make it an identity.
IDENTITY_KEYS = {"user", "username", "email", "mail", "login", "sub", "uid", "user_id", "userid"}

# Chat webhook URLs carry their secret in the URL itself.
WEBHOOK_FORMATS = [(label, re.compile(pattern)) for label, pattern in [
    ("Google Chat webhook URL",
     r"https://chat\.googleapis\.com/v1/spaces/[^/\s\"']+/messages\?[^\s\"']*token=[A-Za-z0-9_%-]{10,}"),
    ("Slack webhook URL",
     r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,}"),
    ("Discord webhook URL",
     r"https://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{30,}"),
]]

# (label, pattern). Order matters: when two matches overlap, the earlier
# entry wins, so a Google Chat webhook URL is reported once as a webhook URL
# and not again for the Google API key inside it.
KEY_FORMATS = WEBHOOK_FORMATS + [(label, re.compile(pattern)) for label, pattern in [
    ("Private key", r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"),
    ("Password in a URL", r"\b[a-z][a-z0-9+.-]*://[^/\s:@\"']+:[^/\s@\"']+@[^/\s\"']+"),
    ("AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    ("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{60,}"),
    ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}"),
    ("Google OAuth client secret", r"\bGOCSPX-[A-Za-z0-9_-]{28}"),
    ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("OpenAI API key", r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
    ("Stripe live key", r"\b[sr]k_live_[A-Za-z0-9]{20,}"),
    ("SendGrid API key", r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ("Telegram bot token", r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
]]
