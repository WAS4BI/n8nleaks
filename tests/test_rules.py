import json

import pytest

from n8nleaks.scan import is_sensitive
from workflows import b64, code, fake, http, rules, scan, send_email, set_values, webhook, workflow

TOKEN = fake("k9X2mQ7v", "L4pR8sT1")
PASSWORD = fake("Winter", "2026!")


# --- things that must stay quiet -------------------------------------------

def test_a_workflow_that_uses_vars_and_env_is_clean():
    wf = workflow(
        webhook(),
        http(headers=[("Authorization", "={{ 'Bearer ' + $vars.CRM_TOKEN }}"),
                      ("x-api-key", "={{ $env.API_KEY }}"),
                      ("Content-Type", "application/json")],
             json_body="={{ JSON.stringify({ password: $vars.PW }) }}",
             url="=https://api.example.com/v1?api_key={{ $vars.KEY }}"),
        code("const token = $vars.TOKEN;\n"
             "const headers = { Authorization: `Bearer ${token}` };\n"
             "const tokenUrl = 'https://auth.example.com/oauth/token';\n"
             "return [{ json: { headers } }];"),
        send_email("ops@example.com"),
    )
    assert scan(wf) == []


@pytest.mark.parametrize("value", [
    "=Bearer {{ $vars.TOKEN }}",
    "={{ $json.token }}",
    "Bearer",
    "<your token here>",
    "YOUR_API_KEY",
    "xxxxxxxx",
])
def test_references_and_placeholders_are_not_secrets(value):
    assert scan(workflow(http(headers=[("Authorization", value)]))) == []


def test_names_about_a_credential_are_not_the_credential():
    wf = workflow(set_values(token_type="Bearer", token_url="https://auth.example.com/token",
                             password_field="password", expires_in="3600"))
    assert scan(wf) == []


def test_a_placeholder_shaped_like_a_key_is_ignored():
    assert scan(workflow(set_values(note=fake("sk-", "x" * 24)))) == []


# Each of these was a false positive on real exports.

def test_aws_secrets_manager_secret_name_is_not_a_secret():
    body = json.dumps({"SecretId": "app/production/main"})
    assert scan(workflow(http(json_body=body))) == []


def test_a_ternary_is_not_an_assignment():
    assert scan(workflow(code("return { next: shouldRetry ? 'pass' : 'finish' };"))) == []


def test_key_value_rows_use_the_key_as_the_name():
    card = json.dumps({"parameters": [{"key": "embedded_sheets_url", "value": "{{ $json.url }}"}]})
    js = "const params = [{ key: 'embedded_sheets_url', value: origin.sheetUrl }];"
    assert scan(workflow(http(json_body=card), code(js))) == []
    assert rules(scan(workflow(http(json_body=json.dumps({"key": "api_token", "value": TOKEN}))))) \
        == ["literal-secret"]


def test_a_date_named_after_authorization_is_not_a_secret():
    assert scan(workflow(code("const p = { AuthorizationDate: '0001-01-01T00:00:00' };"))) == []


@pytest.mark.parametrize("name, sensitive", [
    ("SecretId", False), ("secret_arn", False), ("token_id", False),
    ("session_id", True), ("sessionid", True), ("client_secret", True), ("Authtoken", True),
])
def test_sensitive_names(name, sensitive):
    assert is_sensitive(name) is sensitive


# --- literal credentials -----------------------------------------------------

def test_literal_auth_header():
    [f] = scan(workflow(http(headers=[("Authorization", "Bearer " + TOKEN)])))
    assert f.rule == "literal-auth-header"
    assert f.where == 'node "HTTP Request" parameters.headerParameters.parameters[0].value (Authorization)'
    assert f.value == "Bearer " + TOKEN


def test_an_expression_with_a_typed_in_token_is_still_literal():
    [f] = scan(workflow(http(headers=[("x-api-key", "=" + TOKEN + "{{ '' }}")])))
    assert f.rule == "literal-auth-header"


def test_basic_auth_says_what_it_hides_and_is_reported_once():
    [f] = scan(workflow(http(headers=[("Authorization", "Basic " + b64("api_user:" + PASSWORD))])))
    assert f.rule == "literal-auth-header"
    assert f.detail == "base64 of a username and password"


def test_password_in_a_json_body():
    body = json.dumps({"username": "api", "password": PASSWORD}, indent=2)
    [f] = scan(workflow(http(json_body=body)))
    assert f.rule == "literal-secret"
    assert f.where == 'node "HTTP Request" parameters.jsonBody > password'


def test_json_body_expression_that_still_parses():
    body = '={\n  "user": "{{ $json.user }}",\n  "password": "' + PASSWORD + '"\n}'
    assert rules(scan(workflow(http(json_body=body)))) == ["literal-secret"]


def test_json_body_expression_that_does_not_parse():
    body = '={ "count": {{ $json.n }}, "api_key": "' + TOKEN + '" }'
    assert rules(scan(workflow(http(json_body=body)))) == ["literal-secret"]


def test_key_in_a_url_query_string():
    [f] = scan(workflow(http(url="https://api.example.com/v1?format=json&api_key=" + TOKEN)))
    assert f.rule == "literal-secret"
    assert f.where == 'node "HTTP Request" parameters.url (api_key)'
    assert f.value == TOKEN


def test_query_parameter_rows():
    assert rules(scan(workflow(http(query=[("access_token", TOKEN)])))) == ["literal-secret"]


def test_set_node_assignment():
    assert rules(scan(workflow(set_values(api_key=TOKEN)))) == ["literal-secret"]


def test_code_node_assignment_reports_the_code_line():
    js = "// load the orders\nconst limit = 50;\nconst apiKey = '" + TOKEN + "';\n"
    [f] = scan(workflow(code(js)))
    assert f.rule == "literal-secret"
    assert f.detail == "code line 3"
    assert f.where == 'node "Code" parameters.jsCode (apiKey)'


def test_code_node_header_call():
    js = "const h = new Headers();\nh.set('x-api-key', '" + TOKEN + "');"
    assert rules(scan(workflow(code(js)))) == ["literal-auth-header"]


@pytest.mark.parametrize("js", [
    "const token = 'YOUR_TOKEN';",
    "const password = '';",
    "if (password === 'abc12345') {}",
    "const auth = `Bearer ${$vars.TOKEN}`;",
])
def test_code_without_a_literal_secret(js):
    assert scan(workflow(code(js))) == []


# --- pinned data -------------------------------------------------------------

def test_pinned_webhook_keeps_the_callers_auth_header():
    caller = "Bearer " + b64(json.dumps({"user": "jane.doe@acme.test"}))
    pin = {"Webhook": [{"json": {"headers": {"host": "n8n.example.com", "authorization": caller},
                                 "body": {"order": 1042}}}]}
    found = scan(workflow(webhook(), pin=pin))
    assert rules(found) == ["pinned-data", "pinned-secret"]
    secret = next(f for f in found if f.rule == "pinned-secret")
    assert secret.where == 'pinned data of "Webhook" [0].json.headers.authorization'
    assert secret.detail == "base64 of JSON with user"


def test_pinned_oauth_response():
    pin = {"Get Token": [{"json": {"access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600}}]}
    assert rules(scan(workflow(http(name="Get Token"), pin=pin))) == ["pinned-data", "pinned-secret"]


def test_pinned_data_alone_is_a_warning():
    [f] = scan(workflow(webhook(), pin={"Webhook": [{"json": {"order": 1042}}]}))
    assert (f.rule, f.severity) == ("pinned-data", "warning")


# --- known key formats -------------------------------------------------------

KEYS = [
    ("AWS access key id", fake("AKIA", "Q3J7K2M9P4X8Z5W1")),
    ("GitHub token", fake("gh", "p_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5")),
    ("Slack token", fake("xo", "xb-", "1234567890-0987654321-aBcDeFgHiJkLmN")),
    ("Google API key", fake("AI", "za", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q")),
    ("Google OAuth client secret", fake("GOC", "SPX-", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9b")),
    ("Anthropic API key", fake("sk-", "ant-", "api03-aB3dE5gH7jK9mN1pQ3sT5vW7")),
    ("OpenAI API key", fake("sk-", "proj-", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ")),
    ("Stripe live key", fake("sk_", "live_", "aB3dE5gH7jK9mN1pQ3sT5vW7")),
    ("SendGrid API key", fake("SG", ".", "aB3dE5gH7jK9mN1pQ3sT5v", ".",
                              "wX7yZ9bC1dF3hJ5kL7nP9rS1tV3xZ5aB7cD9eF1gH3")),
    ("Telegram bot token", fake("123456789", ":AA", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3")),
    ("JSON Web Token", fake("eyJ", "hbGciOiJIUzI1NiJ9", ".", "eyJ", "zdWIiOiIxMjM0NTY3ODkwIn0", ".",
                            "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")),
    ("Private key", fake("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA")),
    ("Password in a URL", fake("postgres://n8n:", PASSWORD, "@db.internal:5432/n8n")),
    ("Slack webhook URL", fake("https://hooks.", "slack.com/services/",
                               "T0AB1CD2E/B0FG3HI4J/aB3dE5gH7jK9mN1pQ3sT5vW7")),
    ("Google Chat webhook URL", fake("https://chat.", "googleapis.com/v1/spaces/AAAAbCdEfGh/messages?key=",
                                     "AI", "zaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
                                     "&token=", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5kL7nP9%3D")),
    ("Discord webhook URL", fake("https://discord.", "com/api/webhooks/123456789012345678/",
                                 "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5kL7")),
]


@pytest.mark.parametrize("label, value", KEYS, ids=[k[0] for k in KEYS])
def test_known_key_format_is_reported_once(label, value):
    found = scan(workflow(set_values(note=value)))
    assert [(f.rule, f.detail) for f in found] == [("known-key-format", label)]


def test_known_key_inside_a_code_node():
    js = "const client = new OpenAI({ baseURL: base, key: process.env.K });\n// old: " + KEYS[6][1]
    [f] = scan(workflow(code(js)))
    assert (f.rule, f.detail) == ("known-key-format", "OpenAI API key, code line 2")


# --- identities and emails ---------------------------------------------------

def test_base64_identity_outside_a_header():
    [f] = scan(workflow(set_values(note=b64(json.dumps({"user": "jane.doe@acme.test"})))))
    assert (f.rule, f.detail) == ("encoded-identity", "base64 of JSON with user")


def test_email_address():
    [f] = scan(workflow(send_email("jane.doe@acme.test")))
    assert f.rule == "email-address"
    assert f.where == 'node "Send Email" parameters.toEmail'


def test_allowed_emails():
    assert scan(workflow(send_email("ops@example.com"))) == []
    assert scan(workflow(send_email("jane.doe@acme.test")), allow_emails=["*@ACME.test"]) == []


def test_email_in_sharing_info_from_the_api():
    wf = workflow(webhook(), shared=[{"role": "workflow:owner",
                                      "project": {"name": "Jane Doe <jane.doe@acme.test>"}}])
    [f] = scan(wf)
    assert f.where == "workflow shared[0].project.name"


# --- node notes --------------------------------------------------------------

def test_notes_ignore_everything_on_a_node_including_its_pins():
    wf = workflow(http(headers=[("Authorization", "Bearer " + TOKEN)], notes="Sandbox key. n8nleaks:ignore"),
                  pin={"HTTP Request": [{"json": {"ok": True}}]})
    assert scan(wf) == []


def test_notes_ignore_only_the_rules_listed():
    wf = workflow(http(headers=[("Authorization", "Bearer " + TOKEN)],
                       url="https://api.example.com/?to=jane.doe@acme.test",
                       notes="n8nleaks:ignore email-address, pinned-data"))
    assert rules(scan(wf)) == ["literal-auth-header"]


# --- where it points ---------------------------------------------------------

def test_line_number_points_at_the_value():
    wf = workflow(webhook(), http(headers=[("Authorization", "Bearer " + TOKEN)]))
    text = json.dumps(wf, indent=2)
    [f] = scan(wf)
    assert TOKEN in text.splitlines()[f.line - 1]


def test_line_number_inside_a_json_body():
    body = json.dumps({"password": PASSWORD}, indent=2)
    wf = workflow(webhook(), http(json_body=body))
    text = json.dumps(wf, indent=2)
    [f] = scan(wf)
    assert PASSWORD in text.splitlines()[f.line - 1]
