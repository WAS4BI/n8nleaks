"""
Builders for made-up n8n workflows.

Every token in the tests is fake and built by joining pieces with fake(), so
no file in this repo holds a string that looks like a real key. That keeps
GitHub push protection and other scanners quiet about this one.
"""

import base64
import json

from n8nleaks.config import parse
from n8nleaks.scan import scan_text


def fake(*parts):
    return "".join(parts)


def b64(text):
    return base64.b64encode(text.encode()).decode()


def node(name, type_, parameters=None, notes=None):
    n = {"parameters": parameters or {}, "name": name, "type": type_,
         "typeVersion": 1, "position": [0, 0], "id": f"id-{name}"}
    if notes:
        n["notes"] = notes
    return n


def http(name="HTTP Request", headers=(), query=(), json_body=None,
         url="https://api.example.com/items", notes=None):
    p = {"method": "POST", "url": url}
    if headers:
        p["sendHeaders"] = True
        p["headerParameters"] = {"parameters": [{"name": k, "value": v} for k, v in headers]}
    if query:
        p["sendQuery"] = True
        p["queryParameters"] = {"parameters": [{"name": k, "value": v} for k, v in query]}
    if json_body is not None:
        p["sendBody"] = True
        p["specifyBody"] = "json"
        p["jsonBody"] = json_body
    return node(name, "n8n-nodes-base.httpRequest", p, notes)


def code(js, name="Code"):
    return node(name, "n8n-nodes-base.code", {"jsCode": js})


def set_values(name="Set", **values):
    rows = [{"id": f"a{i}", "name": k, "value": v, "type": "string"}
            for i, (k, v) in enumerate(values.items())]
    return node(name, "n8n-nodes-base.set", {"assignments": {"assignments": rows}})


def webhook(name="Webhook", notes=None):
    return node(name, "n8n-nodes-base.webhook",
                {"path": "orders", "httpMethod": "POST", "authentication": "headerAuth"}, notes)


def send_email(to, name="Send Email"):
    return node(name, "n8n-nodes-base.emailSend",
                {"fromEmail": "bot@example.com", "toEmail": to, "subject": "Daily report"})


def workflow(*nodes, pin=None, name="Test workflow", **extra):
    wf = {"name": name, "nodes": list(nodes), "connections": {}, "pinData": pin or {},
          "settings": {"executionOrder": "v1"}}
    wf.update(extra)
    return wf


def scan(wf, **settings):
    """Findings for one workflow, as n8nleaks would report them."""
    config = parse({k.replace("_", "-"): v for k, v in settings.items()})
    text = json.dumps(wf, indent=2)
    _, findings = scan_text(text, "test.json", config.allowed_emails)
    return findings


def rules(findings):
    return sorted(f.rule for f in findings)
