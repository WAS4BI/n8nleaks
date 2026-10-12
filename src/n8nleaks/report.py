"""
Turns findings into text, JSON or GitHub annotations.

Values are redacted unless asked otherwise. CI logs are often public, and a
scanner that prints the secret it found has leaked it a second time.
"""

import json

from . import __version__
from . import rules as R


def redact(value):
    value = value.strip()
    m = R.AUTH_SCHEME.match(value)
    if m and value[m.end():]:
        return f"{m.group(1)} {redact(value[m.end():])}"
    if R.EMAIL.fullmatch(value):
        local, domain = value.split("@", 1)
        return f"{local[:2]}***@{domain}"
    if value.startswith(("http://", "https://")):
        scheme, _, host = value.split("/")[:3]
        return f"{scheme}//{host}/...({len(value)} chars)"
    if len(value) <= 6:
        return "*" * len(value)
    # Show a little more of long tokens, which helps find them, and very
    # little of short ones, which are usually passwords.
    return f"{value[:min(4, len(value) // 5)]}...({len(value)} chars)"


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def summary(result):
    if not result.workflows:
        return "No n8n workflows found."
    errors = sum(f.severity == R.ERROR for f in result.findings)
    warnings = len(result.findings) - errors
    scanned = f"{plural(result.workflows, 'workflow')} ({plural(result.files, 'file')})"
    if not result.findings:
        return f"Nothing found in {scanned}."
    affected = len({(f.file, f.workflow) for f in result.findings})
    return f"{plural(errors, 'error')} and {plural(warnings, 'warning')} in {affected} of {scanned}."


def shown(finding, redacted):
    value = redact(finding.value) if redacted else finding.value
    if finding.rule == "pinned-data":
        return finding.where
    detail = f"  [{finding.detail}]" if finding.detail else ""
    return f"{finding.where}: {value}{detail}"


def write_text(result, redacted, out):
    files = {}
    for f in result.findings:
        files.setdefault(f.file, []).append(f)

    for file, findings in files.items():
        workflows = {f.workflow for f in findings}
        header = file if len(workflows) > 1 else f'{file}  (workflow "{findings[0].workflow}")'
        print(header, file=out)
        findings.sort(key=lambda f: (f.line, -R.SEVERITY_RANK[f.severity], f.rule))
        line_w = len(str(findings[-1].line))
        rule_w = max(len(f.rule) for f in findings)
        for f in findings:
            prefix = f'"{f.workflow}" ' if len(workflows) > 1 else ""
            print(f"  {f.line:>{line_w}}  {f.severity:<7}  {f.rule:<{rule_w}}  "
                  f"{prefix}{shown(f, redacted)}", file=out)
        print(file=out)

    used = [rule for rule in R.RULES.values() if any(f.rule == rule.id for f in result.findings)]
    if used:
        print("How to fix:", file=out)
        width = max(len(rule.id) for rule in used)
        for rule in used:
            print(f"  {rule.id:<{width}}  {rule.fix}", file=out)
        print(file=out)

    print(summary(result), file=out)


def write_json(result, redacted, out):
    json.dump({
        "version": __version__,
        "files": result.files,
        "workflows": result.workflows,
        "findings": [{
            "rule": f.rule,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "workflow": f.workflow,
            "where": f.where,
            "value": redact(f.value) if redacted else f.value,
            "detail": f.detail,
        } for f in result.findings],
    }, out, indent=2, ensure_ascii=False)
    print(file=out)


def escape_data(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text):
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def write_github(result, redacted, out):
    """One workflow command per finding, so each shows on the file in the
    pull request: https://docs.github.com/actions/reference/workflow-commands-for-github-actions"""
    for f in result.findings:
        props = f"file={escape_property(f.file)},line={f.line},title={escape_property('n8nleaks ' + f.rule)}"
        message = f"{shown(f, redacted)}\n{R.RULES[f.rule].fix}"
        print(f"::{f.severity} {props}::{escape_data(message)}", file=out)
    print(summary(result), file=out)


WRITERS = {"text": write_text, "json": write_json, "github": write_github}
