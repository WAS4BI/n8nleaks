"""
Finds leaks in n8n workflow exports.

A file can hold one workflow (what the editor's Download gives you), a list
of them (`n8n export:workflow --all` without --separate) or a page from the
public API ({"data": [...]}). Anything else is not a workflow and is
skipped, so it is fine to point n8nleaks at a whole repository.

Each workflow gets three passes:

  node parameters   named values (header rows, JSON bodies, URL query
                    strings, Code node assignments) and free text
  pinned data       anything credential-shaped, plus one warning per pin
  everything else   free text only (name, tags, sharing info, meta)

"Free text" is the checks that need no name to go on: known key formats,
email addresses and base64 that decodes to something it should not.
"""

import base64
import json
import os
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from . import rules as R

# A path element meaning "the string here was parsed as JSON, and what
# follows is inside it". Rendered as " > " in locations.
JSON_MARK = object()

CODE_KEYS = {"jsCode", "pythonCode", "functionCode", "code"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox"}

# name: 'value', name = "value", 'x-api-key': `value`
ASSIGNMENT = re.compile(r"""
    (?P<nq>['"]?)(?P<name>[A-Za-z_$][\w$-]*)(?P=nq)\s*[:=]\s*
    (?P<q>['"`])(?P<value>(?:\\.|(?!(?P=q))[^\\\n])*)(?P=q)
""", re.VERBOSE)

# headers.set('x-api-key', 'value'), new Headers([['Authorization', '...']])
CALL_PAIR = re.compile(r"""
    (?P<nq>['"])(?P<name>[\w-]+)(?P=nq)\s*,\s*
    (?P<q>['"`])(?P<value>(?:\\.|(?!(?P=q))[^\\\n])*)(?P=q)
""", re.VERBOSE)

# ?api_key=abc&x=1. A value starting with { is an expression, not a literal.
URL_PARAM = re.compile(r"[?&](?P<name>[A-Za-z0-9_.-]+)=(?P<value>[^&#\s\"'{}]+)")

B64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
CREDENTIALS = re.compile(r"[\w.@+-]+:[^\r\n]+")
IGNORE_NOTE = re.compile(r"n8nleaks:ignore(?:[ \t]+(?P<rules>[\w-]+(?:[ \t]*,[ \t]*[\w-]+)*))?")


@dataclass
class Finding:
    rule: str
    file: str
    line: int
    workflow: str
    where: str
    value: str
    detail: str = ""
    path: tuple = field(default=(), repr=False, compare=False)

    @property
    def severity(self):
        return R.RULES[self.rule].severity


@dataclass
class Result:
    findings: list = field(default_factory=list)
    files: int = 0          # files that held at least one workflow
    workflows: int = 0
    skipped: list = field(default_factory=list)   # (path, reason), named files only


# --- walking -----------------------------------------------------------------

def strings(obj, path):
    """(path, text) for every string anywhere under obj."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from strings(value, path + (key,))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from strings(value, path + (i,))


def assignments(text):
    """ASSIGNMENT and CALL_PAIR matches in code or JSON-ish text, minus the
    ternaries that look like them: ok ? 'pass' : 'finish'."""
    for regex in (ASSIGNMENT, CALL_PAIR):
        for m in regex.finditer(text):
            if not text[:m.start()].rstrip().endswith("?"):
                yield m


def pairs(obj, path):
    """(path, name, value) for every string that has a name: dict keys,
    {"name": ..., "value": ...} and {"key": ..., "value": ...} rows, and the
    names inside strings that hold JSON or a URL."""
    if isinstance(obj, dict):
        for label in ("name", "key"):
            if isinstance(obj.get(label), str) and isinstance(obj.get("value"), str):
                yield path + ("value",), obj[label], obj["value"]
        for key, value in obj.items():
            if isinstance(value, str):
                yield path + (key,), key, value
                yield from pairs_in_text(value, path + (key,))
            else:
                yield from pairs(value, path + (key,))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            if isinstance(value, str):
                yield from pairs_in_text(value, path + (i,))
            else:
                yield from pairs(value, path + (i,))


def pairs_in_text(text, path):
    """Names inside a string: the keys of a JSON body kept as a string
    (jsonBody, jsonHeaders), or the parameters of a URL's query string."""
    body = (text[1:] if text.startswith("=") else text).strip()
    if body.startswith(("{", "[")):
        try:
            data = json.loads(body)
        except ValueError:
            # Usually an expression with {{ }} outside the quotes. Fall back
            # to picking out "name": "value" pairs.
            for m in assignments(body):
                yield path + (JSON_MARK, m["name"]), m["name"], m["value"]
        else:
            yield from pairs(data, path + (JSON_MARK,))
    elif "?" in body and not any(p.search(body) for _, p in R.WEBHOOK_FORMATS):
        # Webhook URLs are reported whole by known-key-format.
        for m in URL_PARAM.finditer(body):
            yield path, m["name"], m["value"]


def render(parts):
    """('headerParameters', 'parameters', 0, 'value') -> headerParameters.parameters[0].value"""
    out = ""
    for part in parts:
        if part is JSON_MARK:
            out += " > "
        elif isinstance(part, int):
            out += f"[{part}]"
        elif re.fullmatch(r"[A-Za-z_$][\w$]*", part):
            out += part if not out or out.endswith(" > ") else "." + part
        else:
            out += f'["{part}"]'
    return out


# --- deciding ----------------------------------------------------------------

def is_sensitive(name):
    return bool(R.SENSITIVE_NAME.search(name)) and not R.NOT_SENSITIVE.search(name)


def literal_part(value):
    """What was typed in, with n8n expressions taken out.
    '={{ $vars.TOKEN }}' -> '', '=Bearer {{ $json.t }}' -> 'Bearer'."""
    if value.startswith("="):
        value = re.sub(r"\{\{.*?\}\}", "", value[1:], flags=re.DOTALL)
    return value.strip()


def looks_secret(name, value):
    """True when a value under a sensitive name is a real typed-in secret,
    not a reference, a placeholder or an empty scheme."""
    if not value or R.REFERENCE.search(value):
        return False
    bare = R.AUTH_SCHEME.sub("", value).strip()
    if not bare or R.PLACEHOLDER.match(bare):
        return False
    if R.PASSWORD_NAME.match(name):
        return len(bare) >= 4
    return (len(bare) >= 8
            and not re.search(r"\s", bare)
            and not bare.isdigit()
            and not bare.lower().startswith(("http://", "https://")))


def is_header(path, name):
    return bool(R.HEADER_NAME.match(name)) or any(
        isinstance(p, str) and "header" in p.lower() for p in path)


def decode_base64(value):
    """What a base64 value hides, when it hides something people mistake
    for a secret. Returns (kind, description) or None, kind being
    "identity" or "credentials"."""
    bare = R.AUTH_SCHEME.sub("", value.strip()).strip()
    if not B64.fullmatch(bare):
        return None
    padded = bare + "=" * (-len(bare) % 4)
    try:
        if re.search(r"[-_]", bare):
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(padded, validate=True)
        text = raw.decode("utf-8")
    except ValueError:
        return None
    if not text.isprintable():
        return None
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        keys = sorted(k for k, v in data.items()
                      if k.lower() in R.IDENTITY_KEYS
                      or (isinstance(v, str) and R.EMAIL.fullmatch(v)))
        return ("identity", "base64 of JSON with " + ", ".join(keys)) if keys else None
    if R.EMAIL.fullmatch(text.strip()):
        return "identity", "base64 of an email address"
    if CREDENTIALS.fullmatch(text):
        return "credentials", "base64 of a username and password"
    return None


def key_formats(text):
    """(label, match) for every known key format in text, overlaps removed."""
    taken = []
    for label, pattern in R.KEY_FORMATS:
        for m in pattern.finditer(text):
            if any(m.start() < end and start < m.end() for start, end in taken):
                continue
            # sk-xxxxxxxxxxxxxxxxxxxxxxxx is a placeholder, not a key.
            if label != "Private key" and len(set(m.group()[-12:])) <= 2:
                continue
            taken.append((m.start(), m.end()))
            yield label, m.group()


# --- one workflow ------------------------------------------------------------

class WorkflowScan:
    def __init__(self, wf, file, text, allowed_emails):
        self.wf = wf
        self.file = file
        self.text = text
        self.allowed_emails = [p.lower() for p in allowed_emails]
        self.name = wf.get("name") or "(unnamed)"
        self.findings = []
        self.flagged = set()    # paths that already have a finding
        self._seen = set()

    def run(self):
        nodes = self.wf.get("nodes") or []
        for i, node in enumerate(nodes):
            if not isinstance(node, dict):
                continue
            params = node.get("parameters")
            if isinstance(params, dict):
                self.named_values(params, ("nodes", i, "parameters"), pinned=False)
            self.free_text(node, ("nodes", i))

        pins = self.wf.get("pinData")
        if isinstance(pins, dict):
            for node_name, items in pins.items():
                if items:
                    self.add("pinned-data", ("pinData", node_name), node_name, after='"pinData"')
                self.named_values(items, ("pinData", node_name), pinned=True)
                self.free_text(items, ("pinData", node_name))

        for key, value in self.wf.items():
            if key not in ("nodes", "pinData"):
                self.free_text(value, (key,))

        self.apply_node_notes(nodes)
        return self.findings

    def named_values(self, obj, base, pinned):
        for path, name, value in pairs(obj, base):
            if not is_sensitive(name):
                continue
            if pinned:
                # Pinned data is a captured run, so every value is literal.
                bare = value.strip()
                if bare and not R.PLACEHOLDER.match(bare):
                    self.add("pinned-secret", path, value, self.hint(value), field=name)
                continue
            literal = literal_part(value)
            if looks_secret(name, literal):
                rule = "literal-auth-header" if is_header(path, name) else "literal-secret"
                self.add(rule, path, literal, self.hint(literal), field=name)
        if not pinned:
            for path, code in strings(obj, base):
                if path[-1] in CODE_KEYS:
                    self.code(path, code)

    def code(self, path, code):
        for m in assignments(code):
            name, value = m["name"], m["value"]
            if is_sensitive(name) and looks_secret(name, value):
                line = code.count("\n", 0, m.start()) + 1
                detail = f"code line {line}"
                if hint := self.hint(value):
                    detail += f", {hint}"
                rule = "literal-auth-header" if R.HEADER_NAME.match(name) else "literal-secret"
                self.add(rule, path, value, detail, field=name)

    def free_text(self, obj, base):
        pinned = base[0] == "pinData"
        for path, value in strings(obj, base):
            in_code = path[-1] in CODE_KEYS

            def where_in_code(match):
                if not in_code:
                    return ""
                return f"code line {value.count(chr(10), 0, value.find(match)) + 1}"

            for label, match in key_formats(value):
                self.add("known-key-format", path, match, ", ".join(filter(None, [label, where_in_code(match)])))
            for email in R.EMAIL.findall(value):
                if not any(fnmatchcase(email.lower(), p) for p in self.allowed_emails):
                    self.add("email-address", path, email, where_in_code(email))
            if path in self.flagged:
                continue
            decoded = decode_base64(value)
            if decoded:
                kind, description = decoded
                if kind == "identity":
                    self.add("encoded-identity", path, value, description)
                else:
                    self.add("pinned-secret" if pinned else "literal-secret", path, value, description)

    @staticmethod
    def hint(value):
        decoded = decode_base64(value)
        return decoded[1] if decoded else ""

    def add(self, rule, path, value, detail="", field=None, after=None):
        key = (rule, path, value, field)
        if key in self._seen:
            return
        self._seen.add(key)
        self.flagged.add(path)
        self.findings.append(Finding(
            rule=rule, file=self.file, line=self.line_of(value, after),
            workflow=self.name, where=self.describe(path, field),
            value=value, detail=detail, path=path,
        ))

    def line_of(self, needle, after=None):
        """Line of the first place needle appears in the file. Values inside
        a JSON string (jsonBody) are escaped twice, so try that form too."""
        start = max(self.text.find(after), 0) if after else 0
        once = json.dumps(needle, ensure_ascii=False)[1:-1]
        for candidate in (needle, once, json.dumps(once, ensure_ascii=False)[1:-1],
                          json.dumps(needle)[1:-1]):
            idx = self.text.find(candidate, start)
            if idx >= 0:
                return self.text.count("\n", 0, idx) + 1
        return 1

    def describe(self, path, field=None):
        if path[0] == "nodes":
            node = self.wf["nodes"][path[1]].get("name", f"#{path[1]}")
            where, rest = f'node "{node}"', path[2:]
        elif path[0] == "pinData":
            where, rest = f'pinned data of "{path[1]}"', path[2:]
        else:
            where, rest = "workflow", path
        if text := render(rest):
            where += " " + text
        if field and (not rest or field != rest[-1]):
            where += f" ({field})"
        return where

    def apply_node_notes(self, nodes):
        """A node whose notes say "n8nleaks:ignore" is skipped, or only the
        rules listed after it: "n8nleaks:ignore email-address, pinned-data"."""
        ignored = {}
        for i, node in enumerate(nodes):
            notes = node.get("notes") if isinstance(node, dict) else None
            if isinstance(notes, str) and (m := IGNORE_NOTE.search(notes)):
                rules = {r.strip() for r in m["rules"].split(",")} if m["rules"] else None
                ignored[("nodes", i)] = rules
                ignored[("pinData", node.get("name"))] = rules

        def keep(f):
            rules = ignored.get(f.path[:2], False)
            return rules is False or (rules is not None and f.rule not in rules)

        self.findings = [f for f in self.findings if keep(f)]


# --- files -------------------------------------------------------------------

def workflows_in(data):
    def is_workflow(obj):
        return isinstance(obj, dict) and isinstance(obj.get("nodes"), list) and "connections" in obj

    if is_workflow(data):
        return [data]
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        data = data["data"]
    if isinstance(data, list):
        return [w for w in data if is_workflow(w)]
    return []


def display_path(path):
    try:
        shown = os.path.relpath(path)
    except ValueError:      # another drive on Windows
        shown = str(path)
    return shown.replace(os.sep, "/")


def iter_files(paths):
    """(path, named) for every .json under paths. named is True when the
    file was given directly rather than found in a folder."""
    for path in paths:
        if path.is_dir():
            for f in sorted(path.rglob("*.json")):
                if not SKIP_DIRS.intersection(f.relative_to(path).parts[:-1]):
                    yield f, False
        else:
            yield path, True


def scan_text(text, file, allowed_emails):
    """(number of workflows, findings) for the JSON in text."""
    found = workflows_in(json.loads(text))
    findings = []
    for wf in found:
        findings += WorkflowScan(wf, file, text, allowed_emails).run()
    return len(found), findings


def scan_paths(paths, config):
    result = Result()
    for path, named in iter_files(paths):
        shown = display_path(path)
        if any(fnmatchcase(shown, pattern) for pattern in config.exclude):
            continue
        reason = None
        try:
            # utf-8-sig: files saved by Windows PowerShell start with a BOM.
            text = path.read_text(encoding="utf-8-sig")
            count, findings = scan_text(text, shown, config.allowed_emails)
        except UnicodeDecodeError:
            reason = "not UTF-8 text"
        except ValueError:
            reason = "not valid JSON"
        except OSError as e:
            reason = e.strerror or str(e)
        if reason:
            if named:
                result.skipped.append((shown, reason))
            continue
        if count:
            result.files += 1
            result.workflows += count
        result.findings += [f for f in findings
                            if f.rule not in config.disable
                            and not any(p.search(f.value) for p in config.allow_values)]
    return result
