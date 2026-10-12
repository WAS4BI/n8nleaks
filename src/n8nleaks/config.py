"""
Settings, read from .n8nleaks.toml or the [tool.n8nleaks] table of
pyproject.toml in the folder n8nleaks runs from.

    fail-on = "error"                   # or "warning"
    disable = ["email-address"]         # rule ids to skip
    allow-emails = ["*@mycompany.com"]  # on top of example.com and friends
    allow-values = ["^test_"]           # regexes; a finding whose value matches is dropped
    exclude = ["tests/fixtures/*"]      # globs on paths, relative, with forward slashes
"""

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import rules as R

KEYS = {"fail-on", "disable", "allow-emails", "allow-values", "exclude"}


class ConfigError(Exception):
    pass


@dataclass
class Config:
    fail_on: str = R.ERROR
    disable: set = field(default_factory=set)
    allow_emails: list = field(default_factory=list)
    allow_values: list = field(default_factory=list)
    exclude: list = field(default_factory=list)
    source: str = ""

    @property
    def allowed_emails(self):
        return R.DEFAULT_ALLOWED_EMAILS + self.allow_emails


def load(path=None, cwd=None):
    """Config from path if given, otherwise the first of .n8nleaks.toml and
    pyproject.toml (when it has a [tool.n8nleaks] table) in cwd."""
    if path is not None:
        return parse(read(Path(path)) or {}, str(path))
    cwd = Path(cwd or Path.cwd())
    for name in (".n8nleaks.toml", "pyproject.toml"):
        candidate = cwd / name
        if candidate.is_file():
            table = read(candidate)
            if table is not None:
                return parse(table, name)
    return Config()


def read(path):
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as e:
        raise ConfigError(f"{path}: {e.strerror or e}") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
    if path.name == "pyproject.toml":
        return data.get("tool", {}).get("n8nleaks")
    return data


def parse(table, source=""):
    unknown = sorted(set(table) - KEYS)
    if unknown:
        raise ConfigError(f"{source}: unknown setting {', '.join(unknown)}. "
                          f"Known: {', '.join(sorted(KEYS))}")

    fail_on = table.get("fail-on", R.ERROR)
    if fail_on not in R.SEVERITY_RANK:
        raise ConfigError(f'{source}: fail-on must be "error" or "warning", not {fail_on!r}')

    disable = set(string_list(table, "disable", source))
    check_rule_ids(disable, source)

    try:
        allow_values = [re.compile(p) for p in string_list(table, "allow-values", source)]
    except re.error as e:
        raise ConfigError(f"{source}: allow-values has a bad regex: {e}") from None

    return Config(
        fail_on=fail_on,
        disable=disable,
        allow_emails=[p.lower() for p in string_list(table, "allow-emails", source)],
        allow_values=allow_values,
        exclude=string_list(table, "exclude", source),
        source=source,
    )


def string_list(table, key, source):
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{source}: {key} must be a list of strings")
    return value


def check_rule_ids(ids, source):
    unknown = sorted(set(ids) - set(R.RULES))
    if unknown:
        raise ConfigError(f"{source}: unknown rule {', '.join(unknown)}. "
                          f"Run n8nleaks --list-rules to see them.")
