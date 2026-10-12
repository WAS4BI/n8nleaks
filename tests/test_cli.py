import json

import pytest

from n8nleaks import __version__
from n8nleaks.cli import main
from n8nleaks.report import redact
from n8nleaks.rules import RULES
from workflows import fake, http, send_email, webhook, workflow

TOKEN = fake("k9X2mQ7v", "L4pR8sT1")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """An empty folder to run n8nleaks in, with a helper to drop workflows into it."""
    monkeypatch.chdir(tmp_path)

    def put(name, content, encoding="utf-8"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_text(text, encoding=encoding)
        return path

    return put


LEAKY = workflow(webhook(), http(headers=[("Authorization", "Bearer " + TOKEN)]), name="Sync Orders")
CLEAN = workflow(webhook(), http(headers=[("Authorization", "={{ 'Bearer ' + $vars.T }}")]), name="Clean")
EMAIL_ONLY = workflow(send_email("jane.doe@acme.test"), name="Report")


def test_clean_exits_0(repo, capsys):
    repo("workflows/clean.json", CLEAN)
    assert main([]) == 0
    assert capsys.readouterr().out.strip() == "Nothing found in 1 workflow (1 file)."


def test_leak_exits_1_and_never_prints_the_secret(repo, capsys):
    repo("workflows/leaky.json", LEAKY)
    assert main(["workflows"]) == 1
    out = capsys.readouterr().out
    assert "literal-auth-header" in out
    assert 'workflows/leaky.json  (workflow "Sync Orders")' in out
    assert "How to fix:" in out
    assert TOKEN not in out


def test_no_redact_prints_the_secret(repo, capsys):
    repo("leaky.json", LEAKY)
    main(["--no-redact"])
    assert TOKEN in capsys.readouterr().out


def test_fail_on_warning(repo):
    repo("report.json", EMAIL_ONLY)
    assert main([]) == 0
    assert main(["--fail-on", "warning"]) == 1


def test_disable(repo, capsys):
    repo("report.json", EMAIL_ONLY)
    assert main(["--fail-on", "warning", "--disable", "email-address,pinned-data"]) == 0
    assert "Nothing found" in capsys.readouterr().out


def test_github_annotations(repo, capsys):
    repo("wf/leaky one.json", LEAKY)
    assert main(["--format", "github"]) == 1
    first = capsys.readouterr().out.splitlines()[0]
    assert first.startswith("::error file=wf/leaky one.json,line=")
    assert ",title=n8nleaks literal-auth-header::" in first
    assert "%0AUse an n8n credential" in first
    assert TOKEN not in first


def test_json_output(repo, capsys):
    repo("leaky.json", LEAKY)
    main(["--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == __version__
    assert (data["files"], data["workflows"]) == (1, 1)
    [f] = data["findings"]
    assert (f["rule"], f["severity"], f["workflow"]) == ("literal-auth-header", "error", "Sync Orders")
    assert TOKEN not in f["value"]


def test_config_in_pyproject(repo):
    repo("report.json", EMAIL_ONLY)
    repo("fixtures/leaky.json", LEAKY)
    repo("pyproject.toml", '[tool.n8nleaks]\nfail-on = "warning"\nexclude = ["fixtures/*"]\n'
                           'allow-emails = ["*@acme.test"]\n')
    assert main([]) == 0


def test_n8nleaks_toml_wins_over_pyproject(repo):
    repo("report.json", EMAIL_ONLY)
    repo(".n8nleaks.toml", 'fail-on = "warning"\n')
    repo("pyproject.toml", '[tool.n8nleaks]\ndisable = ["email-address"]\n')
    assert main([]) == 1


def test_allow_values(repo):
    repo("leaky.json", LEAKY)
    repo(".n8nleaks.toml", 'allow-values = ["^Bearer k9X2"]\n')
    assert main([]) == 0


@pytest.mark.parametrize("args, config, message", [
    (["--disable", "no-such-rule"], None, "unknown rule no-such-rule"),
    ([], 'fail-on = "sometimes"\n', "fail-on must be"),
    ([], 'colour = "red"\n', "unknown setting colour"),
    ([], 'allow-values = ["("]\n', "bad regex"),
    ([], "disable = \n", ".n8nleaks.toml"),
    (["missing.json"], None, "not found: missing.json"),
])
def test_bad_input_exits_2(repo, capsys, args, config, message):
    if config is not None:
        repo(".n8nleaks.toml", config)
    assert main(args) == 2
    assert message in capsys.readouterr().err


def test_reads_files_saved_with_a_bom(repo):
    repo("bom.json", json.dumps(LEAKY), encoding="utf-8-sig")
    assert main(["bom.json"]) == 1


def test_lists_and_api_pages_of_workflows(repo, capsys):
    repo("all.json", [CLEAN, LEAKY])
    repo("page.json", {"data": [LEAKY], "nextCursor": None})
    assert main([]) == 1
    assert "in 2 of 3 workflows (2 files)" in capsys.readouterr().out


def test_other_json_is_skipped_quietly(repo, capsys):
    repo("package.json", {"name": "x", "dependencies": {"n8n": "^1.0.0"}})
    repo("node_modules/pkg/leaky.json", LEAKY)
    assert main([]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "No n8n workflows found."
    assert captured.err == ""


def test_a_named_file_that_is_not_json_is_reported(repo, capsys):
    repo("broken.json", "{ not json")
    assert main(["broken.json"]) == 0
    assert "skipped broken.json: not valid JSON" in capsys.readouterr().err


def test_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    out = capsys.readouterr().out
    assert all(rule in out for rule in RULES)


@pytest.mark.parametrize("value, shown", [
    ("Bearer " + TOKEN, "Bearer k9X...(16 chars)"),
    ("jane.doe@acme.test", "ja***@acme.test"),
    ("https://hooks.example.com/services/T0/B0/abc", "https://hooks.example.com/...(44 chars)"),
    ("hunter2", "h...(7 chars)"),
    ("short", "*****"),
])
def test_redact(value, shown):
    assert redact(value) == shown
