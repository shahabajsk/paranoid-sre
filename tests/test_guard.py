import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))
from guard import check, run_hook  # noqa: E402

GUARD = ROOT / "hooks" / "guard.py"


def rows(name):
    return [json.loads(l) for l in (ROOT / "bench" / name).read_text().splitlines() if l.strip()]


CORPUS = rows("corpus.jsonl") + rows("holdout.jsonl")


@pytest.mark.parametrize("row", CORPUS, ids=[r["cmd"][:60] for r in CORPUS])
def test_corpus_row(row):
    decision = check(row["cmd"]).decision
    if row["label"] == "destructive":
        assert decision in ("ask", "deny"), f"missed: {row['cmd']}"
    else:
        assert decision == "allow", f"false block ({decision}): {row['cmd']}"


@pytest.mark.parametrize("row", rows("known_bypasses.jsonl"), ids=lambda r: r["cmd"][:40])
def test_known_bypasses_are_documented_misses(row):
    """If one of these starts getting caught, move it to the corpus and update the README limits."""
    assert check(row["cmd"]).decision == "allow"


def test_hook_deny_exits_2_with_reason():
    code, out, err = run_hook(json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf ~"}}))
    assert code == 2 and out == "" and "paranoid-sre blocked this" in err


def test_hook_ask_returns_permission_json():
    code, out, err = run_hook(json.dumps({"tool_name": "Bash", "tool_input": {"command": "git reset --hard HEAD~1"}}))
    payload = json.loads(out)["hookSpecificOutput"]
    assert code == 0 and payload["hookEventName"] == "PreToolUse" and payload["permissionDecision"] == "ask"


def test_hook_ignores_other_tools_and_bad_input():
    assert run_hook(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/"}})) == (0, "", "")
    assert run_hook("not json") == (0, "", "")


def test_prod_escalates_ask_to_deny():
    assert check("kubectl delete deployment api -n staging").decision == "ask"
    assert check("kubectl delete deployment api -n production").decision == "deny"


def test_cli_exit_codes():
    def run(cmd):
        return subprocess.run([sys.executable, str(GUARD), "--check", cmd], capture_output=True, text=True).returncode
    assert run("ls -la") == 0
    assert run("git push -f") == 1
    assert run("rm -rf /") == 2


def test_hook_via_stdin_process():
    p = subprocess.run([sys.executable, str(GUARD)], input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "terraform destroy"}}),
                       capture_output=True, text=True)
    assert p.returncode == 2 and "iac-destroy" in p.stderr


def test_prod_inside_resource_names():
    assert check("curl -X DELETE https://api.example-host.com/v1/volumes/vol-prod-db/backups").decision == "deny"
    assert check("curl -X DELETE https://api.example-host.com/v1/volumes/vol-staging-db").decision == "ask"
    assert check("kubectl delete pod web-1 -n production-eu").decision == "deny"
    assert check("echo productivity && ls").decision == "allow"
