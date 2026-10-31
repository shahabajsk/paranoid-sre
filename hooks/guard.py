#!/usr/bin/env python3
"""paranoid-sre guard: a deterministic PreToolUse hook for shell commands.

Reads a Claude Code hook event on stdin. For Bash calls it inspects
tool_input.command and decides:

  allow  exit 0, no output, the normal permission flow continues
  ask    exit 0, JSON on stdout asking the user to confirm
  deny   exit 2, reason on stderr, the call is blocked

CLI mode, for any agent or a git hook:

  python3 hooks/guard.py --check "rm -rf /"

prints ALLOW / ASK / DENY and exits 0 / 1 / 2.

Python standard library only. No network, no model calls.
"""
from __future__ import annotations

import json
import re
import shlex
import sys
from dataclasses import dataclass

ALLOW, ASK, DENY = "allow", "ask", "deny"
RANK = {ALLOW: 0, ASK: 1, DENY: 2}

PROD_RE = re.compile(r"(?<![a-z0-9])(?:prod|production|prd|live)(?![a-z0-9])", re.I)  # vol-prod-db, app_prod, -n production


@dataclass
class Verdict:
    decision: str
    rule: str = ""
    reason: str = ""

    def worse(self, other: "Verdict") -> "Verdict":
        return other if RANK[other.decision] > RANK[self.decision] else self


# ---------------------------------------------------------------------------
# Pattern rules over a single command segment (text between ; && || & newlines).
# Each: (id, decision, regex, reason). Regexes run case-insensitively.
# ---------------------------------------------------------------------------
SEGMENT_RULES: list[tuple[str, str, str, str]] = [
    # git
    ("git-push-delete-protected", DENY,
     r"\bgit\b.*\bpush\b(?=.*(?:\s--delete\b|\s-d\b|\s:(?:main|master|trunk|prod|production)\b))(?=.*[\s:](?:main|master|trunk|prod|production)\b)",
     "deletes a protected branch on the remote"),
    ("git-reflog-expire", DENY, r"\bgit\b.*\breflog\s+expire\b.*--expire(?:-unreachable)?=(?:now|all|0)",
     "expiring the reflog removes the way back to lost commits"),
    ("git-gc-prune-now", ASK, r"\bgit\b.*\bgc\b.*--prune=(?:now|all)",
     "prunes unreachable commits immediately"),
    ("git-discard-worktree", ASK, r"\bgit\b.*\b(?:checkout\s+(?:\S+\s+)?--\s+\.|restore\s+(?:--\S+\s+)*\.)(?:\s|$)",
     "discards every uncommitted change in the working tree"),
    ("git-stash-clear", ASK, r"\bgit\b.*\bstash\s+(?:clear|drop)\b",
     "deletes stashed work"),
    ("git-push-force-protected", DENY,
     r"\bgit\b.*\bpush\b(?=.*(?:\s-f\b|--force\b|--force-with-lease|\s\+\S))(?=.*(?:\s|:|\+)(?:main|master|trunk|prod|production|release\S*)\b)",
     "force-push to a protected branch rewrites history everyone else depends on"),
    ("git-push-mirror", DENY, r"\bgit\b.*\bpush\b.*--mirror\b",
     "push --mirror can delete every remote branch and tag that is not local"),
    ("git-push-force", ASK, r"\bgit\b.*\bpush\b.*(?:\s-f\b|\s--force(?!-with-lease)\b)",
     "plain --force overwrites the remote branch without checking what is there; use --force-with-lease"),
    ("git-delete-protected-branch", DENY,
     r"\bgit\b.*\b(?:branch\s+-D|push\s+\S+\s+(?:--delete|-d|:))\s*(?:main|master|trunk|prod|production)\b",
     "deleting a protected branch"),
    ("git-reset-hard", ASK, r"\bgit\b.*\breset\b.*--hard\b",
     "reset --hard throws away uncommitted work and moves the branch"),
    ("git-clean", ASK, r"\bgit\b.*\bclean\b.*-[a-z]*f[a-z]*d|\bgit\b.*\bclean\b.*-[a-z]*d[a-z]*f|\bgit\b.*\bclean\b.*-[a-z]*x",
     "git clean -fd deletes untracked files with no undo"),
    ("git-filter-history", ASK, r"\bgit\b.*\b(?:filter-branch|filter-repo)\b",
     "history rewrite"),
    # SQL
    ("sql-drop", DENY, r"\bdrop\s+(?:database|schema|table|collection)\b",
     "DROP removes data and structure with no undo"),
    ("sql-truncate", DENY, r"\btruncate\s+(?:table\s+)?[\w.\"`]+",
     "TRUNCATE removes every row"),
    ("sql-delete-no-where", DENY, r"\bdelete\s+from\s+[\w.\"`]+\s*(?:;|$|\"|'|\))(?![^;]*\bwhere\b)",
     "DELETE without WHERE removes every row"),
    ("sql-update-no-where", ASK, r"\bupdate\s+[\w.\"`]+\s+set\b(?![^;]*\bwhere\b)",
     "UPDATE without WHERE changes every row"),
    ("mongo-drop", DENY, r"\.(?:dropDatabase|drop)\s*\(|\bdeleteMany\s*\(\s*\{\s*\}\s*\)",
     "drops a collection or database"),
    ("redis-flush", DENY, r"\bflush(?:all|db)\b",
     "FLUSHALL / FLUSHDB empties the cache or store"),
    # framework database resets
    ("db-reset", DENY,
     r"\bprisma\s+migrate\s+reset\b|\b(?:rails|rake)\s+db:(?:drop|reset|schema:load|purge)\b|\bmanage\.py\s+(?:flush|reset_db)\b|"
     r"\bdropdb\b|\bsupabase\s+db\s+reset\b|\bheroku\s+pg:reset\b|\bdrizzle-kit\s+drop\b|\bknex\s+migrate:rollback\s+--all\b|"
     r"\bsequelize\s+db:drop\b|\bphp\s+artisan\s+(?:migrate:fresh|migrate:reset|db:wipe)\b",
     "resets or drops the database"),
    # infrastructure as code
    ("iac-destroy", DENY, r"\b(?:terraform|tofu|terragrunt)\b.*\bdestroy\b|\bpulumi\s+destroy\b|\bcdk\s+destroy\b|\bsst\s+remove\b|\bserverless\s+remove\b",
     "destroys every resource in the stack"),
    ("iac-auto-approve", ASK, r"\b(?:terraform|tofu|terragrunt)\b.*\bapply\b.*-auto-approve\b|\bpulumi\s+up\b.*(?:--yes|-y)\b",
     "applies infrastructure changes with no plan review"),
    ("terraform-state-rm", ASK, r"\bterraform\b.*\bstate\s+(?:rm|push)\b",
     "edits Terraform state directly"),
    # kubernetes
    ("k8s-scale-all-zero", DENY, r"\bkubectl\b.*\bscale\b(?=.*--all\b)(?=.*--replicas[= ]0\b)",
     "scales every deployment to zero"),
    ("k8s-scale-zero", ASK, r"\bkubectl\b.*\bscale\b.*--replicas[= ]0\b",
     "scales a workload to zero"),
    ("k8s-delete-namespace", DENY, r"\bkubectl\b.*\bdelete\s+(?:ns|namespaces?)\b",
     "deleting a namespace deletes everything in it"),
    ("k8s-delete-all", DENY, r"\bkubectl\b.*\bdelete\b.*(?:--all\b|-A\b|--all-namespaces\b)",
     "deletes every matching resource"),
    ("k8s-delete-pv", DENY, r"\bkubectl\b.*\bdelete\s+(?:pv|pvc|persistentvolumes?|persistentvolumeclaims?|crd|customresourcedefinitions?)\b",
     "deletes persistent storage or resource definitions"),
    ("k8s-delete", ASK, r"\bkubectl\b.*\bdelete\b",
     "kubectl delete"),
    ("helm-uninstall", ASK, r"\bhelm\b.*\b(?:uninstall|delete)\b",
     "removes a release and its resources"),
    # cloud CLIs
    ("aws-s3-destroy", DENY, r"\baws\s+s3\s+rb\b|\baws\s+s3\s+rm\b.*--recursive\b|\baws\s+s3api\s+delete-bucket\b",
     "deletes a bucket or every object under a prefix"),
    ("backup-delete", DENY,
     r"\bdelete-(?:db-)?(?:cluster-)?snapshot\b|\bdelete-backup\b|\bdelete-recovery-point\b|\bdelete-backup-vault\b|"
     r"\bsnapshots?\s+delete\b|\bbackups?\s+delete\b|--skip-final-snapshot\b|--delete-automated-backups\b",
     "deletes backups or skips the final snapshot, which removes the way back"),
    ("aws-delete-db", DENY, r"\baws\s+(?:rds|dynamodb|docdb|neptune|redshift|elasticache)\s+delete-",
     "deletes a database"),
    ("aws-delete", ASK, r"\baws\s+\S+\s+(?:delete|terminate|deregister|remove)-",
     "AWS delete or terminate call"),
    ("gcloud-project-delete", DENY, r"\bgcloud\s+projects\s+delete\b|\bgcloud\s+sql\s+instances\s+delete\b",
     "deletes a project or database instance"),
    ("gcloud-delete", ASK, r"\bgcloud\b.*\bdelete\b|\bgsutil\b.*\brm\b.*-r|\bgsutil\s+rb\b",
     "gcloud delete"),
    ("az-group-delete", DENY, r"\baz\s+group\s+delete\b",
     "deletes a resource group and everything in it"),
    ("az-delete", ASK, r"\baz\s+.*\bdelete\b",
     "az delete"),
    ("paas-destroy", DENY, r"\bheroku\s+apps:destroy\b|\bfly\s+(?:apps\s+destroy|volumes\s+destroy)\b|\brailway\s+(?:down|delete)\b|\bvercel\s+(?:remove|rm)\b.*--yes",
     "destroys a hosted app or volume"),
    ("gh-repo-delete", DENY, r"\bgh\s+repo\s+delete\b",
     "deletes a GitHub repository"),
    ("gh-delete", ASK, r"\bgh\b.*\bdelete\b|\bgh\s+api\b.*(?:-X|--method)\s*DELETE",
     "GitHub delete call"),
    ("api-delete", ASK, r"\bcurl\b.*(?:-X\s*DELETE|--request\s+DELETE)|\bhttp\s+DELETE\b|\bmutation\b.*\b\w*[dD]elete\w*\b",
     "raw API delete call; check what it targets"),
    # containers
    ("docker-prune-all", ASK, r"\bdocker\b.*\b(?:system|volume)\s+prune\b|\bdocker\s+volume\s+rm\b|\bdocker-compose\b.*\bdown\b.*(?:-v\b|--volumes\b)|\bdocker\s+compose\b.*\bdown\b.*(?:-v\b|--volumes\b)",
     "removes volumes or everything unused, including data volumes"),
    # filesystem
    ("chmod-recursive-system", DENY,
     r"\b(?:chmod|chown|chgrp)\b.*-[a-zA-Z]*R[a-zA-Z]*\b.*\s(?:/|/\*|~|~/|\$HOME/?|/(?:etc|usr|var|bin|sbin|boot|lib\w*|home|root|opt|Users))(?:\s|$)",
     "recursive permission change on root, home or a system directory"),
    ("chmod-777-recursive", DENY, r"\bchmod\b.*-[a-z]*R[a-z]*\s+(?:0?777|a\+rwx)\b",
     "recursive world-writable permissions"),
    ("chmod-777", ASK, r"\bchmod\s+(?:0?777|a\+rwx)\b",
     "world-writable permissions"),
    ("chown-root-recursive", DENY, r"\bchown\b.*-[a-z]*R[a-z]*\b.*\s/(?:\s|$|\*)",
     "recursive chown on the filesystem root"),
    ("disk-write", DENY, r"\bdd\b.*\bof=/dev/(?!null\b|zero\b|stdout\b)|\bmkfs(?:\.\w+)?\b|\bwipefs\b|>\s*/dev/(?:sd|nvme|hd|xvd|disk)\w*",
     "writes raw bytes to a disk or formats it"),
    ("disk-partition", ASK, r"\b(?:fdisk|parted|sgdisk|diskutil\s+erase\w*)\b",
     "partitions or erases a disk"),
    ("shred", DENY, r"\bshred\b|\bsrm\b",
     "unrecoverable file deletion"),
    ("find-delete", ASK, r"\bfind\b.*(?:-delete\b|-exec\s+rm\b)",
     "find with delete"),
    ("history-wipe", ASK, r"\bhistory\s+-c\b|>\s*~/\.\w*_history\b",
     "erases shell history"),
]
COMPILED = [(i, d, re.compile(rx, re.I), why) for i, d, rx, why in SEGMENT_RULES]

# Pipe-to-shell is checked on the whole command (it spans a pipe).
PIPE_SHELL_RE = re.compile(r"\b(?:curl|wget|fetch)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b|\beval\s+\"?\$\(\s*(?:curl|wget)\b", re.I)

# ---------------------------------------------------------------------------
# rm: parsed, not pattern-matched
# ---------------------------------------------------------------------------
SAFE_RM_NAMES = {
    "node_modules", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit", ".turbo", ".parcel-cache",
    "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".venv", "venv",
    "coverage", ".coverage", "htmlcov", ".cache", "tmp", ".tmp", "temp", "*.egg-info", ".eggs", ".gradle",
    "bin", "obj", "public/build", ".angular", "storybook-static", "_site", ".docusaurus", "site",
}
SYSTEM_DIRS = {
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root", "/sbin", "/srv",
    "/sys", "/usr", "/var", "/users", "/applications", "/library", "/system", "/private", "/volumes", "/mnt", "/media",
}


def _rm_verdict(tokens: list[str]) -> Verdict:
    flags, targets = [], []
    after_dashdash = False
    for t in tokens[1:]:
        if not after_dashdash and t == "--":
            after_dashdash = True
        elif not after_dashdash and t.startswith("-") and len(t) > 1:
            flags.append(t)
        else:
            targets.append(t)
    joined = " ".join(flags)
    recursive = bool(re.search(r"(?:^|\s)-[a-zA-Z]*[rR]|--recursive", joined))
    force = bool(re.search(r"(?:^|\s)-[a-zA-Z]*f|--force", joined))
    if "--no-preserve-root" in joined:
        return Verdict(DENY, "rm-no-preserve-root", "rm --no-preserve-root")
    if not recursive:
        if any(t.strip("'\"") in ("/*", "~/*", "*") for t in targets) and force:
            return Verdict(ASK, "rm-glob", "rm -f on a wildcard")
        return Verdict(ALLOW)
    if not targets:
        return Verdict(ALLOW)
    worst = Verdict(ALLOW)
    for raw in targets:
        t = raw.strip("'\"")
        bare = t.rstrip("/") or "/"
        low = bare.lower()
        if (low in SYSTEM_DIRS or low in {"~", "$home", "${home}", ".", "..", "*", "./*", "../*", "/*", "~/*", "$home/*", "${home}/*", ".*"}
                or re.fullmatch(r"/[^/]+/?\*?", low) and low.split("/")[1] in {d.strip("/") for d in SYSTEM_DIRS}):
            worst = worst.worse(Verdict(DENY, "rm-rf-broad", f"recursive delete of {raw}: home, root, a system directory or the whole working tree"))
            continue
        if re.match(r"^~/?[^/]*$", low) or re.match(r"^\$\{?home\}?/[^/]*$", low):
            worst = worst.worse(Verdict(DENY, "rm-rf-home", f"recursive delete of {raw}, a top-level folder in home"))
            continue
        # $HOME, $TMPDIR and friends are always set: treat them as paths outside the project
        if re.match(r"^\$\{?(?:home|tmpdir|tmp|xdg_cache_home|pwd)\}?/", low):
            worst = worst.worse(Verdict(ASK, "rm-rf-outside", f"recursive delete of {raw}, outside the project"))
            continue
        # any other variable at the start of a path: if it is empty, this becomes a path under /
        if re.match(r"^\$\{?\w+\}?/", t) and not re.match(r"^\$\{?\w+:\?", t):
            worst = worst.worse(Verdict(DENY, "rm-rf-unset-var", f"recursive delete of {raw}: if the variable is empty this becomes a path under /"))
            continue
        if low.startswith("/tmp/") or low.startswith("/var/tmp/"):
            continue
        name = low.split("/")[-1]
        if name in SAFE_RM_NAMES or low.lstrip("./") in SAFE_RM_NAMES or name.endswith(".egg-info"):
            continue
        if low.startswith("/") or low.startswith("~") or ".." in low.split("/"):
            worst = worst.worse(Verdict(ASK, "rm-rf-outside", f"recursive delete of {raw}, outside the project"))
            continue
        if "*" in low:
            worst = worst.worse(Verdict(ASK, "rm-rf-glob", f"recursive delete of a wildcard: {raw}"))
            continue
        worst = worst.worse(Verdict(ASK, "rm-rf", f"recursive delete of {raw}"))
    return worst


# ---------------------------------------------------------------------------
# Command structure: quote-aware splitting into segments and pipeline stages
# ---------------------------------------------------------------------------
WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "nice", "command", "exec", "timeout", "watch", "stdbuf", "ionice"}

# Commands whose quoted arguments are data, not something executed: a search pattern, a commit
# message, an issue title. SQL or terraform words inside them are not run.
INERT = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "echo", "printf", "cat", "less", "more", "head", "tail",
         "wc", "jq", "yq", "awk", "sort", "uniq", "cut", "tr", "tee", "diff", "ls", "pwd", "true", "test", "["}
INERT_GIT = {"log", "commit", "show", "grep", "tag", "notes", "blame", "diff", "status", "shortlog", "describe"}
INERT_GH = {"issue", "pr", "search", "browse", "label", "status"}

# Commands that execute a string argument as code
EXECUTORS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "su", "ssh", "psql", "mysql", "mariadb", "sqlite3",
             "mongosh", "mongo", "redis-cli", "clickhouse-client", "cqlsh", "duckdb"}

BROAD_PATHS = {"/", "~", "$home", "${home}", ".", "..", "*", "/*", "~/*"}

FORK_BOMB_RE = re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")
# Redirections that overwrite devices or system files; checked even for "inert" commands like echo.
REDIRECT_RULES = [
    ("disk-write", DENY, re.compile(r"(?<![>&\d])>\|?\s*/dev/(?:sd|nvme|hd|xvd|disk|mmcblk)\w*", re.I),
     "writes raw bytes over a disk"),
    ("truncate-system-file", DENY,
     re.compile(r"(?:^|[^>&\d])>\|?\s*(?:/etc/|/usr/|/bin/|/sbin/|/boot/|/lib\w*/|/var/lib/|/root/|~/\.ssh/|\$HOME/\.ssh/)", re.I),
     "overwrites a system or credential file"),
]


def _split(cmd: str, seps: tuple[str, ...]) -> list[str]:
    """Split on separators that sit outside quotes. Longest separators first."""
    out, buf, i, q = [], [], 0, None
    while i < len(cmd):
        c = cmd[i]
        if q:
            buf.append(c)
            if c == "\\" and q == '"' and i + 1 < len(cmd):
                buf.append(cmd[i + 1]); i += 2; continue
            if c == q:
                q = None
            i += 1
            continue
        if c in "'\"":
            q = c; buf.append(c); i += 1; continue
        if c == "\\" and i + 1 < len(cmd):
            buf.append(cmd[i:i + 2]); i += 2; continue
        hit = next((sp for sp in seps if cmd.startswith(sp, i)), None)
        if hit == "&" and (cmd[i - 1:i] in (">", "<", "&") or cmd[i + 1:i + 2] in (">", "&")):
            hit = None  # 2>&1, &>, >&
        if hit == "|" and cmd[i + 1:i + 2] == "|":
            hit = None
        if hit:
            out.append("".join(buf)); buf = []; i += len(hit); continue
        buf.append(c); i += 1
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def _segments(cmd: str) -> list[str]:
    return _split(cmd, ("&&", "||", ";", "\n", "&"))


def _stages(seg: str) -> list[str]:
    return _split(seg, ("|&", "|"))


def _tokens(stage: str) -> list[str]:
    try:
        toks = shlex.split(stage, comments=False, posix=True)
    except ValueError:
        toks = stage.split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in WRAPPERS or re.fullmatch(r"\w+=\S*", t):
            i += 1
            continue
        prev = toks[i - 1] if i else ""
        if prev in ("sudo", "doas", "env", "nice", "ionice", "stdbuf") and t.startswith("-"):
            i += 1
            continue
        if prev == "timeout" and (t.startswith("-") or re.fullmatch(r"[\d.]+[smhd]?", t)):
            i += 1
            continue
        break
    return toks[i:]


def _exe(toks: list[str]) -> str:
    return toks[0].rsplit("/", 1)[-1] if toks else ""


def _is_inert(toks: list[str]) -> bool:
    exe = _exe(toks)
    if exe in INERT:
        return True
    if exe == "xargs":
        rest = toks[1:]
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        return bool(rest) and _is_inert(rest)
    if exe == "find":
        return not any(t in ("-delete", "-exec", "-execdir", "-ok", "-okdir") for t in toks)
    if exe == "git":
        sub = next((t for t in toks[1:] if not t.startswith("-")), "")
        return sub in INERT_GIT
    if exe == "gh":
        sub = next((t for t in toks[1:] if not t.startswith("-")), "")
        return sub in INERT_GH and "delete" not in toks
    return False


def _inner_scripts(toks: list[str]) -> list[str]:
    """String arguments an executor will run: bash -lc "...", psql -c "...", ssh host "...", redis-cli FLUSHALL."""
    exe = _exe(toks)
    if exe not in EXECUTORS:
        return []
    out = []
    for i, t in enumerate(toks[1:], 1):
        if re.fullmatch(r"-[a-zA-Z]*c|--command|-e|--execute|--eval", t) and i + 1 < len(toks):
            out.append(toks[i + 1])
    if exe == "ssh":
        args = [t for t in toks[1:] if not t.startswith("-")]
        out.extend(args[1:])
    return out


def _mv_verdict(toks: list[str]) -> Verdict:
    args = [t for t in toks[1:] if not t.startswith("-")]
    if len(args) < 2:
        return Verdict(ALLOW)
    *srcs, dest = args
    if dest == "/dev/null":
        return Verdict(DENY, "mv-to-null", "moving files to /dev/null destroys them")
    for s in srcs:
        low = s.rstrip("/").lower() or "/"
        if low in BROAD_PATHS or low in SYSTEM_DIRS:
            return Verdict(DENY, "mv-broad", f"moving {s}: home, root or a system directory")
    return Verdict(ALLOW)


def _stage_verdict(toks: list[str], prev_toks: list[str]) -> Verdict:
    exe = _exe(toks)
    if exe == "xargs":
        rest = toks[1:]
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        if rest and _exe(rest) == "rm":
            v = _rm_verdict(rest)
            if v.decision == ALLOW and re.search(r"(?:^|\s)-[a-zA-Z]*[rR]|--recursive", " ".join(rest)):
                piped = [t for t in prev_toks[1:] if not t.startswith("-")] if _exe(prev_toks) in ("echo", "printf") else []
                if piped:
                    return _rm_verdict(rest + piped)
                return Verdict(ASK, "xargs-rm-rf", "recursive delete of paths read from a pipe")
            return v
        return Verdict(ALLOW)
    if exe == "rm":
        return _rm_verdict(toks)
    if exe == "mv":
        return _mv_verdict(toks)
    if exe == "kill" and len(toks) >= 3 and toks[-1] == "-1":
        return Verdict(DENY, "kill-all", "kill -1 signals every process you own")
    if exe == "crontab" and "-r" in toks:
        return Verdict(DENY, "crontab-remove", "crontab -r deletes every scheduled job with no undo")
    return Verdict(ALLOW)


def check(cmd: str, _depth: int = 0) -> Verdict:
    """Decide on one shell command string."""
    if not cmd or not cmd.strip() or _depth > 3:
        return Verdict(ALLOW)
    if FORK_BOMB_RE.search(cmd):
        return Verdict(DENY, "fork-bomb", "fork bomb")
    worst = Verdict(ALLOW)
    if PIPE_SHELL_RE.search(cmd):
        worst = worst.worse(Verdict(ASK, "pipe-to-shell", "downloads a script and runs it unread"))
    for seg in _segments(cmd):
        for rid, decision, rx, why in REDIRECT_RULES:
            if rx.search(seg):
                worst = worst.worse(Verdict(decision, rid, why))
        stages = [_tokens(st) for st in _stages(seg)]
        prev: list[str] = []
        for toks in stages:
            worst = worst.worse(_stage_verdict(toks, prev))
            for script in _inner_scripts(toks):
                worst = worst.worse(check(script, _depth + 1))
            prev = toks
        if stages and all(_is_inert(t) for t in stages if t):
            continue  # quoted text in grep / git commit / gh issue is data, not a command
        for rid, decision, rx, why in COMPILED:
            if rx.search(seg):
                worst = worst.worse(Verdict(decision, rid, why))
                break  # first (most specific) match per segment
    if worst.decision == ASK and PROD_RE.search(cmd):
        worst = Verdict(DENY, worst.rule + "+prod", worst.reason + ", and the command names production")
    return worst


def _message(v: Verdict) -> str:
    return (f"paranoid-sre blocked this ({v.rule}): {v.reason}. "
            "Before retrying: name the blast radius, confirm the environment, take or verify a backup, "
            "dry-run if the tool has one, and write a one-line rollback plan. "
            "If it is still the right call, ask the human to run it.")


def run_hook(stdin_text: str) -> tuple[int, str, str]:
    """Returns (exit_code, stdout, stderr) for a hook event."""
    try:
        event = json.loads(stdin_text or "{}")
    except json.JSONDecodeError:
        return 0, "", ""
    if event.get("tool_name") != "Bash":
        return 0, "", ""
    cmd = (event.get("tool_input") or {}).get("command", "")
    v = check(cmd if isinstance(cmd, str) else "")
    if v.decision == DENY:
        return 2, "", _message(v)
    if v.decision == ASK:
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                      "permissionDecisionReason": f"paranoid-sre ({v.rule}): {v.reason}. Confirm the target and the rollback plan."}}
        return 0, json.dumps(out), ""
    return 0, "", ""


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "--check":
        v = check(" ".join(argv[1:]))
        print(v.decision.upper() + (f"  [{v.rule}] {v.reason}" if v.rule else ""))
        return RANK[v.decision]
    code, out, err = run_hook(sys.stdin.read())
    if out:
        sys.stdout.write(out)
    if err:
        sys.stderr.write(err)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
