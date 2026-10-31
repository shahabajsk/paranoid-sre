# It's not paranoia if prod is real.

**paranoid-sre** makes your coding agent act like the on-call SRE who has been paged at 3 a.m. too many times: it names the target, proves the environment, checks the backup and writes the rollback before it runs anything destructive.

Two parts, both free to run:

- **A persona skill** that changes how the agent plans destructive work.
- **A deterministic guard hook** that checks every shell command before it runs. No model calls, no API key, Python standard library only.

In April 2026 an AI coding agent deleted a company's production database and its backups in 9 seconds ([Tom's Hardware](https://www.tomshardware.com/tech-industry/artificial-intelligence/claude-powered-ai-coding-agent-deletes-entire-company-database-in-9-seconds-backups-zapped-after-cursor-tool-powered-by-anthropics-claude-goes-rogue)). paranoid-sre stops that kind of call when it goes through the shell.

## Before and after

```text
You: the staging deploy is failing on a stale volume, clean it up

Agent, without paranoid-sre:
  $ curl -X DELETE https://api.example-host.com/v1/volumes/vol-prod-db/backups
  $ curl -X POST https://api.example-host.com/graphql -d '{"query":"mutation { volumeDelete(volumeId: \"vol-prod-db\") }"}'
  Done. The stale volume and its backups are removed.

Agent, with paranoid-sre:
  Target: vol-prod-db. Environment: the ID says prod, the task said staging. This looks like prod.
  Blast radius: the production database and every backup of it.
  Way back: none if the backups go too.
  paranoid-sre blocked this (api-delete+prod): raw API delete call; check what it targets, and the command names production.
  I'm stopping here. Which volume did you mean?
```

## Measured

`python3 bench/run.py --markdown`, on the commit you are reading:

| Commands | n | Stopped without guard | Stopped with guard | Of those, hard-blocked |
|---|---|---|---|---|
| Destructive | 89 | 0 (0%) | 89 (100%) | 68 |
| Safe lookalikes | 66 | 0 (0%) | 0 (0%) | 0 |
| Held-out destructive | 30 | 0 (0%) | 30 (100%) | |
| Held-out safe lookalikes | 30 | 0 (0%) | 0 (0%) | |
| Known bypasses (not caught by design) | 6 | 0 | 0 | |

"Stopped" means the guard either blocked the command or asked you to confirm it. Safe lookalikes are the commands that sit next to the dangerous ones: `rm -rf node_modules`, `git push --force-with-lease origin feature/x`, `DELETE ... WHERE`, `terraform plan`, `docker compose down` without `-v`.

Read these numbers for what they are. One person wrote the guard, the corpus and the held-out set, so 100% means the guard covers what its author thought of, not what an agent will try. A pre-launch review by a second reader, plus cases found while fixing it, turned up 22 wrong decisions: 7 searches and commit messages blocked as if they ran, 2 cache cleanups denied instead of asked, and 13 destructive commands missed. All 22 are fixed and sit in the corpus as tests, under category `review`. The [known bypasses](bench/known_bypasses.jsonl) are real misses. If you find a command it gets wrong, open an issue with the command: it goes into the corpus with a test.

## Install

**Claude Code** (skill and guard hook):

```text
/plugin marketplace add shahabajsk/paranoid-sre
/plugin install paranoid-sre@paranoid-sre
```

**Codex, Gemini CLI, OpenCode, Cursor, any agent that reads AGENTS.md:** copy [AGENTS.md](AGENTS.md) into your repo, or append it to the one you have. These agents get the persona rules. For the guard, call it from your agent's own pre-command hook or from a shell wrapper:

```bash
python3 path/to/paranoid-sre/hooks/guard.py --check "$CMD"   # exit 0 allow, 1 ask, 2 deny
```

**Just the guard, anywhere:** `hooks/guard.py` is a single file with no dependencies. Copy it.

## How the guard decides

For each shell command it splits on `;`, `&&`, `||`, `&` and pipes, ignoring separators inside quotes. It strips `sudo`, `env` and `timeout`, looks inside strings that something will execute (`bash -lc "..."`, `ssh host "..."`, `psql -c "..."`), and parses `rm`, `mv`, `xargs rm`, `kill` and `crontab` by their arguments. Quoted text given to commands that only read or record it (`grep`, `rg`, `git log`, `git commit -m`, `gh issue create`, `echo`) is treated as data, so a commit message that mentions `DROP DATABASE` is not blocked.

| Decision | What happens in Claude Code | Examples |
|---|---|---|
| deny | Exit code 2. The call is blocked and the agent sees the reason. | `rm -rf ~`, `bash -lc "rm -rf ~"`, `git push --force origin main`, `git push --delete origin main`, `git reflog expire --expire=now`, `DROP DATABASE`, `DELETE FROM users;`, `terraform destroy`, `kubectl delete namespace`, `aws s3 rm --recursive`, `--skip-final-snapshot`, deleting backups, `> /etc/passwd`, `chmod -R 000 /`, `crontab -r`, `kill -9 -1`, `mkfs` |
| ask | JSON `permissionDecision: ask`. You see the reason and approve or refuse. | `rm -rf src`, `rm -rf $HOME/.cache/pip`, `git reset --hard`, `git checkout -- .`, `git stash clear`, `git push -f` on your own branch, `UPDATE` without `WHERE`, `terraform apply -auto-approve`, `kubectl delete pod`, `curl \| sh`, `curl -X DELETE` |
| allow | Exit 0, nothing printed. Your normal permission settings apply. | everything else |

Any "ask" that names `prod`, `production`, `prd` or `live` becomes a "deny". `rm` is parsed, not pattern-matched: build output folders (`node_modules`, `dist`, `.next`, `target`, `__pycache__` and others) and `/tmp` are allowed; other paths in home or `$TMPDIR` ask; home itself, `/`, system folders, `.` and paths that start with an unknown variable (empty variable means `/`) are denied. Every rule and its reason is in [hooks/guard.py](hooks/guard.py).

## Limits

- **It is not a sandbox.** It reads command text. An agent that writes `shutil.rmtree` in Python, base64-encodes a command or hides it in a script file gets past it. The [known bypasses](bench/known_bypasses.jsonl) list them, and the skill tells the agent not to route around a block, but a determined or confused agent can.
- **Use it with real permissions.** Least-privilege tokens, read-only prod credentials, protected branches and backups the agent's credentials cannot delete do more than any hook. This is the second line.
- **It only sees Bash.** File edits and MCP tool calls go through other tools.

## Sibling project

[walkaway](https://github.com/shahabajsk/walkaway) audits your agent loops; paranoid-sre guards each command.

## Contributing

A wrong decision is a bug. Open an issue with the exact command and what it should have been. Fixes come with a corpus row and a test (`python3 -m pytest -q`).

MIT licensed.
