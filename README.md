# agentnanny

Auto-approve Claude Code permission prompts — scoped to exactly where you need it.

## The Problem

Claude Code prompts for permission on tool use. `--dangerously-skip-permissions` is all-or-nothing and applies machine-wide. You need granular control: auto-approve filesystem operations for an overnight refactor in one terminal, while keeping normal interactive prompts in another.

## Three Permission Scopes

agentnanny gives you three layers of control. A tool must pass **all applicable layers** to be auto-approved.

```
┌─────────────────────────────────────────────────────────┐
│  System-wide (config.toml)                              │
│  Always enforced. Global deny list blocks dangerous     │
│  patterns across every session on the machine.          │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Project (.claude/settings.local.json)            │  │
│  │  Claude Code's own per-repo permissions.          │  │
│  │  Allows specific bash commands, tools, domains.   │  │
│  │                                                   │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │  Session (AGENTNANNY_SCOPE)                 │  │  │
│  │  │  Per-terminal. Lives until deactivated or   │  │  │
│  │  │  TTL expires. Other terminals unaffected.   │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

| Scope | What it controls | Lifetime | Where it lives |
|---|---|---|---|
| **System-wide** | Global deny list, legacy allow list | Permanent until edited | `config.toml [hooks]` |
| **Project** | Per-repo tool/command permissions | Permanent per repo | `.claude/settings.local.json` |
| **Session** | Per-terminal allow groups, tools, deny | Terminal lifetime or TTL | `{tempdir}/agentnanny/sessions/{id}.json` |

### Evaluation order

When Claude Code fires a PermissionRequest:

1. **Global deny** (`config.toml`) — checked first, blocks unconditionally
2. **Session policy** (if `AGENTNANNY_SCOPE` is set) — session deny, then session allow
3. **Legacy fallback** (if no scope) — `config.toml` allow list, or allow-all if none set
4. **Passthrough** — if the tool isn't covered, the hook exits silently and Claude Code shows the normal permission prompt

Project-level permissions (`settings.local.json`) are handled by Claude Code itself, independent of agentnanny.

### Example: all three layers working together

```toml
# config.toml — system-wide: block destructive patterns everywhere
[hooks]
deny = ["Bash(rm -rf*)", "Bash(git push --force*)", "Bash(DROP TABLE*)"]
```

```json
// .claude/settings.local.json — project: allow common dev tools
{
  "permissions": {
    "allow": ["Bash(pytest:*)", "Bash(uv:*)", "Read", "Edit"]
  }
}
```

```bash
# Session: allow filesystem + shell for this terminal, expire in 8 hours
eval $(python agentnanny.py activate -g filesystem,shell --ttl 8h)
```

A `Bash(pytest .)` call passes all three: not globally denied, project-allowed, session-allowed. A `Bash(rm -rf /)` is blocked at layer 1 regardless of session or project settings.

## Install

```bash
# Register the PermissionRequest hook in ~/.claude/settings.json
python agentnanny.py install

# Pre-trust a project directory (skips the trust dialog)
python agentnanny.py trust /path/to/project
```

Uninstall: `python agentnanny.py uninstall`

## Session Commands

### activate — create a session policy for this terminal

```bash
# Allow filesystem + shell operations, deny rm -rf, expire in 8 hours
eval $(python agentnanny.py activate -g filesystem,shell -d "Bash(rm -rf*)" --ttl 8h)

# Allow specific tools instead of groups
eval $(python agentnanny.py activate -t Bash,Read,Write,Edit)

# No TTL (session lives until deactivated)
eval $(python agentnanny.py activate -g all)
```

`activate` prints `export AGENTNANNY_SCOPE=<id>` to stdout. The `eval $(...)` sets it in your shell. Other terminals don't have this env var, so they're unaffected.

### deactivate — remove a session policy

```bash
# Deactivate current session (reads AGENTNANNY_SCOPE from env)
eval $(python agentnanny.py deactivate)

# Deactivate a specific session by ID
python agentnanny.py deactivate abc12345
```

### run — wrap a command with auto-cleanup

```bash
# Creates session, runs command, deletes session on exit
python agentnanny.py run -g filesystem,shell -- claude -p "do the thing"
```

### sessions — list active policies

```bash
python agentnanny.py sessions
# abc12345  age=3600s  25200s remaining  groups=[filesystem, shell]  tools=[-]
```

## Operation Groups

Groups bundle related tools under a name. Defined in `config.toml`:

```toml
[groups]
filesystem = ["Read", "Write", "Edit", "Glob", "Grep"]
shell = ["Bash"]
network = ["WebFetch", "WebSearch"]
all = [".*"]
```

Combine at activation: `-g filesystem,shell,network`

Add your own groups:

```toml
[groups]
safe_bash = ["Bash(ls*)", "Bash(cat*)", "Bash(head*)", "Bash(grep*)"]
dev = ["Bash(pytest*)", "Bash(uv*)", "Bash(npm*)"]
```

## Deny Patterns

Two levels of deny, both using the same pattern syntax:

**Global** (every session, every terminal):

```toml
[hooks]
deny = ["Bash(rm -rf*)", "Bash(git push --force*)", "Bash(DROP TABLE*)"]
```

**Per-session** (at activation time):

```bash
eval $(python agentnanny.py activate -g shell -d "Bash(rm*),Bash(curl*|*sh)")
```

### Pattern syntax

| Pattern | Matches |
|---|---|
| `Bash` | Any Bash tool call |
| `Bash(rm*)` | Bash commands starting with `rm` |
| `Bash(rm -rf*)` | Bash commands starting with `rm -rf` |
| `Bash(curl*\|*sh)` | Bash commands starting with `curl` OR ending with `sh` |
| `Write(/etc/*)` | Write calls to paths under `/etc/` |
| `WebFetch(*evil.com*)` | WebFetch calls with `evil.com` in the URL |
| `.*Fetch.*` | Regex against tool name (matches WebFetch) |
| `.*` | Everything |

## tmux Daemon (Fallback)

For WSL/headless environments where the hook mechanism doesn't cover all prompts, the tmux daemon polls pane buffers and auto-responds to permission widgets.

```bash
python agentnanny.py watch [session-name]   # start
python agentnanny.py stop                    # stop
```

Detects: permission prompts (selects "allow for project" or "yes"), trust prompts, "Continue?" prompts, collapsed transcripts.

## Status and Logging

```bash
python agentnanny.py status   # hook install, daemon, active sessions
python agentnanny.py log      # tail the audit log
```

## Full Configuration Reference

### config.toml

Lives next to `agentnanny.py`. Controls system-wide behavior.

```toml
[hooks]
# Global deny list — blocks these patterns in every session
deny = []
# Legacy allow list (optional) — used when no AGENTNANNY_SCOPE is set
# allow = ["Bash", "Read"]

[groups]
# Named sets of tool patterns for use with activate -g
filesystem = ["Read", "Write", "Edit", "Glob", "Grep"]
shell = ["Bash"]
network = ["WebFetch", "WebSearch"]
all = [".*"]

[daemon]
session = "claude"          # tmux session name
poll_interval = 0.3         # seconds between pane checks
cooldown_seconds = 2.0      # per-pane cooldown after action
dry_run = false             # log without sending keystrokes

[logging]
audit_log = "/tmp/agentnanny.log"
level = "actions"           # "actions" or "all"
max_size_bytes = 10485760   # 10 MB — rotates when exceeded
backup_count = 3            # keep .log.1, .log.2, .log.3
```

### Environment variables

| Variable | Purpose |
|---|---|
| `AGENTNANNY_SCOPE` | Session scope ID (set by `activate`, read by hook) |
| `AGENTNANNY_SESSION` | Override tmux session name for daemon |
| `AGENTNANNY_DENY` | Override global deny list (comma-separated) |
| `AGENTNANNY_LOG` | Override audit log path |
| `AGENTNANNY_DRY_RUN` | Set `1` to log without acting |

### Session policy files

Created by `activate`, stored in `{tempdir}/agentnanny/sessions/{scope_id}.json`:

```json
{
  "scope_id": "a1b2c3d4",
  "created": "2026-03-06T10:00:00+00:00",
  "ttl_seconds": 28800,
  "allow_groups": ["filesystem", "shell"],
  "allow_tools": [],
  "deny": ["Bash(rm -rf*)"]
}
```

Expired policies are automatically deleted on next read.

## Requirements

- Python 3.10+ (stdlib only, no dependencies)
- tmux (daemon mode only)
