# Long Agent Sessions Playbook

Patterns for multi-hour Claude Code sessions, based on community experience and our agentnanny configuration.

## Key Insight

Nobody runs a single Claude Code session for hours. Long-running setups use one or more of:

1. **Subagent delegation** — orchestrator stays light, spawns workers that burn context independently
2. **Session chaining** — persistent memory captures state at session end, bootstraps next session
3. **Permission elimination** — auto-approve via hooks/settings so the agent never blocks on prompts
4. **TDD loops** — recursive "write tests, implement, iterate until green" keeps the agent working without human input
5. **Incremental planning** — many small releasable plans instead of one monolithic task

## What We Already Have

| Capability | Status | Location |
|---|---|---|
| PermissionRequest hook (auto-allow/deny) | Done | `agentnanny.py hook` |
| Session-scoped permissions | Done | `agentnanny.py activate/deactivate/run` |
| Operation groups (filesystem, shell, network) | Done | `config.toml [groups]` |
| tmux daemon (fallback for missed prompts) | Done | `agentnanny.py watch` |
| Deny-list for dangerous patterns | Done | `config.toml [hooks] deny` |
| Per-session deny patterns | Done | `agentnanny.py activate -d` |
| TTL-based session expiry | Done | `agentnanny.py activate --ttl` |
| Trust directory pre-seeding | Done | `agentnanny.py trust` |
| Audit logging | Done | `config.toml [logging]` |
| settings.json broad bash allow list | Done | `~/.claude/settings.json` |

## What We're Missing (Ranked by Impact)

### 1. Context Pressure Hook (HIGH)

A PostToolUse hook that reads context usage from the status bar and warns the orchestrator at 60% and 75% context. At the critical threshold, the agent re-enters plan mode, writes progress/learnings to a file, and the user clears context.

**Implementation**: A `PostToolUse` hook that:
- Reads context window percentage from `~/.claude/status.json` or the status line output
- At threshold (e.g., 60%), injects a warning into the tool output suggesting the agent should save state
- At critical threshold (e.g., 75%), auto-triggers plan mode entry or writes a handoff file

**Settings change needed**:
```json
// ~/.claude/settings.json — add PostToolUse hook
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "python \"/path/to/agentnanny.py\" context-check"
      }]
    }]
  }
}
```

**Config addition**:
```toml
[context]
warn_percent = 60
critical_percent = 75
handoff_dir = ".claude/handoffs"
```

### 2. Expanded settings.json Permissions (MEDIUM)

Current settings.json allows most bash commands but still prompts for some tool combinations. Add:

```json
{
  "permissions": {
    "allow": [
      "Read",
      "Edit",
      "Write",
      "Glob",
      "Grep",
      "WebSearch",
      "WebFetch",
      "Agent",
      "NotebookEdit"
    ]
  }
}
```

These are low-risk tools that never need prompting. Currently only `bash` permissions are specified in our global settings.json — the non-bash tools default to prompting.

### 3. Project-Level settings.local.json Expansion (MEDIUM)

Current `.claude/settings.local.json` allows a narrow set of bash commands. For autonomous runs, expand it:

```json
{
  "permissions": {
    "allow": [
      "Bash(npm root:*)",
      "Bash(npm:*)",
      "Bash(python3:*)",
      "Bash(python:*)",
      "Bash(pytest:*)",
      "Bash(uv:*)",
      "Bash(pip:*)",
      "Bash(ls:*)",
      "Bash(gh:*)",
      "Bash(git:*)",
      "Bash(cat:*)",
      "Bash(head:*)",
      "Bash(tail:*)",
      "Bash(mkdir:*)",
      "Bash(tmux:*)",
      "Read",
      "Edit",
      "Write",
      "Glob",
      "Grep",
      "WebSearch",
      "WebFetch(domain:raw.githubusercontent.com)",
      "WebFetch(domain:docs.anthropic.com)",
      "WebFetch(domain:pypi.org)",
      "Agent"
    ]
  }
}
```

### 4. Session Handoff / Bootstrap System (MEDIUM)

At session end (or context pressure), write a structured handoff file:
```
.claude/handoffs/YYYY-MM-DD-HHMMSS.md
```
Contains:
- What was accomplished
- What remains
- Decisions made
- Files changed
- Ready-to-paste prompt for next session

This doesn't require code changes to agentnanny — it's a CLAUDE.md instruction pattern:
```markdown
## Session Handoff Protocol
Before context reaches 75%, write a handoff file to `.claude/handoffs/` containing:
- Completed tasks
- Remaining tasks
- Key decisions
- Changed files list
```

### 5. Subagent Orchestration Pattern (LOW — already available)

Claude Code already supports the `Agent` tool for subagent spawning. The orchestrator stays light, spawns workers for implementation and validation. The pattern is a CLAUDE.md instruction, not a settings change:

```markdown
## Work Delegation
For multi-file changes, use the Agent tool to spawn subagents:
- Writer agent: implements changes, writes to specific files
- Validator agent: reviews the writer's output, returns pass/fail + reason
- Main thread: orchestrates, tracks progress, never does implementation directly
```

### 6. Pre-ToolUse Deny Hook for Safety (LOW — already have deny list)

The deny list in `config.toml` already covers this. Patterns to add for autonomous runs:

```toml
[hooks]
deny = [
  "Bash(rm -rf /*)",
  "Bash(git push --force*)",
  "Bash(git reset --hard*)",
  "Bash(DROP TABLE*)",
  "Bash(curl*|*sh)",
]
```

## Architecture Summary: What Enables Multi-Hour Sessions

```
┌─────────────────────────────────────────────────────────┐
│                    Human (occasional)                     │
│  Checks in periodically. Reviews handoff files.          │
└──────────────┬───────────────────────────┬──────────────┘
               │                           │
    ┌──────────▼──────────┐    ┌──────────▼──────────┐
    │  Session N          │    │  Session N+1         │
    │  (orchestrator)     │    │  (reads handoff)     │
    │                     │    │                      │
    │  ┌─ subagent 1 ──┐  │    │  ┌─ subagent 3 ──┐  │
    │  │ write code     │  │    │  │ continue work  │  │
    │  └────────────────┘  │    │  └────────────────┘  │
    │  ┌─ subagent 2 ──┐  │    │  ┌─ subagent 4 ──┐  │
    │  │ validate code  │  │    │  │ validate       │  │
    │  └────────────────┘  │    │  └────────────────┘  │
    │                     │    │                      │
    │  writes handoff ────┼────┼─▶ reads handoff      │
    │  at 75% context     │    │                      │
    └─────────────────────┘    └──────────────────────┘
               │
    ┌──────────▼──────────┐
    │  agentnanny              │
    │  - hook: session-scoped  │
    │  - hook: deny list       │
    │  - hook: ctx check       │
    │  - groups: fs/shell/net  │
    │  - daemon: fallback      │
    └──────────────────────────┘
```

## Realistic Expectations

Sessions that truly run 30+ minutes fall into categories:

1. Experimenting (fine)
2. Breaking problems into manageable testable chunks (ideal)
3. Retry-looping with poor preparation (waste)
4. Project-specific orchestration tuned over weeks (rare)

Patterns observed from power users:

- Functions < 30 LOC, files < 200 LOC — keeps agent context small per file
- Every change = smallest releasable unit, complete and working
- Specialized validation subagents: build check, test runner, code reviewer, test reviewer, security reviewer
- ~1 week of intense tuning to get agents configured for each project
- No framework needed — architecture docs + CLAUDE.md + incremental plans

The goal is not making the agent work longer. Clean prompts = clean, fast work.

## Concrete Next Steps for agentnanny

1. ~~**Session-scoped permissions**~~ — Done. `activate`/`deactivate`/`run` commands with operation groups and TTL
2. **Add `context-check` subcommand** — PostToolUse hook that monitors context percentage
3. **Add handoff file writer** — callable from the context-check hook at critical threshold
4. **Expand global settings.json** — add non-bash tool permissions to eliminate remaining prompts
5. **Add deny patterns** — destructive git/rm/sql patterns to config.toml
6. **Document the CLAUDE.md patterns** — orchestration and handoff instructions for project-level use
