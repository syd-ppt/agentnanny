# claude-autopilot: Technical Specification

## Problem

Claude Code's interactive TUI (Ink/React-for-terminal) emits permission prompts that block execution until a human responds. `--dangerously-skip-permissions` does not reliably suppress all prompts (confirmed bugs on WSL: GitHub #1498, #29214, #17544). No existing tool satisfies the full requirement.

## Requirement

A headless daemon that monitors all Claude Code sessions within a single tmux session and auto-responds to permission prompts. Selection logic: option 2 ("yes, allow for the entire conversation") when present, else option 1 ("yes, allow once"). No intelligence. No judgment. Keystroke bot.

## Target environment

- Windows host, Claude Code running inside WSL (Ubuntu)
- tmux as session manager: 1 session = "window", N tmux windows = "tabs"
- Each tmux window runs one Claude Code instance

## Architecture

```
┌─────────────────────────────────────────────┐
│ tmux session: "claude"                      │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│ │ window 0 │ │ window 1 │ │ window N │     │
│ │ (pane 0) │ │ (pane 0) │ │ (pane 0) │     │
│ └──────────┘ └──────────┘ └──────────┘     │
└─────────────────────────────────────────────┘
        ▲           ▲           ▲
        │           │           │
┌───────┴───────────┴───────────┴─────────┐
│           autopilot daemon              │
│  loop:                                  │
│    for each window:                     │
│      capture-pane → strip ANSI → detect │
│      if prompt detected:                │
│        send-keys (option 2 or 1)        │
│    sleep POLL_INTERVAL                  │
└─────────────────────────────────────────┘
```

Single bash/python process. No subprocesses per pane. Sequential polling.

## Core challenges

### 1. Prompt detection from TUI buffer

Claude Code renders with Ink (React for terminals). `tmux capture-pane -p` returns the visible buffer including ANSI escape sequences.

**Problem**: The prompt is not plain text. It's a rendered TUI widget with color codes, cursor positioning, box-drawing characters, and partial renders mid-frame.

**Approach**: `tmux capture-pane -p -t <target>` with `-e` (include escapes) stripped via `sed` or `perl`, then match against known prompt signatures.

**Unknown**: The exact rendered text of permission prompts. This must be empirically captured from a live Claude Code session. Required data:

- Exact text of "Yes, allow once" / "Yes, allow for the entire conversation" / "No" options
- Whether the option text is stable across Claude Code versions
- Whether the prompt uses a selection cursor (e.g., `❯` or `>`) or numbered options
- How the prompt renders when partially scrolled or when terminal is narrow

**Risk**: Ink re-renders the entire viewport on state change. A capture mid-render may show incomplete prompt text. Mitigation: require N consecutive identical captures before acting (debounce).

### 2. Option selection mechanics

If options are a vertical list with a cursor selector (typical Ink `<SelectInput>`):

- Option 1 is likely pre-selected (cursor at top)
- Option 2 requires one `Down` arrow then `Enter`
- Detecting *which* option is currently highlighted requires parsing the cursor indicator from the buffer

If options are numbered (press 1/2/3):

- Simpler: just send the character `2` or `1`

**Unknown**: Which input mode Claude Code uses. Must be determined empirically.

**Risk**: Sending `Down + Enter` when the prompt hasn't fully rendered sends keystrokes to the wrong context. Mitigation: debounce + verify prompt still present after keystroke delay.

### 3. Distinguishing prompt types

Claude Code has multiple interactive states:

| State                                 | Should auto-respond?          |
| ------------------------------------- | ----------------------------- |
| Permission prompt (tool use)          | **Yes** — this is the target  |
| Plan confirmation                     | Maybe — user preference       |
| Clarifying question (free text input) | **No** — requires human input |
| "Continue?" after long output         | **Yes** — but different key   |
| Initial trust directory prompt        | **Yes** — one-time            |
| Cost warning prompt                   | User preference               |

Each has different rendered text. The detector must positively identify permission prompts and ignore everything else. False positives on free-text input would inject garbage into Claude's conversation.

**Approach**: Whitelist-based detection. Only act on buffers matching known prompt patterns. Default to inaction.

### 4. Race conditions and double-sends

- Poll captures buffer → detects prompt → sends keys → next poll captures buffer before TUI updates → detects same prompt → sends keys again
- Result: double keystroke, potentially selecting wrong option or confirming something unintended

**Mitigation**: Track per-pane state. After sending keys to a pane, mark it as "acted" with a cooldown (e.g., 2 seconds). Only re-detect after cooldown expires and buffer content has changed.

### 5. Multi-pane enumeration

```bash
tmux list-windows -t "$SESSION" -F '#{window_index}'
```

Dynamic: windows can be created/destroyed mid-session. Re-enumerate on every poll cycle. Handle panes within windows if user splits (though spec says one pane per window).

### 6. WSL-specific concerns

- tmux runs inside WSL, so no Windows-native issues with tmux itself
- Terminal emulator (Windows Terminal, etc.) is irrelevant — tmux buffer is the source of truth
- WSL clock skew can affect timing — use monotonic counters, not wall time
- WSL I/O performance for rapid `capture-pane` calls: negligible, but measure

## Required empirical data (before implementation)

1. **Capture raw prompt buffers**: Run Claude Code in tmux, trigger a permission prompt, run `tmux capture-pane -p -e -t <target>`, save output verbatim. Do this for:
   
   - File edit permission
   - Bash command permission  
   - MCP tool permission
   - WebFetch permission
   - The "continue?" prompt
   - Plan confirmation prompt
   - A clarifying question (to know what NOT to match)

2. **Determine input mode**: When a permission prompt is shown, test whether pressing `2` selects option 2, or whether arrow keys + Enter are required.

3. **Measure render timing**: Time between prompt appearing partially and fully rendered. Determines minimum debounce interval.

4. **Test across versions**: Capture prompts from at least 2 Claude Code versions to assess text stability.

## Proposed implementation

**Language**: Bash (minimal dependencies, native tmux integration). Python fallback if ANSI stripping or state management becomes unwieldy.

**Config** (env vars or dotfile):

```
AUTOPILOT_SESSION="claude"        # tmux session name
AUTOPILOT_POLL_MS=300             # poll interval
AUTOPILOT_DEBOUNCE_COUNT=2        # consecutive matches before acting
AUTOPILOT_COOLDOWN_MS=2000        # per-pane cooldown after keystroke
AUTOPILOT_PREFER_ALLOW_ALL=true   # prefer option 2 over option 1
AUTOPILOT_DRY_RUN=false           # log detections without sending keys
AUTOPILOT_LOG=/tmp/autopilot.log  # audit trail
```

**Subcommands**:

```
autopilot start [session-name]    # start daemon, background
autopilot stop                    # kill daemon
autopilot status                  # show monitored windows + last action per pane
autopilot log                     # tail the audit log
```

**Audit log format** (append-only, TSV):

```
timestamp  window  action           buffer_hash  prompt_type
1709...    0       sent_allow_all   a3f2b1c8     bash_permission
1709...    1       detected_wait    -            debounce
1709...    2       cooldown_skip    -            -
```

## Open questions

1. Is Claude Code's Ink `<SelectInput>` component using arrow-key navigation or numbered selection? (Determines keystroke strategy entirely.)
2. Does the "yes to all" option (option 2) appear on every permission prompt type, or only on certain tool categories?
3. Can `tmux capture-pane -p` reliably capture the full prompt when Ink uses alternate screen buffer? (Some Ink apps use `process.stdout.write('\x1b[?1049h')` to switch buffers.)
4. What is the terminal width sensitivity? Do prompt strings wrap or truncate at narrow widths?
5. Does `Shift+Tab` (auto-accept mode) in Claude Code cover the same scope as what we're building? If so, is it scriptable via `send-keys`?

## Existing prior art assessment

| Tool                           | Fit                                                                     | Gap                                                                                                                         |
| ------------------------------ | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| claude-yolo/claude-yolo        | Closest. tmux polling, multi-pane, WSL claimed.                         | Sends Enter only (no option 2 selection). Prompt detection patterns unverified.                                             |
| claude-squad -y                | Auto-accept via keystroke.                                              | Heavier (Go binary, git worktree management). Not a daemon — it's a full session manager.                                   |
| PreToolUse hooks               | Native Claude Code mechanism. Returns `{"permissionDecision":"allow"}`. | Doesn't cover non-tool prompts. Requires `.claude/settings.json` config. May not fire for all prompt types (see bug #1498). |
| --dangerously-skip-permissions | Eliminates most prompts.                                                | Leaky (bugs #1498, #29214, #17544). WSL-specific issues. Doesn't compose with other modes.                                  |

## Recommendation

Use `claude-yolo/claude-yolo` as starting point. Replace its prompt detection with empirically-captured patterns. Add option 2 selection logic. Add debounce and cooldown state. Test on WSL with 3+ concurrent Claude Code windows before trusting it.

First step: capture the raw prompt buffers. Everything else depends on knowing exactly what we're parsing.
