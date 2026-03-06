#!/usr/bin/env python3
"""agentnanny — auto-approve Claude Code permission prompts via hooks + tmux daemon."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    tomllib = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_PATH = Path(__file__).resolve()
CONFIG_PATH = SCRIPT_PATH.parent / "config.toml"
SETTINGS_PATH = Path.home() / ".claude" / "settings.json"
CLAUDE_JSON_PATH = Path.home() / ".claude.json"
PID_FILE = Path("/tmp/agentnanny.pid") if sys.platform != "win32" else Path(os.environ.get("TEMP", "/tmp")) / "agentnanny.pid"
SESSION_DIR = Path(tempfile.gettempdir()) / "agentnanny" / "sessions"

# ---------------------------------------------------------------------------
# Minimal TOML parser (stdlib only — handles flat tables, strings, arrays)
# ---------------------------------------------------------------------------


def parse_toml(text: str) -> dict:
    """Parse a subset of TOML sufficient for config.toml."""
    result: dict = {}
    current_table: dict = result
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Table header
        m = re.match(r"^\[([a-zA-Z0-9_.]+)\]$", line)
        if m:
            parts = m.group(1).split(".")
            current_table = result
            for p in parts:
                current_table = current_table.setdefault(p, {})
            continue
        # Key = value
        m = re.match(r'^([a-zA-Z0-9_]+)\s*=\s*(.+)$', line)
        if not m:
            continue
        key, raw = m.group(1), m.group(2).strip()
        current_table[key] = _parse_toml_value(raw)
    return result


def _parse_toml_value(raw: str):
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw == "true":
        return True
    if raw == "false":
        return False
    if raw.startswith("["):
        # Simple flat array of strings
        inner = raw[1:-1].strip()
        if not inner:
            return []
        items = []
        for item in re.findall(r'"([^"]*)"', inner):
            items.append(item)
        return items
    try:
        return float(raw) if "." in raw else int(raw)
    except ValueError:
        return raw


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def load_config() -> dict:
    """Load config.toml, with env var overrides."""
    cfg: dict = {"hooks": {}, "daemon": {}, "logging": {}}
    if CONFIG_PATH.exists():
        if tomllib is not None:
            with open(CONFIG_PATH, "rb") as f:
                cfg = tomllib.load(f)
        else:
            cfg = parse_toml(CONFIG_PATH.read_text(encoding="utf-8"))

    # Env var overrides
    if v := os.environ.get("AGENTNANNY_SESSION"):
        cfg.setdefault("daemon", {})["session"] = v
    if v := os.environ.get("AGENTNANNY_DENY"):
        cfg.setdefault("hooks", {})["deny"] = [x.strip() for x in v.split(",")]
    if v := os.environ.get("AGENTNANNY_LOG"):
        cfg.setdefault("logging", {})["audit_log"] = v
    if v := os.environ.get("AGENTNANNY_DRY_RUN"):
        cfg.setdefault("daemon", {})["dry_run"] = v.lower() in ("1", "true", "yes")

    return cfg


# ---------------------------------------------------------------------------
# Deny-list matching
# ---------------------------------------------------------------------------


def _glob_to_regex(glob_pat: str) -> str:
    """Convert a glob pattern to regex, supporting ``*``, ``?``, and ``|`` alternation.

    The ``|`` character splits the pattern into alternatives:
        ``curl*|*sh`` → matches inputs starting with ``curl`` OR ending with ``sh``.
    Each alternative is independently converted (``*`` → ``.*``, ``?`` → ``.``).
    """
    parts = glob_pat.split("|")
    regex_parts = [re.escape(p).replace(r"\*", ".*").replace(r"\?", ".") for p in parts]
    return "|".join(regex_parts)


def matches_deny(tool_name: str, tool_input: dict, deny_list: list[str]) -> bool:
    """Check if a tool call matches any deny pattern.

    Pattern formats:
        "Bash"              — exact tool name match
        "Bash(rm*)"         — tool name + command pattern (glob-style)
        "Bash(rm -rf*)"     — tool name + command prefix
        "Bash(curl*|*sh)"   — alternation (matches curl… OR …sh)
        ".*dangerous.*"     — regex against tool_name
    """
    for pattern in deny_list:
        # Pattern with tool_input filter: ToolName(input_pattern)
        m = re.match(r'^(\w+)\((.+)\)$', pattern)
        if m:
            pat_tool, pat_input = m.group(1), m.group(2)
            if pat_tool != tool_name:
                continue
            input_str = _primary_input(tool_name, tool_input)
            regex = _glob_to_regex(pat_input)
            if re.match(regex, input_str):
                return True
        else:
            # Plain pattern — match against tool_name
            if pattern == tool_name:
                return True
            try:
                if re.fullmatch(pattern, tool_name):
                    return True
            except re.error:
                pass
    return False


def _primary_input(tool_name: str, tool_input: dict) -> str:
    """Extract the primary input string for a tool call."""
    if tool_name == "Bash":
        return tool_input.get("command", "")
    if tool_name == "Write":
        return tool_input.get("file_path", "")
    if tool_name == "Edit":
        return tool_input.get("file_path", "")
    if tool_name == "Read":
        return tool_input.get("file_path", "")
    if tool_name == "WebFetch":
        return tool_input.get("url", "")
    # Fallback: join all values
    return " ".join(str(v) for v in tool_input.values())


# ---------------------------------------------------------------------------
# Session policies
# ---------------------------------------------------------------------------


def generate_scope_id() -> str:
    """Generate a random 8-char hex scope ID."""
    return os.urandom(4).hex()


def _secure_dir(path: Path) -> None:
    """Ensure directory exists with owner-only permissions (700)."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(stat.S_IRWXU)


def save_session_policy(policy: dict) -> Path:
    """Write a session policy file. Returns the path."""
    _secure_dir(SESSION_DIR)
    path = SESSION_DIR / f"{policy['scope_id']}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 600
    tmp.replace(path)
    return path


def load_session_policy(scope_id: str) -> dict | None:
    """Load a session policy by scope ID. Returns None if missing or expired."""
    path = SESSION_DIR / f"{scope_id}.json"
    if not path.exists():
        return None
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    ttl = policy.get("ttl_seconds", 0)
    if ttl > 0:
        created = datetime.fromisoformat(policy["created"])
        elapsed = (datetime.now(timezone.utc) - created).total_seconds()
        if elapsed > ttl:
            path.unlink(missing_ok=True)
            return None
    return policy


def delete_session_policy(scope_id: str) -> bool:
    """Delete a session policy. Returns True if it existed."""
    path = SESSION_DIR / f"{scope_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def list_session_policies() -> list[dict]:
    """List all active (non-expired) session policies."""
    if not SESSION_DIR.exists():
        return []
    policies = []
    for path in SESSION_DIR.glob("*.json"):
        try:
            policy = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        ttl = policy.get("ttl_seconds", 0)
        if ttl > 0:
            created = datetime.fromisoformat(policy["created"])
            elapsed = (datetime.now(timezone.utc) - created).total_seconds()
            if elapsed > ttl:
                path.unlink(missing_ok=True)
                continue
        policies.append(policy)
    return policies


# ---------------------------------------------------------------------------
# Group resolution
# ---------------------------------------------------------------------------


def resolve_groups(group_names: list[str], cfg: dict) -> list[str]:
    """Expand group names to a flat list of tool patterns."""
    groups_cfg = cfg.get("groups", {})
    patterns: list[str] = []
    for name in group_names:
        group_patterns = groups_cfg.get(name)
        if group_patterns is None:
            raise ValueError(f"Unknown group: {name}")
        patterns.extend(group_patterns)
    return patterns


# ---------------------------------------------------------------------------
# Allow matching
# ---------------------------------------------------------------------------


def matches_allow(tool_name: str, tool_input: dict, allow_patterns: list[str]) -> bool:
    """Check if a tool call matches any allow pattern.

    Same pattern syntax as matches_deny:
        "Bash"              — exact tool name
        "Bash(ls*)"         — tool name + input pattern
        "Bash(git status*|git diff*)" — alternation
        ".*"                — regex wildcard (match all)
    """
    for pattern in allow_patterns:
        m = re.match(r'^(\w+)\((.+)\)$', pattern)
        if m:
            pat_tool, pat_input = m.group(1), m.group(2)
            if pat_tool != tool_name:
                continue
            input_str = _primary_input(tool_name, tool_input)
            regex = _glob_to_regex(pat_input)
            if re.match(regex, input_str):
                return True
        else:
            if pattern == tool_name:
                return True
            try:
                if re.fullmatch(pattern, tool_name):
                    return True
            except re.error:
                pass
    return False


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


LOG_MAX_SIZE_DEFAULT = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT_DEFAULT = 3


def _rotate_log(log_file: Path, cfg: dict) -> None:
    """Rotate audit log when it exceeds max size."""
    log_cfg = cfg.get("logging", {})
    max_size = int(log_cfg.get("max_size_bytes", LOG_MAX_SIZE_DEFAULT))
    backup_count = int(log_cfg.get("backup_count", LOG_BACKUP_COUNT_DEFAULT))

    if not log_file.exists():
        return
    try:
        if log_file.stat().st_size < max_size:
            return
    except OSError:
        return

    # Rotate: .log.3 → delete, .log.2 → .log.3, .log.1 → .log.2, .log → .log.1
    for i in range(backup_count, 0, -1):
        src = log_file.with_suffix(f".log.{i}") if i > 0 else log_file
        dst = log_file.with_suffix(f".log.{i + 1}")
        if i == backup_count:
            src.unlink(missing_ok=True)
        elif src.exists():
            src.rename(dst)
    if log_file.exists():
        log_file.rename(log_file.with_suffix(f".log.1"))


def audit_log(source: str, action: str, tool_name: str, detail: str, cfg: dict | None = None):
    """Append a TSV line to the audit log."""
    cfg = cfg or load_config()
    log_cfg = cfg.get("logging", {})
    level = log_cfg.get("level", "actions")
    log_path = log_cfg.get("audit_log", "/tmp/agentnanny.log")

    if level == "actions" and action not in ("allowed", "denied", "approved", "expanded"):
        return

    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    line = f"{ts}\t{source}\t{action}\t{tool_name}\t{detail}\n"
    try:
        log_file = Path(log_path)
        _rotate_log(log_file, cfg)
        fd = os.open(str(log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        pass  # Log failure is not fatal


# ---------------------------------------------------------------------------
# Mode 1: Hook handler
# ---------------------------------------------------------------------------


def _hook_deny(tool_name: str, message: str, cfg: dict):
    """Output a deny decision and audit log it."""
    audit_log("hook", "denied", tool_name, message, cfg)
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": f"agentnanny: {message}",
            },
        }
    }, sys.stdout)


def _hook_allow(tool_name: str, detail: str, cfg: dict):
    """Output an allow decision and audit log it."""
    audit_log("hook", "allowed", tool_name, detail, cfg)
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"},
        }
    }, sys.stdout)


def handle_hook():
    """PermissionRequest hook handler. Reads JSON from stdin, writes decision to stdout.

    Two modes:
      - Legacy (no AGENTNANNY_SCOPE): uses config.toml deny/allow lists, identical to v1
      - Session-scoped (AGENTNANNY_SCOPE set): loads session policy, applies its rules.
        Passthrough (no output, exit 0) when scope is missing/expired or tool not in allow list.
    """
    event = json.load(sys.stdin)
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {})

    cfg = load_config()
    global_deny = cfg.get("hooks", {}).get("deny", [])

    # Global deny always applies regardless of mode
    if matches_deny(tool_name, tool_input, global_deny):
        _hook_deny(tool_name, f"denied {tool_name}", cfg)
        return

    scope_id = os.environ.get("AGENTNANNY_SCOPE")

    if not scope_id:
        # Legacy mode — original v1 behavior
        allow_list = cfg.get("hooks", {}).get("allow", None)
        if allow_list is not None and tool_name not in allow_list:
            detail = _primary_input(tool_name, tool_input)[:200]
            _hook_deny(tool_name, f"{tool_name} not in allow list", cfg)
            return
        detail = _primary_input(tool_name, tool_input)[:200]
        _hook_allow(tool_name, detail, cfg)
        return

    # Session-scoped mode
    policy = load_session_policy(scope_id)
    if policy is None:
        # No valid policy — passthrough to normal permission dialog
        return

    # Session-level deny (merged with global, which was already checked)
    session_deny = policy.get("deny", [])
    if session_deny and matches_deny(tool_name, tool_input, session_deny):
        _hook_deny(tool_name, f"denied {tool_name} (session {scope_id})", cfg)
        return

    # Resolve session allow list from groups + explicit tools
    allow_patterns: list[str] = list(policy.get("allow_tools", []))
    group_names = policy.get("allow_groups", [])
    if group_names:
        try:
            allow_patterns.extend(resolve_groups(group_names, cfg))
        except ValueError:
            pass  # Unknown group — don't crash the hook

    if matches_allow(tool_name, tool_input, allow_patterns):
        detail = _primary_input(tool_name, tool_input)[:200]
        _hook_allow(tool_name, f"{detail} (session {scope_id})", cfg)
        return

    # Tool not in session's allow list — passthrough to normal permission dialog
    return


# ---------------------------------------------------------------------------
# Mode 2: Install / Uninstall hooks
# ---------------------------------------------------------------------------

HOOK_MARKER = "agentnanny"


def install_hooks():
    """Register agentnanny as a PermissionRequest hook in Claude Code settings."""
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    settings: dict = {}
    if SETTINGS_PATH.exists():
        settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))

    hooks = settings.setdefault("hooks", {})
    perm_hooks: list = hooks.setdefault("PermissionRequest", [])

    # Check if already installed
    for entry in perm_hooks:
        for h in entry.get("hooks", []):
            if HOOK_MARKER in h.get("command", ""):
                print(f"Already installed in {SETTINGS_PATH}", file=sys.stderr)
                raise SystemExit(1)

    script_path = str(SCRIPT_PATH)
    # Use forward slashes for cross-platform compatibility
    script_path = script_path.replace("\\", "/")

    # Use absolute path to the interpreter that ran install — avoids PATH differences
    # between the user's shell and Claude Code's hook execution environment
    python_cmd = sys.executable.replace("\\", "/")

    hook_entry = {
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": f'"{python_cmd}" "{script_path}" hook',
        }],
    }

    perm_hooks.append(hook_entry)
    SETTINGS_PATH.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"Installed PermissionRequest hook in {SETTINGS_PATH}")


def uninstall_hooks():
    """Remove agentnanny hooks from Claude Code settings."""
    if not SETTINGS_PATH.exists():
        print("No settings file found", file=sys.stderr)
        raise SystemExit(1)

    settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    hooks = settings.get("hooks", {})
    modified = False

    for event_name in ("PermissionRequest", "PreToolUse"):
        entries: list = hooks.get(event_name, [])
        filtered = []
        for entry in entries:
            keep = True
            for h in entry.get("hooks", []):
                if HOOK_MARKER in h.get("command", ""):
                    keep = False
                    break
            if keep:
                filtered.append(entry)
        if len(filtered) != len(entries):
            hooks[event_name] = filtered
            modified = True
        # Clean up empty lists
        if not hooks.get(event_name):
            hooks.pop(event_name, None)

    if not modified:
        print("No agentnanny hooks found", file=sys.stderr)
        raise SystemExit(1)

    # Clean up empty hooks dict
    if not hooks:
        settings.pop("hooks", None)

    SETTINGS_PATH.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"Removed agentnanny hooks from {SETTINGS_PATH}")


# ---------------------------------------------------------------------------
# Trust directory
# ---------------------------------------------------------------------------


def trust_directory(directory: str):
    """Write trust entry to ~/.claude.json so the trust prompt never appears."""
    abs_dir = str(Path(directory).resolve())
    settings: dict = {}
    if CLAUDE_JSON_PATH.exists():
        settings = json.loads(CLAUDE_JSON_PATH.read_text(encoding="utf-8"))

    projects = settings.setdefault("projects", {})
    proj = projects.setdefault(abs_dir, {})
    proj["hasTrustDialogAccepted"] = True

    CLAUDE_JSON_PATH.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"Trusted: {abs_dir}")


# ---------------------------------------------------------------------------
# Mode 3: tmux daemon (WSL/headless only)
# ---------------------------------------------------------------------------

# ANSI escape sequence pattern
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\].*?\x07|\x1b\[.*?[a-zA-Z]")

# Separator: 10+ consecutive box-drawing horizontal line characters
SEPARATOR_RE = re.compile(r"[─━]{10,}")

# Prompt detection patterns (below separator)
#
# Real Claude Code permission prompts look like:
#   "Do you want to proceed?"  /  "Do you want to allow Claude to fetch this content?"
#   ❯ 1. Yes
#     2. Yes, allow reading from User\ from this project
#     3. No
#   Esc to cancel · Tab to amend · ctrl+e to explain
#
# The ❯ cursor starts on option 1.  Option 2 = "allow for project/domain".

# Permission question line
PERMISSION_QUESTION_RE = re.compile(
    r"Do you want to (proceed|allow)",
    re.IGNORECASE,
)

# Numbered options with Yes/No (the actual selector lines)
NUMBERED_OPTION_RE = re.compile(
    r"^\s*[❯>]?\s*\d+\.\s*(Yes|No)",
    re.MULTILINE,
)

# Footer that confirms this is a real permission prompt
PERMISSION_FOOTER_RE = re.compile(
    r"Esc to cancel.*Tab to amend",
)

# Trust folder prompt
TRUST_RE = re.compile(
    r"(trust this|Trust this|trust folder|Trust folder|directory trusted)",
    re.IGNORECASE,
)

# "Continue?" prompt
CONTINUE_RE = re.compile(
    r"(Continue\?|Do you want to continue|Press Enter to continue)",
    re.IGNORECASE,
)

# Collapsed transcript indicator (Ctrl+O to expand)
COLLAPSED_RE = re.compile(
    r"(Ctrl\+O|ctrl\+o|collapsed|▶.*transcript|►.*transcript)",
    re.IGNORECASE,
)

# Slash command picker veto — 2+ lines matching "/command  description"
SLASH_PICKER_RE = re.compile(
    r"^\s*/\w+\s{2,}\S",
    re.MULTILINE,
)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return ANSI_RE.sub("", text)


def _extract_below_separator(text: str) -> str:
    """Extract text below the last separator line, or last 15 lines as fallback."""
    lines = text.splitlines()
    sep_idx = None
    for i in range(len(lines) - 1, -1, -1):
        if SEPARATOR_RE.search(lines[i]):
            sep_idx = i
            break
    if sep_idx is not None:
        return "\n".join(lines[sep_idx + 1:])
    return "\n".join(lines[-15:])


def count_options(text: str) -> int:
    """Count numbered options (1. Yes, 2. No, etc.) in prompt text."""
    return len(re.findall(r"^\s*[❯>]?\s*\d+\.\s+\S", text, re.MULTILINE))


def detect_prompt(text: str) -> tuple[str, int] | None:
    """Detect a prompt type in screen content.

    Returns (prompt_type, option_count) or None.

    Uses separator-anchored detection: finds last separator line,
    examines content below it.

    Real Claude Code prompts come in two variants:
      3-option: "Do you want to proceed?" → 1. Yes / 2. Yes, allow for project / 3. No
      2-option: "Do you want to proceed?" → 1. Yes / 2. No  (flagged commands)
    Footer: "Esc to cancel · Tab to amend · ctrl+e to explain"
    """
    below = _extract_below_separator(text)

    if not below.strip():
        return None

    # Veto: slash command picker
    slash_matches = SLASH_PICKER_RE.findall(below)
    if len(slash_matches) >= 2:
        return None

    # Primary detection: "Do you want to proceed/allow" + numbered options
    has_question = bool(PERMISSION_QUESTION_RE.search(below))
    has_numbered = bool(NUMBERED_OPTION_RE.search(below))
    has_footer = bool(PERMISSION_FOOTER_RE.search(below))

    if has_question and has_numbered:
        return ("permission", count_options(below))

    # Numbered options with footer but no question (partial render)
    if has_numbered and has_footer:
        return ("permission", count_options(below))

    if TRUST_RE.search(below):
        return ("trust", 0)

    if CONTINUE_RE.search(below):
        return ("continue", 0)

    return None


def detect_collapsed(text: str) -> bool:
    """Detect collapsed transcript that needs Ctrl+O to expand."""
    return bool(COLLAPSED_RE.search(text))


class PaneState:
    """Per-pane state for cooldown tracking."""
    __slots__ = ("last_action_time", "last_content_hash")

    def __init__(self):
        self.last_action_time: float = 0.0
        self.last_content_hash: int = 0


def tmux_capture(target: str) -> str:
    """Capture tmux pane content."""
    result = subprocess.run(
        ["tmux", "capture-pane", "-p", "-t", target],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0:
        return ""
    return strip_ansi(result.stdout)


def tmux_send_keys(target: str, keys: str, dry_run: bool = False):
    """Send keys to a tmux pane."""
    if dry_run:
        return
    subprocess.run(
        ["tmux", "send-keys", "-t", target, keys],
        capture_output=True, timeout=5,
    )


def tmux_list_panes(session: str) -> list[str]:
    """List all pane targets in a tmux session."""
    result = subprocess.run(
        ["tmux", "list-panes", "-s", "-t", session, "-F", "#{pane_id}"],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0:
        return []
    return [p.strip() for p in result.stdout.strip().splitlines() if p.strip()]


def daemon_loop(session: str, cfg: dict):
    """Main polling loop for the tmux daemon."""
    daemon_cfg = cfg.get("daemon", {})
    poll_interval = float(daemon_cfg.get("poll_interval", 0.3))
    cooldown = float(daemon_cfg.get("cooldown_seconds", 2.0))
    dry_run = bool(daemon_cfg.get("dry_run", False))

    pane_states: dict[str, PaneState] = {}

    print(f"agentnanny daemon started — session={session} poll={poll_interval}s cooldown={cooldown}s dry_run={dry_run}")

    while True:
        panes = tmux_list_panes(session)
        if not panes:
            time.sleep(poll_interval)
            continue

        now = time.monotonic()

        for pane in panes:
            state = pane_states.setdefault(pane, PaneState())

            # Cooldown check
            if now - state.last_action_time < cooldown:
                continue

            content = tmux_capture(pane)
            if not content:
                continue

            content_hash = hash(content)
            if content_hash == state.last_content_hash:
                continue
            state.last_content_hash = content_hash

            # Check for collapsed transcript first
            if detect_collapsed(content):
                tmux_send_keys(pane, "C-o", dry_run)
                state.last_action_time = now
                audit_log("daemon", "expanded", "collapsed", f"pane={pane}", cfg)
                continue

            # Check for prompts
            result = detect_prompt(content)
            if result is None:
                continue

            prompt_type, num_options = result

            if prompt_type == "continue":
                tmux_send_keys(pane, "Enter", dry_run)
                state.last_action_time = now
                audit_log("daemon", "approved", "continue", f"pane={pane}", cfg)
            elif prompt_type == "trust":
                tmux_send_keys(pane, "Enter", dry_run)
                state.last_action_time = now
                audit_log("daemon", "approved", "trust", f"pane={pane}", cfg)
            elif prompt_type == "permission":
                if num_options >= 3:
                    # 3-option: 1. Yes / 2. Yes, allow for project / 3. No
                    # Cursor starts on 1. Down + Enter → option 2 (allow for project).
                    tmux_send_keys(pane, "Down", dry_run)
                    time.sleep(0.05)
                    tmux_send_keys(pane, "Enter", dry_run)
                    state.last_action_time = now
                    audit_log("daemon", "approved", "permission-opt2", f"pane={pane} opts={num_options}", cfg)
                else:
                    # 2-option: 1. Yes / 2. No (flagged commands)
                    # Cursor on 1. Enter → Yes.
                    tmux_send_keys(pane, "Enter", dry_run)
                    state.last_action_time = now
                    audit_log("daemon", "approved", "permission-opt1", f"pane={pane} opts={num_options}", cfg)

        time.sleep(poll_interval)


def start_daemon(session: str | None = None):
    """Start the tmux daemon."""
    cfg = load_config()
    session = session or cfg.get("daemon", {}).get("session", "claude")

    # Write PID file
    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")

    def cleanup(signum, frame):
        PID_FILE.unlink(missing_ok=True)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    try:
        daemon_loop(session, cfg)
    finally:
        PID_FILE.unlink(missing_ok=True)


def stop_daemon():
    """Stop the tmux daemon."""
    if not PID_FILE.exists():
        print("No daemon running (no PID file)", file=sys.stderr)
        raise SystemExit(1)

    pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Stopped daemon (PID {pid})")
    except ProcessLookupError:
        print(f"Daemon (PID {pid}) not running, cleaning up PID file")
    PID_FILE.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def show_status():
    """Show hook installation status and daemon status."""
    # Hook status
    if SETTINGS_PATH.exists():
        settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        hooks = settings.get("hooks", {})
        perm = hooks.get("PermissionRequest", [])
        installed = any(
            HOOK_MARKER in h.get("command", "")
            for entry in perm
            for h in entry.get("hooks", [])
        )
        print(f"Hook installed: {'yes' if installed else 'no'}")
        print(f"Settings: {SETTINGS_PATH}")
    else:
        print("Hook installed: no (no settings file)")

    # Daemon status
    if PID_FILE.exists():
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        try:
            os.kill(pid, 0)  # Check if process exists
            print(f"Daemon running: yes (PID {pid})")
        except (ProcessLookupError, PermissionError):
            print(f"Daemon running: no (stale PID file for {pid})")
    else:
        print("Daemon running: no")

    # Config
    cfg = load_config()
    deny = cfg.get("hooks", {}).get("deny", [])
    if deny:
        print(f"Deny list: {deny}")

    # Session scope
    scope_id = os.environ.get("AGENTNANNY_SCOPE")
    if scope_id:
        policy = load_session_policy(scope_id)
        if policy:
            groups = policy.get("allow_groups", [])
            tools = policy.get("allow_tools", [])
            ttl = policy.get("ttl_seconds", 0)
            created = policy.get("created", "?")
            print(f"Active scope: {scope_id} (created {created}, ttl={ttl}s)")
            if groups:
                print(f"  Groups: {', '.join(groups)}")
            if tools:
                print(f"  Tools: {', '.join(tools)}")
        else:
            print(f"Active scope: {scope_id} (expired or missing)")

    # All sessions
    policies = list_session_policies()
    if policies:
        print(f"Session policies: {len(policies)} active")


def show_log():
    """Tail the audit log."""
    cfg = load_config()
    log_path = cfg.get("logging", {}).get("audit_log", "/tmp/agentnanny.log")
    if not Path(log_path).exists():
        print(f"No log file at {log_path}")
        return
    with open(log_path, encoding="utf-8") as f:
        lines = f.readlines()
    # Show last 50 lines
    for line in lines[-50:]:
        print(line, end="")


# ---------------------------------------------------------------------------
# Session commands
# ---------------------------------------------------------------------------


def _parse_ttl(ttl_str: str) -> int:
    """Parse a TTL string like '8h', '30m', '3600' into seconds."""
    ttl_str = ttl_str.strip().lower()
    if ttl_str.endswith("h"):
        return int(ttl_str[:-1]) * 3600
    if ttl_str.endswith("m"):
        return int(ttl_str[:-1]) * 60
    if ttl_str.endswith("s"):
        return int(ttl_str[:-1])
    return int(ttl_str)


def cmd_activate(groups: str | None, tools: str | None, deny: str | None, ttl: str):
    """Create a session policy and print the env export command."""
    cfg = load_config()

    group_names = [g.strip() for g in groups.split(",")] if groups else []
    tool_names = [t.strip() for t in tools.split(",")] if tools else []
    deny_patterns = [d.strip() for d in deny.split(",")] if deny else []
    ttl_seconds = _parse_ttl(ttl)

    # Validate group names
    if group_names:
        resolve_groups(group_names, cfg)

    scope_id = generate_scope_id()
    policy = {
        "scope_id": scope_id,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ttl_seconds": ttl_seconds,
        "allow_groups": group_names,
        "allow_tools": tool_names,
        "deny": deny_patterns,
    }
    path = save_session_policy(policy)
    print(f"export AGENTNANNY_SCOPE={scope_id}")
    print(f"# Policy: {path}", file=sys.stderr)
    if group_names:
        print(f"# Groups: {', '.join(group_names)}", file=sys.stderr)
    if tool_names:
        print(f"# Tools: {', '.join(tool_names)}", file=sys.stderr)
    if deny_patterns:
        print(f"# Deny: {', '.join(deny_patterns)}", file=sys.stderr)
    if ttl_seconds:
        print(f"# TTL: {ttl_seconds}s", file=sys.stderr)


def cmd_deactivate(scope_id: str | None):
    """Remove a session policy."""
    scope_id = scope_id or os.environ.get("AGENTNANNY_SCOPE")
    if not scope_id:
        print("No scope ID provided and AGENTNANNY_SCOPE not set", file=sys.stderr)
        raise SystemExit(1)
    if delete_session_policy(scope_id):
        print(f"unset AGENTNANNY_SCOPE")
        print(f"# Removed session {scope_id}", file=sys.stderr)
    else:
        print(f"No session policy found for {scope_id}", file=sys.stderr)
        raise SystemExit(1)


def cmd_run(groups: str | None, tools: str | None, deny: str | None, ttl: str, command_args: list[str]):
    """Run a command with session-scoped permissions."""
    if not command_args:
        print("No command specified", file=sys.stderr)
        raise SystemExit(1)
    # Strip leading -- if present
    if command_args and command_args[0] == "--":
        command_args = command_args[1:]
    if not command_args:
        print("No command specified after --", file=sys.stderr)
        raise SystemExit(1)

    cfg = load_config()
    group_names = [g.strip() for g in groups.split(",")] if groups else []
    tool_names = [t.strip() for t in tools.split(",")] if tools else []
    deny_patterns = [d.strip() for d in deny.split(",")] if deny else []
    ttl_seconds = _parse_ttl(ttl)

    if group_names:
        resolve_groups(group_names, cfg)

    scope_id = generate_scope_id()
    policy = {
        "scope_id": scope_id,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ttl_seconds": ttl_seconds,
        "allow_groups": group_names,
        "allow_tools": tool_names,
        "deny": deny_patterns,
    }
    save_session_policy(policy)

    env = os.environ.copy()
    env["AGENTNANNY_SCOPE"] = scope_id

    try:
        result = subprocess.run(command_args, env=env)
        raise SystemExit(result.returncode)
    finally:
        delete_session_policy(scope_id)


def cmd_sessions():
    """List active session policies."""
    policies = list_session_policies()
    if not policies:
        print("No active sessions")
        return
    now = datetime.now(timezone.utc)
    for p in policies:
        scope_id = p["scope_id"]
        created = datetime.fromisoformat(p["created"])
        age = int((now - created).total_seconds())
        ttl = p.get("ttl_seconds", 0)
        groups = ", ".join(p.get("allow_groups", [])) or "-"
        tools = ", ".join(p.get("allow_tools", [])) or "-"
        ttl_str = f"{ttl - age}s remaining" if ttl else "no expiry"
        print(f"{scope_id}  age={age}s  {ttl_str}  groups=[{groups}]  tools=[{tools}]")


def cmd_prune():
    """Remove all expired session policy files."""
    if not SESSION_DIR.exists():
        print("No session directory")
        return
    removed = 0
    now = datetime.now(timezone.utc)
    for path in SESSION_DIR.glob("*.json"):
        try:
            policy = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            path.unlink(missing_ok=True)
            removed += 1
            continue
        ttl = policy.get("ttl_seconds", 0)
        if ttl > 0:
            created = datetime.fromisoformat(policy["created"])
            if (now - created).total_seconds() > ttl:
                path.unlink(missing_ok=True)
                removed += 1
    print(f"Pruned {removed} expired session(s)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        prog="agentnanny",
        description="Auto-approve Claude Code permission prompts via hooks + tmux daemon.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("hook", help="Hook handler (called by Claude Code, not user)")
    sub.add_parser("install", help="Register hooks in ~/.claude/settings.json")
    sub.add_parser("uninstall", help="Remove hooks from ~/.claude/settings.json")

    p_trust = sub.add_parser("trust", help="Pre-trust a directory")
    p_trust.add_argument("directory", nargs="?", default=".", help="Directory to trust (default: .)")

    p_watch = sub.add_parser("watch", help="Start tmux daemon (WSL only)")
    p_watch.add_argument("session", nargs="?", help="tmux session name")

    sub.add_parser("stop", help="Stop tmux daemon")
    sub.add_parser("status", help="Show hook + daemon status")
    sub.add_parser("log", help="Tail audit log")

    p_activate = sub.add_parser("activate", help="Create a session policy (prints export command)")
    p_activate.add_argument("--groups", "-g", default=None, help="Comma-separated group names")
    p_activate.add_argument("--tools", "-t", default=None, help="Comma-separated tool names")
    p_activate.add_argument("--deny", "-d", default=None, help="Comma-separated deny patterns")
    p_activate.add_argument("--ttl", default="0", help="TTL (e.g. 8h, 30m, 3600)")

    p_deactivate = sub.add_parser("deactivate", help="Remove a session policy")
    p_deactivate.add_argument("scope_id", nargs="?", default=None, help="Scope ID (default: from AGENTNANNY_SCOPE)")

    p_run = sub.add_parser("run", help="Run command with session-scoped permissions")
    p_run.add_argument("--groups", "-g", default=None, help="Comma-separated group names")
    p_run.add_argument("--tools", "-t", default=None, help="Comma-separated tool names")
    p_run.add_argument("--deny", "-d", default=None, help="Comma-separated deny patterns")
    p_run.add_argument("--ttl", default="0", help="TTL (e.g. 8h, 30m, 3600)")
    p_run.add_argument("command_args", nargs=argparse.REMAINDER, help="Command to run (after --)")

    sub.add_parser("sessions", help="List active session policies")
    sub.add_parser("prune", help="Remove expired session policies")

    args = parser.parse_args()

    if args.command == "hook":
        handle_hook()
    elif args.command == "install":
        install_hooks()
    elif args.command == "uninstall":
        uninstall_hooks()
    elif args.command == "trust":
        trust_directory(args.directory)
    elif args.command == "watch":
        start_daemon(args.session)
    elif args.command == "stop":
        stop_daemon()
    elif args.command == "status":
        show_status()
    elif args.command == "log":
        show_log()
    elif args.command == "activate":
        cmd_activate(args.groups, args.tools, args.deny, args.ttl)
    elif args.command == "deactivate":
        cmd_deactivate(args.scope_id)
    elif args.command == "run":
        cmd_run(args.groups, args.tools, args.deny, args.ttl, args.command_args)
    elif args.command == "sessions":
        cmd_sessions()
    elif args.command == "prune":
        cmd_prune()
    else:
        parser.print_help()
        raise SystemExit(1)


if __name__ == "__main__":
    main()
