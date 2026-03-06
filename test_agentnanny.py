"""Tests for agentnanny — hook handler, deny matching, install/uninstall, tmux detection."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

# Import the module under test
sys.path.insert(0, str(Path(__file__).parent))
import agentnanny


# ═══════════════════════════════════════════════════════════════════════════
# TOML parser
# ═══════════════════════════════════════════════════════════════════════════


class TestParseToml:
    def test_basic_table(self):
        text = '[hooks]\ndeny = ["Bash", "Write"]'
        result = agentnanny.parse_toml(text)
        assert result["hooks"]["deny"] == ["Bash", "Write"]

    def test_string_value(self):
        text = '[daemon]\nsession = "claude"'
        result = agentnanny.parse_toml(text)
        assert result["daemon"]["session"] == "claude"

    def test_bool_values(self):
        text = '[daemon]\ndry_run = false'
        result = agentnanny.parse_toml(text)
        assert result["daemon"]["dry_run"] is False

    def test_float_value(self):
        text = '[daemon]\npoll_interval = 0.3'
        result = agentnanny.parse_toml(text)
        assert result["daemon"]["poll_interval"] == 0.3

    def test_int_value(self):
        text = '[daemon]\nretries = 3'
        result = agentnanny.parse_toml(text)
        assert result["daemon"]["retries"] == 3

    def test_empty_array(self):
        text = '[hooks]\ndeny = []'
        result = agentnanny.parse_toml(text)
        assert result["hooks"]["deny"] == []

    def test_comments_ignored(self):
        text = '# comment\n[hooks]\n# another comment\ndeny = []'
        result = agentnanny.parse_toml(text)
        assert result["hooks"]["deny"] == []

    def test_multiple_tables(self):
        text = '[hooks]\ndeny = []\n[daemon]\nsession = "claude"\n[logging]\nlevel = "actions"'
        result = agentnanny.parse_toml(text)
        assert result["hooks"]["deny"] == []
        assert result["daemon"]["session"] == "claude"
        assert result["logging"]["level"] == "actions"


# ═══════════════════════════════════════════════════════════════════════════
# Deny-list matching
# ═══════════════════════════════════════════════════════════════════════════


class TestMatchesDeny:
    def test_exact_tool_name(self):
        assert agentnanny.matches_deny("Bash", {}, ["Bash"]) is True

    def test_exact_tool_name_no_match(self):
        assert agentnanny.matches_deny("Read", {}, ["Bash"]) is False

    def test_tool_with_input_pattern(self):
        assert agentnanny.matches_deny(
            "Bash", {"command": "rm -rf /"}, ["Bash(rm*)"]
        ) is True

    def test_tool_with_input_pattern_no_match(self):
        assert agentnanny.matches_deny(
            "Bash", {"command": "ls -la"}, ["Bash(rm*)"]
        ) is False

    def test_tool_input_exact_prefix(self):
        assert agentnanny.matches_deny(
            "Bash", {"command": "rm -rf /tmp"}, ["Bash(rm -rf*)"]
        ) is True

    def test_tool_input_no_match_different_tool(self):
        assert agentnanny.matches_deny(
            "Read", {"file_path": "/etc/passwd"}, ["Bash(rm*)"]
        ) is False

    def test_regex_pattern(self):
        assert agentnanny.matches_deny("WebFetch", {}, [".*Fetch.*"]) is True

    def test_regex_no_match(self):
        assert agentnanny.matches_deny("Read", {}, [".*Fetch.*"]) is False

    def test_empty_deny_list(self):
        assert agentnanny.matches_deny("Bash", {"command": "rm -rf /"}, []) is False

    def test_multiple_patterns(self):
        deny = ["Bash(rm*)", "Bash(dd*)", "WebFetch"]
        assert agentnanny.matches_deny("Bash", {"command": "rm /tmp/x"}, deny) is True
        assert agentnanny.matches_deny("Bash", {"command": "dd if=/dev/zero"}, deny) is True
        assert agentnanny.matches_deny("WebFetch", {"url": "http://x"}, deny) is True
        assert agentnanny.matches_deny("Bash", {"command": "ls"}, deny) is False

    def test_write_file_path_pattern(self):
        assert agentnanny.matches_deny(
            "Write", {"file_path": "/etc/passwd"}, ["Write(/etc/*)"]
        ) is True

    def test_webfetch_url_pattern(self):
        assert agentnanny.matches_deny(
            "WebFetch", {"url": "https://evil.com/payload"}, ["WebFetch(*evil.com*)"]
        ) is True


# ═══════════════════════════════════════════════════════════════════════════
# Primary input extraction
# ═══════════════════════════════════════════════════════════════════════════


class TestPrimaryInput:
    def test_bash(self):
        assert agentnanny._primary_input("Bash", {"command": "ls"}) == "ls"

    def test_write(self):
        assert agentnanny._primary_input("Write", {"file_path": "/tmp/x"}) == "/tmp/x"

    def test_edit(self):
        assert agentnanny._primary_input("Edit", {"file_path": "/tmp/x"}) == "/tmp/x"

    def test_read(self):
        assert agentnanny._primary_input("Read", {"file_path": "/tmp/x"}) == "/tmp/x"

    def test_webfetch(self):
        assert agentnanny._primary_input("WebFetch", {"url": "http://x"}) == "http://x"

    def test_unknown_tool(self):
        result = agentnanny._primary_input("Custom", {"a": "1", "b": "2"})
        assert "1" in result and "2" in result


# ═══════════════════════════════════════════════════════════════════════════
# Hook handler
# ═══════════════════════════════════════════════════════════════════════════


class TestHandleHook:
    def _run_hook(self, event: dict, deny: list[str] | None = None, allow: list[str] | None = None) -> dict:
        """Run handle_hook with mocked stdin/stdout/config."""
        cfg = {"hooks": {}, "logging": {"audit_log": os.devnull, "level": "all"}}
        if deny:
            cfg["hooks"]["deny"] = deny
        if allow:
            cfg["hooks"]["allow"] = allow

        stdin = StringIO(json.dumps(event))
        stdout = StringIO()

        with patch.object(sys, "stdin", stdin), \
             patch.object(sys, "stdout", stdout), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.handle_hook()

        return json.loads(stdout.getvalue())

    def test_allow_bash(self):
        result = self._run_hook({
            "hook_event_name": "PermissionRequest",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        })
        decision = result["hookSpecificOutput"]["decision"]
        assert decision["behavior"] == "allow"

    def test_allow_read(self):
        result = self._run_hook({
            "hook_event_name": "PermissionRequest",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/test.py"},
        })
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_deny_by_tool_name(self):
        result = self._run_hook(
            {"tool_name": "WebFetch", "tool_input": {"url": "http://x"}},
            deny=["WebFetch"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_deny_by_command_pattern(self):
        result = self._run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            deny=["Bash(rm*)"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_allow_when_not_denied(self):
        result = self._run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            deny=["Bash(rm*)"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_allow_list_permits(self):
        result = self._run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            allow=["Bash", "Read"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_allow_list_blocks(self):
        result = self._run_hook(
            {"tool_name": "WebFetch", "tool_input": {"url": "http://x"}},
            allow=["Bash", "Read"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_deny_takes_priority_over_allow(self):
        result = self._run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            deny=["Bash(rm*)"],
            allow=["Bash"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_output_structure(self):
        result = self._run_hook({
            "tool_name": "Bash",
            "tool_input": {"command": "echo hi"},
        })
        assert "hookSpecificOutput" in result
        assert "hookEventName" in result["hookSpecificOutput"]
        assert result["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
        assert "decision" in result["hookSpecificOutput"]
        assert "behavior" in result["hookSpecificOutput"]["decision"]

    def test_missing_tool_name(self):
        result = self._run_hook({"tool_input": {"command": "ls"}})
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_missing_tool_input(self):
        result = self._run_hook({"tool_name": "Bash"})
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"


# ═══════════════════════════════════════════════════════════════════════════
# ANSI stripping
# ═══════════════════════════════════════════════════════════════════════════


class TestStripAnsi:
    def test_no_ansi(self):
        assert agentnanny.strip_ansi("hello world") == "hello world"

    def test_color_codes(self):
        assert agentnanny.strip_ansi("\x1b[31mred\x1b[0m") == "red"

    def test_bold(self):
        assert agentnanny.strip_ansi("\x1b[1mbold\x1b[0m") == "bold"

    def test_cursor_movement(self):
        assert agentnanny.strip_ansi("\x1b[2Aup two\x1b[1Bdown one") == "up twodown one"

    def test_mixed_sequences(self):
        text = "\x1b[32m✓\x1b[0m \x1b[1mDone\x1b[0m"
        assert agentnanny.strip_ansi(text) == "✓ Done"

    def test_osc_sequences(self):
        text = "\x1b]0;title\x07content"
        assert agentnanny.strip_ansi(text) == "content"

    def test_empty_string(self):
        assert agentnanny.strip_ansi("") == ""

    def test_complex_real_world(self):
        text = "\x1b[38;5;208m● \x1b[0m\x1b[1mAllow \x1b[0m\x1b[2mBash\x1b[0m"
        result = agentnanny.strip_ansi(text)
        assert "Allow" in result
        assert "Bash" in result
        assert "\x1b" not in result


# ═══════════════════════════════════════════════════════════════════════════
# Prompt detection
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectPrompt:
    r"""Tests based on real Claude Code permission prompt screenshots.

    3-option (normal):
        Do you want to proceed?
        > 1. Yes
          2. Yes, allow reading from User\ from this project
          3. No
        Esc to cancel . Tab to amend . ctrl+e to explain

    3-option (fetch):
        Do you want to allow Claude to fetch this content?
        > 1. Yes
          2. Yes, and don't ask again for docs.anthropic.com
          3. No, and tell Claude what to do differently (esc)

    2-option (flagged command — shell operators, $(), quoted flags):
        Command contains a backslash before a shell operator (;, |, &, <, >)
        Do you want to proceed?
        > 1. Yes
          2. No
        Esc to cancel . Tab to amend . ctrl+e to explain
    """

    def _make_screen(self, above: str, below: str) -> str:
        sep = "─" * 40
        return f"{above}\n{sep}\n{below}"

    # ── 3-option prompts (normal) ──────────────────────────────────────

    def test_bash_3opt(self):
        screen = self._make_screen(
            "Bash command\n"
            "    cat ~/.claude.json\n"
            "    Check existing .claude.json",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, allow reading from User\\\\ from this project\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_fetch_3opt(self):
        screen = self._make_screen(
            "Fetch\n"
            "    https://docs.anthropic.com/en/docs/claude-code/hooks\n"
            "    Claude wants to fetch content from docs.anthropic.com",
            "Do you want to allow Claude to fetch this content?\n"
            "❯ 1. Yes\n"
            "  2. Yes, and don't ask again for docs.anthropic.com\n"
            "  3. No, and tell Claude what to do differently (esc)",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_write_3opt(self):
        screen = self._make_screen(
            "Write\n    /tmp/test.py\n    Create test file",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, allow writing to this project\n"
            "  3. No",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_3opt_partial_render(self):
        """Numbered options + footer but question scrolled off."""
        screen = self._make_screen(
            "Some output",
            "❯ 1. Yes\n"
            "  2. Yes, allow for this project\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_3opt_cursor_on_opt2(self):
        """Cursor moved to option 2 before daemon acts."""
        screen = self._make_screen(
            "Bash command\n    ls -la",
            "Do you want to proceed?\n"
            "  1. Yes\n"
            "❯ 2. Yes, allow reading from this project\n"
            "  3. No",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    # ── 2-option prompts (flagged commands) ────────────────────────────

    def test_bash_2opt_backslash_shell_operator(self):
        """From screenshot: backslash before shell operator warning."""
        screen = self._make_screen(
            "Bash command\n"
            "    find /home -name \"checkpoint.json\" -exec sh -c 'echo \"---\"' \\;\n"
            "    Summarize all checkpoint statuses\n"
            "\n"
            "Command contains a backslash before a shell operator (;, |, &, <, >) "
            "which can hide command structure",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_command_substitution(self):
        """From screenshot: $() command substitution warning."""
        screen = self._make_screen(
            "Bash command\n"
            "    for repo in /home/user/repos/*/; do bytes=$(git -C \"$repo\" diff | wc -c); done\n"
            "    Check which repos have diffs and sizes\n"
            "\n"
            "Command contains $() command substitution",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_quoted_flags(self):
        """From screenshot: quoted characters in flag names warning."""
        screen = self._make_screen(
            "Bash command\n"
            "    ls -la /home/user/results/; echo \"---\"; for repo in /repos/*/; do done\n"
            "    Check run dir contents and repo diffs\n"
            "\n"
            "Command contains quoted characters in flag names",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_no_warning(self):
        """2-option prompt without a warning line (plain dangerous command)."""
        screen = self._make_screen(
            "Bash command\n"
            "    cat /home/user/results/checkpoint.json | jq '.key'\n"
            "    Check checkpoint and patches for featurebench run",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    # ── 2-option prompts (more warning variants from screenshots) ─────

    def test_bash_2opt_variables_dangerous_contexts(self):
        """From screenshot: variables in dangerous contexts (redirections or pipes)."""
        screen = self._make_screen(
            "Bash command\n"
            "    for info in with_feature/20260303_131030:starter_tasks ...; do\n"
            "    python3 -c \"import json; ...\" 2>/dev/null\n"
            "    Check earlier complete runs",
            "Command contains variables in dangerous contexts (redirections or pipes)\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_newlines_separate_commands(self):
        """From screenshot: newlines that could separate multiple commands."""
        screen = self._make_screen(
            "Bash command\n"
            "    # Check the 213* set (most recent 6 invocations)\n"
            "    for d in 20260303_213418 20260303_213419 ...; do\n"
            "      found=\"\"\n"
            "      for arm in wo_feature with_feature; do\n"
            "        p=\"/home/user/projects/example/results/$arm/$d\"\n"
            "      done\n"
            "    done\n"
            "    Check latest 6 invocations (213* set)",
            "Command contains newlines that could separate multiple commands\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_ambiguous_command_separators(self):
        """From screenshot: ambiguous syntax with command separators."""
        screen = self._make_screen(
            "Bash command\n"
            "    for d in /home/user/projects/example/results/*/2026*/; do "
            "if [ -f \"$d/config.json\" ]; then echo \"=== $d ===\"; "
            "cat \"$d/config.json\" 2>/dev/null; echo; fi; done\n"
            "    Show config.json for all runs",
            "Command contains ambiguous syntax with command separators "
            "that could be misinterpreted\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_cd_git_compound(self):
        """From screenshot: compound commands with cd and git."""
        screen = self._make_screen(
            "Bash command\n"
            "    cd /home/user/projects/example/results/with_feature/20260303_214027"
            "/repos/pydata__xarray && git diff 2>/dev/null\n"
            "    Get pydata__xarray patch (correct dir)",
            "Compound commands with cd and git require approval "
            "to prevent bare repository attacks\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    # ── 3-option prompt variant (tool prefix pattern) ─────────────────

    def test_bash_3opt_dont_ask_again_tool_prefix(self):
        """From screenshot: 'don't ask again for: python3:*' option."""
        screen = self._make_screen(
            "Bash command\n"
            "    echo \"=== with_feature benchmark (214009) ===\" && python3 -c \"\n"
            "    import json\n"
            "    cp = json.load(open('results/with_feature/20260303_214009/checkpoint.json'))\n"
            "    for k,v in cp.items(): print(f'{k}: {v.get(\"status\",\"?\")}')\"\n"
            "    Check checkpoint status for main 10-task runs",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, and don't ask again for: python3:*\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    # ── 2-option prompt variant (Zsh glob qualifier warning) ──────────

    def test_bash_2opt_zsh_glob_qualifier(self):
        """From screenshot: Zsh glob qualifier with command execution."""
        screen = self._make_screen(
            "Bash command\n"
            "    .venv/Scripts/python.exe benchmark.py\n"
            "    Benchmark 10 then 100 images with per-phase timing",
            "Command contains Zsh glob qualifier with command execution\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    # ── 3-option prompt variant (generic approval + don't ask again) ──

    def test_bash_3opt_this_command_requires_approval(self):
        """From screenshot: taskkill with 'This command requires approval'."""
        screen = self._make_screen(
            "Bash command\n"
            "\n"
            "    taskkill //PID 19152 //F\n"
            "    Kill the embedding process",
            "This command requires approval\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, and don't ask again for: taskkill:*\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_bash_3opt_dont_ask_again_windows_venv(self):
        """From screenshot: Windows .venv python with backslash-containing path."""
        screen = self._make_screen(
            "Bash command\n"
            "\n"
            "    cd /d/ppt/OracleAI && .venv/Scripts/python.exe -c "
            "\"from qdrant_client import QdrantClient; print('qdrant_client OK')\"\n"
            "    Verify qdrant_client is available in venv",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, and don\u2019t ask again for: .venv/Scripts/python.exe:*\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_bash_3opt_dont_ask_again_wmic(self):
        """From screenshot: wmic process with 'don't ask again for: wmic process:*'."""
        screen = self._make_screen(
            "Bash command\n"
            "\n"
            "    wmic process where \"ProcessId=27340 or ProcessId=19152\" "
            "get ProcessId,CommandLine /format:list 2>/dev/null | head -20\n"
            "    Identify which python process is the embedder",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, and don\u2019t ask again for: wmic process:*\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    # ── Other prompt types ─────────────────────────────────────────────

    def test_trust_folder(self):
        screen = self._make_screen(
            "Starting Claude Code...",
            "Do you trust this directory?\n  /home/user/project",
        )
        assert agentnanny.detect_prompt(screen) == ("trust", 0)

    def test_continue_prompt(self):
        screen = self._make_screen(
            "Long output...",
            "Continue? Press Enter to continue",
        )
        assert agentnanny.detect_prompt(screen) == ("continue", 0)

    # ── Negative cases ─────────────────────────────────────────────────

    def test_no_prompt_normal_output(self):
        screen = self._make_screen(
            "Code output",
            "function hello() {\n  console.log('hi')\n}",
        )
        assert agentnanny.detect_prompt(screen) is None

    def test_no_prompt_empty_below(self):
        screen = self._make_screen("Code output", "")
        assert agentnanny.detect_prompt(screen) is None

    def test_slash_picker_vetoed(self):
        screen = self._make_screen(
            "Command palette",
            "/commit  Create a git commit\n/help  Show help\n/clear  Clear screen",
        )
        assert agentnanny.detect_prompt(screen) is None

    def test_no_separator_fallback(self):
        lines = ["normal output"] * 20 + [
            "Do you want to proceed?",
            "❯ 1. Yes",
            "  2. Yes, allow for this project",
            "  3. No",
        ]
        screen = "\n".join(lines)
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_no_separator_no_prompt(self):
        lines = ["normal output"] * 20
        screen = "\n".join(lines)
        assert agentnanny.detect_prompt(screen) is None

    def test_plain_text_with_yes_no_not_prompt(self):
        """Numbered list in normal output that isn't a permission prompt."""
        screen = self._make_screen(
            "Instructions",
            "Steps:\n1. Yes, install the package\n2. No need for config",
        )
        assert agentnanny.detect_prompt(screen) is None

    def test_allow_cookies_not_prompt(self):
        screen = self._make_screen(
            "Config",
            "allow_cookies = true\nsome other config",
        )
        assert agentnanny.detect_prompt(screen) is None


# ═══════════════════════════════════════════════════════════════════════════
# Collapsed transcript detection
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectCollapsed:
    def test_ctrl_o_indicator(self):
        assert agentnanny.detect_collapsed("Press Ctrl+O to expand transcript") is True

    def test_collapsed_text(self):
        assert agentnanny.detect_collapsed("▶ collapsed transcript (15 items)") is True

    def test_no_collapsed(self):
        assert agentnanny.detect_collapsed("normal code output here") is False

    def test_empty(self):
        assert agentnanny.detect_collapsed("") is False


# ═══════════════════════════════════════════════════════════════════════════
# Install / Uninstall
# ═══════════════════════════════════════════════════════════════════════════


class TestInstallUninstall:
    def test_install_creates_hook(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        perm = settings["hooks"]["PermissionRequest"]
        assert len(perm) == 1
        assert "agentnanny" in perm[0]["hooks"][0]["command"]

    def test_install_preserves_existing_settings(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text(json.dumps({
            "permissions": {"allow": ["Bash"]},
            "other_setting": True,
        }), encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        assert settings["permissions"]["allow"] == ["Bash"]
        assert settings["other_setting"] is True
        assert "hooks" in settings

    def test_install_idempotent(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()
            with pytest.raises(SystemExit):
                agentnanny.install_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        perm = settings["hooks"]["PermissionRequest"]
        assert len(perm) == 1  # Not duplicated

    def test_install_creates_settings_file(self, tmp_path):
        settings_file = tmp_path / ".claude" / "settings.json"

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()

        assert settings_file.exists()
        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        assert "hooks" in settings

    def test_uninstall_removes_hook(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()
            agentnanny.uninstall_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        # hooks key should be cleaned up
        assert "hooks" not in settings or not settings.get("hooks")

    def test_uninstall_preserves_other_hooks(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text(json.dumps({
            "hooks": {
                "PermissionRequest": [
                    {
                        "matcher": "",
                        "hooks": [{"type": "command", "command": "other-tool hook"}],
                    },
                ],
            },
        }), encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()
            agentnanny.uninstall_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        perm = settings["hooks"]["PermissionRequest"]
        assert len(perm) == 1
        assert "other-tool" in perm[0]["hooks"][0]["command"]

    def test_uninstall_no_hooks_exits(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            with pytest.raises(SystemExit):
                agentnanny.uninstall_hooks()

    def test_uninstall_no_settings_file(self, tmp_path):
        settings_file = tmp_path / "settings.json"

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            with pytest.raises(SystemExit):
                agentnanny.uninstall_hooks()


# ═══════════════════════════════════════════════════════════════════════════
# Trust directory
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustDirectory:
    def test_trust_new_directory(self, tmp_path):
        claude_json = tmp_path / ".claude.json"

        with patch.object(agentnanny, "CLAUDE_JSON_PATH", claude_json):
            agentnanny.trust_directory(str(tmp_path / "myproject"))

        settings = json.loads(claude_json.read_text(encoding="utf-8"))
        proj_key = str((tmp_path / "myproject").resolve())
        assert settings["projects"][proj_key]["hasTrustDialogAccepted"] is True

    def test_trust_preserves_existing(self, tmp_path):
        claude_json = tmp_path / ".claude.json"
        claude_json.write_text(json.dumps({
            "numStartups": 5,
            "projects": {
                "/existing": {"hasTrustDialogAccepted": True},
            },
        }), encoding="utf-8")

        with patch.object(agentnanny, "CLAUDE_JSON_PATH", claude_json):
            agentnanny.trust_directory(str(tmp_path / "newproject"))

        settings = json.loads(claude_json.read_text(encoding="utf-8"))
        assert settings["numStartups"] == 5
        assert settings["projects"]["/existing"]["hasTrustDialogAccepted"] is True

    def test_trust_creates_file(self, tmp_path):
        claude_json = tmp_path / ".claude.json"

        with patch.object(agentnanny, "CLAUDE_JSON_PATH", claude_json):
            agentnanny.trust_directory(str(tmp_path))

        assert claude_json.exists()


# ═══════════════════════════════════════════════════════════════════════════
# Audit log
# ═══════════════════════════════════════════════════════════════════════════


class TestAuditLog:
    def test_log_write(self, tmp_path):
        log_file = tmp_path / "test.log"
        cfg = {"logging": {"audit_log": str(log_file), "level": "all"}}

        agentnanny.audit_log("hook", "allowed", "Bash", "command=ls", cfg)

        content = log_file.read_text(encoding="utf-8")
        assert "hook" in content
        assert "allowed" in content
        assert "Bash" in content
        assert "command=ls" in content

    def test_log_level_actions(self, tmp_path):
        log_file = tmp_path / "test.log"
        cfg = {"logging": {"audit_log": str(log_file), "level": "actions"}}

        agentnanny.audit_log("hook", "allowed", "Bash", "ls", cfg)
        agentnanny.audit_log("hook", "checked", "Bash", "ls", cfg)  # Not an action

        content = log_file.read_text(encoding="utf-8")
        assert "allowed" in content
        assert "checked" not in content

    def test_log_tsv_format(self, tmp_path):
        log_file = tmp_path / "test.log"
        cfg = {"logging": {"audit_log": str(log_file), "level": "all"}}

        agentnanny.audit_log("hook", "allowed", "Bash", "ls", cfg)

        line = log_file.read_text(encoding="utf-8").strip()
        parts = line.split("\t")
        assert len(parts) == 5  # timestamp, source, action, tool, detail


# ═══════════════════════════════════════════════════════════════════════════
# Config loading
# ═══════════════════════════════════════════════════════════════════════════


class TestLoadConfig:
    def test_load_from_file(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('[hooks]\ndeny = ["Bash(rm*)"]\n[daemon]\nsession = "test"', encoding="utf-8")

        with patch.object(agentnanny, "CONFIG_PATH", config_file):
            cfg = agentnanny.load_config()

        assert cfg["hooks"]["deny"] == ["Bash(rm*)"]
        assert cfg["daemon"]["session"] == "test"

    def test_env_override_session(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('[daemon]\nsession = "default"', encoding="utf-8")

        with patch.object(agentnanny, "CONFIG_PATH", config_file), \
             patch.dict(os.environ, {"AGENTNANNY_SESSION": "override"}):
            cfg = agentnanny.load_config()

        assert cfg["daemon"]["session"] == "override"

    def test_env_override_deny(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text("[hooks]\ndeny = []", encoding="utf-8")

        with patch.object(agentnanny, "CONFIG_PATH", config_file), \
             patch.dict(os.environ, {"AGENTNANNY_DENY": "Bash(rm*),WebFetch"}):
            cfg = agentnanny.load_config()

        assert cfg["hooks"]["deny"] == ["Bash(rm*)", "WebFetch"]

    def test_missing_config_file(self, tmp_path):
        config_file = tmp_path / "nonexistent.toml"

        with patch.object(agentnanny, "CONFIG_PATH", config_file):
            cfg = agentnanny.load_config()

        assert isinstance(cfg, dict)
        assert "hooks" in cfg


# ═══════════════════════════════════════════════════════════════════════════
# CLI argument parsing
# ═══════════════════════════════════════════════════════════════════════════


class TestCLI:
    def test_no_command_exits(self):
        with patch("sys.argv", ["agentnanny"]):
            with pytest.raises(SystemExit):
                agentnanny.main()

    def test_hook_command(self):
        event = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        stdin = StringIO(json.dumps(event))
        stdout = StringIO()
        cfg = {"hooks": {}, "logging": {"audit_log": os.devnull, "level": "all"}}

        with patch("sys.argv", ["agentnanny", "hook"]), \
             patch.object(sys, "stdin", stdin), \
             patch.object(sys, "stdout", stdout), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.main()

        result = json.loads(stdout.getvalue())
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_status_command(self, tmp_path, capsys):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")
        pid_file = tmp_path / "agentnanny.pid"

        with patch("sys.argv", ["agentnanny", "status"]), \
             patch.object(agentnanny, "SETTINGS_PATH", settings_file), \
             patch.object(agentnanny, "PID_FILE", pid_file), \
             patch.object(agentnanny, "SESSION_DIR", tmp_path / "sessions"), \
             patch.object(agentnanny, "load_config", return_value={"hooks": {}}), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENTNANNY_SCOPE", None)
            agentnanny.main()

        output = capsys.readouterr().out
        assert "Hook installed: no" in output
        assert "Daemon running: no" in output


# ═══════════════════════════════════════════════════════════════════════════
# Session policies
# ═══════════════════════════════════════════════════════════════════════════


class TestSessionPolicy:
    def test_save_and_load_roundtrip(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            policy = {
                "scope_id": "abc12345",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": ["filesystem"],
                "allow_tools": ["Bash"],
                "deny": [],
            }
            agentnanny.save_session_policy(policy)
            loaded = agentnanny.load_session_policy("abc12345")
            assert loaded is not None
            assert loaded["scope_id"] == "abc12345"
            assert loaded["allow_groups"] == ["filesystem"]

    def test_load_nonexistent(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            assert agentnanny.load_session_policy("nonexistent") is None

    def test_expired_policy_returns_none(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            created = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(timespec="seconds")
            policy = {
                "scope_id": "expired1",
                "created": created,
                "ttl_seconds": 1,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            }
            agentnanny.save_session_policy(policy)
            assert agentnanny.load_session_policy("expired1") is None
            # File should be deleted
            assert not (tmp_path / "expired1.json").exists()

    def test_no_ttl_never_expires(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            created = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(timespec="seconds")
            policy = {
                "scope_id": "forever1",
                "created": created,
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            }
            agentnanny.save_session_policy(policy)
            assert agentnanny.load_session_policy("forever1") is not None

    def test_delete_policy(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            policy = {
                "scope_id": "del12345",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            }
            agentnanny.save_session_policy(policy)
            assert agentnanny.delete_session_policy("del12345") is True
            assert agentnanny.delete_session_policy("del12345") is False

    def test_list_policies(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            for i in range(3):
                agentnanny.save_session_policy({
                    "scope_id": f"list{i:04d}",
                    "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "ttl_seconds": 0,
                    "allow_groups": [],
                    "allow_tools": [],
                    "deny": [],
                })
            policies = agentnanny.list_session_policies()
            assert len(policies) == 3

    def test_generate_scope_id(self):
        sid = agentnanny.generate_scope_id()
        assert len(sid) == 8
        int(sid, 16)  # Must be valid hex


# ═══════════════════════════════════════════════════════════════════════════
# Group resolution
# ═══════════════════════════════════════════════════════════════════════════


class TestResolveGroups:
    CFG = {
        "groups": {
            "filesystem": ["Read", "Write", "Edit", "Glob", "Grep"],
            "shell": ["Bash"],
            "network": ["WebFetch", "WebSearch"],
            "all": [".*"],
        }
    }

    def test_single_group(self):
        result = agentnanny.resolve_groups(["shell"], self.CFG)
        assert result == ["Bash"]

    def test_multiple_groups(self):
        result = agentnanny.resolve_groups(["filesystem", "shell"], self.CFG)
        assert "Read" in result
        assert "Write" in result
        assert "Bash" in result

    def test_unknown_group_raises(self):
        with pytest.raises(ValueError, match="Unknown group"):
            agentnanny.resolve_groups(["nonexistent"], self.CFG)

    def test_empty_groups(self):
        result = agentnanny.resolve_groups([], self.CFG)
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════
# Allow matching
# ═══════════════════════════════════════════════════════════════════════════


class TestMatchesAllow:
    def test_exact_tool_name(self):
        assert agentnanny.matches_allow("Bash", {}, ["Bash"]) is True

    def test_exact_tool_name_no_match(self):
        assert agentnanny.matches_allow("WebFetch", {}, ["Bash"]) is False

    def test_tool_with_input_pattern(self):
        assert agentnanny.matches_allow(
            "Bash", {"command": "ls -la"}, ["Bash(ls*)"]
        ) is True

    def test_tool_with_input_pattern_no_match(self):
        assert agentnanny.matches_allow(
            "Bash", {"command": "rm -rf /"}, ["Bash(ls*)"]
        ) is False

    def test_regex_pattern(self):
        assert agentnanny.matches_allow("WebFetch", {}, [".*Fetch.*"]) is True

    def test_wildcard_all(self):
        assert agentnanny.matches_allow("AnyTool", {}, [".*"]) is True

    def test_no_match(self):
        assert agentnanny.matches_allow("Bash", {}, ["Read", "Write"]) is False


# ═══════════════════════════════════════════════════════════════════════════
# Hook handler — session-scoped mode
# ═══════════════════════════════════════════════════════════════════════════


class TestHandleHookScoped:
    GROUPS_CFG = {
        "groups": {
            "filesystem": ["Read", "Write", "Edit", "Glob", "Grep"],
            "shell": ["Bash"],
        }
    }

    def _run_hook_scoped(self, event: dict, scope_id: str | None = None,
                         policy: dict | None = None, cfg_extra: dict | None = None,
                         global_deny: list[str] | None = None) -> str:
        """Run handle_hook with optional session scope. Returns raw stdout."""
        cfg = {"hooks": {}, "logging": {"audit_log": os.devnull, "level": "all"}}
        cfg.update(self.GROUPS_CFG)
        if global_deny:
            cfg["hooks"]["deny"] = global_deny
        if cfg_extra:
            cfg.update(cfg_extra)

        stdin = StringIO(json.dumps(event))
        stdout = StringIO()

        env_patch = {}
        if scope_id:
            env_patch["AGENTNANNY_SCOPE"] = scope_id

        with patch.object(sys, "stdin", stdin), \
             patch.object(sys, "stdout", stdout), \
             patch.object(agentnanny, "load_config", return_value=cfg), \
             patch.dict(os.environ, env_patch, clear=False):
            if not scope_id:
                os.environ.pop("AGENTNANNY_SCOPE", None)
            if policy:
                with patch.object(agentnanny, "load_session_policy", return_value=policy):
                    agentnanny.handle_hook()
            else:
                agentnanny.handle_hook()

        return stdout.getvalue()

    def test_no_scope_legacy_allows(self):
        """Without AGENTNANNY_SCOPE, hook uses legacy allow-all behavior."""
        raw = self._run_hook_scoped({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        })
        result = json.loads(raw)
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_scope_valid_policy_allows(self):
        """Tool in session allow groups gets allowed."""
        policy = {
            "scope_id": "test1234",
            "allow_groups": ["filesystem"],
            "allow_tools": [],
            "deny": [],
        }
        raw = self._run_hook_scoped(
            {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x"}},
            scope_id="test1234",
            policy=policy,
        )
        result = json.loads(raw)
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_scope_tool_not_in_allow_passthrough(self):
        """Tool not in session allow list → passthrough (empty output)."""
        policy = {
            "scope_id": "test1234",
            "allow_groups": ["filesystem"],
            "allow_tools": [],
            "deny": [],
        }
        raw = self._run_hook_scoped(
            {"tool_name": "WebFetch", "tool_input": {"url": "http://x"}},
            scope_id="test1234",
            policy=policy,
        )
        assert raw == ""

    def test_scope_explicit_tool_allows(self):
        """Explicit tool name in allow_tools gets allowed."""
        policy = {
            "scope_id": "test1234",
            "allow_groups": [],
            "allow_tools": ["WebFetch"],
            "deny": [],
        }
        raw = self._run_hook_scoped(
            {"tool_name": "WebFetch", "tool_input": {"url": "http://x"}},
            scope_id="test1234",
            policy=policy,
        )
        result = json.loads(raw)
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_scope_global_deny_still_applies(self):
        """Global deny list blocks even with valid session scope."""
        policy = {
            "scope_id": "test1234",
            "allow_groups": ["shell"],
            "allow_tools": [],
            "deny": [],
        }
        raw = self._run_hook_scoped(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            scope_id="test1234",
            policy=policy,
            global_deny=["Bash(rm*)"],
        )
        result = json.loads(raw)
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_scope_session_deny_applies(self):
        """Session-level deny blocks the tool."""
        policy = {
            "scope_id": "test1234",
            "allow_groups": ["shell"],
            "allow_tools": [],
            "deny": ["Bash(rm*)"],
        }
        raw = self._run_hook_scoped(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            scope_id="test1234",
            policy=policy,
        )
        result = json.loads(raw)
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_scope_missing_policy_passthrough(self):
        """Missing policy file → passthrough."""
        raw = self._run_hook_scoped(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            scope_id="nonexistent",
            policy=None,
        )
        assert raw == ""

    def test_scope_expired_policy_passthrough(self, tmp_path):
        """Expired policy → passthrough."""
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            created = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(timespec="seconds")
            agentnanny.save_session_policy({
                "scope_id": "expired1",
                "created": created,
                "ttl_seconds": 1,
                "allow_groups": ["shell"],
                "allow_tools": [],
                "deny": [],
            })
            raw = self._run_hook_scoped(
                {"tool_name": "Bash", "tool_input": {"command": "ls"}},
                scope_id="expired1",
            )
            assert raw == ""


# ═══════════════════════════════════════════════════════════════════════════
# Activate / Deactivate commands
# ═══════════════════════════════════════════════════════════════════════════


class TestActivateDeactivate:
    def test_activate_creates_policy(self, tmp_path, capsys):
        cfg = {
            "hooks": {},
            "groups": {"filesystem": ["Read", "Write", "Edit", "Glob", "Grep"]},
            "logging": {"audit_log": os.devnull},
        }
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.cmd_activate("filesystem", None, None, "0")

        out = capsys.readouterr().out
        assert out.startswith("export AGENTNANNY_SCOPE=")
        scope_id = out.strip().split("=")[1]
        assert (tmp_path / f"{scope_id}.json").exists()

    def test_activate_with_ttl(self, tmp_path, capsys):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.cmd_activate(None, "Bash", None, "8h")

        out = capsys.readouterr().out
        scope_id = out.strip().split("=")[1]
        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert policy["ttl_seconds"] == 28800

    def test_activate_unknown_group_raises(self, tmp_path):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            with pytest.raises(ValueError, match="Unknown group"):
                agentnanny.cmd_activate("nonexistent", None, None, "0")

    def test_deactivate_removes_policy(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            agentnanny.save_session_policy({
                "scope_id": "deact123",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            })
            agentnanny.cmd_deactivate("deact123")

        assert not (tmp_path / "deact123.json").exists()
        out = capsys.readouterr().out
        assert "unset AGENTNANNY_SCOPE" in out

    def test_deactivate_from_env(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.dict(os.environ, {"AGENTNANNY_SCOPE": "fromenv1"}):
            agentnanny.save_session_policy({
                "scope_id": "fromenv1",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            })
            agentnanny.cmd_deactivate(None)

        assert not (tmp_path / "fromenv1.json").exists()

    def test_deactivate_nonexistent_exits(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            with pytest.raises(SystemExit):
                agentnanny.cmd_deactivate("nonexist")

    def test_deactivate_no_scope_exits(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENTNANNY_SCOPE", None)
            with pytest.raises(SystemExit):
                agentnanny.cmd_deactivate(None)


# ═══════════════════════════════════════════════════════════════════════════
# Run wrapper
# ═══════════════════════════════════════════════════════════════════════════


class TestRunWrapper:
    def test_run_sets_env_and_cleans_up(self, tmp_path):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        captured_env = {}

        def mock_run(args, env=None):
            captured_env.update(env or {})
            return subprocess.CompletedProcess(args, 0)

        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg), \
             patch("subprocess.run", mock_run), \
             pytest.raises(SystemExit) as exc_info:
            agentnanny.cmd_run(None, "Bash", None, "0", ["--", "echo", "hello"])

        assert exc_info.value.code == 0
        assert "AGENTNANNY_SCOPE" in captured_env
        scope_id = captured_env["AGENTNANNY_SCOPE"]
        # Policy should be cleaned up
        assert not (tmp_path / f"{scope_id}.json").exists()

    def test_run_no_command_exits(self):
        with pytest.raises(SystemExit):
            agentnanny.cmd_run(None, None, None, "0", [])

    def test_run_no_command_after_separator_exits(self):
        with pytest.raises(SystemExit):
            agentnanny.cmd_run(None, None, None, "0", ["--"])


# ═══════════════════════════════════════════════════════════════════════════
# Sessions listing
# ═══════════════════════════════════════════════════════════════════════════


class TestSessions:
    def test_list_empty(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            agentnanny.cmd_sessions()
        assert "No active sessions" in capsys.readouterr().out

    def test_list_shows_policies(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            agentnanny.save_session_policy({
                "scope_id": "sess1234",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": ["shell"],
                "allow_tools": [],
                "deny": [],
            })
            agentnanny.cmd_sessions()
        out = capsys.readouterr().out
        assert "sess1234" in out
        assert "shell" in out


# ═══════════════════════════════════════════════════════════════════════════
# TTL parsing
# ═══════════════════════════════════════════════════════════════════════════


class TestParseTtl:
    def test_hours(self):
        assert agentnanny._parse_ttl("8h") == 28800

    def test_minutes(self):
        assert agentnanny._parse_ttl("30m") == 1800

    def test_seconds_suffix(self):
        assert agentnanny._parse_ttl("60s") == 60

    def test_bare_number(self):
        assert agentnanny._parse_ttl("3600") == 3600

    def test_zero(self):
        assert agentnanny._parse_ttl("0") == 0
