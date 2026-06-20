#!/usr/bin/env python3
"""
explain-tool: a Claude Code hook that explains, in plain English, what a tool
call is about to do and what access it needs, shown right at the permission
prompt.

It reads the hook JSON on stdin and prints a single JSON object with a
`systemMessage` to stdout. It never returns a permission decision, so your
normal allow / deny prompt is left exactly as it was. On any error it stays
silent (exit 0, no output) so it can never block your workflow.

Wire it up on the PreToolUse event (fires on every tool call). Note: a
PermissionRequest hook's systemMessage is NOT rendered in the permission
dialog, so PreToolUse is the event that actually surfaces the explanation.
See README for settings.
"""

import json
import os
import re
import sys

# --- risk levels -----------------------------------------------------------
LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"

# Matches both POSIX (/) and Windows (\) path separators via [\\/].
SENSITIVE_PATH = re.compile(
    r"""(\.env(\.|$)|id_rsa|id_ed25519|[\\/]\.ssh[\\/]|[\\/]\.aws[\\/]|
         credentials|secret|\.pem$|\.key$|\.pfx$|\.p12$|\.npmrc|\.pgpass|
         \.git[\\/]config|[\\/]etc[\\/]|[\\/]\.kube[\\/]|
         [\\/]\.docker[\\/]config)""",
    re.IGNORECASE | re.VERBOSE,
)


def basename(path):
    # Handle both / and \ regardless of the OS the hook runs on.
    cleaned = path.rstrip("/\\")
    name = re.split(r"[\\/]", cleaned)[-1] if cleaned else ""
    return name or path


# --- bash analysis ---------------------------------------------------------
def analyze_bash(cmd):
    c = " ".join(cmd.split())  # collapse whitespace
    low = c.lower()

    # ---- HIGH risk patterns ----
    if re.search(r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\b.*\s-f|-rf|-fr)\b", low) \
            or re.search(r"\brm\s+-r\b", low):
        m = re.search(r"\brm\s+-\S+\s+(.+)", c)
        target = m.group(1).strip() if m else "the target path"
        return (f"Permanently deletes {target} and everything inside it. "
                f"This cannot be undone.",
                "shell / terminal access", HIGH, "recursive force delete")

    if re.search(r"(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", low):
        return ("Downloads a script from the internet and runs it immediately, "
                "with no chance to inspect it first.",
                "shell access + outbound network", HIGH,
                "piping a remote download straight into a shell")

    if re.search(r"\bsudo\b", low):
        return ("Runs a command with administrator (root) privileges.",
                "elevated / root shell access", HIGH,
                "runs as administrator")

    if re.search(r"\bgit\s+push\b.*(--force|-f\b|\+)", low):
        return ("Force-pushes to a git remote, overwriting whatever history is "
                "there. Teammates' commits can be lost.",
                "shell access + your git remote", HIGH,
                "force push rewrites remote history")

    if re.search(r"\b(dd|mkfs|fdisk|shred|truncate)\b", low) \
            or re.search(r">\s*/dev/sd", low):
        return ("Writes directly to a disk or device. Mistakes here can destroy "
                "data irreversibly.",
                "shell access + raw disk", HIGH, "low-level disk operation")

    if re.search(r"\bchmod\s+(-r\s+)?0?777\b", low):
        return ("Makes a file or folder readable, writable, and executable by "
                "everyone on the machine.",
                "shell + filesystem permissions", HIGH,
                "world-writable permissions")

    if ":(){" in c or re.search(r"\b(shutdown|reboot|halt|poweroff)\b", low):
        return ("Affects the whole machine (shutdown / reboot / fork bomb).",
                "system control", HIGH, "system-wide effect")

    if SENSITIVE_PATH.search(c):
        return ("Touches a file that usually holds secrets or credentials "
                "(keys, .env, tokens).",
                "shell + sensitive files", HIGH, "involves a secrets file")

    # ---- MEDIUM risk patterns ----
    pkg = re.search(
        r"\b(npm|pnpm|yarn|bun)\s+(install|add|i)\b\s*(.*)|"
        r"\b(pip3?|pipx)\s+install\s+(.*)|"
        r"\b(cargo|go)\s+install\s+(.*)|"
        r"\b(apt|apt-get|brew|dnf|yum|pacman)\s+install\s+(.*)", low)
    if pkg:
        names = next((pkg.group(i) for i in (3, 5, 7, 9) if pkg.group(i)), "").strip()
        names = re.sub(r"^-{1,2}\S+\s*", "", names)  # drop a leading flag
        what = names.split()[0] if names else "dependencies"
        more = " and others" if names and len(names.split()) > 1 else ""
        return (f"Installs {what}{more} into your project.",
                "shell + package downloads", MEDIUM, "installs third-party code")

    if re.search(r"\bgit\s+push\b", low):
        return ("Pushes your local commits to a git remote.",
                "shell + your git remote", MEDIUM, "publishes commits")

    if re.search(r"\bgit\s+(reset\s+--hard|clean\s+-\S*f|checkout\s+\.)", low):
        return ("Discards uncommitted changes in your working tree.",
                "shell + filesystem", MEDIUM, "throws away local changes")

    if re.search(r"\b(migrate|db:migrate|alembic|prisma\s+migrate)\b", low):
        return ("Runs database migrations, which change your database schema.",
                "shell + database", MEDIUM, "modifies a database")

    if re.search(r"\b(docker|kubectl|terraform|helm)\b", low):
        return ("Runs an infrastructure command (containers / cluster / infra).",
                "shell + infrastructure", MEDIUM, "changes infrastructure state")

    if re.search(r"\b(curl|wget|http|nc|ssh|scp|rsync)\b", low):
        return ("Makes a network connection to a remote host.",
                "shell + outbound network", MEDIUM, "talks to the network")

    if re.search(r"\b(mv|cp)\b", low):
        return ("Moves or copies files, which can overwrite existing ones.",
                "shell + filesystem", MEDIUM, "may overwrite files")

    if re.search(r"\b(chmod|chown)\b", low):
        return ("Changes file permissions or ownership.",
                "shell + filesystem permissions", MEDIUM, "alters permissions")

    # chained commands: surface that several things run, before low-risk shortcuts
    if re.search(r"(&&|\|\||;|\|)", c):
        return ("Runs several shell commands in sequence.",
                "shell access", MEDIUM, "multiple chained commands")

    # ---- LOW risk (read-only / harmless) ----
    if re.match(r"^(ls|pwd|cd|cat|head|tail|echo|which|whoami|date|"
                r"git\s+(status|diff|log|branch|show)|find|grep|wc|tree)\b", low):
        return ("Reads information or lists files. Read-only, makes no changes.",
                "shell (read-only)", LOW, "read-only command")

    if re.match(r"^(npm|pnpm|yarn|bun)\s+(run|test|build|lint|start)\b", low):
        return ("Runs a project script defined in your package config.",
                "shell + your project", LOW, "runs a project script")

    first = c.split()[0] if c.split() else "a command"
    return (f"Runs the shell command '{first}' in your terminal.",
            "shell / terminal access", LOW, "general shell command")


# --- powershell analysis ---------------------------------------------------
def analyze_powershell(cmd):
    c = " ".join(cmd.split())
    low = c.lower()

    if re.search(r"\bremove-item\b.*-recurse\b.*-force\b", low) \
            or re.search(r"\bremove-item\b.*-force\b.*-recurse\b", low) \
            or re.search(r"\b(rm|del|rd|rmdir)\b.*-recurse\b", low):
        return ("Permanently deletes a folder and everything inside it. "
                "This cannot be undone.",
                "shell / terminal access", HIGH, "recursive force delete")

    if re.search(r"(invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget)\b"
                 r"[^|]*\|\s*(iex|invoke-expression)", low):
        return ("Downloads a script from the internet and runs it immediately, "
                "with no chance to inspect it first.",
                "shell access + outbound network", HIGH,
                "piping a remote download straight into a shell")

    if re.search(r"\bstart-process\b.*-verb\s+runas", low) \
            or re.search(r"\b(sudo|gsudo)\b", low):
        return ("Runs a command with administrator privileges.",
                "elevated / admin shell access", HIGH, "runs as administrator")

    if re.search(r"\b(stop-computer|restart-computer|shutdown)\b", low):
        return ("Affects the whole machine (shutdown / restart).",
                "system control", HIGH, "system-wide effect")

    if SENSITIVE_PATH.search(c):
        return ("Touches a file that usually holds secrets or credentials "
                "(keys, .env, tokens).",
                "shell + sensitive files", HIGH, "involves a secrets file")

    if re.search(r"\b(install-module|install-package)\b", low) \
            or re.search(r"\b(npm|pnpm|yarn|bun)\s+(install|add|i)\b", low) \
            or re.search(r"\b(pip3?|pipx)\s+install\b", low):
        return ("Installs third-party code into your system or project.",
                "shell + package downloads", MEDIUM, "installs third-party code")

    if re.search(r"\b(invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget)\b", low):
        return ("Makes a network connection to a remote host.",
                "shell + outbound network", MEDIUM, "talks to the network")

    if re.search(r"\b(move-item|copy-item|mv|cp|copy|move)\b", low):
        return ("Moves or copies files, which can overwrite existing ones.",
                "shell + filesystem", MEDIUM, "may overwrite files")

    if re.search(r"\b(remove-item|rm|del|rd|rmdir)\b", low):
        return ("Deletes one or more files.",
                "shell + filesystem", MEDIUM, "deletes files")

    if re.match(r"^(get-childitem|gci|ls|dir|get-content|gc|cat|type|"
                r"get-location|pwd|write-output|echo|select-string|"
                r"get-command|where-object|measure-object|test-path)\b", low):
        return ("Reads information or lists files. Read-only, makes no changes.",
                "shell (read-only)", LOW, "read-only command")

    first = c.split()[0] if c.split() else "a command"
    return (f"Runs the PowerShell command '{first}' in your terminal.",
            "shell / terminal access", LOW, "general shell command")


# --- file / web / agent / mcp ----------------------------------------------
def analyze_write(ti):
    p = ti.get("file_path", "")
    risk, reason = (HIGH, "writes a secrets file") if SENSITIVE_PATH.search(p) \
        else (MEDIUM, "creates or overwrites a file")
    return (f"Creates or overwrites \"{basename(p)}\".",
            "writes to your filesystem", risk, reason)


def analyze_edit(ti):
    p = ti.get("file_path", "")
    risk, reason = (HIGH, "edits a secrets file") if SENSITIVE_PATH.search(p) \
        else (LOW, "edits a file in place")
    return (f"Modifies \"{basename(p)}\" (find-and-replace).",
            "writes to your filesystem", risk, reason)


def analyze_read(ti):
    p = ti.get("file_path", "")
    if SENSITIVE_PATH.search(p):
        return (f"Reads \"{basename(p)}\", which may contain secrets or keys.",
                "reads your filesystem", MEDIUM, "reads a sensitive file")
    return (f"Reads the contents of \"{basename(p)}\".",
            "reads your filesystem", LOW, "read-only")


def analyze_glob(ti):
    return (f"Searches for files matching \"{ti.get('pattern','')}\".",
            "reads your filesystem", LOW, "read-only file search")


def analyze_grep(ti):
    return (f"Searches file contents for \"{ti.get('pattern','')}\".",
            "reads your filesystem", LOW, "read-only content search")


def analyze_webfetch(ti):
    url = ti.get("url", "")
    host = re.sub(r"^https?://", "", url).split("/")[0]
    return (f"Fetches content from {host or url}.",
            "outbound network", MEDIUM, "pulls content from the internet")


def analyze_websearch(ti):
    return (f"Searches the web for \"{ti.get('query','')}\".",
            "outbound network", LOW, "web search")


def analyze_agent(ti):
    desc = ti.get("description") or ti.get("prompt", "a task")
    return (f"Spawns a sub-agent to: {desc[:120]}",
            "whatever tools that sub-agent uses", MEDIUM,
            "delegates work to an autonomous agent")


def analyze_mcp(tool_name, ti):
    m = re.match(r"mcp__([^_]+(?:_[^_]+)*?)__(.+)$", tool_name)
    server = m.group(1) if m else "an external server"
    tool = m.group(2) if m else tool_name
    verb = HIGH if re.search(r"(delete|remove|send|pay|transfer|drop|write|update|create)",
                             tool.lower()) else MEDIUM
    reason = "external integration that can change data" if verb == HIGH \
        else "calls an external integration"
    return (f"Calls \"{tool}\" on the \"{server}\" integration (outside this project).",
            f"external service: {server}", verb, reason)


def analyze(tool_name, ti):
    if tool_name == "Bash":
        return analyze_bash(ti.get("command", ""))
    if tool_name == "PowerShell":
        return analyze_powershell(ti.get("command", ""))
    if tool_name == "Write":
        return analyze_write(ti)
    if tool_name == "Edit" or tool_name == "MultiEdit":
        return analyze_edit(ti)
    if tool_name == "Read":
        return analyze_read(ti)
    if tool_name == "Glob":
        return analyze_glob(ti)
    if tool_name == "Grep":
        return analyze_grep(ti)
    if tool_name == "WebFetch":
        return analyze_webfetch(ti)
    if tool_name == "WebSearch":
        return analyze_websearch(ti)
    if tool_name == "Agent":
        return analyze_agent(ti)
    if tool_name.startswith("mcp__"):
        return analyze_mcp(tool_name, ti)
    return (f"Uses the {tool_name} tool.", "see the request below", LOW,
            "unrecognized tool")


def detail_line(tool_name, ti):
    if tool_name in ("Bash", "PowerShell"):
        return " ".join(ti.get("command", "").split())[:300]
    if tool_name in ("Write", "Edit", "MultiEdit", "Read"):
        return ti.get("file_path", "")
    if tool_name == "WebFetch":
        return ti.get("url", "")
    if tool_name == "WebSearch":
        return ti.get("query", "")
    if tool_name in ("Glob", "Grep"):
        return ti.get("pattern", "")
    return ""


# --- rendering: a tidy box with an emoji risk badge ------------------------
RISK_EMOJI = {LOW: "\U0001F7E2", MEDIUM: "\U0001F7E1", HIGH: "\U0001F534"}
WIDE = set("\U0001F7E2\U0001F7E1\U0001F534")  # risk emoji render two columns
DOT = "·"
INNER = 56          # content width inside the box
LABEL_W = 6         # width of the Does / Needs / Risk label column


def _dwidth(s):
    # Display width: the risk emoji take two terminal columns, the rest one.
    return sum(2 if ch in WIDE else 1 for ch in s)


def _pad(s, width):
    return s + " " * max(0, width - _dwidth(s))


def _wrap(text, width):
    out, cur = [], ""
    for word in text.split():
        if cur and _dwidth(cur) + 1 + _dwidth(word) > width:
            out.append(cur)
            cur = word
        else:
            cur = word if not cur else cur + " " + word
    if cur:
        out.append(cur)
    return out or [""]


def render_box(tool_name, detail, does, wants, risk, reason):
    emoji = RISK_EMOJI.get(risk, "")
    header = f"{tool_name}  {DOT}  {emoji} {risk} RISK"
    if _dwidth(header) > INNER - 1:           # keep the top border from breaking
        header = header[:INNER - 2]

    # Explanation leads: the plain-English summary is the first thing shown.
    body = [""]
    for label, value in (("Does", does), ("Needs", wants), ("Risk", reason)):
        wrapped = _wrap(value, INNER - LABEL_W - 2)
        body.append(f"{label:<{LABEL_W}}  {wrapped[0]}")
        for cont in wrapped[1:]:
            body.append(" " * (LABEL_W + 2) + cont)
    # The raw command/detail is de-emphasised at the bottom (Claude Code's own
    # prompt shows it in full, so this is just a short echo for reference).
    if detail:
        prefix = "cmd: " if tool_name in ("Bash", "PowerShell") else ""
        line = prefix + detail
        d = line if _dwidth(line) <= INNER else line[:INNER - 1] + "…"
        body.append("")
        body.append(d)
    body.append("")

    dashes = "─" * max(0, INNER - 1 - _dwidth(header))
    top = f"╭─ {header} {dashes}╮"
    bottom = "╰" + "─" * (INNER + 2) + "╯"
    middle = [f"│ {_pad(line, INNER)} │" for line in body]
    box = "\n".join([top, *middle, bottom])
    # Wrap in a fenced code block so the VSCode chat panel renders it in a
    # fixed-width font instead of reflowing it into a jagged mess.
    return f"```\n{box}\n```"


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        data = json.loads(raw)
        tool_name = data.get("tool_name", "")
        ti = data.get("tool_input", {}) or {}
        if not tool_name:
            return

        does, wants, risk, reason = analyze(tool_name, ti)
        detail = detail_line(tool_name, ti)
        message = render_box(tool_name, detail, does, wants, risk, reason)

        # Only systemMessage, no decision -> normal allow/deny prompt is untouched.
        sys.stdout.write(json.dumps({"systemMessage": message}))
    except Exception:
        # Fail silent: never block the user's workflow.
        return


if __name__ == "__main__":
    main()
