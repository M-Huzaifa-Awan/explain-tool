# explain-tool

A Claude Code hook that shows a short, plain-English explanation of what a tool
call is about to do, and what access it needs, right at the permission prompt.
Instead of bare `Bash: rm -rf node_modules`, you see what it means and how risky
it is before you press allow.

Author: Muhammad Huzaifa Awan

## What it shows

```
╭─ Bash  ·  🔴 HIGH RISK ──────────────────────────────────╮
│                                                          │
│ $ rm -rf node_modules                                    │
│                                                          │
│ Does    Permanently deletes node_modules and everything  │
│         inside it. This cannot be undone.                │
│ Needs   shell / terminal access                          │
│ Risk    recursive force delete                           │
│                                                          │
╰──────────────────────────────────────────────────────────╯
```

Risk shows at a glance with a colored badge: 🟢 LOW, 🟡 MEDIUM, 🔴 HIGH.

It covers Bash and PowerShell (with risk detection for things like `rm -rf` /
`Remove-Item -Recurse -Force`, `sudo`, force push, piping a remote script into a
shell, and secret files), Write, Edit, Read, Glob, Grep, WebFetch, WebSearch,
sub-agents, and any MCP integration. Paths are matched with both `/` and `\`, so
secret-file detection works the same on Windows as on macOS and Linux.

## How it works

The hook runs on the `PreToolUse` event, which fires on every tool call. It
reads the tool name and inputs, classifies the action, and returns a single
`systemMessage` that Claude Code shows you before the tool runs. It never
returns a permission decision, so your normal allow / deny prompt is untouched.
If anything goes wrong it stays silent and exits cleanly, so it can never block
your work.

> **Why not `PermissionRequest`?** That event only fires when you're actually
> asked, which sounds ideal — but a `PermissionRequest` hook's `systemMessage`
> is **not rendered in the permission dialog**, so the explanation never shows.
> `PreToolUse` is the event that actually surfaces the message.

## Install (one command)

Download or clone this repo, then run the installer:

```bash
git clone https://github.com/M-Huzaifa-Awan/explain-tool.git
cd explain-tool
python install.py
```

On macOS / Linux use `python3 install.py` if `python` isn't found.

That's it. The installer copies the hook into `~/.claude/hooks/` and registers
it in `~/.claude/settings.json` for you — no JSON editing. It backs up any
existing settings to `settings.json.bak`, never touches your other hooks, and
running it again just updates in place (no duplicates).

Then **start a new Claude Code session** (hooks load at startup) and run
`/hooks` to confirm it's registered.

To remove it later:

```bash
python install.py --uninstall
```

<details>
<summary>Manual install (if you prefer to do it by hand)</summary>

1. Copy the script and make it executable:

   ```bash
   mkdir -p ~/.claude/hooks
   cp explain_tool.py ~/.claude/hooks/explain_tool.py
   chmod +x ~/.claude/hooks/explain_tool.py
   ```

2. Register the hook in `~/.claude/settings.json` (merge into the existing file
   if you already have one):

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "*",
           "hooks": [
             {
               "type": "command",
               "command": "python3 \"$HOME/.claude/hooks/explain_tool.py\""
             }
           ]
         }
       ]
     }
   }
   ```

   On Windows, use `python` instead of `python3` and point at
   `%USERPROFILE%\.claude\hooks\explain_tool.py`.

3. Start a new Claude Code session and run `/hooks` to confirm.

</details>

## Test it without Claude Code

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf build"}}' \
  | python3 ~/.claude/hooks/explain_tool.py
```

You should get a JSON object containing a `systemMessage`.

## Notes

- Requires Python 3 (standard library only, no dependencies). Works on Windows,
  macOS, and Linux.
- The hook uses the `PreToolUse` event, so it explains every tool call —
  including ones already on your allow list. (`PermissionRequest` would only
  fire when you're prompted, but its `systemMessage` doesn't render in the
  dialog, so it can't show the explanation.)
- The risk labels are a guide, not a guarantee. Always read the command itself.
