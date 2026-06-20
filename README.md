# explain-tool

A Claude Code hook that shows a short, plain-English explanation of what a tool
call is about to do, and what access it needs, right at the permission prompt.
Instead of bare `Bash: rm -rf node_modules`, you see what it means and how risky
it is before you press allow.

Author: Muhammad Huzaifa Awan

## What it shows

```
[ Permission check · Bash ]
  $ rm -rf node_modules

  Does:  Permanently deletes node_modules and everything inside it. This cannot be undone.
  Wants: shell / terminal access
  Risk:  HIGH (recursive force delete)
```

It covers Bash and PowerShell (with risk detection for things like `rm -rf` /
`Remove-Item -Recurse -Force`, `sudo`, force push, piping a remote script into a
shell, and secret files), Write, Edit, Read, Glob, Grep, WebFetch, WebSearch,
sub-agents, and any MCP integration. Paths are matched with both `/` and `\`, so
secret-file detection works the same on Windows as on macOS and Linux.

## How it works

The hook runs on the `PermissionRequest` event, which fires only when Claude
Code is about to ask you to allow or deny something. It reads the tool name and
inputs, classifies the action, and returns a single `systemMessage`. It never
returns a permission decision, so your normal allow / deny prompt is untouched.
If anything goes wrong it stays silent and exits cleanly, so it can never block
your work.

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
       "PermissionRequest": [
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
- To explain every tool call, including ones already on your allow list, change
  the event from `PermissionRequest` to `PreToolUse`. The same script works for
  both. `PermissionRequest` is the recommended default because it only speaks up
  when you are actually being asked.
- The risk labels are a guide, not a guarantee. Always read the command itself.
