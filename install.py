#!/usr/bin/env python3
"""
One-command installer for explain-tool.

It copies explain_tool.py into your Claude Code hooks folder and registers the
hook in settings.json for you, so you never have to edit JSON by hand. Run it
again any time to update to a newer version; it will not create duplicates.

    python install.py            # install / update
    python install.py --uninstall

Works on Windows, macOS, and Linux. Standard library only.
"""

import json
import os
import shutil
import sys

HOOK_FILENAME = "explain_tool.py"
EVENT = "PreToolUse"  # fires on every tool call; its systemMessage is shown to you


def claude_dir():
    return os.path.join(os.path.expanduser("~"), ".claude")


def hooks_dir():
    return os.path.join(claude_dir(), "hooks")


def settings_path():
    return os.path.join(claude_dir(), "settings.json")


def installed_hook_path():
    return os.path.join(hooks_dir(), HOOK_FILENAME)


def hook_command():
    # Use the exact interpreter running this installer, so the registered
    # command always points at a Python that exists on this machine.
    py = sys.executable or "python"
    return f'"{py}" "{installed_hook_path()}"'


def load_settings():
    p = settings_path()
    if not os.path.exists(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            text = f.read().strip()
        return json.loads(text) if text else {}
    except (OSError, json.JSONDecodeError) as e:
        print(f"  ! Could not read {p}: {e}")
        print("    Please fix or remove that file and run the installer again.")
        sys.exit(1)


def save_settings(data):
    p = settings_path()
    if os.path.exists(p):
        shutil.copy2(p, p + ".bak")
        print(f"  - Backed up existing settings to {p}.bak")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def our_entry():
    return {
        "matcher": "*",
        "hooks": [{"type": "command", "command": hook_command()}],
    }


def is_ours(entry):
    for h in entry.get("hooks", []):
        if HOOK_FILENAME in h.get("command", ""):
            return True
    return False


def install():
    os.makedirs(hooks_dir(), exist_ok=True)

    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), HOOK_FILENAME)
    if not os.path.exists(src):
        print(f"  ! Could not find {HOOK_FILENAME} next to this installer.")
        sys.exit(1)
    shutil.copy2(src, installed_hook_path())
    print(f"  - Copied hook to {installed_hook_path()}")
    try:
        os.chmod(installed_hook_path(), 0o755)
    except OSError:
        pass

    settings = load_settings()
    hooks = settings.setdefault("hooks", {})
    bucket = hooks.setdefault(EVENT, [])

    # Replace any previous entry of ours (keeps the command path up to date),
    # leave everyone else's hooks untouched.
    bucket[:] = [e for e in bucket if not is_ours(e)]
    bucket.append(our_entry())
    save_settings(settings)
    print(f"  - Registered the hook on the {EVENT} event in {settings_path()}")

    print("\nDone! Start a new Claude Code session (hooks load at startup),")
    print("then run /hooks to confirm it's registered.")


def uninstall():
    settings = load_settings()
    bucket = settings.get("hooks", {}).get(EVENT, [])
    before = len(bucket)
    bucket[:] = [e for e in bucket if not is_ours(e)]
    if before != len(bucket):
        save_settings(settings)
        print(f"  - Removed the hook from {settings_path()}")
    else:
        print("  - No explain-tool entry found in settings.")

    if os.path.exists(installed_hook_path()):
        os.remove(installed_hook_path())
        print(f"  - Deleted {installed_hook_path()}")

    print("\nUninstalled. Restart Claude Code for it to take effect.")


def main():
    print("explain-tool installer\n")
    if "--uninstall" in sys.argv:
        uninstall()
    else:
        install()


if __name__ == "__main__":
    main()
