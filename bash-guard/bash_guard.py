#!/usr/bin/env python3
"""
Bash command safety guard for Claude Code.

Three-tier decision model that sits on top of Claude Code's native permission system:

  ALLOW — clearly safe, read-only operations.
          Returns permissionDecision:"allow" so Claude Code skips its own prompt.

  DENY  — catastrophic and irreversible (disk destruction, fork bombs, OS crashes).
          Returns permissionDecision:"deny" — no permission prompt is ever shown.

  WARN  — suspicious but not necessarily catastrophic (reverse shells, credential
          reads, env-var injection, etc.). Returns permissionDecision:"ask" plus
          a systemMessage, so the user confirms the command and Claude already has
          context on why it is risky.

          Not "defer": Claude Code treats "defer" as "suspend this tool call until an
          external host resumes it". Claude desktop has no such host, so a deferred
          call ended the whole turn ("Tool result missing due to internal error").

Location: ~/.claude/hooks/bash_guard.py
Loaded by: ~/.claude/settings.json (PreToolUse hook, Bash matcher)
"""

import sys
import json
import re


# ── Tier 1: ALLOW ─────────────────────────────────────────────────────────────
# Clearly safe, read-only operations with no dangerous variant.
# Only matches standalone commands — anything with && || ; is excluded below
# so a chained `git status && rm -rf /` can't sneak through here.
#
# Patterns are applied against the full command string with IGNORECASE.

_ALLOW_PATTERNS = [
    r'^\s*l[sla]+(\s|$)',                                   # ls, ll, la, ls -la …
    r'^\s*pwd(\s|$)',
    r'^\s*(which|type)\s+\S',                               # which python3
    r'^\s*uname(\s|-)',                                     # uname -a
    r'^\s*ps\b',                                            # ps, ps aux
    r'^\s*df\b',                                            # df -h
    r'^\s*du\s+-[shHd]',                                    # du -sh …
    r'^\s*git\s+(status|log|diff|branch|show|stash\s+list|remote\s+-v|tag)\b',
    r'--version\b',                                         # any --version flag
]

# Reject chaining operators — ALLOW only fires for simple, single-stage commands.
_CHAIN_RE = re.compile(r'&&|\|\||(?<![\|&]);')


def _is_safe_standalone(cmd: str) -> bool:
    if _CHAIN_RE.search(cmd):
        return False
    return any(re.search(p, cmd, re.IGNORECASE) for p in _ALLOW_PATTERNS)


# ── Tier 2: DENY ──────────────────────────────────────────────────────────────
# Catastrophic, irreversible actions with near-zero legitimate use.
# Hard-blocked — no permission prompt is shown to the user.
#
# Each entry: (regex_pattern, one-sentence explanation shown to the user)

DENY_PATTERNS = [

    # Root / home filesystem destruction
    (r'\brm\s+(-\w+\s+)*-\w*r\w*f\w*\s+(-\w+\s+)*/$',
     "This deletes every file on the root filesystem — the OS cannot recover."),

    (r'\brm\s+(-\w+\s+)*-\w*r\w*f\w*\s+(-\w+\s+)*/\*',
     "This deletes everything under / — the OS cannot recover."),

    (r'\brm\s+(-\w+\s+)*-\w*r\w*f\w*\s+(-\w+\s+)*~/?(\s|$)',
     "This deletes the entire home directory and everything in it."),

    (r'\brm\s+(-\w+\s+)*-\w*r\w*f\w*\s+(-\w+\s+)*\$HOME/?(\s|$)',
     "This deletes the entire home directory and everything in it."),

    (r'\brm\s+(-\w+\s+)*-\w*r\w*f\w*\s+(-\w+\s+)*""/',
     "An unquoted empty variable expands to /, which would delete the root filesystem."),

    (r'--no-preserve-root',
     "This flag removes the last safety guard on recursive root deletion."),

    # Disk device destruction
    (r'\bdd\b.+\bof=/dev/(sd|hd|nvme|vd|xvd)',
     "Writing directly to a disk device permanently destroys its partition table and data."),

    (r'\bcat\s+/dev/(zero|urandom)\s+>\s*/dev/',
     "Overwriting a disk device with /dev/zero permanently erases all its data."),

    (r'>\s*/dev/(sd|hd|nvme)[a-z0-9]',
     "Redirecting output to a raw disk device will corrupt it permanently."),

    (r'\bshred\b.+/dev/(sd|hd|nvme)',
     "Shredding a disk device permanently destroys all data on it — no recovery possible."),

    (r'\bmkfs\b.*/dev/',
     "Formatting a partition erases everything on it permanently."),

    # Fork bombs and resource exhaustion.
    # A function whose body pipes itself into itself (":(){ :|:& };:") or starts
    # itself in the background ("f(){ f & f; }"). Any other function that merely
    # contains "|" and "&" ("2>&1", "&&") is ordinary shell code.
    (r'(?<![\w.:-])(?P<fn>[\w-]+|\.|:)\s*\(\s*\)\s*\{[^}]*?(?<![\w.:-])(?P=fn)\s*'
     r'(?:\|&?\s*(?P=fn)(?![\w.:-])|&(?![&>]))',
     "This is a fork bomb — it spawns processes exponentially and will freeze the system."),

    (r'while\s+true\s*;\s*do\s+\$0\s*&',
     "This self-replicates infinitely in the background and will exhaust all system resources."),

    # Kernel crash / forced reboot
    (r'echo\s+[cb]\s*>\s*/proc/sysrq-trigger',
     "Writing to sysrq-trigger triggers an immediate kernel crash or forced reboot."),
]


# ── Tier 3: WARN ──────────────────────────────────────────────────────────────
# Suspicious but not necessarily catastrophic.
# Asks the user to confirm the command (permissionDecision "ask") and injects a
# systemMessage so Claude already has context on the risk.
#
# Each entry: (regex_pattern, one-sentence explanation for Claude and the user)

# A cat invocation and its own arguments: same line, before any pipe, redirect or
# separator. The secret-file rules below use it, so a heredoc that merely mentions
# a secret path (a script written with `cat > file <<'EOF'`) is not flagged.
_CAT_ARGS = r'\bcat\b(?:[ \t]+[^\s|;&<>]+)*?[ \t]+[^\s|;&<>]*'

WARN_PATTERNS = [

    # Remote code execution
    (r'\bcurl\b[^|#\n]*\|\s*-?\s*(ba?sh|sh)\b',
     "Piping curl into bash runs whatever the remote server sends — the script is never shown to you."),

    (r'\bwget\b[^|#\n]*\|\s*-?\s*(ba?sh|sh)\b',
     "Piping wget into bash runs whatever the remote server sends — the script is never shown to you."),

    (r'\bcurl\b[^|#\n]*\|\s*(python3?|perl|ruby|node)\b',
     "Piping curl into an interpreter executes remote code without any local review."),

    (r'\bwget\b[^|#\n]*\|\s*(python3?|perl|ruby|node)\b',
     "Piping wget into an interpreter executes remote code without any local review."),

    (r'(bash|sh)\s*<\s*\(\s*(curl|wget)',
     "bash <(curl ...) downloads and immediately executes a script — its contents are never shown."),

    (r'\.\s+<\s*\(\s*(curl|wget)',
     "Sourcing a remote script via process substitution injects it into the current shell."),

    (r'\bsource\s+<\s*\(\s*(curl|wget)',
     "Sourcing a remote script injects its code directly into the current shell environment."),

    (r'\beval\s+["\'\`\$\(]',
     "eval executes a string as code — if that string comes from user input or a remote source, it's a code injection risk."),

    # Reverse shells
    (r'/dev/tcp/',
     "Using /dev/tcp in bash can open a direct TCP connection to a remote host — a common reverse shell technique."),

    (r'/dev/udp/',
     "Using /dev/udp in bash can be used to send data to or receive commands from a remote host."),

    (r'bash\s+-i\s+>&',
     "This is a classic reverse shell pattern — it hands an interactive bash session to a remote IP."),

    (r'\bnc\b.+-e\s+/bin/(sh|bash)',
     "nc -e /bin/sh sends a live shell over the network to whoever is listening."),

    (r'mkfifo\s+.+\|\s*(sh|bash)\s+-i.+nc\b',
     "This mkfifo + nc combination is a well-known technique for establishing a reverse shell."),

    (r'\bncat\b.+-e\s+/bin/(sh|bash)',
     "ncat -e /bin/sh sends a live shell over the network to whoever is listening."),

    # Credential and sensitive file access
    (r'\bcat\s+/etc/shadow\b',
     "/etc/shadow contains hashed passwords for every system user."),

    (r'\bcat\s+/etc/sudoers\b',
     "/etc/sudoers controls who can run commands as root — exposing it aids privilege escalation."),

    (_CAT_ARGS + r'\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)\b(?!\.pub\b)',
     "This prints an SSH private key — it should never leave the local machine."),

    (_CAT_ARGS + r'\.aws/(?:credentials|config)\b',
     "AWS credentials grant full programmatic access to your cloud account."),

    (_CAT_ARGS + r'(?<![\w-])\.env\b(?!\.(?:example|sample|template|dist)\b)',
     ".env files typically contain API keys, database passwords, and other secrets."),

    (r'\bcat\s+/proc/\d+/(mem|environ)\b',
     "Reading /proc/<pid>/mem or environ can extract secrets from a running process."),

    # History and log tampering
    (r'HISTFILE\s*=\s*/dev/null',
     "Redirecting HISTFILE to /dev/null prevents all shell commands from being recorded."),

    (r'HISTSIZE\s*=\s*0|HISTFILESIZE\s*=\s*0',
     "Setting history size to 0 clears the command history and stops new commands being saved."),

    (r'\bhistory\s+-[cw]\b',
     "history -c clears the in-memory command history; -w wipes the saved history file."),

    (r'\bln\s+-sf?\s+/dev/null\s+.*bash_history',
     "Symlinking bash_history to /dev/null permanently disables history recording."),

    (r'(cat\s+/dev/null|echo\s+""?)\s*>\s*/var/log/(auth|syslog|messages|secure)',
     "Clearing system log files destroys the audit trail for recent activity."),

    (r'\brm\s+-rf?\s+/var/log/',
     "Removing /var/log deletes all system audit trails and application logs."),

    (r'(service|systemctl)\s+(stop|disable)\s+audit',
     "Stopping the audit daemon disables system-wide security event logging."),

    # Environment variable injection
    (r'\bLD_PRELOAD\s*=',
     "LD_PRELOAD forces a shared library to load before all others — a common rootkit injection technique."),

    (r'\bLD_LIBRARY_PATH\s*=\s*/tmp',
     "Pointing LD_LIBRARY_PATH at /tmp can cause any process to load malicious libraries."),

    (r'\bLD_AUDIT\s*=',
     "LD_AUDIT hooks into the dynamic linker and can intercept every library call made by a process."),

    (r'\bBASH_ENV\s*=',
     "BASH_ENV runs a file on every new bash invocation — an easy persistent injection point."),

    (r'\bPROMPT_COMMAND\s*=',
     "PROMPT_COMMAND executes a command before every shell prompt — a common persistence mechanism."),

    (r'\bPYTHONSTARTUP\s*=',
     "PYTHONSTARTUP runs a file whenever Python starts — it can inject code into every Python process."),

    (r'\bNODE_OPTIONS\s*=.*--require',
     "NODE_OPTIONS --require auto-loads a module into every Node.js process."),

    (r'\bJAVA_TOOL_OPTIONS\s*=.*-agent',
     "JAVA_TOOL_OPTIONS -agent injects a JVM agent into every Java process automatically."),

    # Privilege escalation
    (r'\bchmod\b.+[0-9]*4[0-9]*7[0-9]*\s+.*(bash|sh|zsh|python|perl|ruby)',
     "Setting the SUID bit on a shell or interpreter lets any user run it as root."),

    (r'\bchmod\b\s+(-R|--recursive)\s+[0-9]*7[0-9]*7\s+/',
     "Recursively setting world-writable permissions on system paths is a serious security hole."),

    (r'\bsudo\s+(su|bash|sh|zsh|fish)(\s|$)',
     "sudo bash opens a root shell where subsequent commands leave no per-command audit trail."),

    (r'\bsudo\s+-[si]\b',
     "sudo -s/-i opens an interactive root shell."),

    (r'\bsudo\b.+\brm\b.+-[rf].+/',
     "Recursively removing paths under / with sudo can delete OS files and leave the system unbootable."),

    (r'\bsudo\b.+\bdd\b',
     "dd with sudo can overwrite disk devices or critical system files with no recovery path."),

    (r'\bsudo\b.+\bmkfs\b',
     "mkfs with sudo formats a partition, permanently erasing all data on it."),

    (r'\bsudo\b.+\bchmod\b.+(-R|--recursive).+/',
     "Recursively changing permissions on system paths with sudo can break OS access controls."),

    (r'\bsudo\b.+\bchown\b.+(-R|--recursive).+/',
     "Recursively changing ownership of system paths can lock out legitimate users and services."),

    (r'>>\s*/etc/(passwd|shadow)',
     "Appending to /etc/passwd or /etc/shadow can add backdoor accounts or corrupt authentication."),

    (r'echo\b.+>>\s*/etc/(passwd|shadow)',
     "Writing to /etc/passwd or /etc/shadow can introduce a root-level backdoor account."),

    # Persistence mechanisms
    (r'>>\s*~/?\.(bashrc|bash_profile|profile|zshrc|zprofile)',
     "Appending to shell startup files runs arbitrary code every time a new shell opens."),

    (r'>>\s*/etc/(bash\.bashrc|profile|bashrc)',
     "Appending to system-wide shell startup files runs code for every user on the machine."),

    (r'>>\s*/etc/(crontab|cron\.d/)',
     "Adding a job to the system crontab schedules code to run automatically and persistently."),

    (r'\bcrontab\b[^|]*\|\s*crontab\b',
     "Piping into crontab replaces the existing cron schedule entirely — a common persistence trick."),

    (r'\buseradd\b.+-u\s+0\b',
     "Creating a user with UID 0 gives them full root privileges without using the root account."),

    (r'>>\s*~?/\.ssh/authorized_keys',
     "Adding to authorized_keys grants SSH access to whoever holds the matching private key."),

    # Firewall and security controls
    (r'\biptables\s+-F\b',
     "iptables -F flushes all firewall rules, leaving every port on the machine open."),

    (r'\biptables\s+-P\s+INPUT\s+ACCEPT\b',
     "Setting the default INPUT policy to ACCEPT allows all inbound network connections."),

    (r'\bufw\s+disable\b',
     "Disabling UFW turns off the firewall and exposes all services to the network."),

    (r'\bsystemctl\s+(stop|disable)\s+firewalld\b',
     "Stopping firewalld removes all active firewall rules immediately."),

    (r'\bsetenforce\s+0\b',
     "setenforce 0 switches SELinux to permissive mode, disabling mandatory access controls."),

    (r'echo\s+0\s*>\s*/sys/fs/selinux/enforce',
     "Writing 0 to selinux/enforce disables SELinux enforcement system-wide."),
]


# ── Decision engine ────────────────────────────────────────────────────────────

def _make_deny(hook_event: str, reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": hook_event,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": f"Blocked — {reason}",
    }


def _make_warn(hook_event: str, reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": hook_event,
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        },
        "systemMessage": (
            f"Heads up: {reason} "
            f"Confirm with the user before proceeding."
        ),
    }


def _make_allow(hook_event: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": hook_event,
            "permissionDecision": "allow",
        }
    }


def main():
    try:
        data = json.load(sys.stdin)
        cmd = data.get("tool_input", {}).get("command", "")
        hook_event = data.get("hook_event_name", "PreToolUse")

        # 1. DENY — checked first so a chained command like
        #    `git status && rm -rf /` can't slip through the ALLOW tier.
        for pattern, reason in DENY_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE | re.DOTALL):
                print(json.dumps(_make_deny(hook_event, reason), ensure_ascii=False))
                return

        # 2. WARN — suspicious but not catastrophic; ask the user to confirm.
        for pattern, reason in WARN_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE | re.DOTALL):
                print(json.dumps(_make_warn(hook_event, reason), ensure_ascii=False))
                return

        # 3. ALLOW — explicitly safe standalone command; skip permission prompt.
        if _is_safe_standalone(cmd):
            print(json.dumps(_make_allow(hook_event), ensure_ascii=False))
            return

        # 4. No opinion — let Claude Code decide normally.
        print("{}")

    except Exception as e:
        # Never block on hook errors; surface a warning and let Claude Code proceed.
        print(json.dumps({"systemMessage": f"bash_guard error: {e}"}))
    finally:
        sys.exit(0)


if __name__ == "__main__":
    main()
