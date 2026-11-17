# bash-guard

A `PreToolUse` hook for Claude Code that applies a **three-tier decision model** to every bash command, sitting on top of Claude Code's native permission system rather than replacing it.

## How it works

Commands are evaluated in order against three tiers:

| Tier | Decision | Effect |
|------|----------|--------|
| **DENY** | `permissionDecision: "deny"` | Hard-blocked immediately. No permission prompt is ever shown. Reserved for catastrophic, irreversible actions. |
| **WARN** | `permissionDecision: "ask"` + `permissionDecisionReason` + `systemMessage` | Asks the user to confirm the command. The prompt shows a one-sentence explanation of the risk, and the same explanation is injected for Claude. |
| **ALLOW** | `permissionDecision: "allow"` | Skips Claude Code's permission prompt entirely. Reserved for clearly safe, read-only operations. |
| *(no match)* | `{}` | Hook has no opinion. Claude Code decides normally. |

Detection runs on the **full command string**, so `ls /tmp && rm -rf /` is caught by DENY even though it starts with `ls`.

## DENY — hard-blocked (14 rules)

Reserved for actions that are irreversible and have near-zero legitimate use:

| Category | Examples |
|----------|---------|
| Root/home filesystem deletion | `rm -rf /`, `rm -rf /*`, `rm -rf ~`, `rm -rf $HOME`, `--no-preserve-root` |
| Disk device destruction | `dd of=/dev/sda`, `mkfs /dev/sda1`, `shred /dev/nvme0n1`, `> /dev/sda` |
| System crash | `echo c > /proc/sysrq-trigger` |
| Fork bombs | `:(){ :|:& };:` and variants |

## WARN — ask with context (58 rules)

Suspicious commands that may have legitimate uses. The user is asked to confirm, with a human-readable risk summary in the prompt and injected as context for Claude:

| Category | Examples |
|----------|---------|
| Remote code execution | `curl url \| bash`, `bash <(curl ...)`, `eval "$(curl ...)"` |
| Reverse shells | `bash -i >& /dev/tcp/...`, `nc -e /bin/bash`, `/dev/udp/` |
| Credential access | `cat /etc/shadow`, `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials` |
| History/log tampering | `HISTFILE=/dev/null`, `history -c`, `systemctl stop auditd` |
| Environment injection | `LD_PRELOAD=`, `BASH_ENV=`, `PROMPT_COMMAND=` |
| Privilege escalation | `sudo bash`, `chmod 4777 /bin/bash`, `>> /etc/passwd` |
| Persistence | `>> ~/.bashrc`, `>> /etc/crontab`, `>> ~/.ssh/authorized_keys` |
| Firewall disabling | `iptables -F`, `ufw disable`, `setenforce 0` |

> Why `ask` and not `defer`: Claude Code treats `defer` as "suspend this tool call until an external host resumes it". The Claude desktop app has no such host, so a deferred call ended the whole turn.

## ALLOW — auto-approved (no prompt)

Narrow set of clearly safe, read-only, standalone commands (no `&&` / `||` / `;` chaining):

`ls` · `pwd` · `which` / `type` · `uname` · `ps` · `df` · `du -sh` · `git status/log/diff/branch/show` · `--version`

## Installation

**1. Copy the script**

```bash
cp bash_guard.py ~/.claude/hooks/bash_guard.py
```

**2. Add to `~/.claude/settings.json`**

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /Users/<you>/.claude/hooks/bash_guard.py"
          }
        ]
      }
    ]
  }
}
```

> Use an absolute path — the Claude Code desktop app on macOS does not always inherit `PATH` from your shell, so `python3` may not resolve if invoked via `~` or a relative path.

**3. Restart Claude Code** to reload the settings.

## Testing

```bash
python3 tests/test_bash_guard.py                                # repo copy
python3 tests/test_bash_guard.py ~/.claude/hooks/bash_guard.py  # installed copy
```

Non-destructive — pipes command strings to the script, never executes them.
Expected: **74/74 passed**.

## Adjusting coverage

- To move a rule from WARN to DENY (or vice versa), cut the entry from one list and paste it into the other.
- To add a new rule, append a `(pattern, reason)` tuple to `DENY_PATTERNS` or `WARN_PATTERNS`.
- To expand the auto-allow list, add a regex to `_ALLOW_PATTERNS` (remember: only match commands with no chaining operators).
