# bash-guard

A `PreToolUse` hook for Claude Code that scans the **full bash command string** — including combined commands joined by `&&`, `||`, `;`, or `|` — and blocks dangerous patterns before they execute.

## What it blocks

| Category | Examples |
|----------|---------|
| Filesystem destruction | `rm -rf /`, `rm -rf ~`, `dd of=/dev/sda`, `mkfs` |
| Remote code execution | `curl url \| bash`, `bash <(curl ...)`, `eval "$(curl ...)"` |
| Reverse shells | `bash -i >& /dev/tcp/...`, `nc -e /bin/bash` |
| Credential access | `cat /etc/shadow`, `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials` |
| History/log tampering | `HISTFILE=/dev/null`, `history -c`, `systemctl stop auditd` |
| Environment injection | `LD_PRELOAD=`, `BASH_ENV=`, `PROMPT_COMMAND=` |
| Privilege escalation | `sudo bash`, `chmod 4777 /bin/bash`, `>> /etc/passwd` |
| Persistence | `>> ~/.bashrc`, `>> /etc/crontab`, `>> ~/.ssh/authorized_keys` |
| Firewall disabling | `iptables -F`, `ufw disable`, `setenforce 0` |
| Fork bombs | `:(){ :|:& };:` and variants |

Detection happens on the **complete command string**, so `ls /tmp && rm -rf /` is caught even though it starts with `ls`.

## Installation

**1. Copy the script**

```bash
cp bash_guard.py ~/.claude/hooks/bash_guard.py
```

**2. Add to `~/.claude/settings.json`**

```json
{
  "permissions": {
    "allow": ["Bash"]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/bash_guard.py"
          }
        ]
      }
    ]
  }
}
```

> Use absolute path if `~` expansion is unreliable in your shell:
> `"python3 /Users/<you>/.claude/hooks/bash_guard.py"`

**3. Restart Claude Code** to reload the settings.

## Testing

```bash
python3 tests/test_bash_guard.py
```

Non-destructive — pipes command strings to the script, never executes them.
Expected: **66/66 passed**.

## False positives

Legitimate commands are intentionally allowed through:

- `rm -rf node_modules`, `rm -rf ./tmp` — relative/non-root paths
- `sudo apt install`, `sudo systemctl restart` — safe sudo usage
- `curl https://api.github.com/user` — curl without pipe-to-shell
- `chmod +x script.sh`, `chmod 755 build/app` — non-SUID chmod
- `cat ~/.ssh/config`, `cat ~/.ssh/known_hosts` — non-private-key SSH files

If you need to adjust coverage, edit `DANGEROUS_PATTERNS` in `bash_guard.py`.
