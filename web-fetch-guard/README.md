# web-fetch-guard

A two-layer prompt injection guard for Claude Code's `WebFetch` tool.

| Hook | Trigger | Action |
|------|---------|--------|
| `PreToolUse` | Before fetch | Checks URL domain against trusted allowlist; warns Claude for unknown domains |
| `PostToolUse` | After fetch | Scans returned content for common injection phrases; warns Claude if detected |

## What it detects

**Unknown domains (PreToolUse)**

Any domain not in the trusted allowlist triggers a warning injected into Claude's context, instructing it to ignore any behavioural directives in the fetched content.

**Injection patterns (PostToolUse)**

| Pattern | Example |
|---------|---------|
| Instruction override | `ignore all previous instructions` |
| Role hijack | `you are now a`, `act as if you are` |
| System prompt exposure | `system prompt:`, `<system>` |
| Instruction redefinition | `new instructions:`, `your new role is` |

## Installation

**1. Copy the script**

```bash
cp web_fetch_guard.py ~/.claude/hooks/web_fetch_guard.py
```

**2. Add to `~/.claude/settings.json`**

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "WebFetch",
        "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/web_fetch_guard.py" }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch",
        "hooks": [{ "type": "command", "command": "python3 ~/.claude/hooks/web_fetch_guard.py" }]
      }
    ]
  }
}
```

**3. Restart Claude Code** to reload the settings.

## Trusted domains

The allowlist covers common documentation and reference sites (GitHub, MDN, PyPI, Anthropic docs, etc.). To add a domain, edit `TRUSTED_DOMAINS` in `web_fetch_guard.py`.

## Limitations

Pattern-based detection cannot catch heavily obfuscated attacks (e.g. injection hidden in code comments or encoded text). This guard reduces risk; it does not eliminate it.
