# agent-hooks

> **Claude Code only.** These hooks use the [Claude Code hook system](https://docs.anthropic.com/en/docs/claude-code/hooks) (`PreToolUse` / `PostToolUse` events in `~/.claude/settings.json`) and are not compatible with other agent frameworks (OpenClaw, Gemini CLI, etc.).

A collection of hooks for safer, more automated Claude Code workflows. Each hook lives in its own directory and is self-contained.

## Hooks

| Hook | Trigger | Purpose |
|------|---------|---------|
| [bash-guard](./bash-guard/) | `PreToolUse / Bash` | Block dangerous shell commands before execution |
| [web-fetch-guard](./web-fetch-guard/) | `PreToolUse + PostToolUse / WebFetch` | Prompt injection protection for fetched web content |

## Installation pattern

1. Copy the hook script to `~/.claude/hooks/`
2. Add the hook entry to `~/.claude/settings.json`

Each hook's README contains the exact `settings.json` snippet to paste.

## Repo structure

```
agent-hooks/
├── README.md
└── <hook-name>/
    ├── <hook>.py          # hook script
    ├── README.md          # setup instructions + settings.json snippet
    └── tests/
        └── test_<hook>.py # non-destructive test suite
```
