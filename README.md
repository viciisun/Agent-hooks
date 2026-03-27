# agent-hooks

A collection of Claude Code `PreToolUse` / `PostToolUse` hooks for safer, more automated agentic workflows.

Each hook lives in its own directory and is self-contained.

## Hooks

| Hook | Trigger | Purpose |
|------|---------|---------|
| [bash-guard](./bash-guard/) | `PreToolUse / Bash` | Block dangerous shell commands before execution |

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
