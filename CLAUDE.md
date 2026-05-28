# CLAUDE.md

@AGENTS.md

## Worktree Location (Claude Code override)

When using Claude Code, worktrees are created inside the repo under `.claude/worktrees/<branch-name>` — **not** in the sibling `amqp-client.worktrees/` folder described in AGENTS.md. All other worktree lifecycle rules from AGENTS.md still apply.

## Worktree Setup

After any worktree is created, always run this before any other command:

```bash
bash scripts/setup-worktree.sh
```

This installs dependencies and symlinks `.env` from the main repo. Skipping it causes silent failures in tests and other commands.

### Branch Naming

At the start of every session, check the current branch name. If it matches the auto-generated `claude/<adjective-name-hash>` pattern, rename it to follow the branch naming convention before doing any work:

```bash
git branch -m <type>/<short-description>
```

Use the task at hand to determine the appropriate type (`feat`, `fix`, `refactor`, etc.) and a short kebab-case description. This ensures PRs and git history are always descriptive.

Do not remove a worktree on your own initiative. Ask the user explicitly once all PRs for the plan have been created.