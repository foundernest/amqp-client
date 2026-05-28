# AGENTS.md

This file provides guidance when working with code in the foundernest-amqp-client project.
When developing, always look for examples or similar patterns in other files before starting any work.
You can ask the developer for references.

## Preferred Languages & Tools

- Use **TypeScript** for all new code
- For dependencies: use **npm**

## Coding Standards

- Keep pull requests small and focused—ideally under 300 changed lines
- Follow clean code principles: descriptive names, single-responsibility, modular functions/classes
- This is a **published library** — all changes to exported types, interfaces, or method signatures are breaking changes and require careful consideration

## Stylistic Guidelines

- Prioritize **TypeScript's type safety**: use strict typing, interfaces, type guards
- Use consistent naming casing: camelCase in TypeScript
- Keep code DRY → reuse common utilities, avoid duplication

## Error Handling

- Use `try/catch` and typed error handling; always propagate or log errors
- AMQP errors carry a `code` field — use the private `isAmqpError()` guard to discriminate them safely
- Never allow an unhandled rejection in connection or channel event handlers

## Security & Dependency Awareness

- **Never embed connection credentials in code** — always pass them via constructor options
- Vet dependencies for known vulnerabilities before adding; this package is consumed by other services
- Avoid adding runtime dependencies unless strictly necessary — keep the package lightweight
- `amqplib` is the only runtime dependency; adding more requires explicit justification

## Testing & Coverage

- **Test framework**: Vitest
- Write **unit tests** that mock `amqplib` at the module level using `vi.mock('amqplib')`
- Cover: connection setup, message publishing, message consumption, reconnection logic, dead-letter handling, error paths

### Test File Naming

- Tests live under `tests/` as `{Name}.spec.ts`
- Keep test file count low — the library is small; a single spec file per module is preferred

### Test Structure

- Use `describe` → `it` hierarchy; add nested `describe` for complex scenarios
- Use `beforeAll` for module-level mock setup (e.g., casting `connect` as `Mock`)
- Use `beforeEach` / `afterEach` with `vi.clearAllMocks()` to prevent cross-test pollution
- Name tests after observable behaviour: `it('should nack the message and requeue it')`

### Mocking Strategy

- Mock `amqplib` at module level with `vi.mock('amqplib')` at the top of the test file
- Create `mockConnection` and `mockChannel` objects with `vi.fn()` for each method
- Restore default mock implementations in `beforeEach` — do not rely on call order across tests
- **NEVER assert log messages** — focus on return values and observable side effects (ack, nack, sendToQueue calls)

## Documentation & Comments

- Comments should clarify _why_, not _what_, unless logic is non-obvious
- Comments should only be added when the logic is complex or a non-obvious invariant must be preserved
- Keep JSDoc on public interfaces and types — consumers of the library rely on them

## Interaction & Response Style

- Respond concisely using **bullet points** and minimal preamble
- Always explain how new code follows the existing API design
- Prefer **code-first** answers with minimal extra text

## Pull Request Protocol

All agents must follow this protocol whenever they create, update, review, or manage pull requests.

### Ownership

- By default, the user driving the current agent session must be the PR author
- Use the currently authenticated GitHub account for that user when creating the PR
- Do not create PRs using shared, bot, or alternate accounts unless the user explicitly requests it

### Readiness Before Opening a PR

- Verify the branch is ready for review before opening a PR
- Run `npm test` and `npm run build` before opening the PR
- If any checks are skipped for time, environment, or dependency reasons, the PR description must clearly state what was not run and why

### Branch, Commit, and PR Naming

- Use lowercase kebab-case after a conventional prefix for branch names: `feat/<short-description>`, `fix/<short-description>`, `refactor/<short-description>`, `chore/<short-description>`, `docs/<short-description>`, `test/<short-description>`
- Use Conventional Commit style for agent-authored commits: `feat: add priority support`, `fix: handle reconnect on channel close`, `refactor: extract backoff calculation`
- Use the same Conventional Commit format for PR titles
- Make the PR title describe the actual reviewable unit being merged, not the internal plan name

### Pull Request Body Template

- Use this structure when creating PRs:

```markdown
## Why

- Explain the product or technical reason for this change.
- Describe the risk, pain point, or opportunity being addressed.

## What

- Summarize the main implementation decisions in 2-4 bullets.
- Focus on reviewer-relevant changes, not a full changelog.

## Validation

- List the checks that were run.
- Include the exact commands when useful.
- Mention any checks that could not be run and why.

## Dependencies

- List prerequisite PRs if this PR depends on others.
- If there are no dependencies, write: `None`.

## Risks

- Call out breaking API changes, version bumps, follow-up work, or rollout concerns.
- If there are no special risks, write: `Low`.

## Screenshots

- Add screenshots or recordings when the change affects UI.
- If not applicable, write: `N/A`.
```

### Follow-up PRs and Stacked PRs

- Make dependency chains explicit when the work is part of a sequence
- Add all blocking or prerequisite PRs in the `## Dependencies` section
- If the PR is a follow-up to an earlier PR, briefly explain what was intentionally deferred

### PR Review Comments

- Always respond in the PR thread when assessing or fixing PR comments
- Never resolve or ignore a review comment silently
- Reply with a short explanation of the action taken before resolving the thread when resolution is appropriate
- If the agent cannot act on a comment, it must still reply with the reason and the proposed next step

### Scope Control

- Keep PRs small and reviewable, ideally under 300 changed lines, unless the user explicitly requests otherwise or the change cannot be split safely
- Do not mix refactors with feature work unless the refactor is required for the implementation

### Final Verification Before PR Creation

- Verify the branch is pushed and up to date
- Verify the PR title follows the naming convention
- Verify the PR body follows the required template
- Verify dependencies are listed when applicable
- Verify validation steps are documented accurately
- Verify no unrelated changes are included

## Development Commands

### Testing

```bash
npm test          # Run all tests (Vitest)
```

### Code Quality

```bash
npm run build     # TypeScript compilation (tsc) + Rollup bundle
npm run format    # Prettier auto-format
```

## Architecture Overview

### Tech Stack

- **Runtime**: Node.js with ESM modules (`"type": "module"`)
- **Core dependency**: `amqplib` (AMQP 0-9-1 protocol — RabbitMQ)
- **Build**: TypeScript (`tsc`) + Rollup (ESM bundle output to `dist/`)
- **Testing**: Vitest with `vi.mock` for module-level mocking
- **Formatting/Linting**: Prettier + ESLint (typescript-eslint)

### Package Purpose

`foundernest-amqp-client` is a **thin wrapper around `amqplib`** that provides:

- Lazy connection (connects on first use, not on construction)
- Automatic reconnection with exponential backoff + jitter
- A single shared producer channel per client instance
- One dedicated consumer channel per queue listener
- Dead-letter queue (DLQ) setup as opt-in (default: enabled)
- JSON serialization/deserialization of message payloads

### Folder Structure

```
src/
├── amqp-client.ts                    # AMQPClient class (main implementation)
├── amqp-client.interface.ts          # AMQPClientInterface (public API contract)
├── amqp-client.types.ts              # All shared types and interfaces
├── amqp-client-logger.interface.ts   # AMQPClientLoggerInterface
└── index.ts                          # Barrel export (re-exports all public API)

tests/
└── amqp-client.spec.ts               # Unit tests

dist/                                 # Build output — not committed
docs/
├── adr/                              # Architecture Decision Records
├── features/                         # Feature-level documentation
└── tech-debt/                        # Tracked tech debt
```

### Key Patterns

#### Public API

The library exposes three methods through `AMQPClientInterface`:

| Method           | Signature                                                              | Description                       |
| ---------------- | ---------------------------------------------------------------------- | --------------------------------- |
| `sendMessage`    | `sendMessage<T>(queue, message, options?): Promise<boolean>`           | Publish a JSON message to a queue |
| `createListener` | `createListener<T>(queue, onMessage, options?): Promise<void>`         | Subscribe to a queue              |
| `close`          | `close(): Promise<void>`                                               | Gracefully close all channels     |

#### Connection and Channel Model

```
AMQPClient
├── connection: amqp.ChannelModel | null   ← single shared connection
├── producer: amqp.Channel | null          ← single shared producer channel
└── consumers: Map<string, amqp.Channel>   ← one channel per queue listener
```

- Connection is created lazily on the first `sendMessage` or `createListener` call
- Reconnection uses exponential backoff: `delay = min(maxDelay, initialDelay * 2^attempt) + random(0..1000ms)`
- Default reconnection: 50 attempts, starting at 1 s, capping at 32 s

#### Dead-Letter Queue Pattern

When `createListener` is called with `deadLetter: true` (default), the client sets up:

```
[main queue] ──(nack, no requeue)──▶ [exchange: {queue}.dlx] ──▶ [DLQ: {queue}.dlq]
```

- Main queue TTL: 24 hours, max 3 delivery attempts
- DLQ TTL: 30 days
- Queue type: `quorum` (RabbitMQ quorum queues)
- If a queue already exists with different arguments (AMQP error 406) and is empty, the client deletes and recreates it automatically

#### Message Retry Logic

The consumer tracks `x-delivery-count` header to count delivery attempts:

- `onMessage` returns `true` → `ack`
- `onMessage` returns `false` and attempts ≤ `defaultMaxRetries` (3) → `nack` with requeue
- `onMessage` returns `false` and attempts > `defaultMaxRetries` → `nack` without requeue → message moves to DLQ
- `onMessage` throws → `nack` without requeue immediately

#### Logger Interface

```typescript
interface AMQPClientLoggerInterface {
  debug(message: string, ...args: any[]): void
  info(message: string, ...args: any[]): void
  warn(message: string, ...args: any[]): void
  error(message: string, ...args: any[]): void
}
```

Defaults to `console`. Pass a custom logger (e.g., Pino, Winston) via the constructor's `logger` option.

## Git Worktree Policy

All agents must follow this policy when working with git worktrees to ensure consistency across sessions and avoid orphaned worktrees.

### Location Convention

Worktrees must always be created as siblings of the main repo, under a dedicated directory named `amqp-client.worktrees`:

```
~/path/to/repos/
  amqp-client/                              ← main repo
  amqp-client.worktrees/
    fix-reconnect-bug/                      ← worktree for branch fix/reconnect-bug
    feat-custom-headers/                    ← worktree for branch feat/custom-headers
```

Always name the worktree folder after the branch, replacing `/` with `-`. Use `{branch-name}` to refer to the git branch and `{worktree-dir}` to refer to the folder name. For example, branch `feat/custom-headers` → folder `feat-custom-headers`.

### Lifecycle

Agents must follow this exact sequence — no steps may be skipped:

**1. Create**

```bash
git worktree add -b {branch-name} ../amqp-client.worktrees/{worktree-dir} main
cd ../amqp-client.worktrees/{worktree-dir}
```

**2. Setup (mandatory before any other command)**

```bash
npm install
```

No `.env` file is required — this is a library with no runtime configuration.

**3. Implement**

Work normally. All commands (`npm test`, `npm run build`, etc.) run from within the worktree directory.

**4. Cleanup**

The agent must **not** remove the worktree on its own initiative. Cleanup is only appropriate once the implementation plan has been fully executed and all PRs have been created. At that point, the agent must ask the user explicitly:

> "The plan is complete and all PRs have been created. Should I remove the worktree for `{worktree-dir}`?"

Only proceed with removal after the user confirms:

```bash
cd /path/to/amqp-client
git worktree remove ../amqp-client.worktrees/{worktree-dir}
```

If the worktree has uncommitted work that should be discarded:

```bash
git worktree remove --force ../amqp-client.worktrees/{worktree-dir}
```

### Maintenance

Run `git worktree list` before creating a new worktree to inspect the current state.
Run `git worktree prune` from the main repo if stale worktree references accumulate, for example after a crash or interrupted session.

## Versioning & Release Process

### Semver Policy

This is a published library. Every version bump must follow semantic versioning strictly:

| Change type | Version bump | Examples |
|---|---|---|
| Breaking change | **major** | Remove or rename exported symbol, change method signature, change queue behavior/defaults |
| New capability (backwards-compatible) | **minor** | New optional field on an interface, new method, new option |
| Bug fix (no API change) | **patch** | Fix reconnection logic, fix retry count, internal refactor |

### What Counts as a Breaking Change

- Removing or renaming any symbol exported from `index.ts`
- Changing the signature of `sendMessage`, `createListener`, or `close`
- Adding a **required** field to any exported interface
- Changing queue topology defaults (`queueTTL`, `deadLetterQueueTTL`, `defaultMaxRetries`) — all
  services using the library share queue declarations, so these values are part of the contract

### Deprecation Cycle

Do not remove an exported symbol in the same release that deprecates it:

1. **Deprecation release (minor bump)**: mark with a JSDoc `@deprecated` comment, add a replacement
2. **Removal release (major bump)**: remove in a subsequent major version with a changelog notice

### Release Steps

```bash
npm run format          # Prettier
npm test                # All tests must pass
npm run build           # TypeScript + Rollup — must produce dist/ cleanly
# Bump version in package.json (follow semver above)
git add package.json
git commit -m "chore: release vX.Y.Z"
npm publish
```

Keep `dist/` out of version control — it is published to npm but not committed to git.

## Critical Development Guidelines

### Public API Stability

- **Any change to exported types, interfaces, or method signatures is a breaking change** — bump the minor version for new non-breaking additions, major version for breaking changes
- Do not rename or remove exported symbols without a deprecation cycle
- Keep `index.ts` as the sole entry point — never add deep import paths as public API

### Keeping the Package Lightweight

- `amqplib` is the only runtime dependency — keep it that way unless there is a strong reason
- Avoid adding runtime dependencies for things that consumers can inject (logging, serialization)
- Do not add framework-specific code (e.g., NestJS, Express) into the library itself

### Code Formatting Rules

- **No trailing whitespace**: Never add trailing whitespace to any lines in files
- **Consistent line endings**: Use LF line endings
- **Final newline**: End files with a single newline character
- Run `npm run format` before committing to keep Prettier formatting consistent
