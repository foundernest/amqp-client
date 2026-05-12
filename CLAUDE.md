# CLAUDE.md

Guidance for contributing to `foundernest-amqp-client`, a TypeScript-based AMQP client library for RabbitMQ. When developing, examine existing code patterns in `src/` and test examples in `tests/` before starting work.

For deeper context, refer to the docs in `docs/`:
- `docs/architecture.md` — core patterns, connection management, reconnection strategy, DLQ design, build process
- `docs/examples.md` — usage examples, custom logger, test writing patterns

## Preferred Languages & Tools

- **TypeScript** for all code
- **yarn** for dependency management
- **Vitest** for testing
- **Prettier** for formatting

## Coding Standards

- Follow **clean code principles**: descriptive names, single-responsibility functions, modular design
- Prioritize **TypeScript's type safety**: use strict typing, interfaces, avoid `any`
- Use camelCase for functions, methods, and variables
- Keep code **DRY**: reuse existing utilities, avoid duplication
- No trailing whitespace, LF line endings, final newline in all files

## TypeScript & Type Safety

- Leverage strict TypeScript configuration (`tsconfig.json` uses strict mode)
- Define interfaces for all public API contracts (see `src/amqp-client.interface.ts` as reference)
- Use **JSDoc** comments on public types and interfaces to document purpose, parameters, and generics
- Avoid `any` types; use generics (`<T>`) for reusable, type-safe abstractions

## Error Handling

- Use `try/catch` for async operations and connection failures
- Log errors at appropriate levels: `error()` for failures, `warn()` for recovery attempts
- Always propagate or log errors; never silently swallow exceptions
- Connection errors should trigger reconnection logic (see `amqp-client.ts:reconnect()`)

## Code Organization

### Folder Structure

```
src/
  amqp-client.ts                    ← Main implementation
  amqp-client.interface.ts          ← Public API contract
  amqp-client.types.ts              ← TypeScript types and interfaces
  amqp-client-logger.interface.ts   ← Logger contract
  index.ts                          ← Public exports

tests/
  amqp-client.spec.ts               ← Unit tests (mirrors src/ file structure)

docs/
  architecture.md                   ← Core patterns and implementation details
  examples.md                       ← Usage examples and test patterns
```

### Key Files

- **`src/amqp-client.ts`** - Core AMQP client logic: connection, publishing, consuming, reconnection strategy
- **`src/amqp-client.interface.ts`** - Public interface (`AMQPClientInterface`) defining `sendMessage()`, `createListener()`, `close()`
- **`src/amqp-client.types.ts`** - Type definitions: `AMQPMessage<T>`, `ConnectionOptions`, `MessagePublishOptions`, `ConsumeOptions`
- **`src/amqp-client-logger.interface.ts`** - Logger contract with `debug()`, `info()`, `warn()`, `error()` methods

## Testing

- Tests live in `tests/`, mirroring source files
- Use **Vitest** with `vi.mock('amqplib')`; avoid mocking internal library behavior
- Use `beforeAll()` for common mocks, `afterEach()` for cleanup
- See `docs/examples.md` for test writing patterns

## Development Commands

```bash
yarn test                           # Run all tests
yarn test amqp-client              # Run tests matching pattern
yarn format                         # Format code with Prettier
yarn build                          # Full build: tsc → rollup
yarn build:esm                      # TypeScript to ESM
yarn build:types                    # Generate .d.ts files
```

## TypeScript Configuration

- **Target**: ES2020 | **Module**: ESNext | **Strict mode**: enabled
- Output: `dist/` with declaration files (`.d.ts`)

## Pull Request Protocol

### Branch & Commit Naming

Use Conventional Commits with lowercase kebab-case branches:

- **Branches**: `feat/queue-priority-support`, `fix/reconnection-delay`, `chore/update-dependencies`
- **Commits**: `feat: add priority header to message publish`, `fix: handle connection timeout edge case`

### Before Opening a PR

1. Run tests: `yarn test`
2. Format code: `yarn format`
3. Build successfully: `yarn build`
4. Verify type checking passes (strict mode)
5. Ensure no unrelated changes

### PR Body Template

```markdown
## Why
- Describe the problem or feature request

## What
- Summarize main changes (2-4 bullets)

## Validation
- Tests added/updated: [list test cases]
- Build status: ✅ passing

## Risks
- Low / None / [specific concern]
```

### Scope & Review

- Keep PRs under 300 changed lines
- Prefer small, focused changes over bundling
- Respond to review comments in PR threads before resolving

## Security & Dependencies

- Avoid hardcoding secrets; use environment variables
- Validate input to `sendMessage()` and `createListener()`
- Vet dependencies before adding (check for known vulnerabilities)
- Keep `amqplib` and dev tools up to date
