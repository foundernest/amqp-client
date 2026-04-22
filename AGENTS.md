# AGENTS.md

Guidance for contributing to `foundernest-amqp-client`, a TypeScript-based AMQP client library for RabbitMQ. When developing, examine existing code patterns in `src/` and test examples in `tests/` before starting work.

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
- Example: `AMQPMessage<T>` allows type-safe message handling

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
```

### Key Files

- **`src/amqp-client.ts`** - Core AMQP client logic: connection, publishing, consuming, reconnection strategy
- **`src/amqp-client.interface.ts`** - Public interface (`AMQPClientInterface`) defining `sendMessage()`, `createListener()`, `close()`
- **`src/amqp-client.types.ts`** - Type definitions: `AMQPMessage<T>`, `ConnectionOptions`, `MessagePublishOptions`, `ConsumeOptions`
- **`src/amqp-client-logger.interface.ts`** - Logger contract with `debug()`, `info()`, `warn()`, `error()` methods

## Architecture & Patterns

### Core Patterns

**Public Interface**
- The library exports a single class `AMQPClient` implementing `AMQPClientInterface`
- All public methods are type-safe and support generics for message payloads
- Example: `sendMessage<T>(queueName: string, message: T, options?: MessagePublishOptions): Promise<boolean>`

**Connection Management**
- Single connection per client instance, stored in `this.connection`
- Lazy connection: established on first `createListener()` or `sendMessage()` call
- Reconnection uses exponential backoff; configurable via `ConnectionOptions.reconnection`
- Default: `initialDelay: 1000ms`, `maxDelay: 32000ms`, `maxAttempts: 50`

**Message Handling**
- **Publishing** (`sendMessage`): Messages serialized to JSON, optional headers and correlation ID
- **Consuming** (`createListener`): Messages parsed, wrapped in `AMQPMessage<T>` with metadata
- **Dead-letter queues**: Automatic for failed messages; configurable via `ConsumeOptions.deadLetter`
- **TTL defaults** (immutable per library design):
  - Main queue: 24 hours (3 retry attempts)
  - Dead-letter queue: 30 days

**Logging**
- Accept optional logger via constructor (defaults to `console`)
- Must implement `AMQPClientLoggerInterface`; allows custom loggers (Pino, Winston, etc.)
- Use emoji prefixes for clarity: `📭️` (connect), `🚨` (error), `⚠️` (warn), etc.

## Testing & Coverage

### Test Structure

- Tests coexist in `tests/` mirroring source files (e.g., `amqp-client.spec.ts` tests `amqp-client.ts`)
- Use **Vitest** with mocking for amqplib (vi.mock('amqplib'))
- Avoid mocking internal library behavior; test actual side effects

### Testing Strategy

- **Unit tests**: Connection logic, message serialization, reconnection delays
- **Integration tests**: Full publish-subscribe flow with mock broker
- **Edge cases**: Connection failures, message retries, dead-letter routing
- Use `beforeAll()` to set up common mocks, `afterEach()` to clean up
- Example test naming: `it('reconnects with exponential backoff after connection failure')`

### Writing Tests

```typescript
// DO: Test behavior, not implementation details
it('sends message with correlation ID', async () => {
  await client.sendMessage('queue', { data: 'value' }, { correlationId: '123' })
  expect(mockChannel.sendToQueue).toHaveBeenCalledWith(
    'queue',
    expect.anything(),
    expect.objectContaining({ correlationId: '123' })
  )
})

// DON'T: Mock internal methods or assert on logs
// DON'T: Test what amqplib does; assume it works
```

## Development Commands

### Testing

```bash
yarn test                           # Run all tests
yarn test amqp-client              # Run tests matching pattern
```

### Code Quality

```bash
yarn format                         # Format code with Prettier
yarn build                          # Full build: tsc → rollup
yarn build:esm                      # TypeScript to ESM
yarn build:types                    # Generate .d.ts files
```

### Debugging Build Output

```bash
ls -la dist/                        # Verify build artifacts
cat dist/index.d.ts                 # Check type definitions
```

## TypeScript Configuration

- **Target**: ES2020 (modern async/await support)
- **Module**: ESNext (tree-shakeable)
- **Strict mode**: Enabled (no `implicit any`, null checking required)
- Output: `dist/` with declaration files (`.d.ts`)

## Build & Distribution

### Build Process

1. **`tsc`** → Compile TypeScript to JavaScript in `dist/`
2. **`tsc --declaration`** → Generate type definitions (`.d.ts`)
3. **`rollup`** → Bundle ESM format with CommonJS dependencies resolved

### Output

- `dist/index.js` - ESM bundle for direct import
- `dist/index.d.ts` - Type definitions for IDE support
- All source files preserved in `dist/` for source maps

### Package Metadata

- **Name**: `foundernest-amqp-client`
- **Entry point**: `dist/index.js`
- **Types**: `dist/index.d.ts`
- **Distribution files**: `dist/`, `README.md`, `package.json`

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
- Explain business/technical impact

## What

- Summarize main changes (2-4 bullets)
- Focus on what reviewers need to know

## Validation

- Tests added/updated: [list test cases]
- Manual testing: [if applicable]
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

## Common Patterns & Examples

### Using the Client

```typescript
import { AMQPClient } from 'foundernest-amqp-client'

// Create client
const client = new AMQPClient({
  host: 'localhost',
  username: 'guest',
  password: 'guest',
  reconnection: {
    initialDelay: 1000,
    maxDelay: 32000,
    maxAttempts: 50,
  },
})

// Send typed message
interface UserEvent { userId: string; action: string }
await client.sendMessage<UserEvent>('user-events', { userId: '123', action: 'login' })

// Create listener
await client.createListener<UserEvent>('user-events', async (msg) => {
  console.log('User:', msg.content.userId)
  console.log('Correlation:', msg.metadata.correlationId)
  return true // acknowledge
})

// Close
await client.close()
```

### Custom Logger

```typescript
import { AMQPClientLoggerInterface } from 'foundernest-amqp-client'

class MyLogger implements AMQPClientLoggerInterface {
  debug(msg: string, ...args: any[]) { console.debug(`[DEBUG] ${msg}`, args) }
  info(msg: string, ...args: any[]) { console.info(`[INFO] ${msg}`, args) }
  warn(msg: string, ...args: any[]) { console.warn(`[WARN] ${msg}`, args) }
  error(msg: string, ...args: any[]) { console.error(`[ERROR] ${msg}`, args) }
}

const client = new AMQPClient({
  host: 'localhost',
  username: 'guest',
  password: 'guest',
  logger: new MyLogger(),
})
```

## Key Implementation Details

### Reconnection Strategy

- Uses exponential backoff: `delay = Math.min(initialDelay * 2^attempt, maxDelay)`
- Resets counter on successful connection
- Logs warning on each attempt; error when max attempts reached
- Reference: `src/amqp-client.ts:calculateBackoffDelay()`, `reconnect()`

### Dead-Letter Queue Design

- Automatic setup when `ConsumeOptions.deadLetter === true` (default)
- Queue naming: `{queueName}-dlq` for dead-letter queue
- Messages move to DLQ after max retries exceeded
- TTL prevents orphaned messages (30-day retention)

### Message Correlation

- Optional `correlationId` for tracking related messages across services
- Passed in `MessagePublishOptions` and returned in `AMQPMessage.metadata`
- Useful for request-reply patterns and distributed tracing

## References

- **README**: Comprehensive usage guide and API reference
- **Type Definitions**: `src/amqp-client.types.ts` for all contract types
- **Interface**: `src/amqp-client.interface.ts` for public method signatures
- **Tests**: `tests/amqp-client.spec.ts` for usage examples and edge cases
