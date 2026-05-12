# Architecture & Implementation Details

## Core Patterns

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

## Reconnection Strategy

- Uses exponential backoff: `delay = Math.min(initialDelay * 2^attempt, maxDelay)`
- Resets counter on successful connection
- Logs warning on each attempt; error when max attempts reached
- Reference: `src/amqp-client.ts:calculateBackoffDelay()`, `reconnect()`

## Dead-Letter Queue Design

- Automatic setup when `ConsumeOptions.deadLetter === true` (default)
- Queue naming: `{queueName}-dlq` for dead-letter queue
- Messages move to DLQ after max retries exceeded
- TTL prevents orphaned messages (30-day retention)

## Message Correlation

- Optional `correlationId` for tracking related messages across services
- Passed in `MessagePublishOptions` and returned in `AMQPMessage.metadata`
- Useful for request-reply patterns and distributed tracing

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
