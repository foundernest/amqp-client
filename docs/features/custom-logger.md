# Feature: Custom Logger

## Summary

By default the client logs to `console`. A custom logger implementing `AMQPClientLoggerInterface`
can be injected via the constructor to integrate with Pino, Winston, or any structured logging
library.

## Interface

```typescript
interface AMQPClientLoggerInterface {
  debug(message: string, ...args: any[]): void
  info(message: string, ...args: any[]): void
  warn(message: string, ...args: any[]): void
  error(message: string, ...args: any[]): void
}
```

The interface is intentionally narrow. Any logger with `debug`, `info`, `warn`, and `error` methods
is compatible without an adapter — including `console`, Pino, and Winston out of the box.

## Usage

```typescript
import pino from 'pino'
import { AMQPClient } from 'foundernest-amqp-client'

const logger = pino({ name: 'amqp-client' })

const client = new AMQPClient({
  host: 'localhost',
  username: 'guest',
  password: 'guest',
  logger,
})
```

## Log Levels Used

| Level | When |
|-------|------|
| `debug` | Channel creation, queue assertions, message send/receive lifecycle |
| `info` | Connection established, channels and connection closed |
| `warn` | Connection closed unexpectedly, reconnection attempts, DLQ routing |
| `error` | Connection failure, channel errors, message processing errors |

## Notes

- The logger is never tested in unit tests. Do not assert log output in tests (per AGENTS.md).
- `AMQPClientLoggerInterface` is exported from `index.ts` so consumers can type their custom logger
  wrappers.

## Related

- `src/amqp-client-logger.interface.ts` — interface definition
- `src/amqp-client.ts:24` — logger injected in constructor with `console` as default
