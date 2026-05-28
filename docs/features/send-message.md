# Feature: sendMessage

## Summary

`sendMessage` publishes a JSON-serialized message to a named AMQP queue. Returns `true` if the
broker accepted the message, `false` on any failure (never throws).

## API

```typescript
sendMessage<T extends object>(
  queueName: string,
  message: T,
  options?: MessagePublishOptions
): Promise<boolean>
```

### Options

```typescript
interface MessagePublishOptions {
  headers?: Record<string, unknown>  // Custom headers attached to the message
  correlationId?: string             // Identifier for message correlation/tracking
  priority?: number                  // Message priority (0–255, higher = more urgent)
}
```

## Behavior

1. Creates a producer channel lazily on the first call (shared across all subsequent sends)
2. Serializes `message` as JSON and wraps it in a `Buffer`
3. Calls `channel.sendToQueue` with:
   - `persistent: true`, `deliveryMode: 2` — survives broker restarts
   - `contentType: 'application/json'`
   - `expiration: queueTTL` (24 hours, set per-message)
4. Returns `false` (never throws) if publishing fails

## Example

```typescript
const client = new AMQPClient({ host: 'localhost', username: 'guest', password: 'guest' })

const sent = await client.sendMessage('company.enrichment', { companyId: 'abc-123' })

// With options
await client.sendMessage('company.enrichment', { companyId: 'abc-123' }, {
  correlationId: 'request-xyz',
  headers: { source: 'api-gateway' },
  priority: 5,
})
```

## Notes

- The producer channel is shared across all `sendMessage` calls. A channel error resets it to
  `null`; the next call creates a new one.
- Queue declaration is the consumer's responsibility via `createListener`. The producer does not
  assert the queue before sending.
- `priority` requires the queue to be declared with `x-max-priority`. The library does not set
  this argument on the queue — priority-aware queues must be configured externally.

## Related

- [Message Priority](./message-priority.md)
- [Reconnection](./reconnection.md)
- [ADR-04: JSON-Only Serialization](../adr/04-json-only-message-serialization.md)
- `src/amqp-client.ts:75` — `sendMessage` implementation
