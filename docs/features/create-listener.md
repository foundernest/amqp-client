# Feature: createListener

## Summary

`createListener` subscribes to a named AMQP queue. The provided callback is invoked for each
received message. The library handles ack/nack automatically based on the callback's return value.

## API

```typescript
createListener<T extends object>(
  queueName: string,
  onMessage: (msg: AMQPMessage<T>) => Promise<boolean>,
  options?: ConsumeOptions
): Promise<void>
```

### Callback contract

| Return value | Effect |
|--------------|--------|
| `true` | Message is `ack`'d — processing succeeded |
| `false` | Message is `nack`'d with or without requeue (see retry logic below) |
| throws | Message is `nack`'d without requeue immediately |

### Options

```typescript
interface ConsumeOptions {
  deadLetter?: boolean    // Enable DLQ setup (default: true)
  correlationId?: string  // Only process messages with this correlationId; requeue others
}
```

## Retry Logic

Delivery attempts are tracked via the `x-delivery-count` header set by the broker:

```
attempts = (x-delivery-count ?? 0) + 1

result === true   → ack
result === false  → nack(requeue = attempts <= defaultMaxRetries)  // defaultMaxRetries = 3
throws            → nack(requeue = false)
```

After `defaultMaxRetries` failed attempts, the message is `nack`'d without requeue and routed
to the DLQ (if enabled).

## Message Shape

```typescript
interface AMQPMessage<T> {
  content: T                          // Deserialized JSON payload
  metadata: {
    headers?: Record<string, unknown>
    correlationId?: string
    redelivered: boolean
  }
}
```

## Example

```typescript
await client.createListener<CompanyJob>('company.enrichment', async (msg) => {
  const { companyId } = msg.content
  try {
    await enrichCompany(companyId)
    return true
  } catch (err) {
    logger.error(err)
    return false  // Will retry up to 3 times, then route to DLQ
  }
})
```

## Notes

- Each `createListener` call creates a dedicated channel with `prefetch(1)`, ensuring at-most-one
  in-flight message per listener.
- The queue is declared (asserted) by the consumer, not the producer. Sending to a queue before
  any listener has been registered will create the queue implicitly on the broker side only if
  it already exists — otherwise the message may be dropped.
- If a queue already exists with different arguments (AMQP error 406), the library attempts to
  recreate it if it is empty.
- Consumer listeners are **not** re-registered after a channel error — see
  [tech debt](../tech-debt/consumer-not-restored-on-channel-error.md).

## Related

- [Dead Letter Queue](./dead-letter-queue.md)
- [Reconnection](./reconnection.md)
- `src/amqp-client.ts:103` — `createListener` implementation
