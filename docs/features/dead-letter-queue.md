# Feature: Dead Letter Queue

## Summary

When a message cannot be processed after the configured number of retries, it is routed to a dead
letter queue (DLQ) for later inspection. The library auto-creates the necessary AMQP topology when
`createListener` is called with `deadLetter: true` (the default).

## Topology

```
[main queue]
  ├── x-queue-type: quorum
  ├── x-max-retries: 3
  └── x-dead-letter-exchange: {queue}.dlx
      └── routing-key: {queue}.dead
          └── [DLQ: {queue}.dlq]
                ├── x-queue-type: quorum
                └── x-message-ttl: 30 days
```

## Naming Convention

| Resource | Pattern | Example (queue = `company.enrichment`) |
|----------|---------|---------------------------------------|
| Dead letter exchange | `{queue}.dlx` | `company.enrichment.dlx` |
| DLQ | `{queue}.dlq` | `company.enrichment.dlq` |
| Routing key | `{queue}.dead` | `company.enrichment.dead` |

## TTL Constants

| Setting | Value | Where applied |
|---------|-------|---------------|
| Main queue TTL | 24 hours | Per-message `expiration` on publish |
| DLQ TTL | 30 days | `x-message-ttl` on the DLQ |
| Max retries | 3 | Client-side via `x-delivery-count` |

These values are intentionally hardcoded — they are encoded into queue declarations and must be
identical across all services sharing a queue. See
[ADR-03](../adr/03-dead-letter-queue-auto-setup.md) and
[tech debt](../tech-debt/messageexpiration-constants-not-overridable.md).

## Queue Conflict Recovery (AMQP 406)

If a queue already exists with different arguments (PRECONDITION_FAILED):

1. The errored channel is discarded (AMQP channels are unusable after a channel-level error)
2. A new channel checks the queue's message count
3. If **empty** → queue is deleted and recreated with current arguments
4. If **non-empty** → listener starts without re-declaring (existing arguments are preserved)

## Disabling DLQ

Pass `{ deadLetter: false }` to skip DLQ setup entirely:

```typescript
await client.createListener('ephemeral.tasks', handler, { deadLetter: false })
```

Useful for queues where failed messages do not need investigation.

## Related

- [ADR-03: Dead Letter Queue Auto-Setup](../adr/03-dead-letter-queue-auto-setup.md)
- [createListener](./create-listener.md)
- `src/amqp-client.ts:138` — `getConsumerChannel` where DLQ options are assembled
- `src/amqp-client.ts:195` — `bindQueueToChannel` where exchange, DLQ, and binding are asserted
