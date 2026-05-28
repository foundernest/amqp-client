# ADR-03: Dead Letter Queue Auto-Setup with Convention-Based Naming

## Status

Accepted

## Context

When a consumer fails to process a message after several retries, the message needs a place to go.
Options:

1. Discard silently
2. Require operators to set up DLQ infrastructure manually before calling `createListener`
3. Auto-create DLQ infrastructure when a listener is registered

Discarding messages is unacceptable for business-critical pipelines. Manual setup adds operational
burden and is error-prone — services would silently drop failed messages if they forgot to enable it.

## Decision

When `createListener` is called with `deadLetter: true` (the default), the client automatically
asserts:

```
[main queue] ──(nack, no requeue)──▶ [exchange: {queue}.dlx] ──▶ [DLQ: {queue}.dlq]
```

| Resource | Name pattern | Type |
|----------|-------------|------|
| Dead letter exchange | `{queue}.dlx` | direct |
| Routing key | `{queue}.dead` | — |
| Dead letter queue | `{queue}.dlq` | quorum |

TTL constants are hardcoded and shared across all services:

| Constant | Value | Reason |
|----------|-------|--------|
| `queueTTL` | 24 hours | Per-message expiration on publish — 3 attempts within a day |
| `deadLetterQueueTTL` | 30 days | Via `x-message-ttl` on the DLQ — investigation window |
| `defaultMaxRetries` | 3 | Tracked client-side via `x-delivery-count` |

The TTL values are hardcoded intentionally: they are encoded into queue declarations and must be
identical across all services consuming the same queue. A mismatch triggers AMQP error 406.

## Alternatives Considered

- **Opt-in DLQ** (`deadLetter: false` default): simpler, but services would silently drop failed
  messages unless they remembered to enable it. The risk of silent data loss outweighs setup overhead.
- **Configurable TTLs per consumer**: would require coordination across all services sharing a queue.
  Not feasible in a distributed system without a central schema registry.

## Consequences

- DLQ is enabled by default — consumers must explicitly pass `{ deadLetter: false }` to skip it
- Queue argument mismatches (AMQP error 406) are handled: if the queue is empty it is deleted and
  recreated; if it has messages, the listener starts without re-declaring
- All services using the library share the same TTL contract — upgrading the library with different
  TTL defaults requires a coordinated migration (treat as a breaking change)

## References

- `src/amqp-client.ts:138` — `getConsumerChannel` where DLQ options are applied
- `src/amqp-client.ts:195` — `bindQueueToChannel` where exchange, DLQ, and binding are asserted
- [ADR-01](./01-quorum-queues-as-default-queue-type.md) — why quorum queues are used for both main
  queue and DLQ
- `docs/tech-debt/messageexpiration-constants-not-overridable.md` — risk of TTL mismatch during deploys
