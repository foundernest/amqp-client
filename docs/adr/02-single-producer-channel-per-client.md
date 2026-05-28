# ADR-02: Single Shared Producer Channel, One Consumer Channel Per Queue

## Status

Accepted

## Context

AMQP 0-9-1 allows multiple channels to be multiplexed over a single connection. Each channel has
independent state: prefetch settings, transaction state, and confirm mode. The question is how to
allocate channels across publishing (sending) and consuming operations.

## Decision

- **Producer**: one shared channel per `AMQPClient` instance, created lazily on the first
  `sendMessage` call and reused for all subsequent sends.
- **Consumer**: one dedicated channel per `createListener` call, keyed by
  `consumer-{queueName}-{timestamp}`.

## Rationale

| Concern | Producer (shared) | Consumer (dedicated) |
|---------|-------------------|----------------------|
| Prefetch | Not needed — publishers do not consume | Each queue needs independent prefetch (set to 1) |
| Isolation | Publishes are fire-and-forget, no state to isolate | Slow or failed consumers must not starve other queues |
| Overhead | Low — one channel for all publishes | Acceptable — one channel per subscribed queue |

## Consequences

- If the producer channel closes (error or broker restart), `this.producer` is set to `null` and
  recreated on the next `sendMessage` call. There is no buffering during the gap.
- Consumer channels are stored in `this.consumers: Map<string, amqp.Channel>` keyed by
  `consumer-{queueName}-{timestamp}`; the timestamp ensures uniqueness on re-registration.
- A crashed consumer channel removes itself from the map but does not re-register the listener
  automatically — see [tech debt](../tech-debt/consumer-not-restored-on-channel-error.md).

## References

- `src/amqp-client.ts:95` — `getProducerChannel` (lazy creation, error handler nulls `this.producer`)
- `src/amqp-client.ts:218` — `createConsumerChannel` (prefetch 1, stored in `this.consumers`)
- `docs/tech-debt/consumer-not-restored-on-channel-error.md` — known gap in channel recovery
