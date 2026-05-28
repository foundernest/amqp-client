# ADR-01: Quorum Queues as Default Queue Type

## Status

Accepted

## Context

When declaring AMQP queues, RabbitMQ offers two main queue types: classic and quorum. Classic queues
use a single-node replicated log. Quorum queues use the Raft consensus algorithm and replicate across
multiple cluster nodes, providing stronger durability guarantees at the cost of some throughput.

The library creates queues on behalf of its consumers via `createListener`. The queue type must be
consistent — any mismatch between a queue's declared type and what a reconnecting consumer expects
triggers AMQP error 406 (PRECONDITION_FAILED).

## Decision

Use `x-queue-type: quorum` for all queues (main queue and DLQ) created by the client.

## Alternatives Considered

- **Classic queues**: Higher throughput, but messages can be lost on broker node failure. Unacceptable
  for the financial and pipeline data processed by Foundernest services.
- **Stream queues**: Designed for log-style, high-throughput scenarios. Not a fit for the task-queue
  usage pattern here.

## Consequences

- Messages survive broker restarts and single-node failures in a cluster
- Minimum RabbitMQ version 3.8 required
- `x-max-retries` queue argument is supported on quorum queues (RabbitMQ 3.10+), enabling broker-side
  delivery count tracking alongside the client-side `x-delivery-count` check
- Per-message TTL is set via the `expiration` property on publish, not via `x-message-ttl` on the
  main queue, to keep TTL enforcement as a per-message concern
- The DLQ uses `x-message-ttl` to enforce 30-day retention at the queue level

## References

- `src/amqp-client.ts:160` — `assertQueueOptions` where `x-queue-type: quorum` is set
- [ADR-03](./03-dead-letter-queue-auto-setup.md) — DLQ setup that also uses quorum queues
