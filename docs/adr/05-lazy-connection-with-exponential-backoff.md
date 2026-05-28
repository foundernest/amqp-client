# ADR-05: Lazy Connection with Exponential Backoff Reconnection

## Status

Accepted

## Context

When should the AMQP client establish its connection to the broker? Two options:

1. **Eager**: connect in the constructor or at service startup
2. **Lazy**: connect on the first operation

Additionally, what reconnection strategy should be used when the broker is unavailable or drops
the connection?

## Decision

**Connection**: Lazy — established on the first `sendMessage` or `createListener` call, not in the
constructor.

**Reconnection algorithm**:

```
delay = min(maxDelay, initialDelay × 2^attempt) + random(0..1000 ms)
```

Defaults: `initialDelay = 1000 ms`, `maxDelay = 32000 ms`, `maxAttempts = 50`.

## Rationale

**Lazy connection:**
- Services that import the library but do not immediately send or receive messages do not fail at
  startup when the broker is not yet ready
- Aligns with dependency-injection patterns where the client is instantiated early but used later
- Consistent with how `amqplib` itself works (no connection until `connect()` is called)

**Exponential backoff + jitter:**
- Exponential backoff avoids hammering the broker during restarts
- Jitter (`+ random(0..1000 ms)`) prevents a thundering-herd where multiple service instances
  reconnect simultaneously after a broker restart
- Capping at `maxDelay` (default 32 s) keeps recovery time bounded even during extended outages
- `maxAttempts = 50` allows roughly 25+ minutes of total retry time before giving up

## Consequences

- The first operation after a service starts will be slightly slower (includes connection setup)
- If the broker is unavailable at startup, the first call will not fail immediately — it will block
  until connection succeeds or `maxAttempts` is exhausted
- After `maxAttempts` failures, the client logs an error and stops trying; the service must restart
- There is no circuit-breaker or health-check endpoint — connection state is internal

## References

- `src/amqp-client.ts:27` — `connect()` method (lazy, called from `getProducerChannel` and
  `createConsumerChannel`)
- `src/amqp-client.ts:65` — `calculateBackoffDelay()` — the algorithm
- `src/amqp-client.ts:49` — `reconnect()` — retry loop with `maxAttempts` guard
