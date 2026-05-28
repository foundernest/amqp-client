# Feature: Reconnection

## Summary

The client reconnects automatically when the AMQP connection or a channel is closed unexpectedly.
Reconnection uses exponential backoff with jitter to avoid broker overload.

## Algorithm

```
delay = min(maxDelay, initialDelay × 2^attempt) + random(0..1000 ms)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `initialDelay` | 1000 ms | Delay before first reconnection attempt |
| `maxDelay` | 32000 ms | Upper bound on delay between attempts |
| `maxAttempts` | 50 | Maximum attempts before giving up |

Example delay sequence (no jitter): 1 s → 2 s → 4 s → 8 s → 16 s → 32 s → 32 s → …

## Configuration

```typescript
const client = new AMQPClient({
  host: 'localhost',
  username: 'guest',
  password: 'guest',
  reconnection: {
    initialDelay: 500,
    maxDelay: 16000,
    maxAttempts: 20,
  },
})
```

## Trigger Points

| Event | Source |
|-------|--------|
| `connection.on('error')` | Broker-side error (e.g., forced close) |
| `connection.on('close')` | Connection dropped |
| `connect()` throws | Failed initial connection attempt |

## What Reconnects and What Doesn't

| Component | Behavior on reconnect |
|-----------|----------------------|
| `connection` | Recreated by `connect()` |
| Producer channel | Nulled on error/close; recreated lazily on next `sendMessage` |
| Consumer channels | Removed from map on error/close; **listeners are not re-registered** |

Consumer listener re-registration after channel recovery is a known gap — see
[tech debt](../tech-debt/consumer-not-restored-on-channel-error.md).

## After maxAttempts

The client logs an error and stops trying. No process exit, no exception. The service must be
restarted to resume normal operation.

## Related

- [ADR-05: Lazy Connection with Exponential Backoff](../adr/05-lazy-connection-with-exponential-backoff.md)
- `src/amqp-client.ts:49` — `reconnect()` implementation
- `src/amqp-client.ts:65` — `calculateBackoffDelay()` implementation
