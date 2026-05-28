# Feature: Message Priority

## Summary

Messages can be assigned a numeric priority (0–255) to influence delivery order within a queue.
Higher values mean higher priority. Added in v0.2.6.

## API

```typescript
await client.sendMessage('tasks', payload, { priority: 10 })
```

The `priority` field is part of `MessagePublishOptions`:

```typescript
interface MessagePublishOptions {
  headers?: Record<string, unknown>
  correlationId?: string
  priority?: number  // 0–255, higher = more urgent; omit for no priority
}
```

## Requirement: Queue Must Support Priority

RabbitMQ only honours the `priority` AMQP property if the queue was declared with `x-max-priority`.
Sending a priority value to a standard queue silently ignores it.

`createListener` does **not** declare `x-max-priority` — priority-aware queues must be set up
externally (e.g., via the RabbitMQ management UI, Terraform, or an infrastructure script).

## Example

```typescript
// High-priority job (enterprise tier)
await client.sendMessage('company.enrichment', { companyId: 'abc-123', tier: 'enterprise' }, {
  priority: 100,
})

// Standard job (free tier)
await client.sendMessage('company.enrichment', { companyId: 'xyz-789', tier: 'free' }, {
  priority: 1,
})
```

## Related

- `src/amqp-client.types.ts:22` — `MessagePublishOptions` type definition
- `src/amqp-client.ts:82` — `priority` passed through to `channel.sendToQueue`
