# Tech Debt: Consumer Listeners Not Restored After Channel Error

## Problem

When a consumer channel errors or closes, it is removed from `this.consumers` — but the
`channel.consume()` callback registered in `createListener` is not re-registered. Messages on
that queue stop being processed silently.

## Where Code Lives

- `src/amqp-client.ts:222` — `channel.on('error', () => this.consumers.delete(queueName))`
- `src/amqp-client.ts:226` — `channel.on('close', () => this.consumers.delete(queueName))`
- `src/amqp-client.ts:103` — `createListener`: calls `getConsumerChannel` once, registers
  `channel.consume()` once — never called again after channel loss

## Current Behavior

1. Consumer channel errors (e.g., broker restart, channel-level AMQP error)
2. Channel is removed from `this.consumers`
3. Connection may eventually reconnect
4. No code re-calls `createListener` or `channel.consume()`
5. The queue accumulates unprocessed messages with no consumer

## Impact

- Silent loss of consuming capacity — no error is thrown, the service continues running
- Messages pile up on the queue until the service is restarted or a new listener is registered
- Particularly problematic in long-running services that survive broker restarts

## Suggested Fix

Store the `(queueName, onMessage, options)` arguments passed to `createListener`. On channel
error/close, schedule re-registration once the connection is restored.

High-level approach:

1. Add a `listenerRegistry: Map<string, { onMessage, options }>` alongside `this.consumers`
2. In the channel `error`/`close` handler, after removing from `consumers`, call a
   `restoreConsumers()` method that waits for `this.connection` to be available
3. `restoreConsumers()` calls `getConsumerChannel` + `channel.consume()` for each registered
   listener
4. Clear `listenerRegistry` in `close()` to prevent ghost re-registration after intentional
   shutdown

## How to Change Safely

- This is an internal implementation change — the public API signature of `createListener` does
  not change
- Add integration-level tests that simulate channel drops (mock `channel.emit('error')`) and
  verify messages are still consumed after recovery
- The fix must guard against concurrent re-registration if multiple channels error simultaneously
