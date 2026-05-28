# Tech Debt: Message Expiration Constants Are Not Overridable

## Problem

The `messageExpiration` config (queue TTL, DLQ TTL, max retries) is hardcoded in the constructor
and cannot be changed per-instance. The inline comment says "this config must remain constant
between all the services using the queue" — but the constraint is not enforced at the API level;
it assumes all deployed services use the same library version with the same defaults.

## Where Code Lives

- `src/amqp-client.ts:22` — `defaultOptions.messageExpiration` hardcodes all three values
- `src/amqp-client.ts:155` — `x-max-retries` in queue assertions
- `src/amqp-client.ts:201` — `x-message-ttl` in DLQ assertions

## Current Constants

| Constant | Value | Declared in |
|----------|-------|-------------|
| `queueTTL` | 86400000 ms (24 h) | Per-message `expiration` on publish |
| `deadLetterQueueTTL` | 2592000000 ms (30 days) | `x-message-ttl` on DLQ |
| `defaultMaxRetries` | 3 | Client-side via `x-delivery-count` |

## Risk

If two library versions with different defaults coexist during a rolling deploy (e.g., after a
library upgrade that changes TTLs), both will attempt to assert queues with different arguments.
This triggers AMQP error 406 (PRECONDITION_FAILED), which the library handles by deleting and
recreating the queue if empty — potentially causing message loss during the deploy window.

## Suggested Mitigation

- Keep the current defaults as-is and document them as part of the library's public contract
- Any future change to `queueTTL`, `deadLetterQueueTTL`, or `defaultMaxRetries` must be treated
  as a **breaking change** (major version bump) and require a coordinated deploy
- Before a rolling deploy that changes these constants, drain affected queues first

A longer-term option is to expose `messageExpiration` as constructor options, but this requires
careful coordination and should only be done once all consumers are on a version that supports it.

## How to Change Safely

- Never change the default values in a minor or patch release
- If a change is unavoidable, add a changelog entry explicitly calling out the TTL values that
  changed and the migration steps
- Consider adding a startup log line that prints the active TTL/retry constants so operators can
  verify consistency across services
