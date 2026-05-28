# ADR-04: JSON-Only Message Serialization

## Status

Accepted

## Context

AMQP messages are raw bytes. The library must decide how to serialize the `message: T` argument
passed to `sendMessage` and how to deserialize bytes back into `T` on receipt.

Serialization formats considered: JSON, MessagePack, Protocol Buffers, raw Buffer passthrough.

## Decision

All messages are JSON-serialized (`JSON.stringify`) on send and JSON-deserialized (`JSON.parse`) on
receive. `contentType` is set to `application/json` on every published message.

## Rationale

- All current Foundernest producer and consumer services exchange JSON payloads
- JSON is human-readable and inspectable in the RabbitMQ management UI without tooling
- No schema registry or code-generation step is needed
- The library's generic type parameter `T extends object` already implies structured data

## Consequences

- Binary payloads cannot be sent through this client
- Large payloads are less efficient than binary formats; accepted for the current data volumes
- Adding support for other formats would require either a new `sendRaw` method or content-type
  negotiation on receive — both are breaking API changes
- Consumers receive `content: T` already deserialized; they cannot access the raw bytes

## References

- `src/amqp-client.ts:82` — `Buffer.from(JSON.stringify(message))` on send
- `src/amqp-client.ts:117` — `JSON.parse(msg.content.toString())` on receive
- `src/amqp-client.types.ts:4` — `AMQPMessage<T>` where `content: T` is the deserialized payload
