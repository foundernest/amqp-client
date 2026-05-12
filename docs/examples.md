# Examples

## Using the Client

```typescript
import { AMQPClient } from 'foundernest-amqp-client'

const client = new AMQPClient({
  host: 'localhost',
  username: 'guest',
  password: 'guest',
  reconnection: {
    initialDelay: 1000,
    maxDelay: 32000,
    maxAttempts: 50,
  },
})

// Send typed message
interface UserEvent { userId: string; action: string }
await client.sendMessage<UserEvent>('user-events', { userId: '123', action: 'login' })

// Create listener
await client.createListener<UserEvent>('user-events', async (msg) => {
  console.log('User:', msg.content.userId)
  console.log('Correlation:', msg.metadata.correlationId)
  return true // acknowledge
})

// Close
await client.close()
```

## Custom Logger

```typescript
import { AMQPClientLoggerInterface } from 'foundernest-amqp-client'

class MyLogger implements AMQPClientLoggerInterface {
  debug(msg: string, ...args: any[]) { console.debug(`[DEBUG] ${msg}`, args) }
  info(msg: string, ...args: any[]) { console.info(`[INFO] ${msg}`, args) }
  warn(msg: string, ...args: any[]) { console.warn(`[WARN] ${msg}`, args) }
  error(msg: string, ...args: any[]) { console.error(`[ERROR] ${msg}`, args) }
}

const client = new AMQPClient({
  host: 'localhost',
  username: 'guest',
  password: 'guest',
  logger: new MyLogger(),
})
```

## Writing Tests

```typescript
// DO: Test behavior, not implementation details
it('sends message with correlation ID', async () => {
  await client.sendMessage('queue', { data: 'value' }, { correlationId: '123' })
  expect(mockChannel.sendToQueue).toHaveBeenCalledWith(
    'queue',
    expect.anything(),
    expect.objectContaining({ correlationId: '123' })
  )
})

// DON'T: Mock internal methods or assert on logs
// DON'T: Test what amqplib does; assume it works
```
