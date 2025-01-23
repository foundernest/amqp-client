import { describe, it, beforeEach, beforeAll, expect, vi, Mock } from 'vitest'

vi.mock('amqplib')
import { connect } from 'amqplib'
import { AMQPClient } from '../src'

const mockConnection = {
  createChannel: vi.fn(),
  on: vi.fn(),
  close: vi.fn(),
}

const mockChannel = {
  assertQueue: vi.fn(),
  sendToQueue: vi.fn(),
  consume: vi.fn(),
  prefetch: vi.fn(),
  close: vi.fn(),
  ack: vi.fn(),
  nack: vi.fn(),
  assertExchange: vi.fn(),
  bindQueue: vi.fn(),
}

const generateClient = () => {
  return new AMQPClient({
    host: 'localhost',
    username: 'guest',
    password: 'guest',
    port: 1234,
    vhost: 'test',
    logger: console,
  })
}

let connectMock: Mock
let onMessageMock = vi.fn()

beforeAll(() => {
  vi.clearAllMocks()
  connectMock = connect as Mock
})

beforeEach(() => {
  vi.clearAllMocks()
  connectMock.mockResolvedValue(mockConnection)
  mockConnection.createChannel.mockResolvedValue(mockChannel)
})

describe('When a message is sent', () => {
  beforeEach(async () => {
    const client = generateClient()
    await client.sendMessage('test-queue', { key: 'value' })
  })

  it('should create a connection', async () => {
    expect(connectMock).toHaveBeenCalledWith('amqp://guest:guest@localhost:1234/test')
    expect(mockConnection.createChannel).toHaveBeenCalled()
    expect(mockChannel.prefetch).toHaveBeenCalledWith(1)
  })

  it('should enqueue a message', async () => {
    expect(mockChannel.sendToQueue).toHaveBeenCalledWith(
      'test-queue',
      Buffer.from(JSON.stringify({ key: 'value' })),
      expect.objectContaining({
        contentType: 'application/json',
        persistent: true,
        deliveryMode: 2,
      })
    )
  })
})

describe('When a queue is listened', () => {
  beforeEach(async () => {
    onMessageMock.mockResolvedValue(true)
    const client = generateClient()
    await client.createListener('test-queue', onMessageMock)
  })

  it('should create a connection', async () => {
    expect(connectMock).toHaveBeenCalledWith('amqp://guest:guest@localhost:1234/test')
    expect(mockConnection.createChannel).toHaveBeenCalled()
    expect(mockChannel.prefetch).toHaveBeenCalledWith(1)
  })

  it('should ensure a quorum queue exists', async () => {
    expect(mockChannel.assertQueue).toHaveBeenCalledWith('test-queue', {
      arguments: {
        'x-dead-letter-exchange': 'test-queue.dlx',
        'x-dead-letter-routing-key': 'test-queue.dead',
        'x-max-retries': 3,
        'x-queue-type': 'quorum',
      },
      deadLetterExchange: 'test-queue.dlx',
      deadLetterRoutingKey: 'test-queue.dead',
      durable: true,
      exclusive: false,
    })
  })

  it('should consume messages', async () => {
    const mockMsg = {
      content: Buffer.from(JSON.stringify({ key: 'value' })),
      properties: { headers: {}, correlationId: null },
      fields: { redelivered: false },
    }
    const consumeCallback = mockChannel.consume.mock.calls[0][1]
    await consumeCallback(mockMsg)
    expect(mockChannel.consume).toHaveBeenCalledWith('test-queue', expect.any(Function))
    expect(onMessageMock).toHaveBeenCalledWith({
      content: { key: 'value' },
      metadata: {
        headers: {},
        correlationId: null,
        redelivered: false,
      },
    })
    expect(mockChannel.ack).toHaveBeenCalledWith(mockMsg)
  })
})

describe('When a connection fails', () => {
  it('should successfully reconnect and send a message', async () => {
    connectMock.mockRejectedValueOnce(new Error('Connection failed')).mockResolvedValueOnce(mockConnection)
    const client = generateClient()
    await client.sendMessage('test-queue', { key: 'value' })
    expect(connectMock).toHaveBeenCalledTimes(2)
    expect(mockChannel.sendToQueue).toHaveBeenCalled()
  })

  it('should successfully reconnect and consume messages', async () => {
    connectMock.mockRejectedValueOnce(new Error('Connection failed')).mockResolvedValueOnce(mockConnection)
    const client = generateClient()
    await client.createListener('test-queue', onMessageMock)
    const consumeCallback = mockChannel.consume.mock.calls[0][1]
    await consumeCallback({
      content: Buffer.from(JSON.stringify({ key: 'value' })),
      properties: { headers: {}, correlationId: null },
      fields: { redelivered: false },
    })
    expect(mockChannel.ack).toHaveBeenCalled()
  })

  it('should stop reconnecting after reaching the maximum number reconnection of attempts', async () => {
    connectMock.mockRejectedValue(new Error('Connection failed'))
    const client = generateClient()
    await expect(client.sendMessage('test-queue', { key: 'value' })).rejects.toThrow('Channel is not available')
    expect(connectMock).toBeCalledTimes(6)
  }, 50000)
})

describe('When a logger is provided', () => {
  it('should use the custom logger', async () => {
    const client = generateClient()
    await client.sendMessage('test-queue', { key: 'value' })
  })
})

describe('When Dead Letter Queue is enabled', () => {
  it('should create a dead letter queue for the main queue', async () => {
    const client = generateClient()
    await client.createListener('test-queue', onMessageMock)
    expect(mockChannel.assertQueue).toHaveBeenNthCalledWith(1, 'test-queue.dlq', {
      durable: true,
      arguments: {
        'x-message-ttl': 30 * 24 * 60 * 60 * 1000, // 30 days
        'x-queue-type': 'quorum',
      },
    })
    expect(mockChannel.assertQueue).toHaveBeenNthCalledWith(2, 'test-queue', {
      arguments: {
        'x-dead-letter-exchange': 'test-queue.dlx',
        'x-dead-letter-routing-key': 'test-queue.dead',
        'x-max-retries': 3,
        'x-queue-type': 'quorum',
      },
      deadLetterExchange: 'test-queue.dlx',
      deadLetterRoutingKey: 'test-queue.dead',
      durable: true,
      exclusive: false,
    })
  })
})

describe('When correlation ID is used', () => {
  let client: AMQPClient
  beforeEach(async () => {
    client = generateClient()
    await client.sendMessage('test-queue', { key: 'value' }, { correlationId: 'test-correlation-id' })
  })

  it('should set the correlation ID when sending a message', async () => {
    expect(mockChannel.sendToQueue).toHaveBeenCalledWith(
      'test-queue',
      Buffer.from(JSON.stringify({ key: 'value' })),
      expect.objectContaining({
        correlationId: 'test-correlation-id',
        contentType: 'application/json',
        persistent: true,
        deliveryMode: 2,
      })
    )
  })

  it('should only consume message with matching correlation ID', async () => {
    // Create the listener
    await client.createListener('test-queue', onMessageMock)
    await client.sendMessage('test-queue', { key: 'value' }, { correlationId: 'test-correlation-id' })
    await client.sendMessage('test-queue', { key: 'value' }, { correlationId: 'non-matching-id' })
    const mockMsg = {
      content: Buffer.from(JSON.stringify({ key: 'value' })),
      properties: { headers: {}, correlationId: null },
      fields: { redelivered: false },
    }
    const consumeCallback = mockChannel.consume.mock.calls[0][1]
    await consumeCallback(mockMsg)
    expect(mockChannel.consume).toHaveBeenCalledWith('test-queue', expect.any(Function))
    expect(onMessageMock).toHaveBeenCalledWith({
      content: { key: 'value' },
      metadata: {
        headers: {},
        correlationId: null,
        redelivered: false,
      },
    })
    expect(mockChannel.ack).toHaveBeenCalledWith(mockMsg)
  })
})
