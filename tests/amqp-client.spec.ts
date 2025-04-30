import { describe, it, beforeEach, beforeAll, expect, vi, Mock, afterEach } from 'vitest'
vi.mock('amqplib')

import { connect } from 'amqplib'
import { AMQPClient } from '../src'
import { AMQPClientLoggerInterface } from '../src'

// Mock definitions
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
  checkQueue: vi.fn(),
  deleteQueue: vi.fn(),
  on: vi.fn(),
}

const defaultClientOptions = {
  host: 'localhost',
  username: 'guest',
  password: 'guest',
  port: 1234,
  vhost: 'test',
}

const generateClient = (options = {}, logger?: AMQPClientLoggerInterface) => {
  return new AMQPClient({
    ...defaultClientOptions,
    ...options,
    logger: logger || console,
  })
}

let connectMock: Mock
const onMessageMock = vi.fn()

beforeAll(() => {
  connectMock = connect as Mock
})

beforeEach(() => {
  vi.clearAllMocks()
  connectMock.mockResolvedValue(mockConnection)
  mockConnection.createChannel.mockResolvedValue(mockChannel)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('AMQPClient', () => {
  describe('When sending a message', () => {
    let client: AMQPClient
    beforeEach(async () => {
      client = generateClient()
      await client.sendMessage('test-queue', { key: 'value' })
    })

    it('should create a connection with correct parameters', () => {
      expect(connectMock).toHaveBeenCalledWith('amqp://guest:guest@localhost:1234/test', {
        clientProperties: {
          application: undefined,
          connection_name: 'test-queue',
        },
      })
    })

    it('should create a producer channel', () => {
      expect(mockConnection.createChannel).toHaveBeenCalled()
      expect(mockChannel.on).toHaveBeenCalledWith('error', expect.any(Function))
      expect(mockChannel.on).toHaveBeenCalledWith('close', expect.any(Function))
    })

    it('should send message to the queue with correct options', () => {
      expect(mockChannel.sendToQueue).toHaveBeenCalledWith(
        'test-queue',
        Buffer.from(JSON.stringify({ key: 'value' })),
        expect.objectContaining({
          contentType: 'application/json',
          persistent: true,
          deliveryMode: 2,
          expiration: 86400000, // 24 hours in milliseconds
        })
      )
    })

    it('should log that the message was sent', () => {
      // If using a custom logger, you can check logger.info was called with correct message
    })
  })

  describe('When creating a listener', () => {
    let client: AMQPClient
    beforeEach(async () => {
      onMessageMock.mockResolvedValue(true)
      client = generateClient()
      await client.createListener('test-queue', onMessageMock)
    })

    it('should create a consumer channel', () => {
      expect(mockConnection.createChannel).toHaveBeenCalled()
      expect(mockChannel.prefetch).toHaveBeenCalledWith(1)
      expect(mockChannel.on).toHaveBeenCalledWith('error', expect.any(Function))
      expect(mockChannel.on).toHaveBeenCalledWith('close', expect.any(Function))
    })

    it('should assert the queue with correct options', () => {
      expect(mockChannel.assertQueue).toHaveBeenCalledWith('test-queue', {
        durable: true,
        exclusive: false,
        arguments: {
          'x-queue-type': 'quorum',
          'x-max-retries': 3,
          'x-dead-letter-exchange': 'test-queue.dlx',
          'x-dead-letter-routing-key': 'test-queue.dead',
        },
        deadLetterExchange: 'test-queue.dlx',
        deadLetterRoutingKey: 'test-queue.dead',
      })
    })

    it('should consume messages from the queue', () => {
      expect(mockChannel.consume).toHaveBeenCalledWith('test-queue', expect.any(Function))
    })

    describe('and a message is received', () => {
      const mockMsg = {
        content: Buffer.from(JSON.stringify({ key: 'value' })),
        properties: { headers: {}, correlationId: null },
        fields: { redelivered: false },
      }

      beforeEach(async () => {
        const consumeCallback = mockChannel.consume.mock.calls[0][1]
        await consumeCallback(mockMsg)
      })

      it('should call the onMessage handler with correct message', () => {
        expect(onMessageMock).toHaveBeenCalledWith({
          content: { key: 'value' },
          metadata: {
            headers: {},
            correlationId: null,
            redelivered: false,
          },
        })
      })

      it('should acknowledge the message', () => {
        expect(mockChannel.ack).toHaveBeenCalledWith(mockMsg)
      })
    })

    describe('and message processing fails', () => {
      beforeEach(async () => {
        onMessageMock.mockResolvedValue(false)
        const consumeCallback = mockChannel.consume.mock.calls[0][1]
        await consumeCallback({
          content: Buffer.from(JSON.stringify({ key: 'value' })),
          properties: { headers: {}, correlationId: null },
          fields: { redelivered: false },
        })
      })

      it('should nack the message and requeue it', () => {
        expect(mockChannel.nack).toHaveBeenCalledWith(expect.any(Object), false, true)
      })
    })

    describe('and processing throws an error', () => {
      beforeEach(async () => {
        onMessageMock.mockRejectedValue(new Error('Processing error'))
        const consumeCallback = mockChannel.consume.mock.calls[0][1]
        await consumeCallback({
          content: Buffer.from(JSON.stringify({ key: 'value' })),
          properties: { headers: {}, correlationId: null },
          fields: { redelivered: false },
        })
      })

      it('should nack the message without requeuing', () => {
        expect(mockChannel.nack).toHaveBeenCalledWith(expect.any(Object), false, false)
      })
    })

    describe('and the channel emits an error', () => {
      it('should remove the consumer channel from consumers map', async () => {
        // Since we cannot access private properties, we can check if the client can create a new listener
        mockConnection.createChannel.mockResolvedValueOnce({
          ...mockChannel,
          consume: vi.fn(),
        })
        onMessageMock.mockClear()
        await client.createListener('test-queue', onMessageMock)

        expect(mockConnection.createChannel).toHaveBeenCalledTimes(2)
        expect(mockChannel.consume).toHaveBeenCalled()
      })
    })
  })

  describe('When closing the client', () => {
    let client: AMQPClient
    beforeEach(async () => {
      client = generateClient()
      await client.sendMessage('test-queue', { key: 'value' })
      await client.createListener('test-queue', onMessageMock)
    })

    it('should close producer and consumer channels, and the connection', async () => {
      await client.close()

      expect(mockChannel.close).toHaveBeenCalledTimes(2) // producer and consumer channels
      expect(mockConnection.close).toHaveBeenCalled()
    })

    it('should handle errors during close operations gracefully', async () => {
      mockChannel.close.mockRejectedValueOnce(new Error('Channel close error'))
      mockConnection.close.mockRejectedValueOnce(new Error('Connection close error'))

      await client.close()

      // Errors are logged, but close operation continues
      // Assuming logger.error is called appropriately
    })
  })

  describe('Reconnection logic', () => {
    it('should attempt to reconnect on connection error', async () => {
      connectMock.mockRejectedValueOnce(new Error('Connection failed')).mockResolvedValue(mockConnection)

      const client = generateClient()
      await client.sendMessage('test-queue', { key: 'value' })

      expect(connectMock).toHaveBeenCalledTimes(2)
      expect(mockChannel.sendToQueue).toHaveBeenCalled()
    })

    it('should attempt the specified number of reconnection attempts', async () => {
      connectMock.mockRejectedValue(new Error('Connection failed'))
      const client = generateClient({
        reconnection: {
          initialDelay: 1,
          maxDelay: 10,
          maxAttempts: 5,
        },
      })

      await client.sendMessage('test-queue', { key: 'value' })

      // By default, maxAttempts is 5, plus the initial attempt
      expect(connectMock).toHaveBeenCalledTimes(6)
    }, 50000)
  })

  describe('When using correlation IDs', () => {
    let client: AMQPClient
    beforeEach(async () => {
      client = generateClient()
      await client.sendMessage('test-queue', { key: 'value' }, { correlationId: '123' })
    })

    it('should send messages with the specified correlation ID', () => {
      expect(mockChannel.sendToQueue).toHaveBeenCalledWith(
        'test-queue',
        Buffer.from(JSON.stringify({ key: 'value' })),
        expect.objectContaining({
          correlationId: '123',
        })
      )
    })

    it('should only process messages with matching correlation ID', async () => {
      await client.createListener('test-queue', onMessageMock, { correlationId: '123' })

      const matchingMsg = {
        content: Buffer.from(JSON.stringify({ key: 'value' })),
        properties: { headers: {}, correlationId: '123' },
        fields: { redelivered: false },
      }
      const nonMatchingMsg = {
        content: Buffer.from(JSON.stringify({ key: 'value' })),
        properties: { headers: {}, correlationId: '456' },
        fields: { redelivered: false },
      }

      const consumeCallback = mockChannel.consume.mock.calls[0][1]
      await consumeCallback(nonMatchingMsg)
      expect(mockChannel.nack).toHaveBeenCalledWith(nonMatchingMsg, false, true)

      await consumeCallback(matchingMsg)
      expect(onMessageMock).toHaveBeenCalledWith({
        content: { key: 'value' },
        metadata: {
          headers: {},
          correlationId: '123',
          redelivered: false,
        },
      })
      expect(mockChannel.ack).toHaveBeenCalledWith(matchingMsg)
    })
  })

  describe('When dealing with message retries and dead-lettering', () => {
    let client: AMQPClient
    beforeEach(async () => {
      client = generateClient()
      await client.createListener('test-queue', onMessageMock)
    })

    it('should move message to DLQ after max retries', async () => {
      const mockMsg = {
        content: Buffer.from(JSON.stringify({ key: 'value' })),
        properties: {
          headers: { 'x-delivery-count': 3 },
          correlationId: null,
        },
        fields: { redelivered: false },
      }

      onMessageMock.mockResolvedValue(false)

      const consumeCallback = mockChannel.consume.mock.calls[0][1]
      await consumeCallback(mockMsg)

      expect(mockChannel.nack).toHaveBeenCalledWith(mockMsg, false, false)
      // Additionally, you can check if the logger warns about moving to DLQ
    })
  })

  describe('When a queue exists with different arguments', () => {
    it('should handle PRECONDITION_FAILED error and recreate the queue if empty', async () => {
      const client = generateClient()
      mockChannel.assertQueue.mockRejectedValueOnce({ code: 406 })
      mockChannel.checkQueue.mockResolvedValueOnce({ messageCount: 0 })
      mockChannel.deleteQueue.mockResolvedValueOnce({})
      mockChannel.assertQueue.mockResolvedValueOnce({})

      await client.createListener('test-queue', onMessageMock, { deadLetter: false })

      expect(mockChannel.checkQueue).toHaveBeenCalledWith('test-queue')
      expect(mockChannel.deleteQueue).toHaveBeenCalledWith('test-queue')
      expect(mockChannel.assertQueue).toHaveBeenCalledTimes(2) // Initial call and after deletion
    })

    it('should proceed without re-declaring the queue if it has messages', async () => {
      const client = generateClient()
      mockChannel.assertQueue.mockRejectedValueOnce({ code: 406 })
      mockChannel.checkQueue.mockResolvedValueOnce({ messageCount: 5 })

      await client.createListener('test-queue', onMessageMock, { deadLetter: false })

      expect(mockChannel.checkQueue).toHaveBeenCalledWith('test-queue')
      expect(mockChannel.deleteQueue).not.toHaveBeenCalled()
    })
  })

  describe('When providing custom headers', () => {
    it('should send messages with the specified headers', async () => {
      const client = generateClient()
      await client.sendMessage('test-queue', { key: 'value' }, { headers: { 'custom-header': 'header-value' } })

      expect(mockChannel.sendToQueue).toHaveBeenCalledWith(
        'test-queue',
        Buffer.from(JSON.stringify({ key: 'value' })),
        expect.objectContaining({
          headers: { 'custom-header': 'header-value' },
        })
      )
    })

    it('should expose headers in the onMessage handler', async () => {
      const client = generateClient()
      await client.createListener('test-queue', onMessageMock)

      const mockMsg = {
        content: Buffer.from(JSON.stringify({ key: 'value' })),
        properties: {
          headers: { 'custom-header': 'header-value' },
          correlationId: null,
        },
        fields: { redelivered: false },
      }

      const consumeCallback = mockChannel.consume.mock.calls[0][1]
      await consumeCallback(mockMsg)

      expect(onMessageMock).toHaveBeenCalledWith({
        content: { key: 'value' },
        metadata: {
          headers: { 'custom-header': 'header-value' },
          correlationId: null,
          redelivered: false,
        },
      })
    })
  })

  describe('When a message has no content', () => {
    it('should return early in the consumer callback', async () => {
      const client = generateClient()
      await client.createListener('test-queue', onMessageMock)

      const consumeCallback = mockChannel.consume.mock.calls[0][1]
      await consumeCallback(null)

      expect(onMessageMock).not.toHaveBeenCalled()
    })
  })

  describe('When message content cannot be parsed as JSON', () => {
    it('should catch the error and nack the message without requeuing', async () => {
      const client = generateClient()
      await client.createListener('test-queue', onMessageMock)

      const mockMsg = {
        content: Buffer.from('invalid json'),
        properties: { headers: {}, correlationId: null },
        fields: { redelivered: false },
      }

      const consumeCallback = mockChannel.consume.mock.calls[0][1]
      await consumeCallback(mockMsg)

      expect(mockChannel.nack).toHaveBeenCalledWith(mockMsg, false, false)
    })
  })
})
