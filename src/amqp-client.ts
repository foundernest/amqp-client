import * as amqp from 'amqplib'
import { type AMQPClientLoggerInterface } from './amqp-client-logger.interface'
import { type AMQPClientInterface } from './amqp-client.interface'
import {
  type AMQPMessage,
  type ClientOptions,
  type ConnectionOptions,
  type ConsumeOptions,
  type MessagePublishOptions,
} from './amqp-client.types'

export type AMQPClientArgs = ConnectionOptions & {
  logger?: AMQPClientLoggerInterface
}

type AMQPError = { code: number; message: string }

export class AMQPClient implements AMQPClientInterface {
  private connection: amqp.ChannelModel | null = null
  private producer: amqp.Channel | null = null
  private consumers: Map<string, amqp.Channel> = new Map<string, amqp.Channel>()
  private reconnectAttempts = 0
  private readonly options: ClientOptions
  private readonly logger: AMQPClientLoggerInterface

  constructor({ logger = console, ...options }: AMQPClientArgs) {
    this.options = {
      ...options,
      // Constants for exponential backoff strategy.
      reconnection: {
        // 5 retries in 32 seconds max
        // Retry in 1, 2, 4, 8, 16 seconds
        initialDelay: 1000,
        maxDelay: 32000,
        maxAttempts: 50,
      },
      // This config must remain constant between all the services using the queue, that's why is constant.
      messageExpiration: {
        // Within 24 hours, a message has 3 attempts to be consumed. If not, it will be sent to the dead letter queue.
        // We have 30 days to analyze what's going on with the discarded message. If not, it will be discarded.
        queueTTL: 24 * 60 * 60 * 1000,
        deadLetterQueueTTL: 30 * 24 * 60 * 60 * 1000,
        defaultMaxRetries: 3,
      },
    }
    this.logger = logger
  }

  private async connect(): Promise<void> {
    const { host, port = 5672, username, password, vhost = '/' } = this.options
    const connectionString = `amqp://${username ? `${username}:${password}@` : ''}${host}:${port}/${vhost}`

    try {
      this.connection = await amqp.connect(connectionString)

      this.reconnectAttempts = 0

      this.logger.info('📭️ Connected to AMQP broker.')

      this.connection.on('error', (err: Error): void => {
        this.logger.error('🚨 AMQP Connection Error:', err)
        this.reconnect()
      })

      this.connection.on('close', (): void => {
        this.logger.warn('⚠️ AMQP Connection Closed')
        this.reconnect()
      })
    } catch (error) {
      this.logger.error('🚨 Failed to connect to AMQP broker:', error)
      await this.reconnect()
    }
  }

  private async reconnect(): Promise<void> {
    if (this.reconnectAttempts >= this.options.reconnection.maxAttempts) {
      this.logger.error('🚨 Max reconnection attempts reached. Giving up.')
      return
    }

    const delay = this.calculateBackoffDelay(this.reconnectAttempts)
    this.reconnectAttempts++

    this.logger.warn(`⚠️ Reconnecting (Attempt ${this.reconnectAttempts})`)

    return new Promise((resolve) => {
      setTimeout(async () => {
        try {
          await this.connect()
          resolve()
        } catch (err) {
          this.logger.error('🚨 Reconnection failed:', err)
          resolve()
        }
      }, delay)
    })
  }

  private calculateBackoffDelay(attempt: number): number {
    const exponentialDelay = Math.min(
      this.options.reconnection.maxDelay,
      this.options.reconnection.initialDelay * Math.pow(2, attempt)
    )
    return Math.ceil(exponentialDelay + Math.random() * 1000)
  }

  async close(): Promise<void> {
    try {
      if (this.producer) {
        await this.producer.close()
        this.producer = null
      }
      this.logger.info('📪️ AMQP producer channel closed.')
    } catch (error) {
      this.logger.error('🚨 Error closing AMQP producer channel:', error)
    }
    try {
      if (this.consumers.size) {
        await Promise.all(Array.from(this.consumers.values()).map(async (channel) => channel.close()))
      }
      this.logger.info('📪️ AMQP consumer channels closed.')
    } catch (error) {
      this.logger.error('🚨 Error closing AMQP consumer channels:', error)
    }

    try {
      if (this.connection) {
        await this.connection.close()
      }
      this.logger.info('📪️ AMQP connection closed.')
    } catch (error) {
      this.logger.error('🚨 Error closing AMQP connection:', error)
    } finally {
      this.connection = null
    }
  }

  async sendMessage<T extends object>(
    queueName: string,
    message: T,
    { headers, correlationId }: MessagePublishOptions = {}
  ): Promise<boolean> {
    try {
      if (!this.producer) {
        this.producer = await this.getProducerChannel()
      }
      this.logger.debug(`📨 Sending message to queue: ${queueName}`)

      return this.producer.sendToQueue(queueName, Buffer.from(JSON.stringify(message)), {
        headers,
        correlationId,
        persistent: true,
        deliveryMode: 2,
        contentType: 'application/json',
        expiration: this.options.messageExpiration.queueTTL,
      })
    } catch (error) {
      this.logger.error(`💥 Failed sending message to queue: ${queueName}`, JSON.stringify(error, null, 2))
    }

    return false
  }

  async createListener<T extends object>(
    queueName: string,
    onMessage: (msg: AMQPMessage<T>) => Promise<boolean>,
    options?: ConsumeOptions
  ): Promise<void> {
    const channel = await this.getConsumerChannel({
      queueName,
      deadLetter: options?.deadLetter !== undefined ? options.deadLetter : true,
    })

    this.logger.info(`📬️ Starting to consume messages from queue: ${queueName}`)
    await channel.consume(queueName, async (msg) => {
      if (!msg) {
        return
      }

      if (options?.correlationId && options.correlationId !== msg.properties.correlationId) {
        channel.nack(msg, false, true)
        return
      }

      try {
        const content: T = JSON.parse(msg.content.toString())
        const message: AMQPMessage<T> = {
          content,
          metadata: {
            headers: msg.properties.headers,
            correlationId: msg.properties.correlationId,
            redelivered: msg.fields.redelivered,
          },
        }

        const deathCount = msg.properties.headers?.['x-delivery-count'] || 0
        const attempts = deathCount + 1
        const result = await onMessage(message)

        if (!result) {
          const requeue = attempts <= this.options.messageExpiration.defaultMaxRetries
          channel.nack(msg, false, requeue)
          if (!requeue) {
            this.logger.warn(
              `⚠️ Message exceeded retry limit (${this.options.messageExpiration.defaultMaxRetries}) and will be moved to DLQ: ${queueName}.dlq`
            )
          }
        } else {
          channel.ack(msg)
          this.logger.debug(`✅ Message successfully processed`)
        }
      } catch (error) {
        this.logger.error('🚨 Message processing error:', error)
        channel.nack(msg, false, false)
      }
    })
  }

  private async getProducerChannel(): Promise<amqp.Channel> {
    this.logger.debug(`🗿 Creating new producer Channel`)
    if (!this.connection) {
      await this.connect()
    }

    let producer
    if (this.connection) {
      producer = await this.connection.createChannel()
      producer.on('error', (err: Error) => {
        this.logger.error('🚨 AMQP Channel Error:', err)
        this.producer = null
      })
      producer.on('close', () => {
        this.logger.warn('⚠️ AMQP Channel Closed')
        this.producer = null
      })
    }
    if (!producer) {
      throw new Error('💥 Channel is not available')
    }
    return producer
  }

  private async getConsumerChannel({ queueName, deadLetter }: { queueName: string; deadLetter: boolean }) {
    this.logger.debug(`🗿 Asserting queue ${queueName} ${deadLetter ? 'with dead letter queue' : ''}`)

    const channelQueueName = `consumer-${queueName}-${Date.now()}`
    const channel = await this.createConsumerChannel(channelQueueName, 1)
    const assertQueueOptions: amqp.Options.AssertQueue = {
      durable: true,
      exclusive: false,
      arguments: {
        'x-queue-type': 'quorum',
        'x-max-retries': this.options.messageExpiration.defaultMaxRetries,
      },
    }

    const exchangeName = `${queueName}.dlx`
    const dlqName = `${queueName}.dlq`
    const routingKey = `${queueName}.dead`

    if (deadLetter) {
      assertQueueOptions.deadLetterExchange = exchangeName
      assertQueueOptions.deadLetterRoutingKey = routingKey
      assertQueueOptions.arguments = {
        ...assertQueueOptions.arguments,
        'x-dead-letter-exchange': exchangeName,
        'x-dead-letter-routing-key': routingKey,
      }
    }

    try {
      this.logger.debug(`🗿 Asserting queue "${queueName}"`)
      await this.bindQueueToChannel({
        channel,
        queueName,
        assertQueueOptions,
        deadLetter,
        exchangeName,
        dlqName,
        routingKey,
      })

      return channel
    } catch (error) {
      // PRECONDITION_FAILED ERROR | QUEUE EXISTS WITH DIFFERENT CONFIG
      if (this.isAmqpError(error) && error.code === 406) {
        this.logger.warn(`⚠️ Queue "${queueName}" exists with different arguments.`)

        try {
          // WE NEED TO RECREATE THE CHANNEL. WHENEVER ASSERT QUEUE THROWS AN ERROR, THE CHANNEL BREAKS
          const channel = await this.createConsumerChannel(channelQueueName, 1)
          const queue = await channel.checkQueue(queueName)
          if (queue.messageCount === 0) {
            this.logger.info(`🔄 Queue "${queueName}" is empty. Recreating it with new arguments.`)
            await channel.deleteQueue(queueName)

            await this.bindQueueToChannel({
              channel,
              queueName,
              assertQueueOptions,
              deadLetter,
              exchangeName,
              dlqName,
              routingKey,
            })
            return channel
          } else {
            this.logger.warn(`⚠️ Queue "${queueName}" has messages. Proceeding without re-declaring the queue.`)
            return channel
          }
        } catch (checkError) {
          this.logger.error(`💥 Failed recreating queue "${queueName}":`, checkError)
          throw checkError
        }
      } else {
        throw error
      }
    }
  }

  private async bindQueueToChannel({
    channel,
    queueName,
    assertQueueOptions,
    deadLetter,
    exchangeName,
    dlqName,
    routingKey,
  }: {
    channel: amqp.Channel
    queueName: string
    assertQueueOptions: amqp.Options.AssertQueue
    deadLetter: boolean
    exchangeName: string
    dlqName: string
    routingKey: string
  }) {
    await channel.assertQueue(queueName, assertQueueOptions)
    if (deadLetter) {
      this.logger.debug(`🗿 Asserting exchange "${exchangeName}"`)
      await channel.assertExchange(exchangeName, 'direct', {
        durable: true,
        autoDelete: false,
      })

      this.logger.debug(`🗿 Asserting and binding dead letter queue "${dlqName}"`)
      await channel.assertQueue(dlqName, {
        durable: true,
        arguments: {
          'x-queue-type': 'quorum',
          'x-message-ttl': this.options.messageExpiration.deadLetterQueueTTL,
        },
      })
      await channel.bindQueue(dlqName, exchangeName, routingKey)
    }
  }

  private async createConsumerChannel(queueName: string, prefetch?: number): Promise<amqp.Channel> {
    this.logger.debug(`🗿 Creating new consumer Channel for "${queueName}"`)
    if (!this.connection) {
      await this.connect()
    }

    let channel
    if (this.connection) {
      channel = await this.connection.createChannel()
      if (prefetch) {
        await channel.prefetch(prefetch)
      }
      channel.on('error', (err: Error) => {
        this.logger.error('🚨 AMQP Channel Error:', err)
        this.consumers.delete(queueName)
      })
      channel.on('close', () => {
        this.logger.warn('⚠️ AMQP Channel Closed')
        this.consumers.delete(queueName)
      })
      this.consumers.set(queueName, channel)
    }
    if (!channel) {
      throw new Error('💥 Channel is not available')
    }

    return channel
  }

  private isAmqpError(error: unknown): error is AMQPError {
    return typeof error === 'object' && error !== null && 'code' in error
  }
}
