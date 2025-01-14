import { type AMQPMessage, type ConsumeOptions, type MessagePublishOptions } from './amqp-client.types'

export interface AMQPClientInterface {
  close(): Promise<void>
  sendMessage<T>(queueName: string, message: T, options?: MessagePublishOptions): Promise<boolean>
  createListener<T>(
    queueName: string,
    onMessage: (msg: AMQPMessage<T>) => Promise<boolean | void>,
    options?: ConsumeOptions
  ): Promise<void>
}
