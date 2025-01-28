import { type AMQPMessage, type ConsumeOptions, type MessagePublishOptions } from './amqp-client.types';
export interface AMQPClientInterface {
    close(): Promise<void>;
    sendMessage<T extends object>(queueName: string, message: T, options?: MessagePublishOptions): Promise<boolean>;
    createListener<T extends object>(queueName: string, onMessage: (msg: AMQPMessage<T>) => Promise<boolean>, options?: ConsumeOptions): Promise<void>;
}
