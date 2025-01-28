import { type AMQPMessage, type ConnectionOptions, type ConsumeOptions, type MessagePublishOptions } from './amqp-client.types';
import { AMQPClientInterface } from './amqp-client.interface';
import { AMQPClientLoggerInterface } from './amqp-client-logger.interface';
export type AMQPClientArgs = ConnectionOptions & {
    logger?: AMQPClientLoggerInterface;
};
export declare class AMQPClient implements AMQPClientInterface {
    private connection;
    private channel;
    private reconnectAttempts;
    private readonly options;
    private readonly logger;
    constructor({ logger, ...options }: AMQPClientArgs);
    private connect;
    private reconnect;
    private calculateBackoffDelay;
    close(): Promise<void>;
    sendMessage<T extends object>(queueName: string, message: T, { headers, correlationId }?: MessagePublishOptions): Promise<boolean>;
    private ensureConnection;
    createListener<T extends object>(queueName: string, onMessage: (msg: AMQPMessage<T>) => Promise<boolean>, options?: ConsumeOptions): Promise<void>;
    private assertQueue;
    private isAmqpError;
}
