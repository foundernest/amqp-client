import { type AMQPMessage, type ConnectionOptions, type ConsumeOptions, type MessagePublishOptions } from './amqp-client.types';
import { AMQPClientInterface } from "./amqp-client.interface";
import { AMQPClientLoggerInterface } from "./amqp-client-logger.interface";
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
    sendMessage<T = any>(queueName: string, message: T, { headers, persistent, deliveryMode, correlationId }?: MessagePublishOptions): Promise<boolean>;
    private ensureConnection;
    createListener<T = any>(queueName: string, onMessage: (msg: AMQPMessage<T>) => Promise<boolean | void>, options?: ConsumeOptions): Promise<void>;
    private assertQueue;
}
