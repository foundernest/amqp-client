import { type AMQPClientLoggerInterface } from './amqp-client-logger.interface';
import { type AMQPClientInterface } from './amqp-client.interface';
import { type AMQPMessage, type ConnectionOptions, type ConsumeOptions, type MessagePublishOptions } from './amqp-client.types';
export type AMQPClientArgs = ConnectionOptions & {
    logger?: AMQPClientLoggerInterface;
};
export declare class AMQPClient implements AMQPClientInterface {
    private connection;
    private producer;
    private consumers;
    private reconnectAttempts;
    private readonly options;
    private readonly logger;
    constructor({ logger, ...options }: AMQPClientArgs);
    private connect;
    private reconnect;
    private calculateBackoffDelay;
    close(): Promise<void>;
    sendMessage<T extends object>(queueName: string, message: T, { headers, correlationId, priority }?: MessagePublishOptions): Promise<boolean>;
    createListener<T extends object>(queueName: string, onMessage: (msg: AMQPMessage<T>) => Promise<boolean>, options?: ConsumeOptions): Promise<void>;
    private getProducerChannel;
    private getConsumerChannel;
    private bindQueueToChannel;
    private createConsumerChannel;
    private isAmqpError;
}
