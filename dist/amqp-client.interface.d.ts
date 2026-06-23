import { type AMQPClientHealth, type AMQPMessage, type ConsumeOptions, type MessagePublishOptions } from './amqp-client.types';
export interface AMQPClientInterface {
    close(): Promise<void>;
    sendMessage<T extends object>(queueName: string, message: T, options?: MessagePublishOptions): Promise<boolean>;
    createListener<T extends object>(queueName: string, onMessage: (msg: AMQPMessage<T>) => Promise<boolean>, options?: ConsumeOptions): Promise<void>;
    /** Whether the underlying connection to the broker is currently established. */
    isConnected(): boolean;
    /** A snapshot of connectivity and consumer state for health/liveness checks. */
    getHealth(): AMQPClientHealth;
}
