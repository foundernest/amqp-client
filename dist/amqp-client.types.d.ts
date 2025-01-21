/**
 * Represents a message received from an AMQP queue, containing the message content and metadata.
 * @template T - The type of the message content
 */
export interface AMQPMessage<T = any> {
    /** The deserialized message content */
    content: T;
    /** Metadata associated with the message */
    metadata: {
        /** Optional headers attached to the message */
        headers?: Record<string, any>;
        /** Unique identifier used for message correlation and tracking */
        correlationId?: string;
        /** Indicates whether this message has been redelivered after a failed processing attempt */
        redelivered: boolean;
    };
}
/**
 * Options for publishing messages to an AMQP queue.
 */
export interface MessagePublishOptions {
    /** Custom headers to attach to the message */
    headers?: Record<string, any>;
    /** Unique identifier for message correlation and tracking */
    correlationId?: string;
}
/**
 * Configuration options for consuming messages from an AMQP queue.
 */
export interface ConsumeOptions {
    /** Whether to enable dead letter queue for failed messages (default: true) */
    deadLetter?: boolean;
    /** Only process messages with matching correlation ID */
    correlationId?: string;
}
/**
 * Configuration options for establishing a connection to an AMQP broker.
 */
export interface ConnectionOptions {
    /** The hostname or IP address of the AMQP broker */
    host: string;
    /** The port number the AMQP broker is listening on (default: 5672) */
    port?: number;
    /** Username for authentication with the AMQP broker */
    username: string;
    /** Password for authentication with the AMQP broker */
    password: string;
    /** The virtual host to connect to (default: '/') */
    vhost?: string;
}
/**
 * Constants used for AMQP connection and message handling configuration.
 */
export type ConnectionConstants = {
    /** Configuration for connection retry behavior */
    reconnection: {
        /** Initial delay in milliseconds before the first reconnection attempt */
        initialDelay: number;
        /** Maximum number of reconnection attempts before giving up */
        maxAttempts: number;
        /** Maximum delay in milliseconds between reconnection attempts */
        maxDelay: number;
    };
    /** Message handling configuration */
    messageExpiration: {
        /** Time-to-live in milliseconds for messages in the main queue */
        queueTTL: number;
        /** Time-to-live in milliseconds for messages in the dead letter queue */
        deadLetterQueueTTL: number;
        /** Default number of retry attempts for failed messages */
        defaultMaxRetries: number;
    };
};
export type ClientOptions = ConnectionOptions & ConnectionConstants;
