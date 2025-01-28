import * as amqp from 'amqplib';
export class AMQPClient {
    constructor({ logger = console, ...options }) {
        this.connection = null;
        this.channel = null;
        this.reconnectAttempts = 0;
        this.options = {
            ...options,
            // Constants for exponential backoff strategy.
            reconnection: {
                // 5 retries in 32 seconds max
                // Retry in 1, 2, 4, 8, 16 seconds
                initialDelay: 1000,
                maxDelay: 32000,
                maxAttempts: 5,
            },
            // This config must remain constant between all the services using the queue, that's why is constant.
            messageExpiration: {
                // Within 24 hours, a message has 3 attempts to be consumed. If not, it will be sent to the dead letter queue.
                // We have 30 days to analyze what's going on with the discarded message. If not, it will be discarded.
                queueTTL: 24 * 60 * 60 * 1000,
                deadLetterQueueTTL: 30 * 24 * 60 * 60 * 1000,
                defaultMaxRetries: 3,
            },
        };
        this.logger = logger;
    }
    async connect() {
        const { host, port = 5672, username, password, vhost = '/' } = this.options;
        const connectionString = `amqp://${username ? `${username}:${password}@` : ''}${host}:${port}/${vhost}`;
        try {
            this.connection = await amqp.connect(connectionString);
            this.channel = await this.connection.createChannel();
            await this.channel.prefetch(1);
            this.reconnectAttempts = 0;
            this.logger.info('📭️ Connected to AMQP broker.');
            this.connection.on('error', (err) => {
                this.logger.error('🚨 AMQP Connection Error:', err);
                this.reconnect();
            });
            this.connection.on('close', () => {
                this.logger.warn('⚠️ AMQP Connection Closed');
                this.reconnect();
            });
        }
        catch (error) {
            this.logger.error('🚨 Failed to connect to AMQP broker:', error);
            await this.reconnect();
        }
    }
    async reconnect() {
        if (this.reconnectAttempts >= this.options.reconnection.maxAttempts) {
            this.logger.error('🚨 Max reconnection attempts reached. Giving up.');
            return;
        }
        const delay = this.calculateBackoffDelay(this.reconnectAttempts);
        this.reconnectAttempts++;
        this.logger.warn(`⚠️ Reconnecting (Attempt ${this.reconnectAttempts})`);
        return new Promise((resolve) => {
            setTimeout(async () => {
                try {
                    await this.connect();
                    resolve();
                }
                catch (err) {
                    this.logger.error('🚨 Reconnection failed:', err);
                    resolve();
                }
            }, delay);
        });
    }
    calculateBackoffDelay(attempt) {
        const exponentialDelay = Math.min(this.options.reconnection.maxDelay, this.options.reconnection.initialDelay * Math.pow(2, attempt));
        return Math.ceil(exponentialDelay + Math.random() * 1000);
    }
    async close() {
        try {
            if (this.channel) {
                await this.channel.close();
            }
            if (this.connection) {
                await this.connection.close();
            }
            this.logger.info('📪️ AMQP connection closed.');
        }
        catch (error) {
            this.logger.error('🚨 Error closing AMQP connection:', error);
        }
        finally {
            this.connection = null;
            this.channel = null;
        }
    }
    async sendMessage(queueName, message, { headers, correlationId } = {}) {
        await this.ensureConnection();
        if (!this.channel) {
            throw new Error('💥 Channel is not available');
        }
        try {
            this.logger.info(`📨 Sending message to queue: ${queueName}`);
            return this.channel.sendToQueue(queueName, Buffer.from(JSON.stringify(message)), {
                headers,
                correlationId,
                persistent: true,
                deliveryMode: 2,
                contentType: 'application/json',
                expiration: this.options.messageExpiration.queueTTL,
            });
        }
        catch (error) {
            this.logger.error(`💥 Failed sending message to queue: ${queueName}`, JSON.stringify(error, null, 2));
        }
        return false;
    }
    async ensureConnection() {
        if (!this.connection) {
            await this.connect();
        }
        if (this.connection && !this.channel) {
            this.channel = await this.connection.createChannel();
            await this.channel.prefetch(1);
        }
    }
    async createListener(queueName, onMessage, options) {
        await this.ensureConnection();
        if (!this.channel) {
            throw new Error('💥 Channel is not available');
        }
        await this.assertQueue({
            queueName,
            deadLetter: options?.deadLetter !== undefined ? options.deadLetter : true,
        });
        this.logger.info(`📬️ Starting to consume messages from queue: ${queueName}`);
        await this.channel.consume(queueName, async (msg) => {
            if (!msg || !this.channel) {
                return;
            }
            if (options?.correlationId && options.correlationId !== msg.properties.correlationId) {
                this.channel.nack(msg, false, true);
                return;
            }
            try {
                const content = JSON.parse(msg.content.toString());
                const message = {
                    content,
                    metadata: {
                        headers: msg.properties.headers,
                        correlationId: msg.properties.correlationId,
                        redelivered: msg.fields.redelivered,
                    },
                };
                const deathCount = msg.properties.headers?.['x-delivery-count'] || 0;
                const attempts = deathCount + 1;
                const result = await onMessage(message);
                if (!result) {
                    const requeue = attempts <= this.options.messageExpiration.defaultMaxRetries;
                    this.channel.nack(msg, false, requeue);
                    if (!requeue) {
                        this.logger.warn(`⚠️ Message exceeded retry limit (${this.options.messageExpiration.defaultMaxRetries}) and will be moved to DLQ: ${queueName}.dlq`);
                    }
                }
                else {
                    this.channel.ack(msg);
                    this.logger.debug(`✅ Message successfully processed`);
                }
            }
            catch (error) {
                this.logger.error('🚨 Message processing error:', error);
                this.channel.nack(msg, false, false);
            }
        });
    }
    async assertQueue({ queueName, deadLetter, }) {
        this.logger.info(`🗿 Asserting queue ${queueName} ${deadLetter ? 'with dead letter queue' : ''}`);
        await this.ensureConnection();
        if (!this.channel) {
            throw new Error('💥 Channel is not available');
        }
        const queueOptions = {
            durable: true,
            exclusive: false,
            arguments: {
                'x-queue-type': 'quorum',
                'x-max-retries': this.options.messageExpiration.defaultMaxRetries,
            },
        };
        if (deadLetter) {
            const exchangeName = `${queueName}.dlx`;
            const dlqName = `${queueName}.dlq`;
            const routingKey = `${queueName}.dead`;
            this.logger.info(`🗿 Asserting exchange "${exchangeName}"`);
            await this.channel.assertExchange(exchangeName, 'direct', {
                durable: true,
                autoDelete: false,
            });
            this.logger.info(`🗿 Asserting and binding dead letter queue "${dlqName}"`);
            await this.channel.assertQueue(dlqName, {
                durable: true,
                arguments: {
                    'x-queue-type': 'quorum',
                    'x-message-ttl': this.options.messageExpiration.deadLetterQueueTTL,
                },
            });
            await this.channel.bindQueue(dlqName, exchangeName, routingKey);
            queueOptions.deadLetterExchange = exchangeName;
            queueOptions.deadLetterRoutingKey = routingKey;
            queueOptions.arguments = {
                ...queueOptions.arguments,
                'x-dead-letter-exchange': exchangeName,
                'x-dead-letter-routing-key': routingKey,
            };
        }
        try {
            this.logger.info(`🗿 Asserting queue "${queueName}"`);
            return this.channel.assertQueue(queueName, queueOptions);
        }
        catch (error) {
            // PRECONDITION_FAILED ERROR | QUEUE EXISTS WITH DIFFERENT CONFIG
            if (this.isAmqpError(error) && error.code === 406) {
                this.logger.warn(`⚠️ Queue "${queueName}" exists with different arguments.`);
                try {
                    // WE NEED TO RECREATE THE CHANNEL. WHENEVER ASSERT QUEUE THROWS AN ERROR, THE CHANNEL BREAKS
                    await this.ensureConnection();
                    const queue = await this.channel.checkQueue(queueName);
                    if (queue.messageCount === 0) {
                        this.logger.info(`🔄 Queue "${queueName}" is empty. Recreating it with new arguments.`);
                        await this.channel.deleteQueue(queueName);
                        return await this.channel.assertQueue(queueName, queueOptions);
                    }
                    else {
                        this.logger.warn(`⚠️ Queue "${queueName}" has messages. Proceeding without re-declaring the queue.`);
                        return queue;
                    }
                }
                catch (checkError) {
                    this.logger.error(`💥 Failed to check queue "${queueName}":`, checkError);
                    throw checkError;
                }
            }
            else {
                throw error;
            }
        }
    }
    isAmqpError(error) {
        return typeof error === 'object' && error !== null && 'code' in error;
    }
}
