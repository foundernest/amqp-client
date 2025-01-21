
# AMQP Client

A TypeScript-based AMQP client designed to work with RabbitMQ and provides functionalities for connecting to the broker, sending messages, and consuming messages with support for dead-letter queues and reconnection strategies.

## Features

-   Written in TypeScript
-   Handles automatic reconnection with exponential backoff
-   Supports dead-letter queues
-   Customizable logging

## Installation

To install the package, use npm or yarn:

-   `npm install foundernest-amqp-client`
-   `yarn add foundernest-amqp-client`

## Usage

### Creating an AMQP Client

Create an instance of  `AMQPClient`  by providing connection options and, optionally, a custom logger:  

Example:  
```
import { AMQPClient } from 'foundernest-amqp-client';

const myLogger = new MyLogger()
const client = new AMQPClient({ 
  options: { 
    host: 'localhost', 
    username: 'guest', 
    password: 'guest',
    logger: myLogger,
  } 
});
```

### Sending messages

To send a message to a queue, use the  `sendMessage`  method:  
Example:  
```
await client.sendMessage('test-queue', { key: 'value' });
```

You can send headers and a correlation id along with the message:
```
await client.sendMessage('test-queue', data, { 
    correlationId: 1234
    headers: { 
      key: 'value'
    }, 
  }
);
```

### Creating a listener

To create a listener for a queue, use the  `createListener`  method. This method sets up the necessary queue and binds it to a dead-letter queue if specified. Ensure that the connection is established before starting to consume messages:  
Example:  
```
const client = new AMQPClient(config);
await client.createListener('test-queue', async (message) => {
    checkAuth(message.headers) 
    processMessage(message.content); 
});
```
### Connecting to the Broker

You don't need to explicitly connect to the broker, each time a listener is created a connection will be created if needed.  
If the connection to the broker is lost, the client will attempt to reconnect using a exponential backoff strategy.

### Closing the connection

To close the AMQP connection and channel, call the  `close`  method:  
Example:  
```
await client.close();
```

## Configuration

### Client options

-   `host`: The hostname of the AMQP broker.
-   `port`: The port of the AMQP broker (default: 5672).
-   `username`: The username for authentication.
-   `password`: The password for authentication.
-   `vhost`: The virtual host to connect to (default: '/').

### Logging

You can provide a custom logger that implements the methods  `debug`,  `info`,  `warn`, and  `error`. By default, the client's logging will use the console.

## Testing

This project uses Vitest for testing. To run the tests, use the following command:

-   `npm test`

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

This README provides an overview of your AMQP client, including installation instructions, usage examples, configuration options, and information on testing and contributing. Feel free to customize it further based on your specific requirements.