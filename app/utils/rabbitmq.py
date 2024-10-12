import pika
import json
import os
import logging
from time import sleep

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RabbitMQConnection:
    def __init__(self, queue_name: str = None, exchange_name: str = None, exchange_type: str = 'direct', retries: int = 5, retry_delay: int = 5):
        self.url = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672/')
        self.queue_name = queue_name
        self.exchange_name = exchange_name
        self.exchange_type = exchange_type
        self.retries = retries
        self.retry_delay = retry_delay

        self.connection = None
        self.channel = None

        self._connect()

    def _connect(self):
        """
        Attempt to connect to RabbitMQ with retry logic and error handling.
        """
        attempt = 0
        while attempt < self.retries:
            try:
                logger.info(f"Attempting to connect to RabbitMQ ({attempt+1}/{self.retries})")
                self.connection = pika.BlockingConnection(pika.URLParameters(self.url))
                self.channel = self.connection.channel()

                if self.exchange_name:
                    # Declare exchange if provided (fanout, direct, topic)
                    self.channel.exchange_declare(exchange=self.exchange_name, exchange_type=self.exchange_type, durable=True)
                if self.queue_name:
                    # Declare queue if provided
                    self.channel.queue_declare(queue=self.queue_name, durable=True)
                
                logger.info("RabbitMQ connection established successfully.")
                break
            except pika.exceptions.AMQPConnectionError as e:
                attempt += 1
                logger.error(f"RabbitMQ connection failed: {e}. Retrying in {self.retry_delay} seconds...")
                sleep(self.retry_delay)
        
        if attempt == self.retries:
            logger.critical("Failed to establish RabbitMQ connection after multiple retries. Exiting.")
            raise ConnectionError("Failed to establish RabbitMQ connection after retries.")

    def publish_message(self, message: dict, routing_key: str = None):
        """
        Publish a message to the given RabbitMQ queue or exchange.
        If an exchange is specified, publish to the exchange with the routing_key.
        """
        try:
            routing_key = routing_key or self.queue_name
            if not routing_key:
                raise ValueError("A queue name or routing key must be provided.")

            self.channel.basic_publish(
                exchange=self.exchange_name or '',
                routing_key=routing_key,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Make message persistent
                )
            )
            logger.info(f"Message published to {routing_key}: {message}")

        except Exception as e:
            logger.error(f"Failed to publish message: {e}")
            raise

    def consume_messages(self, callback):
        """
        Consume messages from the given queue using the provided callback function.
        """
        if not self.queue_name:
            raise ValueError("Queue name must be specified for consuming messages.")

        try:
            self.channel.basic_qos(prefetch_count=1)  # Fair dispatch: only send 1 message at a time
            self.channel.basic_consume(queue=self.queue_name, on_message_callback=callback, auto_ack=False)
            logger.info(f"Waiting for messages in {self.queue_name}. To exit, press CTRL+C.")
            self.channel.start_consuming()

        except Exception as e:
            logger.error(f"Failed to consume messages: {e}")
            raise

    def close_connection(self):
        """
        Close the RabbitMQ connection gracefully.
        """
        try:
            if self.connection:
                self.connection.close()
                logger.info("RabbitMQ connection closed successfully.")
        except Exception as e:
            logger.error(f"Failed to close RabbitMQ connection: {e}")
            raise

