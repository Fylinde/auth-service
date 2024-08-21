import pika
import json
import logging
from app.config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def publish_user_created_event(user_data):
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=settings.RABBITMQ_HOST)
    )
    channel = connection.channel()

    # Declare the fanout exchange
    channel.exchange_declare(exchange='user_events', exchange_type='fanout')

    message = json.dumps(user_data)
    channel.basic_publish(exchange='user_events', routing_key='', body=message)
    connection.close()

    # Log the event
    logger.info(f"Published user_created event to RabbitMQ for user_id: {user_data['id']}")


def publish_vendor_created_event(vendor_data):
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=settings.RABBITMQ_HOST)
    )
    channel = connection.channel()

    # Declare the fanout exchange
    channel.exchange_declare(exchange='vendor_events', exchange_type='fanout')

    message = json.dumps(vendor_data)
    channel.basic_publish(exchange='vendor_events', routing_key='', body=message)
    connection.close()

    # Log the event
    logger.info(f"Published vendor_created event to RabbitMQ for vendor_id: {vendor_data['id']}")