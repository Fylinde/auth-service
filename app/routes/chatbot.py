import pika
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from datetime import datetime

router = APIRouter()

def publish_chatbot_interaction_event(chatbot_data):
    connection = pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))
    channel = connection.channel()

    channel.queue_declare(queue='chatbot_interaction_created')

    channel.basic_publish(
        exchange='',
        routing_key='chatbot_interaction_created',
        body=json.dumps(chatbot_data)
    )

    connection.close()

@router.post("/interact")
def create_chatbot_interaction(chatbot: dict, db: Session = Depends(get_db)):
    # Prepare the chatbot interaction data
    chatbot_data = {
        "user_id": chatbot.get('user_id'),
        "vendor_id": chatbot.get('vendor_id'),
        "interaction_type": chatbot.get('interaction_type'),
        "message": chatbot.get('message'),
        "response": chatbot.get('response'),
        "created_at": datetime.utcnow().isoformat()
    }

    # Publish the chatbot interaction event
    publish_chatbot_interaction_event(chatbot_data)

    return {"message": "Chatbot interaction event published successfully"}
