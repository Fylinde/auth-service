import logging
from fastapi import FastAPI,  WebSocket
from fastapi.middleware.cors import CORSMiddleware  # Import CORSMiddleware
import pika
from app.config import settings
from app.routes.user_auth import router as user_router
from app.routes.seller_auth import router as seller_router
from app.routes import seller_verification


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Initialize the FastAPI app with metadata for Swagger
app = FastAPI(
    title="Auth Service API",
    description="This is the API documentation for the Auth Service, which handles user authentication, authorization, and related operations.",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "Operations related to user authentication and authorization"},
        {"name": "admin", "description": "Admin-specific operations"},
        {"name": "seller", "description": "seller-related operations"},
        {"name": "chatbot", "description": "Chatbot integration for user interactions"},
    ],
)


# Define the list of allowed origins explicitly
origins = [
    "http://localhost:3000",  # Your frontend application
]


# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allow these origins
    allow_credentials=True,  # Allow cookies and credentials
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        await websocket.send_text(f"Message text was: {data}")


# Include routers for user and seller authentication
app.include_router(user_router, prefix="/auth", tags=["user-auth"])
app.include_router(seller_router, prefix="/auth/seller", tags=["seller-auth"])
# Mount the auth router
#app.include_router(user_router, prefix="/auth")
# Include the seller verification router
app.include_router(seller_verification.router, prefix="/auth", tags=["seller_verification"])


@app.on_event("startup")
async def startup_event():
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=settings.RABBITMQ_HOST)
        )
        connection.close()
        logger.info("Successfully connected to RabbitMQ")
    except Exception as e:
        logger.error(f"Failed to connect to RabbitMQ: {e}")

    for route in app.router.routes:
        print(route.path, route.name)