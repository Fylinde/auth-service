import logging
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
import pika
import asyncio  # ✅ Import asyncio
from app.config import settings
from app.routes.user_auth import router as user_router
from app.routes.seller_auth import router as seller_router
from app.routes import seller_verification

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Auth Service API",
    description="API for authentication and authorization",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "User authentication"},
        {"name": "admin", "description": "Admin operations"},
        {"name": "seller", "description": "Seller operations"},
        {"name": "chatbot", "description": "Chatbot API"},
    ],
)

origins = ["http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        await websocket.send_text(f"Message text was: {data}")

# Include routers
app.include_router(user_router, prefix="/auth", tags=["user-auth"])
app.include_router(seller_router, prefix="/auth/seller", tags=["seller-auth"])
app.include_router(seller_verification.router, prefix="/auth", tags=["seller_verification"])

@app.on_event("startup")
async def startup_event():
    """Startup event for connecting to RabbitMQ and logging available routes."""
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=settings.RABBITMQ_HOST)
        )
        connection.close()
        logger.info("Successfully connected to RabbitMQ")
    except Exception as e:
        logger.error(f"Failed to connect to RabbitMQ: {e}")

    # ✅ Use asyncio.create_task instead of asyncio.run()
    asyncio.create_task(log_routes(app))  # ✅ Ensure routes are logged correctly

async def log_routes(app: FastAPI):
    """Logs all registered routes safely (handles WebSocket routes)"""
    await asyncio.sleep(1)  # Ensure FastAPI is fully initialized before logging

    logger.info("Available Routes:")
    for route in app.router.routes:
        if hasattr(route, "methods"):  # ✅ Only log methods for HTTP routes
            logger.info(f"Path: {route.path}, Name: {route.name}, Methods: {route.methods}")
        else:  # ✅ Handle WebSocket routes separately
            logger.info(f"Path: {route.path}, Name: {route.name}, WebSocket Route")
