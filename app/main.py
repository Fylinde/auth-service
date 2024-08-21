import logging
from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from app.routes.user import router as auth_router
from app.routes.admin import router as admin_router
from app.routes.vendor import router as vendor_router
from app.routes.chatbot import router as chatbot_router
from app.models.user import UserModel
from app.models.admin import AdminModel  # Import AdminModel if it's being used in admin.py
from app.database import engine, BaseModel  # Import the base model
from app.security import get_current_user  # Import your security logic
import os

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
        {"name": "vendor", "description": "Vendor-related operations"},
        {"name": "chatbot", "description": "Chatbot integration for user interactions"},
    ],
)

# Include routers
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(admin_router, prefix="/admin", tags=["admin"])
app.include_router(vendor_router, prefix="/vendor", tags=["vendor"])
app.include_router(chatbot_router, prefix="/chatbot", tags=["chatbot"])

# Serve the static directory
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.on_event("startup")
async def startup():
    # Create database tables
    logger.info("Creating all tables in the database...")
    BaseModel.metadata.create_all(bind=engine)
    logger.info("All tables created successfully.")

@app.get("/")
async def root():
    return {"message": "Welcome to the Auth Service!"}

@app.middleware("http")
async def log_request(request: Request, call_next):
    logger.info(f"Headers: {request.headers}")
    response = await call_next(request)
    return response

@app.get("/protected")
async def protected(current_user: UserModel = Depends(get_current_user)):
    return {"message": "This is a protected endpoint", "user": current_user.username}


# ReDoc: http://localhost:8001/redoc
# http://localhost:8001/docs
# http://localhost:8000/openapi.json