import logging
from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from app.routes import auth, admin
from app.models.user import UserModel
from app.database import engine  # Add the correct import for engine
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(admin.router, prefix="/admin", tags=["admin"])

# Serve the static directory
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.on_event("startup")
async def startup():
    # Create database tables
    logger.info("Creating all tables in the database...")
    UserModel.metadata.create_all(bind=engine)
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
async def protected(current_user: UserModel = Depends(auth.get_current_user)):
    return {"message": "This is a protected endpoint", "user": current_user.username}
