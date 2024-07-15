import logging
from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from routes import auth
from database import engine
from models import user

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Include the auth router
app.include_router(auth.router, prefix="/auth")


# Serve the static directory
app.mount("/static", StaticFiles(directory="./static"), name="static")

@app.on_event("startup")
async def startup():
    # Create database tables
    logger.info("Creating all tables in the database...")
    user.Base.metadata.create_all(bind=engine)
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
async def protected(current_user: user.User = Depends(auth.get_current_user)):
    return {"message": "This is a protected endpoint", "user": current_user.username}
