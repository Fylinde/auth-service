import requests
from app.schemas.auth_schemas import UserLogin
from fastapi import HTTPException

USER_SERVICE_URL = "http://localhost:8001/users"

def authenticate_user_service(user_data: UserLogin):
    response = requests.get(f"{USER_SERVICE_URL}/users/{user_data.email}")

    if response.status_code != 200:
        raise HTTPException(status_code=403, detail="Invalid credentials or unverified email.")

    user = response.json()
    if not user["is_email_verified"]:
        raise HTTPException(status_code=403, detail="Email is not verified.")
    
    return {"message": "Login successful", "access_token": "your_token_here"}
