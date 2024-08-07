import os
from dotenv import load_dotenv

# Load the .env file
load_dotenv()


class Settings:
    SECRET_KEY = os.getenv("SECRET_KEY", "DbSLoIREJtu6z3CVnpTd_DdFeMMRoteCU0UjJcNreZI")
    PROJECT_NAME: str = "Auth Service"
    PROJECT_VERSION: str = "1.0.0"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:Sylvian@db:5433/auth_service_db")
    DATABASE_USER: str = os.getenv("DATABASE_USER", "postgres")
    DATABASE_PASSWORD: str = os.getenv("DATABASE_PASSWORD", "Sylvian")
    DATABASE_DB: str = os.getenv("DATABASE_DB", "auth_service_db")
    DATABASE_PORT: int = int(os.getenv("DATABASE_PORT", "5433"))
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
    MAILGUN_API_KEY: str = os.getenv("MAILGUN_API_KEY", "b1783faf183126ff644b5013b99d4b2d-91fbbdba-10527e3b")
    MAILGUN_SENDER_EMAIL: str = os.getenv("MAILGUN_SENDER_EMAIL", "ifionuf@gmail.com")
    MAILGUN_DOMAIN: str = os.getenv("MAILGUN_DOMAIN", "sandboxbc6bd08084c94220be9b418c7732ee1b.mailgun.org")
    SECURITY_PASSWORD_SALT: str = os.getenv("SECURITY_PASSWORD_SALT", "mX-rk2vC6fyBmWPncH54sbHVLv4dT0FqQE2mysbkeKM")

settings = Settings()
