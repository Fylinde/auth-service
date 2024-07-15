import os

class Settings:
    SECRET_KEY = "DbSLoIREJtu6z3CVnpTd_DdFeMMRoteCU0UjJcNreZI"
    PROJECT_NAME: str = "Auth Service"
    PROJECT_VERSION: str = "1.0.0"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+psycopg2://fylinde:Sylvian@db:5432/auth_service_db")

settings = Settings()
