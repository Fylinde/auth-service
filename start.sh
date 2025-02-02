#!/bin/bash

# Log start of the script
echo "Starting start.sh script..."

# Ensure the wait-for-it script is executable
chmod +x ./wait-for-it.sh
echo "wait-for-it.sh script is now executable."

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL server to be available on port 5433..."
./wait-for-it.sh db:5433 --timeout=180 --strict

if [ $? -ne 0 ]; then
  echo "ERROR: PostgreSQL did not become available. Exiting..."
  exit 1
else
  echo "SUCCESS: PostgreSQL is ready and reachable on port 5433."
fi

# Additional verification to confirm actual connection to the database
echo "Verifying actual connection to PostgreSQL database..."

# Use a small Python script to attempt the connection
python3 - <<END
import psycopg2
import os

try:
    connection = psycopg2.connect(
        dbname=os.getenv("POSTGRES_DB", "auth_service_db"),
        user=os.getenv("POSTGRES_USER", "postgres"),
        password=os.getenv("POSTGRES_PASSWORD", "Sylvian"),
        host="db",
        port="5433"
    )
    connection.close()
    print("SUCCESS: Successfully connected to the PostgreSQL database on port 5433.")
except Exception as e:
    print("ERROR: Could not connect to the PostgreSQL database on port 5433.")
    print(f"DETAILS: {e}")
    exit(1)
END

# Wait for RabbitMQ to be ready
echo "Waiting for RabbitMQ server to be available..."
./wait-for-it.sh rabbitmq:5672 --timeout=180 --strict

if [ $? -ne 0 ]; then
  echo "RabbitMQ is not ready. Exiting..."
  exit 1
fi

# Log RabbitMQ readiness
echo "RabbitMQ is ready."

# Start the FastAPI app
export CHOKIDAR_USEPOLLING=true

# Set the PYTHONPATH environment variable
export PYTHONPATH=/app
echo "PYTHONPATH is set to $PYTHONPATH"

# Set the SECRET_KEY environment variable
export SECRET_KEY="DbSLoIREJtu6z3CVnpTd_DdFeMMRoteCU0UjJcNreZI"
echo "SECRET_KEY is set to $SECRET_KEY"

# Navigate to the app directory
cd /app
echo "Current directory is $(pwd)"

# Log the files in the current directory
echo "Files in the /app directory:"
ls -l

# Log the files in the /app/app directory
echo "Files in the /app/app directory:"
ls -l app

# Log the files in the /app/app/models directory
echo "Files in the /app/app/models directory:"
ls -l app/models

# Log the files in the /app/app/migrations directory
echo "Files in the /app/app/migrations directory:"
ls -l app/migrations

# Log the files in the /app/app/static directory
echo "Files in the /app/app/static directory:"
ls -l app/static

# Check if main.py exists
if [ ! -f app/main.py ]; then
  echo "main.py does not exist in the /app/app directory. Exiting..."
  exit 1
else
  echo "main.py exists in the /app/app directory."
fi

# Check if alembic.ini exists
if [ ! -f alembic.ini ]; then
  echo "alembic.ini does not exist in the /app directory. Exiting..."
  exit 1
else
  echo "alembic.ini exists in the /app directory."
fi

# Check if the migrations directory exists
if [ ! -d app/migrations ]; then
  echo "Migrations directory does not exist in the /app/app directory. Exiting..."
  exit 1
else
 echo "Migrations directory exists in the /app/app directory."
fi

# Log successful migration
echo "Database migrations completed successfully (if migrations were run)."

# Start the FastAPI application with hot reload and debug logs
echo "Starting auth-service with hot reload and debug logs..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --log-level debug

