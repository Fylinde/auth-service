#!/bin/bash

# Log start of the script
echo "Starting start.sh script..."

# Ensure the wait-for-it script is executable
chmod +x /app/wait-for-it.sh
echo "wait-for-it.sh script is now executable."

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL server to be available..."
/app/wait-for-it.sh db:5432 --timeout=180 --strict

if [ $? -ne 0 ]; then
  echo "PostgreSQL is not ready. Exiting..."
  exit 1
fi

# Log PostgreSQL readiness
echo "PostgreSQL is ready."

# Set the PYTHONPATH environment variable
export PYTHONPATH=/app
echo "PYTHONPATH is set to $PYTHONPATH"

# Navigate to the app directory
cd /app
echo "Current directory is $(pwd)"

# Log the files in the current directory
echo "Files in the current directory:"
ls -l

# Check if main.py exists
if [ ! -f main.py ]; then
  echo "main.py does not exist in the /app directory. Exiting..."
  exit 1
fi

# Check if alembic directory exists
if [ ! -d "alembic" ]; then
  echo "Alembic directory does not exist. Initializing alembic..."
  alembic init alembic
fi

# Run database migrations using alembic.ini configuration file
echo "Running database migrations..."
alembic -c alembic.ini upgrade head
if [ $? -ne 0 ]; then
  echo "Database migrations failed. Exiting..."
  exit 1
fi

# Log successful migration
echo "Database migrations completed successfully."

# Start the FastAPI application
echo "Starting auth-service..."
PYTHONPATH=/app uvicorn main:app --host 0.0.0.0 --port 8000
