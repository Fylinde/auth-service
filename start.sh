#!/bin/bash

# Log start of the script
echo "Starting start.sh script..."

# Ensure the wait-for-it script is executable
chmod +x ./wait-for-it.sh
echo "wait-for-it.sh script is now executable."

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL server to be available..."
./wait-for-it.sh db:5433 --timeout=180 --strict

if [ $? -ne 0 ]; then
  echo "PostgreSQL is not ready. Exiting..."
  exit 1
fi

# Log PostgreSQL readiness
echo "PostgreSQL is ready."

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

# Start the FastAPI application with debug logs
echo "Starting auth-service with debug logs..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level debug
