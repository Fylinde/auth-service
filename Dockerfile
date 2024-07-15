FROM python:3.9-slim

WORKDIR /app

# Copy requirements.txt from the correct directory
COPY requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy the app directory
COPY app /app

# Copy the alembic.ini file
COPY alembic.ini /app/alembic.ini

# Copy the start.sh and wait-for-it.sh scripts
COPY start.sh /app/start.sh
COPY wait-for-it.sh /app/wait-for-it.sh

# Make scripts executable
RUN chmod +x /app/start.sh /app/wait-for-it.sh

# Explicitly set PYTHONPATH
ENV PYTHONPATH=/app

CMD ["/app/start.sh"]
