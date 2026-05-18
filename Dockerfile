FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create the data directory for SQLite persistence
RUN mkdir -p /app/data

# Expose API port
EXPOSE 8000

# Default environment – override via docker-compose or -e flags
ENV ICSMOG_HOST=0.0.0.0
ENV ICSMOG_PORT=8000
ENV ICSMOG_STORAGE_PATH=/app/data/cybersecurity.db

# Non-root user for security
RUN adduser --disabled-password --gecos "" icsmog \
    && chown -R icsmog:icsmog /app
USER icsmog

CMD ["python", "main.py", "--serve-api"]
