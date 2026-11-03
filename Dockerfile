# Step 1: Use a minimal, secure base image
FROM python:3.12-slim AS base

# Set environment variables:
# - PYTHONDONTWRITEBYTECODE: Prevents Python from writing .pyc files
# - PYTHONUNBUFFERED: Ensures logs are flushed directly to stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=3000

# Set working directory
WORKDIR /app

# Install security patches and build essentials if native C extensions are needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Step 2: Install dependencies in a separate layer for optimal Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Step 3: Copy application source code
COPY . .

# Create a non-root user for security compliance in production
RUN useradd -m -u 10001 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose port (matching your server configuration)
EXPOSE 3000

# Step 4: Define container start command
CMD ["python", "src/main.py"]