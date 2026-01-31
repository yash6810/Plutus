# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set environment variables for Python paths
ENV PYTHONPATH=/app

# Expose port (Render uses $PORT)
EXPOSE 8000

# Run the application using gunicorn for production stability
# -w 1: Reduced to 1 worker to fit in 512MB RAM
# --timeout 120: Increased timeout for slow AI initialization
CMD gunicorn -w 1 -k uvicorn.workers.UvicornWorker api.main:app --bind 0.0.0.0:$PORT --timeout 120


