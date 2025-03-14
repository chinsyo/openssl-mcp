FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Create directory for certificates
RUN mkdir -p /app/certs

# Expose port
EXPOSE 8080

# Run the server
CMD ["python", "-m", "src.openssl_server"]