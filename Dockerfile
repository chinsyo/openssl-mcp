FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Install the package in editable mode
RUN pip install -e .

# Create directory for certificates
RUN mkdir -p /app/certs

# Expose port
EXPOSE 8080

# Run the server
CMD ["python", "-m", "src.openssl_server"]