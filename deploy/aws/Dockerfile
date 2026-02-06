# Kai AWS Deployment Dockerfile
# Optimized for long-running security analysis jobs

FROM python:3.12-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (Solidity toolchain)
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup

# Add Foundry to PATH
ENV PATH="/root/.foundry/bin:${PATH}"

# Verify Foundry installation
RUN forge --version

# Set working directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY pyproject.toml ./
COPY src/kai ./kai

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Copy the rest of the application
COPY scripts/ ./scripts/
COPY deploy/aws/entrypoint.sh ./entrypoint.sh

# Make entrypoint executable
RUN chmod +x ./entrypoint.sh

# Create output directory
RUN mkdir -p /app/output

# Default environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Entrypoint
ENTRYPOINT ["./entrypoint.sh"]
