# A3 Python - Advanced Automated Analysis for Python
# Docker image for static analysis and security checking

FROM python:3.11-slim

LABEL maintainer="a3-python"
LABEL description="Find real bugs in Python codebases automatically with A3"
LABEL version="0.1.21"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies (if any additional ones needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md MANIFEST.in ./
COPY a3_python/ ./a3_python/

# Install the package
RUN pip install --no-cache-dir -e .

# Create a directory for mounting target code to analyze
RUN mkdir -p /target

# Set the entrypoint to the CLI
ENTRYPOINT ["a3"]

# Default to showing help if no arguments provided
CMD ["--help"]
