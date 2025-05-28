# Multi-stage Docker container build configuration for Flask application deployment
# Optimizing Flask application deployment using python:3.13.3-slim base image
# for reduced attack surface and consistent environment provisioning
# 
# This Dockerfile implements enterprise-grade containerization following 
# Section 8.3 CONTAINERIZATION requirements with multi-stage build process,
# security scanning support, and AWS ECR integration capabilities

# =============================================================================
# BUILDER STAGE - Dependency Installation and Build Preparation
# =============================================================================
FROM python:3.13.3-slim as builder

# Set environment variables for build optimization
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create application directory
WORKDIR /app

# Install system dependencies required for Python package compilation
# Essential for building Python packages with C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file for dependency installation
# This is done early to leverage Docker layer caching
COPY requirements.txt .

# Install Python dependencies with frozen requirements for security verification
# per Section 8.1.1 - Runtime Security requirements
RUN pip install --no-cache-dir --user -r requirements.txt

# =============================================================================
# PRODUCTION STAGE - Minimal Production Image with Security Optimizations
# =============================================================================
FROM python:3.13.3-slim as production

# Set production environment variables following Flask best practices
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    PATH="/home/flaskuser/.local/bin:$PATH"

# Install runtime dependencies only (no build tools for security)
# libpq5 required for PostgreSQL connectivity per Section 5.2.4
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security best practices
# Prevents privilege escalation and improves container security posture
RUN groupadd --gid 1000 flaskuser \
    && useradd --uid 1000 --gid flaskuser --shell /bin/bash --create-home flaskuser

# Set working directory
WORKDIR /app

# Copy Python packages from builder stage
# This transfers only the installed packages without build dependencies
COPY --from=builder /root/.local /home/flaskuser/.local

# Copy application source code with proper ownership
# Maintains security by ensuring non-root ownership of application files
COPY --chown=flaskuser:flaskuser . .

# Switch to non-root user for all subsequent operations
USER flaskuser

# Expose port 5000 for Flask application
# Standard Flask development port, configurable via environment variables
EXPOSE 5000

# Configure health check for container orchestration and monitoring
# Enables proper health monitoring in Kubernetes and AWS ECS environments
HEALTHCHECK --interval=30s --timeout=30s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Configure Gunicorn WSGI server for production deployment
# per Section 8.3.2 - Container Build Configuration requirements
# Optimized for Flask application factory pattern per Section 5.1.1
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "4", \
     "--worker-class", "sync", \
     "--worker-connections", "1000", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--preload", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "app:app"]

# =============================================================================
# Container Labels for AWS ECR Integration and Metadata Management
# =============================================================================
LABEL maintainer="Blitzy Platform Engineering" \
      version="1.0.0" \
      description="Flask 3.1.1 application with Python 3.13.3 runtime" \
      runtime="python:3.13.3-slim" \
      framework="Flask 3.1.1" \
      architecture="blueprint-based modular" \
      deployment="gunicorn-wsgi" \
      security="vulnerability-scanned" \
      registry="aws-ecr"

# =============================================================================
# Production Deployment Notes:
# 
# Environment Variables Required:
# - DATABASE_URL: PostgreSQL connection string for Flask-SQLAlchemy
# - SECRET_KEY: Flask application secret key for session management
# - FLASK_ENV: Application environment (production/staging/development)
# 
# Volume Mounts:
# - /app/logs: Application log directory for persistent logging
# 
# Port Configuration:
# - Container exposes port 5000
# - Map to desired host port during deployment
# 
# Resource Recommendations:
# - Memory: 512MB minimum, 1GB recommended for production
# - CPU: 0.5 cores minimum, 1 core recommended for production
# 
# Security Scanning:
# - Compatible with Amazon ECR vulnerability scanning
# - Regular base image updates for security patches
# - Non-root user execution for reduced attack surface
# =============================================================================