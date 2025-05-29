# Multi-stage Docker build for Flask application migration from Node.js
# Optimized for Python 3.13.3 runtime with Flask 3.1.1 production deployment
# Supporting AWS ECR integration and security-focused minimal production images

# =============================================================================
# STAGE 1: Builder Stage - Dependency Installation and Build Optimization
# =============================================================================
FROM python:3.13.3-slim as builder

# Build stage metadata and labels for ECR integration
LABEL stage="builder"
LABEL description="Flask application builder stage for dependency optimization"
LABEL python.version="3.13.3"
LABEL flask.version="3.1.1"

# Install system dependencies required for Python package compilation
# Security optimization: Install only essential build tools and clean up immediately
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory for build operations
WORKDIR /build

# Copy requirements file for dependency installation
# Leverage Docker layer caching by copying requirements first
COPY requirements.txt .

# Install Python dependencies with optimization flags
# Security: Use --no-cache-dir to prevent cache-based attacks
# Performance: Use --user install for faster subsequent stage copy
RUN pip install --no-cache-dir --upgrade pip==24.0 && \
    pip install --no-cache-dir --user -r requirements.txt

# Validate installed packages and generate security report
# Create frozen dependency list for production reproducibility
RUN pip freeze > /build/installed-packages.txt && \
    pip check

# =============================================================================
# STAGE 2: Production Stage - Minimal Runtime Environment
# =============================================================================
FROM python:3.13.3-slim as production

# Production stage metadata for container management
LABEL stage="production"
LABEL description="Flask application production runtime"
LABEL maintainer="Blitzy Development Team"
LABEL version="1.0.0"
LABEL python.version="3.13.3"
LABEL flask.version="3.1.1"
LABEL gunicorn.enabled="true"
LABEL aws.ecr.compatible="true"

# Install minimal runtime dependencies
# Security: Install only essential runtime packages
RUN apt-get update && apt-get install -y \
    libffi8 \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security best practices
# Security: Run Flask application as non-privileged user
RUN useradd --create-home --shell /bin/bash --uid 1000 flaskuser

# Set working directory for application
WORKDIR /app

# Copy Python packages from builder stage
# Performance: Copy pre-built packages to avoid rebuilding
COPY --from=builder /root/.local /home/flaskuser/.local

# Copy installed packages list for audit and debugging
COPY --from=builder /build/installed-packages.txt /app/

# Update PATH to include user-installed packages
ENV PATH=/home/flaskuser/.local/bin:$PATH

# Copy application source code
# Performance: Copy application files after dependencies for better layer caching
COPY --chown=flaskuser:flaskuser . .

# Set Flask application configuration environment variables
# Configuration: Environment-specific settings for Flask application factory
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV FLASK_DEBUG=false
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Gunicorn WSGI server configuration for production deployment
# Performance: Optimized for Flask application with worker management
ENV GUNICORN_WORKERS=4
ENV GUNICORN_WORKER_CLASS=sync
ENV GUNICORN_WORKER_CONNECTIONS=1000
ENV GUNICORN_MAX_REQUESTS=1000
ENV GUNICORN_MAX_REQUESTS_JITTER=100
ENV GUNICORN_TIMEOUT=30
ENV GUNICORN_KEEPALIVE=2
ENV GUNICORN_BIND=0.0.0.0:5000

# Flask application configuration
# Configuration: Flask-specific environment variables for production
ENV FLASK_CONFIG=production
ENV DATABASE_URL=""
ENV SECRET_KEY=""
ENV SESSION_COOKIE_SECURE=true
ENV SESSION_COOKIE_HTTPONLY=true
ENV SESSION_COOKIE_SAMESITE=Strict

# Create required application directories
# Security: Ensure proper permissions for application directories
RUN mkdir -p /app/logs /app/tmp /app/static /app/migrations/versions && \
    chown -R flaskuser:flaskuser /app

# Switch to non-root user for security
USER flaskuser

# Expose Flask application port
# Network: Standard Flask application port for container orchestration
EXPOSE 5000

# Add health check endpoint for container orchestration
# Monitoring: Health check for AWS ALB and container orchestration
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Production command: Gunicorn WSGI server for Flask application
# Production: High-performance WSGI server configuration for Flask
CMD ["sh", "-c", "gunicorn --workers ${GUNICORN_WORKERS} --worker-class ${GUNICORN_WORKER_CLASS} --worker-connections ${GUNICORN_WORKER_CONNECTIONS} --max-requests ${GUNICORN_MAX_REQUESTS} --max-requests-jitter ${GUNICORN_MAX_REQUESTS_JITTER} --timeout ${GUNICORN_TIMEOUT} --keepalive ${GUNICORN_KEEPALIVE} --bind ${GUNICORN_BIND} --access-logfile - --error-logfile - --log-level info --preload app:app"]

# =============================================================================
# STAGE 3: Development Stage - Enhanced Development Environment (Optional)
# =============================================================================
FROM production as development

# Development stage metadata
LABEL stage="development"
LABEL description="Flask application development environment"

# Switch back to root for development tool installation
USER root

# Install development dependencies
RUN apt-get update && apt-get install -y \
    git \
    vim \
    htop \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install development Python packages
RUN pip install --no-cache-dir \
    pytest==7.4.3 \
    pytest-cov==4.1.0 \
    pytest-flask==1.3.0 \
    black==23.12.0 \
    flake8==6.1.0 \
    isort==5.13.2

# Switch back to application user
USER flaskuser

# Override environment variables for development
ENV FLASK_ENV=development
ENV FLASK_DEBUG=true
ENV GUNICORN_WORKERS=1
ENV GUNICORN_TIMEOUT=300

# Development command: Flask development server with hot reload
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000", "--debug"]

# =============================================================================
# Build Arguments for Customization
# =============================================================================
# Build-time arguments for flexible container builds
ARG ENVIRONMENT=production
ARG BUILD_VERSION=latest
ARG BUILD_DATE
ARG GIT_COMMIT

# Add build metadata as labels
LABEL build.version=${BUILD_VERSION}
LABEL build.date=${BUILD_DATE}
LABEL build.git-commit=${GIT_COMMIT}
LABEL build.environment=${ENVIRONMENT}

# =============================================================================
# Security and Compliance Annotations
# =============================================================================
# Container security and compliance metadata
LABEL security.non-root=true
LABEL security.minimal-base=true
LABEL security.vulnerability-scan=required
LABEL compliance.framework="Flask 3.1.1 Migration"
LABEL compliance.python.version="3.13.3"
LABEL compliance.aws.ecr=compatible