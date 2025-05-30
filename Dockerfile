# Multi-stage Docker build for Flask application deployment
# Python 3.13.3 Flask-based backend migration from Node.js
# Optimized for production deployment with security and performance enhancements

# ==============================================================================
# Stage 1: Python Dependencies Builder
# Optimized dependency installation with build tools and compilation environment
# ==============================================================================

FROM python:3.13.3-slim as builder

# Build arguments for configuration
ARG BUILD_DATE
ARG BUILD_VERSION=1.0.0
ARG BUILD_COMMIT=latest

# Set environment variables for build optimization
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=100

# Set working directory for dependency installation
WORKDIR /build

# Install system dependencies required for Python package compilation
# Optimized for Flask dependencies including psycopg2, cryptography, and gevent
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    zlib1g-dev \
    pkg-config \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy requirements file for dependency installation
COPY requirements.txt .

# Create virtual environment for dependency isolation
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies with optimized pip configuration
# Using pinned versions from requirements.txt for reproducible builds
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --no-deps -r requirements.txt && \
    pip install --no-cache-dir -r requirements.txt

# Verify critical dependencies installation
RUN python -c "import flask; print(f'Flask {flask.__version__} installed')" && \
    python -c "import gunicorn; print(f'Gunicorn {gunicorn.__version__} installed')" && \
    python -c "import sqlalchemy; print(f'SQLAlchemy {sqlalchemy.__version__} installed')"

# ==============================================================================
# Stage 2: Production Runtime Environment
# Minimal production image with security optimizations and monitoring support
# ==============================================================================

FROM python:3.13.3-slim as production

# Build metadata for container identification and monitoring
LABEL maintainer="Flask Migration Team" \
      version="${BUILD_VERSION}" \
      build-date="${BUILD_DATE}" \
      commit="${BUILD_COMMIT}" \
      description="Flask application container for Node.js migration" \
      python.version="3.13.3" \
      framework="Flask 3.1.1" \
      wsgi.server="Gunicorn 20.x"

# Production environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    FLASK_ENV=production \
    FLASK_APP=app.py \
    GUNICORN_WORKERS=4 \
    GUNICORN_WORKER_CLASS=sync \
    GUNICORN_WORKER_TIMEOUT=30 \
    GUNICORN_KEEPALIVE=5 \
    GUNICORN_MAX_REQUESTS=1000 \
    GUNICORN_MAX_REQUESTS_JITTER=100 \
    PORT=5000

# Create application user for security (non-root execution)
RUN groupadd --gid 1000 flask && \
    useradd --uid 1000 --gid flask --shell /bin/bash --create-home flask

# Install minimal runtime dependencies only
# Optimized for production with security patches and performance enhancements
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libffi8 \
    libssl3 \
    libxml2 \
    libxslt1.1 \
    libjpeg62-turbo \
    zlib1g \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && apt-get autoremove -y

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set application working directory
WORKDIR /app

# Copy application code with proper ownership
COPY --chown=flask:flask . .

# Ensure WSGI entry point is executable
RUN chmod +x wsgi.py

# Create necessary directories for Flask application
RUN mkdir -p /app/logs /app/instance /app/static /app/templates && \
    chown -R flask:flask /app

# Security hardening: remove unnecessary packages and files
RUN find /opt/venv -name "*.pyc" -delete && \
    find /opt/venv -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Switch to non-root user for security
USER flask

# Health check configuration for container orchestration
# Supports both Application Load Balancer and Kubernetes health monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Expose application port for service communication
EXPOSE ${PORT}

# Production startup command using Gunicorn WSGI server
# Optimized for container orchestration with graceful shutdown support
CMD exec gunicorn \
    --bind 0.0.0.0:${PORT} \
    --workers ${GUNICORN_WORKERS} \
    --worker-class ${GUNICORN_WORKER_CLASS} \
    --worker-tmp-dir /dev/shm \
    --timeout ${GUNICORN_WORKER_TIMEOUT} \
    --keepalive ${GUNICORN_KEEPALIVE} \
    --max-requests ${GUNICORN_MAX_REQUESTS} \
    --max-requests-jitter ${GUNICORN_MAX_REQUESTS_JITTER} \
    --preload \
    --log-level info \
    --log-file - \
    --access-logfile - \
    --access-logformat '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s' \
    --capture-output \
    --enable-stdio-inheritance \
    --graceful-timeout 30 \
    --worker-connections 1000 \
    wsgi:application

# ==============================================================================
# Development Override Stage (Optional)
# Provides development-specific configuration for testing and debugging
# ==============================================================================

FROM production as development

# Override environment for development mode
ENV FLASK_ENV=development \
    FLASK_DEBUG=1 \
    GUNICORN_WORKERS=1 \
    GUNICORN_RELOAD=1

# Switch back to root for development tools installation
USER root

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    git \
    openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install development Python packages
RUN pip install --no-cache-dir \
    flask-debugtoolbar \
    pytest-benchmark \
    coverage \
    black \
    flake8 \
    mypy

# Switch back to flask user
USER flask

# Development startup command with debugging enabled
CMD exec gunicorn \
    --bind 0.0.0.0:${PORT} \
    --workers ${GUNICORN_WORKERS} \
    --worker-class ${GUNICORN_WORKER_CLASS} \
    --timeout ${GUNICORN_WORKER_TIMEOUT} \
    --reload \
    --log-level debug \
    --log-file - \
    --access-logfile - \
    wsgi:application

# ==============================================================================
# Container Build Instructions and Usage Examples
# ==============================================================================

# Build production image:
# docker build --target production -t flask-app:latest .
#
# Build development image:
# docker build --target development -t flask-app:dev .
#
# Build with metadata:
# docker build --target production \
#   --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
#   --build-arg BUILD_VERSION=1.0.0 \
#   --build-arg BUILD_COMMIT=$(git rev-parse --short HEAD) \
#   -t flask-app:1.0.0 .
#
# Run production container:
# docker run -d \
#   --name flask-app \
#   -p 5000:5000 \
#   -e FLASK_CONFIG=production \
#   -e DATABASE_URL=postgresql://user:pass@host:5432/db \
#   -e SECRET_KEY=your-secret-key \
#   flask-app:latest
#
# Run with custom Gunicorn configuration:
# docker run -d \
#   --name flask-app \
#   -p 5000:5000 \
#   -e GUNICORN_WORKERS=8 \
#   -e GUNICORN_WORKER_CLASS=gevent \
#   -e GUNICORN_WORKER_TIMEOUT=60 \
#   flask-app:latest
#
# Health check endpoint verification:
# curl http://localhost:5000/health
# curl http://localhost:5000/metrics
#
# Container security scanning:
# docker scan flask-app:latest
#
# Container resource limits for Kubernetes:
# resources:
#   requests:
#     memory: "256Mi"
#     cpu: "250m"
#   limits:
#     memory: "512Mi"
#     cpu: "500m"