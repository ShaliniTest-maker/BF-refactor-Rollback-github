# Multi-stage Docker build for Flask application deployment
# Base image: Official Python 3.13.3 with security patches and performance optimizations

# Stage 1: Build environment for dependency installation
FROM python:3.13.3-slim as builder

# Set build arguments for dependency optimization
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Add metadata labels for container orchestration compatibility
LABEL maintainer="Flask Migration Team" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0" \
      org.opencontainers.image.title="Flask Application" \
      org.opencontainers.image.description="Production Flask application container" \
      org.opencontainers.image.source="https://github.com/organization/flask-migration"

# Install system dependencies required for Python packages
# Update package lists and install essential build tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security best practices
RUN groupadd -r flask && useradd -r -g flask flask

# Set working directory for build operations
WORKDIR /app

# Copy requirements file first for Docker layer caching optimization
COPY requirements.txt .

# Install Python dependencies with pinned versions for reproducible builds
# Use pip cache and wheel builds for faster subsequent builds
RUN pip install --no-cache-dir --upgrade pip==24.3.1 \
    && pip install --no-cache-dir wheel==0.45.1 \
    && pip install --no-cache-dir -r requirements.txt

# Stage 2: Production runtime environment
FROM python:3.13.3-slim as production

# Install runtime system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for production security
RUN groupadd -r flask && useradd -r -g flask flask

# Set production working directory
WORKDIR /app

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code with proper ownership
COPY --chown=flask:flask . .

# Create necessary directories for Flask application
RUN mkdir -p /app/instance \
    && mkdir -p /app/logs \
    && chown -R flask:flask /app

# Set environment variables for Flask production configuration
ENV FLASK_ENV=production \
    FLASK_CONFIG=production \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PATH="/home/flask/.local/bin:$PATH"

# Switch to non-root user for security
USER flask

# Expose port 5000 for Flask application
EXPOSE 5000

# Health check endpoint for container orchestration
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Production WSGI server configuration using Gunicorn
# Optimized worker configuration: 2-4 workers per CPU core
# Timeout settings: worker-timeout=30s, graceful-timeout=30s, keepalive=5s
# Resource management compatible with Kubernetes deployment
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "4", \
     "--worker-class", "sync", \
     "--worker-timeout", "30", \
     "--graceful-timeout", "30", \
     "--keepalive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--preload", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "--capture-output", \
     "wsgi:application"]

# Alternative uWSGI configuration (commented for Gunicorn preference)
# CMD ["uwsgi", \
#      "--http", "0.0.0.0:5000", \
#      "--module", "wsgi:application", \
#      "--master", \
#      "--processes", "4", \
#      "--threads", "2", \
#      "--buffer-size", "32768", \
#      "--max-requests", "1000", \
#      "--disable-logging", \
#      "--log-4xx", \
#      "--log-5xx"]