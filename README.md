# Python Flask Backend Application

A robust Python Flask backend application migrated from Node.js, implementing enterprise-grade REST API services with Flask 3.1.1 and blueprint-based modular architecture. This system leverages Python's extensive ecosystem for enhanced data processing capabilities while maintaining complete functional parity with the original implementation.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [Running the Application](#running-the-application)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Deployment](#deployment)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Overview

This Flask application represents a strategic technology migration from Node.js to Python, designed to leverage Python's superior data science and machine learning ecosystem while preserving all existing system functionalities and performance characteristics. The system implements Flask's blueprint-based modular architecture for organized route management and scalable application development.

### Key Technologies

- **Framework**: Flask 3.1.1 - Lightweight micro-framework with blueprint support
- **Database**: PostgreSQL 14.12+ with Flask-SQLAlchemy 3.1.1 ORM
- **Migration Management**: Flask-Migrate 4.1.0 (Alembic-based)
- **Authentication**: Flask-Login with ItsDangerous 2.2+ secure sessions
- **Testing**: Pytest 8.3.3 with Flask testing utilities
- **Deployment**: WSGI server (Gunicorn 20.x / uWSGI 2.x)

## Features

- **Blueprint-Based Architecture**: Modular route organization for maintainable code structure
- **Service Layer Pattern**: Enhanced business logic orchestration and workflow implementation
- **Flask-SQLAlchemy Integration**: Declarative models with relationship mapping
- **Database Migration Support**: Alembic-based schema versioning with rollback capabilities
- **Environment Configuration**: Flexible configuration management for multiple deployment environments
- **Comprehensive Testing**: Pytest-based testing framework with Flask test client integration
- **Production-Ready Deployment**: WSGI server configuration with connection pooling
- **Security**: Session management with secure cookie protection and authentication decorators

## Prerequisites

- **Python**: 3.13.3 or higher
- **Database**: PostgreSQL 14.12+ (recommended for production)
- **Package Manager**: pip (Python package installer)
- **Virtual Environment**: python3-venv or virtualenv for dependency isolation

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd <project-directory>
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Upgrade pip to latest version
pip install --upgrade pip

# Install application dependencies
pip install -r requirements.txt
```

### 4. Install Development Dependencies (Optional)

```bash
# For development and testing
pip install -r requirements-dev.txt
```

## Configuration

### Environment Variables

The application uses environment variables for configuration management. Copy the example environment file and configure your settings:

```bash
cp .env.example .env
```

### Required Environment Variables

Configure the following variables in your `.env` file:

```bash
# Flask Configuration
FLASK_ENV=development                    # development, testing, production
FLASK_CONFIG=development                 # Configuration class to use
SECRET_KEY=your-secret-key-here         # Flask session security key

# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/database_name
SQLALCHEMY_TRACK_MODIFICATIONS=false    # Disable to improve performance

# Database Connection Pool (Production)
SQLALCHEMY_POOL_SIZE=20                  # Base connection pool size
SQLALCHEMY_MAX_OVERFLOW=30               # Additional connections beyond pool_size
SQLALCHEMY_POOL_TIMEOUT=30               # Connection acquisition timeout (seconds)
SQLALCHEMY_POOL_RECYCLE=3600            # Connection lifetime (1 hour)
SQLALCHEMY_POOL_PRE_PING=true           # Validate connections before use

# Optional: SSL Configuration for Production
SQLALCHEMY_ENGINE_OPTIONS={"connect_args":{"sslmode":"require"}}
```

### Configuration Classes

The application supports multiple configuration environments:

- **Development**: `config.py` - Development settings with debug mode
- **Testing**: `config.py` - Testing configuration with test database
- **Production**: `config.py` - Production-optimized settings

## Database Setup

### 1. PostgreSQL Installation

Install PostgreSQL on your system:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql postgresql-contrib

# macOS (using Homebrew)
brew install postgresql

# Windows
# Download from https://www.postgresql.org/download/windows/
```

### 2. Database Creation

```bash
# Connect to PostgreSQL
sudo -u postgres psql

# Create database and user
CREATE DATABASE your_database_name;
CREATE USER your_username WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE your_database_name TO your_username;
\q
```

### 3. Database Migration

```bash
# Initialize migration repository (first time only)
flask db init

# Create migration for current models
flask db migrate -m "Initial migration"

# Apply migrations to database
flask db upgrade
```

### 4. Verify Database Setup

```bash
# Check database connection
flask shell
>>> from app import db
>>> db.engine.execute('SELECT 1').scalar()
1
>>> exit()
```

## Running the Application

### Development Server

```bash
# Ensure virtual environment is activated
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Set Flask environment (if not in .env)
export FLASK_ENV=development  # or set FLASK_ENV=development on Windows

# Run development server
flask run

# Or specify host and port
flask run --host=0.0.0.0 --port=5000
```

### Application Entry Points

- **Development**: Flask built-in development server with auto-reload
- **Production**: WSGI server via `wsgi.py` entry point

```bash
# Development
python app.py

# Production (see Deployment section)
gunicorn --config gunicorn.conf.py wsgi:application
```

## API Documentation

### Blueprint Architecture

The application uses Flask blueprints for modular route organization:

```
/blueprints/
├── __init__.py          # Blueprint registration
├── auth/               # Authentication routes
├── users/              # User management routes
├── api/                # Core API endpoints
└── health/             # Health check endpoints
```

### API Endpoints

| Endpoint | Method | Description | Authentication |
|----------|--------|-------------|----------------|
| `/health` | GET | Application health check | None |
| `/api/v1/auth/login` | POST | User authentication | None |
| `/api/v1/auth/logout` | POST | User logout | Required |
| `/api/v1/users` | GET | List users | Required |
| `/api/v1/users/<id>` | GET | Get user by ID | Required |
| `/api/v1/users` | POST | Create new user | Required |
| `/api/v1/users/<id>` | PUT | Update user | Required |
| `/api/v1/users/<id>` | DELETE | Delete user | Required |

### Request/Response Format

All API endpoints use JSON format:

```json
{
  "status": "success|error",
  "data": {...},
  "message": "Optional message",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Error Handling

Standard HTTP status codes with consistent error responses:

```json
{
  "status": "error",
  "error": {
    "code": 400,
    "message": "Validation error",
    "details": {...}
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## Testing

### Pytest Framework

The application uses Pytest 8.3.3 for comprehensive testing:

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_users.py

# Run tests with verbose output
pytest -v

# Run tests matching pattern
pytest -k "test_user"
```

### Test Structure

```
/tests/
├── __init__.py
├── conftest.py          # Pytest fixtures and configuration
├── test_auth.py         # Authentication tests
├── test_users.py        # User management tests
├── test_api.py          # API endpoint tests
└── integration/         # Integration tests
    ├── test_database.py
    └── test_workflows.py
```

### Testing Configuration

The testing framework includes:

- **Database Fixtures**: Isolated test database with transaction rollback
- **Flask Test Client**: HTTP request testing utilities
- **Authentication Mocking**: User session and permission testing
- **Coverage Reporting**: Comprehensive code coverage analysis (target: ≥95%)

### Running Performance Tests

```bash
# Database performance validation
pytest tests/performance/ --benchmark-only

# API endpoint performance testing
pytest tests/integration/test_api_performance.py
```

## Deployment

### Production WSGI Server

#### Gunicorn Configuration (Recommended)

```bash
# Install Gunicorn (included in requirements.txt)
pip install gunicorn

# Run with Gunicorn
gunicorn --config gunicorn.conf.py wsgi:application

# Manual configuration
gunicorn --workers 4 --worker-class sync --bind 0.0.0.0:8000 --timeout 30 wsgi:application
```

#### Gunicorn Configuration File (`gunicorn.conf.py`)

```python
# Gunicorn configuration
bind = "0.0.0.0:8000"
workers = 4                    # 2-4 workers per CPU core
worker_class = "sync"          # sync workers for database-intensive operations
worker_connections = 1000      # Max simultaneous connections per worker
max_requests = 1000           # Worker recycling for memory management
max_requests_jitter = 100     # Randomize worker recycling
timeout = 30                  # Request timeout
keepalive = 5                 # Keep-alive connections
preload_app = True           # Improve memory usage
```

#### uWSGI Alternative

```bash
# Install uWSGI
pip install uwsgi

# Run with uWSGI
uwsgi --ini uwsgi.ini

# Manual configuration
uwsgi --module wsgi:application --processes 4 --threads 2 --master --http :8000
```

### Docker Deployment

```bash
# Build Docker image
docker build -t flask-app .

# Run container
docker run -p 8000:8000 --env-file .env flask-app

# Docker Compose (if docker-compose.yml exists)
docker-compose up -d
```

### Environment-Specific Deployment

```bash
# Production environment
export FLASK_ENV=production
export FLASK_CONFIG=production
gunicorn wsgi:application

# Staging environment
export FLASK_ENV=staging
export FLASK_CONFIG=staging
gunicorn wsgi:application
```

## Development

### Database Migrations

```bash
# Create new migration after model changes
flask db migrate -m "Description of changes"

# Review generated migration file
# Edit migrations/versions/xxx_description_of_changes.py if needed

# Apply migration
flask db upgrade

# Rollback migration (if needed)
flask db downgrade
```

### Adding New Features

1. **Create Blueprint**: Add new blueprint in `/blueprints/` directory
2. **Register Blueprint**: Import and register in `blueprints/__init__.py`
3. **Add Models**: Create SQLAlchemy models in `/models/` directory
4. **Service Layer**: Implement business logic in `/services/` directory
5. **Write Tests**: Add comprehensive tests in `/tests/` directory
6. **Update Documentation**: Update API documentation and README

### Code Quality

```bash
# Code formatting with Black
black app/ tests/

# Import sorting with isort
isort app/ tests/

# Linting with flake8
flake8 app/ tests/

# Type checking with mypy (if configured)
mypy app/
```

### Development Server Configuration

```bash
# Enable debug mode
export FLASK_ENV=development
export FLASK_DEBUG=1

# Auto-reload on code changes
flask run --reload

# Custom host and port
flask run --host=127.0.0.1 --port=5001
```

## Performance Optimization

### Connection Pool Tuning

Optimize database connections based on deployment:

```bash
# Development
SQLALCHEMY_POOL_SIZE=5
SQLALCHEMY_MAX_OVERFLOW=10

# Production
SQLALCHEMY_POOL_SIZE=20
SQLALCHEMY_MAX_OVERFLOW=30
```

### Caching (Optional)

If Flask-Caching is implemented:

```bash
# Redis cache configuration
CACHE_TYPE=redis
CACHE_REDIS_URL=redis://localhost:6379/0
CACHE_DEFAULT_TIMEOUT=300
```

## Monitoring and Logging

### Application Logging

```python
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Use in application
logger.info("Application started")
logger.error("Error occurred", exc_info=True)
```

### Health Checks

```bash
# Application health
curl http://localhost:5000/health

# Database connectivity
curl http://localhost:5000/health/db
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-feature`)
3. Make changes and add tests
4. Run test suite (`pytest`)
5. Commit changes (`git commit -am 'Add new feature'`)
6. Push to branch (`git push origin feature/new-feature`)
7. Create Pull Request

### Development Guidelines

- Follow PEP 8 Python style guide
- Write comprehensive tests for new features
- Update documentation for API changes
- Use meaningful commit messages
- Ensure all tests pass before submitting PR

## Troubleshooting

### Common Issues

1. **Database Connection Errors**
   ```bash
   # Check PostgreSQL service
   sudo systemctl status postgresql
   
   # Verify connection string
   echo $DATABASE_URL
   ```

2. **Migration Conflicts**
   ```bash
   # Reset migrations (development only)
   flask db downgrade base
   flask db upgrade
   ```

3. **Import Errors**
   ```bash
   # Ensure virtual environment is activated
   source venv/bin/activate
   
   # Verify PYTHONPATH
   export PYTHONPATH=$PYTHONPATH:$(pwd)
   ```

4. **Port Already in Use**
   ```bash
   # Kill process using port
   lsof -ti:5000 | xargs kill -9
   
   # Use different port
   flask run --port=5001
   ```

### Getting Help

- Check application logs: `tail -f logs/app.log`
- Review Flask documentation: https://flask.palletsprojects.com/
- SQLAlchemy documentation: https://docs.sqlalchemy.org/
- Submit issues: [GitHub Issues](link-to-issues)

## License

[Specify your license here]

---

**Note**: This application maintains complete functional parity with the original Node.js implementation while leveraging Python's enhanced capabilities for data processing and machine learning integration.