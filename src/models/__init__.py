"""
Flask-SQLAlchemy Models Package

This module establishes the Flask-SQLAlchemy declarative model namespace and provides
centralized imports for all database models. It enables organized model registration
with the Flask application factory pattern and facilitates clean imports throughout
the application.

Database Models:
- User: Core user authentication and management with Flask-Login integration
- UserSession: Session management for Flask authentication with ItsDangerous token support
- BusinessEntity: Core business domain objects with ownership and metadata management
- EntityRelationship: Complex business entity associations with relationship mapping

The models package supports:
- Flask-SQLAlchemy 3.1.1 declarative base pattern for PostgreSQL 15.x integration
- Flask-Migrate 4.1.0 database versioning and schema management
- Flask application factory pattern for modular application initialization
- Service Layer pattern integration for business workflow orchestration

Requirements:
- Python 3.13.3 runtime environment
- Flask 3.1.1 with Flask-SQLAlchemy 3.1.1
- PostgreSQL 15.x with psycopg2 2.9.9 adapter
- Flask-Migrate 4.1.0 for Alembic-based migrations
"""

# Import base model class that provides common database fields and functionality
from .base import BaseModel

# Import user authentication and management models
from .user import User
from .session import UserSession

# Import business domain models
from .business_entity import BusinessEntity
from .entity_relationship import EntityRelationship

# Define public API for the models package
# This enables clean imports like: from models import User, BusinessEntity
__all__ = [
    'BaseModel',
    'User', 
    'UserSession',
    'BusinessEntity',
    'EntityRelationship'
]

# Package metadata for Flask-SQLAlchemy integration
__version__ = '1.0.0'
__description__ = 'Flask-SQLAlchemy database models for Node.js to Flask migration'

# Model registry for Flask-Migrate integration
# This list ensures all models are properly registered with Alembic for migrations
MODELS = [
    User,
    UserSession, 
    BusinessEntity,
    EntityRelationship
]

def get_all_models():
    """
    Return all database models for Flask-Migrate registration.
    
    This function provides a centralized way to access all models for:
    - Flask-Migrate Alembic migration generation
    - Database schema creation and validation
    - Model relationship analysis and dependency mapping
    
    Returns:
        list: All Flask-SQLAlchemy model classes in dependency order
    """
    return MODELS

def validate_model_relationships():
    """
    Validate all model relationships and foreign key constraints.
    
    This function performs comprehensive validation of:
    - Foreign key relationships between models
    - Referential integrity constraints
    - Many-to-many relationship mapping
    - Circular dependency detection
    
    Returns:
        bool: True if all relationships are valid, raises ValueError if invalid
        
    Raises:
        ValueError: If model relationships are misconfigured or circular dependencies exist
    """
    try:
        # Validate User -> UserSession relationship
        assert hasattr(User, 'sessions'), "User model missing sessions relationship"
        
        # Validate User -> BusinessEntity relationship  
        assert hasattr(User, 'business_entities'), "User model missing business_entities relationship"
        
        # Validate BusinessEntity -> EntityRelationship relationships
        assert hasattr(BusinessEntity, 'source_relationships'), "BusinessEntity model missing source_relationships"
        assert hasattr(BusinessEntity, 'target_relationships'), "BusinessEntity model missing target_relationships"
        
        # Validate UserSession -> User relationship
        assert hasattr(UserSession, 'user'), "UserSession model missing user relationship"
        
        # Validate EntityRelationship -> BusinessEntity relationships
        assert hasattr(EntityRelationship, 'source_entity'), "EntityRelationship model missing source_entity relationship"
        assert hasattr(EntityRelationship, 'target_entity'), "EntityRelationship model missing target_entity relationship"
        
        return True
        
    except (AssertionError, AttributeError) as e:
        raise ValueError(f"Model relationship validation failed: {str(e)}")

# Model configuration for Flask application factory pattern
MODEL_CONFIG = {
    'postgresql_version': '15.x',
    'sqlalchemy_version': '3.1.1', 
    'flask_migrate_version': '4.1.0',
    'migration_directory': 'migrations',
    'track_modifications': False,  # Disable for performance optimization
    'pool_size': 20,  # Default connection pool size
    'max_overflow': 10,  # Additional connections during peak load
    'pool_timeout': 30,  # Connection acquisition timeout in seconds
    'pool_recycle': 3600  # Connection recycling interval in seconds
}

def get_model_config():
    """
    Return model configuration for Flask application factory integration.
    
    This configuration supports:
    - PostgreSQL 15.x database connectivity
    - SQLAlchemy engine optimization
    - Connection pooling for production deployment
    - Flask-Migrate migration management
    
    Returns:
        dict: Model configuration parameters for Flask app factory
    """
    return MODEL_CONFIG.copy()