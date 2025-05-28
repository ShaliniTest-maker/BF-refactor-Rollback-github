"""
Alembic Migration Environment Configuration for Flask Application Factory Pattern

This module orchestrates Flask application context, SQLAlchemy metadata loading,
and database connection management for migration execution. It integrates with
Flask application factory pattern to ensure proper model discovery and relationship
mapping during migration generation and execution.

Key Features:
- Flask application factory integration for SQLAlchemy metadata discovery per Section 5.1.1
- PostgreSQL connection management with psycopg2 adapter configuration per Section 6.2.1
- Model import and relationship mapping detection for Flask-SQLAlchemy 3.1.1 per Section 5.2.4
- Real-time data verification framework for migration validation per Section 4.4.2

Dependencies:
- Flask 3.1.1 with application factory pattern
- Flask-SQLAlchemy 3.1.1 for database ORM functionality
- Flask-Migrate 4.1.0 for Alembic-based database versioning
- PostgreSQL 15.x with psycopg2 2.9.9 adapter
- Python 3.13.3 runtime environment
"""

import logging
import os
import sys
from logging.config import fileConfig
from typing import Optional, Dict, Any

from sqlalchemy import create_engine, pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import OperationalError, ProgrammingError
from alembic import context
from alembic.config import Config

# Add the project root to Python path to enable model imports
sys.path.insert(0, os.path.abspath('.'))

try:
    # Flask application and model imports
    from app import create_app
    from src.models import db
    from src.models.base import BaseModel
    from src.models.user import User
    from src.models.session import UserSession
    from src.models.business_entity import BusinessEntity
    from src.models.entity_relationship import EntityRelationship
except ImportError as e:
    logging.error(f"Failed to import Flask application or models: {e}")
    raise

# Alembic Config object providing access to values in the .ini file
config: Config = context.config

# Setup logging configuration from alembic.ini if available
if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except Exception as e:
        logging.warning(f"Failed to configure logging from alembic.ini: {e}")

# Configure logger for migration operations
logger = logging.getLogger('alembic.env')

def get_flask_app():
    """
    Create and configure Flask application with proper model registration.
    
    This function implements the Flask application factory pattern integration
    to ensure all SQLAlchemy models are properly registered and metadata is
    available for migration operations.
    
    Returns:
        Flask: Configured Flask application instance with models registered
        
    Raises:
        RuntimeError: If Flask application creation or model registration fails
    """
    try:
        # Create Flask application using factory pattern
        app = create_app()
        
        # Ensure application context for database operations
        with app.app_context():
            # Import all models to ensure they are registered with SQLAlchemy metadata
            # This is critical for Flask-Migrate to detect model changes
            models = [
                BaseModel,
                User, 
                UserSession,
                BusinessEntity,
                EntityRelationship
            ]
            
            # Verify model registration with SQLAlchemy metadata
            registered_tables = list(db.metadata.tables.keys())
            logger.info(f"Registered SQLAlchemy tables: {registered_tables}")
            
            if not registered_tables:
                raise RuntimeError("No SQLAlchemy models found in metadata. "
                                 "Ensure all models are properly imported and defined.")
            
            # Validate model relationships for migration integrity
            for model in models:
                if hasattr(model, '__tablename__'):
                    table_name = model.__tablename__
                    if table_name not in registered_tables:
                        logger.warning(f"Model {model.__name__} table '{table_name}' "
                                     f"not found in metadata")
            
            logger.info(f"Flask application successfully created with {len(registered_tables)} models")
            return app
            
    except Exception as e:
        logger.error(f"Failed to create Flask application: {e}")
        raise RuntimeError(f"Flask application initialization failed: {e}")

def get_database_url() -> str:
    """
    Retrieve database URL from Flask configuration or environment variables.
    
    This function implements PostgreSQL connection management with proper
    psycopg2 adapter configuration as specified in Section 6.2.1.
    
    Returns:
        str: Database connection URL with psycopg2 adapter
        
    Raises:
        ValueError: If database URL is not configured or invalid
    """
    app = get_flask_app()
    
    with app.app_context():
        # Try to get database URL from Flask configuration first
        db_url = app.config.get('SQLALCHEMY_DATABASE_URI')
        
        # Fallback to environment variable if not in Flask config
        if not db_url:
            db_url = os.environ.get('SQLALCHEMY_DATABASE_URI')
        
        # Final fallback to DATABASE_URL environment variable
        if not db_url:
            db_url = os.environ.get('DATABASE_URL')
        
        if not db_url:
            raise ValueError(
                "Database URL not found. Please set SQLALCHEMY_DATABASE_URI "
                "in Flask configuration or environment variables."
            )
        
        # Ensure PostgreSQL with psycopg2 adapter for optimal performance
        if db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql+psycopg2://', 1)
        elif not db_url.startswith('postgresql+psycopg2://'):
            if db_url.startswith('postgresql://'):
                db_url = db_url.replace('postgresql://', 'postgresql+psycopg2://', 1)
            else:
                logger.warning(f"Database URL may not be using psycopg2 adapter: {db_url}")
        
        logger.info(f"Database URL configured: {db_url.split('@')[0]}@***")
        return db_url

def get_metadata():
    """
    Get SQLAlchemy metadata with all models registered.
    
    This function ensures proper model discovery and relationship mapping
    for Flask-SQLAlchemy 3.1.1 integration as specified in Section 5.2.4.
    
    Returns:
        MetaData: SQLAlchemy metadata with all registered models
    """
    app = get_flask_app()
    
    with app.app_context():
        # Ensure database instance is bound to the application
        db.init_app(app)
        
        # Return the metadata with all registered models
        metadata = db.metadata
        
        logger.info(f"Metadata retrieved with {len(metadata.tables)} tables: "
                   f"{list(metadata.tables.keys())}")
        
        return metadata

def validate_migration_environment() -> bool:
    """
    Validate migration environment and database connectivity.
    
    This function implements real-time data verification framework
    for migration validation as specified in Section 4.4.2.
    
    Returns:
        bool: True if environment is valid for migration execution
        
    Raises:
        RuntimeError: If validation fails
    """
    try:
        # Test database connectivity
        db_url = get_database_url()
        engine = create_engine(
            db_url,
            poolclass=pool.NullPool,
            echo=False
        )
        
        with engine.connect() as connection:
            # Test basic database connectivity
            result = connection.execute(text("SELECT version()"))
            db_version = result.scalar()
            logger.info(f"Database connectivity verified: {db_version}")
            
            # Verify PostgreSQL version compatibility
            if 'PostgreSQL' not in db_version:
                logger.warning(f"Expected PostgreSQL, found: {db_version}")
            
            # Test transaction support for migration safety
            with connection.begin() as trans:
                connection.execute(text("SELECT 1"))
                trans.rollback()
            
            logger.info("Transaction support verified")
        
        # Validate Flask application and model registration
        app = get_flask_app()
        with app.app_context():
            metadata = get_metadata()
            
            if not metadata.tables:
                raise RuntimeError("No tables found in metadata")
            
            # Validate critical models are present
            required_tables = ['user', 'user_session', 'business_entity', 'entity_relationship']
            missing_tables = [table for table in required_tables 
                            if table not in metadata.tables]
            
            if missing_tables:
                logger.warning(f"Missing expected tables: {missing_tables}")
            
            logger.info("Model registration validation completed")
        
        logger.info("Migration environment validation successful")
        return True
        
    except (OperationalError, ProgrammingError) as e:
        logger.error(f"Database connectivity validation failed: {e}")
        raise RuntimeError(f"Database validation failed: {e}")
    except Exception as e:
        logger.error(f"Migration environment validation failed: {e}")
        raise RuntimeError(f"Environment validation failed: {e}")

def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode for script generation without database connectivity.
    
    This configures the context with database URL and metadata for
    script generation purposes.
    """
    logger.info("Starting offline migration mode")
    
    try:
        # Get database URL and metadata
        url = get_database_url()
        metadata = get_metadata()
        
        # Configure migration context
        context.configure(
            url=url,
            target_metadata=metadata,
            literal_binds=True,
            dialect_opts={"paramstyle": "named"},
            compare_type=True,
            compare_server_default=True,
            render_as_batch=False,  # PostgreSQL supports direct ALTER TABLE
        )
        
        with context.begin_transaction():
            context.run_migrations()
            
        logger.info("Offline migration completed successfully")
        
    except Exception as e:
        logger.error(f"Offline migration failed: {e}")
        raise

def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode with live database connection.
    
    This function implements connection pooling and transaction management
    for migration safety as specified in Section 4.4.2.
    """
    logger.info("Starting online migration mode")
    
    try:
        # Validate migration environment before proceeding
        validate_migration_environment()
        
        # Get database URL and metadata
        db_url = get_database_url()
        metadata = get_metadata()
        
        # Create engine with connection pooling for migration safety
        connectable = create_engine(
            db_url,
            poolclass=pool.NullPool,  # No pooling for migrations
            echo=True if os.environ.get('MIGRATION_DEBUG') else False,
            connect_args={
                'options': '-c lock_timeout=30000',  # 30 second lock timeout
                'application_name': 'flask_migrate_alembic'
            }
        )
        
        with connectable.connect() as connection:
            # Configure migration context with enhanced settings
            context.configure(
                connection=connection,
                target_metadata=metadata,
                compare_type=True,
                compare_server_default=True,
                render_as_batch=False,  # PostgreSQL supports direct ALTER TABLE
                transaction_per_migration=True,  # Each migration in separate transaction
                transactional_ddl=True,  # Enable transactional DDL for PostgreSQL
            )
            
            # Execute migrations within transaction context
            with context.begin_transaction():
                logger.info("Beginning migration transaction")
                
                # Run the actual migrations
                context.run_migrations()
                
                # Real-time validation during migration
                logger.info("Migration completed, performing validation")
                
                # Verify metadata consistency after migration
                try:
                    # Refresh metadata to reflect changes
                    metadata.reflect(bind=connection)
                    logger.info(f"Post-migration validation: {len(metadata.tables)} tables present")
                except Exception as e:
                    logger.error(f"Post-migration validation failed: {e}")
                    raise RuntimeError(f"Migration validation failed: {e}")
        
        logger.info("Online migration completed successfully")
        
    except Exception as e:
        logger.error(f"Online migration failed: {e}")
        raise

def run_migration_with_verification() -> None:
    """
    Main migration entry point with comprehensive verification.
    
    This function implements the complete migration workflow with
    real-time verification and rollback capabilities.
    """
    try:
        logger.info("=" * 60)
        logger.info("Flask-Migrate Alembic Environment Initialization")
        logger.info("=" * 60)
        
        # Log environment information
        logger.info(f"Python version: {sys.version}")
        logger.info(f"Working directory: {os.getcwd()}")
        logger.info(f"Migration mode: {'offline' if context.is_offline_mode() else 'online'}")
        
        # Execute appropriate migration mode
        if context.is_offline_mode():
            run_migrations_offline()
        else:
            run_migrations_online()
            
        logger.info("Migration process completed successfully")
        
    except Exception as e:
        logger.error(f"Migration process failed: {e}")
        logger.error("=" * 60)
        logger.error("MIGRATION FAILED - ROLLBACK MAY BE REQUIRED")
        logger.error("=" * 60)
        raise

# Main execution block
if __name__ == '__main__':
    # This block allows the script to be run directly for testing
    run_migration_with_verification()
else:
    # Standard Alembic execution path
    run_migration_with_verification()