"""
Base model classes and mixin utilities for Flask-SQLAlchemy models.

This module provides foundational model architecture including:
- AuditMixin for automatic timestamp and user attribution tracking
- EncryptedMixin for sensitive data field encryption with FernetEngine
- BaseModel with common functionality across all entity models
- SQLAlchemy event hooks for automatic audit field population

The architecture ensures comprehensive audit trails, data encryption capabilities,
and consistent model behavior across the Flask application while maintaining
functional parity with the original Node.js implementation.
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List, Union
from contextlib import contextmanager

from flask import current_app, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, Column, DateTime, String, Integer, Boolean, inspect
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy_utils import EncryptedType, FernetEngine
from werkzeug.exceptions import ValidationError

# Initialize SQLAlchemy instance
db = SQLAlchemy()

# Configure logging for base model operations
logger = logging.getLogger(__name__)


class AuditMixin:
    """
    Mixin providing automated audit trail functionality for all database models.
    
    Automatically tracks creation and modification timestamps along with user
    attribution through SQLAlchemy event hooks. Integrates with Flask-Login
    for user context capture during database operations.
    
    Features:
    - Automatic created_at and updated_at timestamp management
    - User attribution for created_by and updated_by fields
    - Integration with Flask-Login sessions for user context
    - Thread-safe operation in multi-worker WSGI environments
    """
    
    @declared_attr
    def created_at(cls):
        """Timestamp when the record was created."""
        return Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    @declared_attr
    def updated_at(cls):
        """Timestamp when the record was last updated."""
        return Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    @declared_attr
    def created_by(cls):
        """User identifier who created the record."""
        return Column(String(255), nullable=True)
    
    @declared_attr
    def updated_by(cls):
        """User identifier who last updated the record."""
        return Column(String(255), nullable=True)
    
    def get_audit_info(self) -> Dict[str, Any]:
        """
        Return audit information for the current record.
        
        Returns:
            Dict containing audit timestamps and user attribution
        """
        return {
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by,
            'updated_by': self.updated_by
        }


class EncryptedMixin:
    """
    Mixin providing field-level encryption capabilities for sensitive data.
    
    Utilizes SQLAlchemy-Utils EncryptedType with FernetEngine for cryptographically
    secure encryption of personally identifiable information (PII) and other
    sensitive data fields. Supports transparent encryption/decryption during
    database operations.
    
    Features:
    - FernetEngine encryption for maximum security
    - Automatic encryption/decryption during ORM operations
    - Configurable encryption keys via environment variables
    - Support for multiple encrypted fields per model
    """
    
    @staticmethod
    def get_encryption_key() -> bytes:
        """
        Retrieve encryption key from environment variables.
        
        Returns:
            Encryption key for FernetEngine
            
        Raises:
            ValueError: If encryption key is not configured
        """
        key = os.environ.get('FIELD_ENCRYPTION_KEY')
        if not key:
            raise ValueError(
                "FIELD_ENCRYPTION_KEY environment variable is required for encrypted fields"
            )
        return key.encode('utf-8')
    
    @classmethod
    def create_encrypted_field(cls, field_type, length: Optional[int] = None) -> Column:
        """
        Create an encrypted column using FernetEngine.
        
        Args:
            field_type: SQLAlchemy column type (e.g., String, Text)
            length: Optional field length for String types
            
        Returns:
            Encrypted column definition
        """
        if length:
            column_type = field_type(length)
        else:
            column_type = field_type
            
        return Column(
            EncryptedType(column_type, cls.get_encryption_key(), FernetEngine),
            nullable=True
        )
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """
        Manually encrypt sensitive data using the configured encryption key.
        
        Args:
            data: Plain text data to encrypt
            
        Returns:
            Encrypted data string
        """
        from cryptography.fernet import Fernet
        fernet = Fernet(self.get_encryption_key())
        return fernet.encrypt(data.encode()).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """
        Manually decrypt sensitive data using the configured encryption key.
        
        Args:
            encrypted_data: Encrypted data string
            
        Returns:
            Decrypted plain text data
        """
        from cryptography.fernet import Fernet
        fernet = Fernet(self.get_encryption_key())
        return fernet.decrypt(encrypted_data.encode()).decode()


class BaseModel(db.Model, AuditMixin):
    """
    Abstract base model providing common functionality for all entity models.
    
    Includes audit trail capabilities, serialization methods, query helpers,
    and validation utilities. Provides consistent behavior across all models
    while maintaining performance and security standards.
    
    Features:
    - Automatic audit trail tracking via AuditMixin
    - JSON serialization with sensitive data protection
    - Common query methods and utilities
    - Validation framework integration
    - Thread-safe database operations
    """
    
    __abstract__ = True
    
    # Primary key column - all models should have an integer primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    def to_dict(self, include_sensitive: bool = False, exclude_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Convert model instance to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive/encrypted fields
            exclude_fields: List of field names to exclude from output
            
        Returns:
            Dictionary representation of the model
        """
        exclude_fields = exclude_fields or []
        result = {}
        
        # Get model columns using SQLAlchemy inspection
        mapper = inspect(self.__class__)
        
        for column in mapper.columns:
            column_name = column.name
            
            # Skip excluded fields
            if column_name in exclude_fields:
                continue
                
            # Get column value
            value = getattr(self, column_name, None)
            
            # Handle encrypted fields
            if isinstance(column.type, EncryptedType) and not include_sensitive:
                result[column_name] = '[ENCRYPTED]'
                continue
            
            # Handle datetime serialization
            if isinstance(value, datetime):
                result[column_name] = value.isoformat()
            else:
                result[column_name] = value
        
        # Include audit information
        result.update(self.get_audit_info())
        
        return result
    
    def to_json(self, include_sensitive: bool = False, exclude_fields: Optional[List[str]] = None) -> str:
        """
        Convert model instance to JSON string.
        
        Args:
            include_sensitive: Whether to include sensitive/encrypted fields
            exclude_fields: List of field names to exclude from output
            
        Returns:
            JSON string representation of the model
        """
        import json
        return json.dumps(self.to_dict(include_sensitive, exclude_fields), default=str)
    
    @classmethod
    def create(cls, **kwargs) -> 'BaseModel':
        """
        Create a new model instance with validation.
        
        Args:
            **kwargs: Model field values
            
        Returns:
            Created model instance
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            instance = cls(**kwargs)
            instance.validate()
            db.session.add(instance)
            return instance
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to create {cls.__name__}: {e}")
            raise ValidationError(f"Failed to create {cls.__name__}: {str(e)}")
    
    def update(self, **kwargs) -> 'BaseModel':
        """
        Update model instance with validation.
        
        Args:
            **kwargs: Fields to update
            
        Returns:
            Updated model instance
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)
            
            self.validate()
            return self
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to update {self.__class__.__name__} {self.id}: {e}")
            raise ValidationError(f"Failed to update {self.__class__.__name__}: {str(e)}")
    
    def delete(self) -> bool:
        """
        Delete model instance with audit trail.
        
        Returns:
            True if deletion was successful
            
        Raises:
            SQLAlchemyError: If deletion fails
        """
        try:
            db.session.delete(self)
            logger.info(f"Deleted {self.__class__.__name__} {self.id}")
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to delete {self.__class__.__name__} {self.id}: {e}")
            raise SQLAlchemyError(f"Failed to delete record: {str(e)}")
    
    def validate(self) -> bool:
        """
        Validate model instance data.
        
        Override this method in subclasses to implement model-specific validation.
        
        Returns:
            True if validation passes
            
        Raises:
            ValidationError: If validation fails
        """
        # Base validation - ensure required fields are present
        mapper = inspect(self.__class__)
        
        for column in mapper.columns:
            if not column.nullable and column.default is None:
                value = getattr(self, column.name, None)
                if value is None:
                    raise ValidationError(f"Required field '{column.name}' cannot be null")
        
        return True
    
    @classmethod
    def get_by_id(cls, record_id: int) -> Optional['BaseModel']:
        """
        Retrieve model instance by ID.
        
        Args:
            record_id: Primary key value
            
        Returns:
            Model instance or None if not found
        """
        try:
            return cls.query.get(record_id)
        except Exception as e:
            logger.error(f"Error retrieving {cls.__name__} {record_id}: {e}")
            return None
    
    @classmethod
    def get_all(cls, limit: Optional[int] = None, offset: Optional[int] = None) -> List['BaseModel']:
        """
        Retrieve all model instances with optional pagination.
        
        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            
        Returns:
            List of model instances
        """
        try:
            query = cls.query
            
            if offset:
                query = query.offset(offset)
            if limit:
                query = query.limit(limit)
                
            return query.all()
        except Exception as e:
            logger.error(f"Error retrieving {cls.__name__} records: {e}")
            return []
    
    @classmethod
    def count(cls) -> int:
        """
        Get total count of records for this model.
        
        Returns:
            Total number of records
        """
        try:
            return cls.query.count()
        except Exception as e:
            logger.error(f"Error counting {cls.__name__} records: {e}")
            return 0
    
    def __repr__(self) -> str:
        """String representation of the model instance."""
        return f"<{self.__class__.__name__}(id={self.id})>"


# Database session management utilities
class DatabaseManager:
    """
    Database session and transaction management utilities.
    
    Provides thread-safe session management, transaction boundaries,
    and connection handling for Flask-SQLAlchemy integration.
    """
    
    @staticmethod
    @contextmanager
    def transaction():
        """
        Context manager for explicit transaction boundary control.
        
        Ensures proper commit/rollback behavior for complex operations
        spanning multiple database entities.
        
        Example:
            with DatabaseManager.transaction():
                user = User.create(username='test')
                profile = UserProfile.create(user_id=user.id)
        """
        try:
            db.session.begin()
            yield db.session
            db.session.commit()
            logger.debug("Transaction committed successfully")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Transaction failed, rolled back: {e}")
            raise
    
    @staticmethod
    def safe_commit() -> bool:
        """
        Safely commit current transaction with error handling.
        
        Returns:
            True if commit was successful, False otherwise
        """
        try:
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"Commit failed: {e}")
            return False
    
    @staticmethod
    def safe_rollback() -> bool:
        """
        Safely rollback current transaction.
        
        Returns:
            True if rollback was successful, False otherwise
        """
        try:
            db.session.rollback()
            return True
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False


# SQLAlchemy event listeners for automatic audit field population
def get_current_user_context() -> Optional[str]:
    """
    Retrieve current user context from Flask-Login session.
    
    Returns:
        User identifier string or None if not authenticated
    """
    try:
        # Try to get user from Flask-Login current_user
        from flask_login import current_user
        if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            # Return username or user ID based on available attributes
            if hasattr(current_user, 'username'):
                return current_user.username
            elif hasattr(current_user, 'id'):
                return str(current_user.id)
    except ImportError:
        # Flask-Login not available, try to get from Flask g object
        pass
    
    # Fallback to Flask g object for user context
    if hasattr(g, 'current_user_id'):
        return str(g.current_user_id)
    elif hasattr(g, 'current_user'):
        return str(g.current_user)
    
    # Return system user for background operations
    return 'system'


@event.listens_for(db.session, 'before_commit')
def before_commit_audit_handler(session):
    """
    SQLAlchemy event handler for automatic audit field population.
    
    Captures user context from Flask-Login sessions and populates
    created_by and updated_by fields for all new and modified records.
    
    Args:
        session: SQLAlchemy session about to commit
    """
    try:
        user_context = get_current_user_context()
        
        # Handle new records
        for obj in session.new:
            if hasattr(obj, 'created_by') and obj.created_by is None:
                obj.created_by = user_context
                logger.debug(f"Set created_by={user_context} for new {obj.__class__.__name__}")
        
        # Handle modified records
        for obj in session.dirty:
            if hasattr(obj, 'updated_by'):
                obj.updated_by = user_context
                logger.debug(f"Set updated_by={user_context} for modified {obj.__class__.__name__}")
                
    except Exception as e:
        logger.error(f"Error in audit field population: {e}")
        # Don't raise exception to avoid breaking the transaction


@event.listens_for(db.session, 'after_commit')
def after_commit_audit_handler(session):
    """
    SQLAlchemy event handler for post-commit audit logging.
    
    Logs successful database operations for audit trail and monitoring purposes.
    
    Args:
        session: SQLAlchemy session that was committed
    """
    try:
        # Log successful operations for monitoring
        if hasattr(session, 'info') and session.info.get('audit_operations'):
            operations = session.info['audit_operations']
            logger.info(f"Audit trail: {len(operations)} operations committed successfully")
    except Exception as e:
        logger.error(f"Error in post-commit audit logging: {e}")


def initialize_database(app):
    """
    Initialize database configuration and event listeners for Flask application.
    
    Args:
        app: Flask application instance
    """
    # Initialize SQLAlchemy with the Flask app
    db.init_app(app)
    
    # Configure database engine options for optimal performance
    engine_options = {
        'pool_size': int(os.environ.get('SQLALCHEMY_POOL_SIZE', 20)),
        'max_overflow': int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', 30)),
        'pool_timeout': int(os.environ.get('SQLALCHEMY_POOL_TIMEOUT', 30)),
        'pool_recycle': int(os.environ.get('SQLALCHEMY_POOL_RECYCLE', 3600)),
        'pool_pre_ping': os.environ.get('SQLALCHEMY_POOL_PRE_PING', 'true').lower() == 'true'
    }
    
    # Apply engine configuration
    app.config.setdefault('SQLALCHEMY_ENGINE_OPTIONS', engine_options)
    
    # Disable modification tracking for performance
    app.config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', False)
    
    logger.info("Database configuration initialized successfully")


# Export main components for easy importing
__all__ = [
    'db',
    'AuditMixin',
    'EncryptedMixin', 
    'BaseModel',
    'DatabaseManager',
    'initialize_database'
]