"""
Base Model Classes and Mixin Utilities for Flask-SQLAlchemy

This module provides foundational model architecture for the Flask migration, including
audit trail mixins, encryption support, and common database functionality. These
base classes ensure consistent behavior across all entity models in the system.

Key Components:
- AuditMixin: Automatic timestamp and user attribution tracking
- EncryptedMixin: SQLAlchemy-Utils EncryptedType for sensitive data protection  
- BaseModel: Common model functionality and serialization methods
- SQLAlchemy event hooks: Automatic audit field population with user context

Dependencies:
- Flask-SQLAlchemy 3.1.1: Database ORM integration
- SQLAlchemy-Utils: EncryptedType implementation with FernetEngine
- python-dotenv: Environment variable management for encryption keys
- ItsDangerous 2.2+: Session security and cryptographic operations

Author: Flask Migration System
Version: 1.0.0
Compatibility: Flask 3.1.1, Flask-SQLAlchemy 3.1.1, PostgreSQL 14.12+
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List, Union
from decimal import Decimal

# Core Flask and SQLAlchemy imports
from flask import current_app, g, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, DateTime, String, Boolean, Integer, event, text
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import Session, class_mapper
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

# SQLAlchemy-Utils for encryption support
try:
    from sqlalchemy_utils import EncryptedType
    from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine, FernetEngine
    ENCRYPTION_AVAILABLE = True
except ImportError:
    # Graceful degradation if SQLAlchemy-Utils is not available
    EncryptedType = None
    FernetEngine = None
    AesEngine = None
    ENCRYPTION_AVAILABLE = False

# Environment variable management
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging for base model operations
logger = logging.getLogger(__name__)

# Global SQLAlchemy instance (will be initialized by Flask app)
db = SQLAlchemy()


class DatabaseError(Exception):
    """Custom exception for database-related errors in base model operations."""
    pass


class EncryptionError(Exception):
    """Custom exception for encryption-related errors in model operations."""
    pass


class ValidationError(Exception):
    """Custom exception for model validation errors."""
    pass


def get_encryption_key() -> str:
    """
    Retrieve encryption key from environment variables with validation.
    
    Returns:
        str: Base64-encoded encryption key for FernetEngine
        
    Raises:
        EncryptionError: If encryption key is not configured or invalid
    """
    encryption_key = os.environ.get('FIELD_ENCRYPTION_KEY')
    
    if not encryption_key:
        if current_app:
            current_app.logger.error("FIELD_ENCRYPTION_KEY not configured in environment")
        raise EncryptionError("Encryption key not configured. Set FIELD_ENCRYPTION_KEY environment variable.")
    
    # Validate key length for Fernet compatibility (must be 32 url-safe base64-encoded bytes)
    try:
        import base64
        key_bytes = base64.urlsafe_b64decode(encryption_key)
        if len(key_bytes) != 32:
            raise EncryptionError("Encryption key must be 32 bytes when base64 decoded")
    except Exception as e:
        raise EncryptionError(f"Invalid encryption key format: {str(e)}")
    
    return encryption_key


def get_current_user_id() -> Optional[str]:
    """
    Extract current user ID from Flask application context.
    
    This function attempts to retrieve the current user ID from various sources
    in the Flask application context, including Flask-Login current_user,
    request context, and Flask's g object.
    
    Returns:
        Optional[str]: Current user ID if available, None otherwise
    """
    user_id = None
    
    try:
        # Try to get user ID from Flask-Login current_user
        try:
            from flask_login import current_user
            if hasattr(current_user, 'id') and current_user.is_authenticated:
                user_id = str(current_user.id)
        except ImportError:
            # Flask-Login not available, continue with other methods
            pass
        
        # Fallback to Flask's g object
        if not user_id and hasattr(g, 'current_user_id'):
            user_id = str(g.current_user_id)
        
        # Fallback to request context (for API authentication)
        if not user_id and request and hasattr(request, 'user_id'):
            user_id = str(request.user_id)
        
        # Final fallback to g.user_id (custom user tracking)
        if not user_id and hasattr(g, 'user_id'):
            user_id = str(g.user_id)
            
    except RuntimeError:
        # Outside application context, return None
        pass
    except Exception as e:
        # Log unexpected errors but don't fail the operation
        if current_app:
            current_app.logger.warning(f"Error retrieving current user ID: {str(e)}")
    
    return user_id or 'system'


class AuditMixin:
    """
    Mixin providing automated audit fields for all database models.
    
    This mixin adds standard audit columns to track record creation and modification:
    - created_at: Timestamp of record creation
    - updated_at: Timestamp of last modification (auto-updated)
    - created_by: User who created the record
    - updated_by: User who last modified the record
    
    The audit fields are automatically populated through SQLAlchemy event hooks
    that capture user context from Flask-Login sessions or application context.
    
    Usage:
        class User(BaseModel, AuditMixin):
            __tablename__ = 'users'
            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String(100), nullable=False)
    """
    
    @declared_attr
    def created_at(cls):
        """Timestamp when the record was created (auto-populated)."""
        return Column(DateTime, default=datetime.utcnow, nullable=False, 
                     comment="Timestamp when the record was created")
    
    @declared_attr
    def updated_at(cls):
        """Timestamp when the record was last updated (auto-populated on changes)."""
        return Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, 
                     nullable=False, comment="Timestamp when the record was last updated")
    
    @declared_attr
    def created_by(cls):
        """User ID who created the record (auto-populated from Flask context)."""
        return Column(String(255), nullable=True, 
                     comment="User ID who created the record")
    
    @declared_attr
    def updated_by(cls):
        """User ID who last updated the record (auto-populated from Flask context)."""
        return Column(String(255), nullable=True, 
                     comment="User ID who last updated the record")
    
    def get_audit_info(self) -> Dict[str, Any]:
        """
        Retrieve audit information for this record.
        
        Returns:
            Dict[str, Any]: Dictionary containing audit trail information
        """
        return {
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by,
            'updated_by': self.updated_by
        }


class EncryptedMixin:
    """
    Mixin providing SQLAlchemy-Utils EncryptedType integration for sensitive data fields.
    
    This mixin provides utility methods and configuration for field-level encryption
    using FernetEngine cryptographic security. It offers both static methods for
    creating encrypted columns and instance methods for encryption operations.
    
    Key Features:
    - FernetEngine encryption for maximum security
    - Environment variable-based key management
    - Graceful degradation when encryption is not available
    - Support for PII field encryption (emails, phone numbers, personal data)
    
    Usage:
        class UserProfile(BaseModel, EncryptedMixin):
            __tablename__ = 'user_profiles'
            id = db.Column(db.Integer, primary_key=True)
            
            # Create encrypted email field
            email = EncryptedMixin.create_encrypted_field(String(255), unique=True)
            
            # Create encrypted phone number field
            phone = EncryptedMixin.create_encrypted_field(String(50))
    """
    
    @staticmethod
    def create_encrypted_field(column_type, unique=False, nullable=True, **kwargs):
        """
        Create an encrypted database column using SQLAlchemy-Utils EncryptedType.
        
        Args:
            column_type: SQLAlchemy column type (e.g., String(255), Text)
            unique (bool): Whether the column should have a unique constraint
            nullable (bool): Whether the column can be NULL
            **kwargs: Additional column arguments
            
        Returns:
            Column: SQLAlchemy Column with EncryptedType or fallback to regular type
            
        Raises:
            EncryptionError: If encryption is required but not available
        """
        if not ENCRYPTION_AVAILABLE:
            logger.warning("SQLAlchemy-Utils not available, creating unencrypted field")
            # Graceful degradation to regular column type
            return Column(column_type, unique=unique, nullable=nullable, **kwargs)
        
        try:
            encryption_key = get_encryption_key()
            
            # Create encrypted column using FernetEngine for maximum security
            encrypted_type = EncryptedType(column_type, encryption_key, FernetEngine)
            
            return Column(encrypted_type, unique=unique, nullable=nullable, **kwargs)
            
        except EncryptionError as e:
            logger.error(f"Failed to create encrypted field: {str(e)}")
            if os.environ.get('FLASK_ENV') == 'production':
                # In production, fail fast if encryption is not properly configured
                raise e
            else:
                # In development, warn and create unencrypted field
                logger.warning("Creating unencrypted field due to encryption configuration issue")
                return Column(column_type, unique=unique, nullable=nullable, **kwargs)
    
    @staticmethod
    def create_encrypted_text_field(unique=False, nullable=True, **kwargs):
        """
        Create an encrypted text field for larger sensitive data.
        
        Args:
            unique (bool): Whether the field should be unique
            nullable (bool): Whether the field can be NULL
            **kwargs: Additional column arguments
            
        Returns:
            Column: Encrypted text column
        """
        from sqlalchemy import Text
        return EncryptedMixin.create_encrypted_field(
            Text, unique=unique, nullable=nullable, **kwargs
        )
    
    @staticmethod
    def create_encrypted_string_field(length=255, unique=False, nullable=True, **kwargs):
        """
        Create an encrypted string field with specified length.
        
        Args:
            length (int): Maximum string length
            unique (bool): Whether the field should be unique
            nullable (bool): Whether the field can be NULL
            **kwargs: Additional column arguments
            
        Returns:
            Column: Encrypted string column
        """
        return EncryptedMixin.create_encrypted_field(
            String(length), unique=unique, nullable=nullable, **kwargs
        )
    
    def encrypt_value(self, value: str) -> str:
        """
        Manually encrypt a value using the configured encryption engine.
        
        Args:
            value (str): Plain text value to encrypt
            
        Returns:
            str: Encrypted value
            
        Raises:
            EncryptionError: If encryption fails or is not available
        """
        if not ENCRYPTION_AVAILABLE:
            raise EncryptionError("Encryption not available - SQLAlchemy-Utils not installed")
        
        try:
            encryption_key = get_encryption_key()
            from cryptography.fernet import Fernet
            
            fernet = Fernet(encryption_key.encode())
            encrypted_bytes = fernet.encrypt(value.encode())
            return encrypted_bytes.decode()
            
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt value: {str(e)}")
    
    def decrypt_value(self, encrypted_value: str) -> str:
        """
        Manually decrypt a value using the configured encryption engine.
        
        Args:
            encrypted_value (str): Encrypted value to decrypt
            
        Returns:
            str: Decrypted plain text value
            
        Raises:
            EncryptionError: If decryption fails or is not available
        """
        if not ENCRYPTION_AVAILABLE:
            raise EncryptionError("Encryption not available - SQLAlchemy-Utils not installed")
        
        try:
            encryption_key = get_encryption_key()
            from cryptography.fernet import Fernet
            
            fernet = Fernet(encryption_key.encode())
            decrypted_bytes = fernet.decrypt(encrypted_value.encode())
            return decrypted_bytes.decode()
            
        except Exception as e:
            raise EncryptionError(f"Failed to decrypt value: {str(e)}")


class BaseModel(db.Model):
    """
    Base model class providing common functionality for all Flask-SQLAlchemy models.
    
    This abstract base class provides essential functionality that all models inherit:
    - Consistent data serialization through to_dict() method
    - Query helper methods for common operations
    - Validation framework for data integrity
    - Error handling and logging integration
    - Session management utilities
    
    All application models should inherit from this class along with appropriate mixins:
    
    Usage:
        class User(BaseModel, AuditMixin):
            __tablename__ = 'users'
            id = db.Column(db.Integer, primary_key=True)
            username = db.Column(db.String(100), nullable=False)
            
            def validate(self):
                super().validate()
                if not self.username or len(self.username) < 3:
                    raise ValidationError("Username must be at least 3 characters")
    """
    
    # Mark as abstract so SQLAlchemy doesn't create a table for this class
    __abstract__ = True
    
    def to_dict(self, include_relationships=False, exclude_fields=None, 
                include_audit=True) -> Dict[str, Any]:
        """
        Convert model instance to dictionary for JSON serialization.
        
        This method provides comprehensive serialization with support for:
        - Relationship inclusion/exclusion
        - Field filtering for sensitive data
        - Automatic type conversion for JSON compatibility
        - Audit field inclusion control
        
        Args:
            include_relationships (bool): Whether to include relationship data
            exclude_fields (List[str]): Field names to exclude from output
            include_audit (bool): Whether to include audit fields
            
        Returns:
            Dict[str, Any]: Dictionary representation of the model
        """
        exclude_fields = exclude_fields or []
        result = {}
        
        try:
            # Get model columns
            mapper = class_mapper(self.__class__)
            
            for column in mapper.columns:
                column_name = column.name
                
                # Skip excluded fields
                if column_name in exclude_fields:
                    continue
                
                # Skip audit fields if not requested
                if not include_audit and column_name in ['created_at', 'updated_at', 'created_by', 'updated_by']:
                    continue
                
                # Get column value
                value = getattr(self, column_name, None)
                
                # Convert value for JSON serialization
                if value is not None:
                    result[column_name] = self._serialize_value(value)
                else:
                    result[column_name] = None
            
            # Include relationships if requested
            if include_relationships:
                for relationship in mapper.relationships:
                    relationship_name = relationship.key
                    
                    # Skip excluded relationships
                    if relationship_name in exclude_fields:
                        continue
                    
                    relationship_value = getattr(self, relationship_name, None)
                    
                    if relationship_value is not None:
                        if hasattr(relationship_value, '__iter__') and not isinstance(relationship_value, str):
                            # Collection relationship
                            result[relationship_name] = [
                                item.to_dict(include_relationships=False, exclude_fields=exclude_fields)
                                if hasattr(item, 'to_dict') else str(item)
                                for item in relationship_value
                            ]
                        else:
                            # Single relationship
                            if hasattr(relationship_value, 'to_dict'):
                                result[relationship_name] = relationship_value.to_dict(
                                    include_relationships=False, exclude_fields=exclude_fields
                                )
                            else:
                                result[relationship_name] = str(relationship_value)
            
            return result
            
        except Exception as e:
            logger.error(f"Error serializing {self.__class__.__name__}: {str(e)}")
            # Return basic serialization on error
            return {'id': getattr(self, 'id', None), 'error': 'Serialization failed'}
    
    def _serialize_value(self, value: Any) -> Any:
        """
        Convert individual values for JSON serialization.
        
        Args:
            value: Value to serialize
            
        Returns:
            Any: JSON-compatible value
        """
        if isinstance(value, datetime):
            return value.isoformat()
        elif isinstance(value, Decimal):
            return float(value)
        elif hasattr(value, '__dict__'):
            # Complex object - try to serialize if it has to_dict method
            if hasattr(value, 'to_dict'):
                return value.to_dict()
            else:
                return str(value)
        else:
            return value
    
    def update_from_dict(self, data: Dict[str, Any], exclude_fields=None, 
                        validate_after_update=True) -> None:
        """
        Update model instance from dictionary data.
        
        Args:
            data (Dict[str, Any]): Dictionary containing update data
            exclude_fields (List[str]): Field names to exclude from update
            validate_after_update (bool): Whether to validate after updating
            
        Raises:
            ValidationError: If validation fails after update
            AttributeError: If trying to update non-existent field
        """
        exclude_fields = exclude_fields or ['id', 'created_at', 'created_by']
        
        try:
            for key, value in data.items():
                # Skip excluded fields
                if key in exclude_fields:
                    continue
                
                # Only update if attribute exists
                if hasattr(self, key):
                    setattr(self, key, value)
                else:
                    logger.warning(f"Attempted to update non-existent field '{key}' on {self.__class__.__name__}")
            
            # Run validation if requested
            if validate_after_update:
                self.validate()
                
        except Exception as e:
            logger.error(f"Error updating {self.__class__.__name__} from dict: {str(e)}")
            raise ValidationError(f"Failed to update model: {str(e)}")
    
    def validate(self) -> None:
        """
        Validate model instance data.
        
        This method should be overridden by subclasses to implement
        model-specific validation logic. The base implementation
        performs basic validation checks.
        
        Raises:
            ValidationError: If validation fails
        """
        try:
            # Basic validation - check for required fields
            mapper = class_mapper(self.__class__)
            
            for column in mapper.columns:
                if not column.nullable and not column.default and not column.server_default:
                    value = getattr(self, column.name, None)
                    if value is None:
                        raise ValidationError(f"Required field '{column.name}' cannot be None")
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            else:
                logger.error(f"Error during validation of {self.__class__.__name__}: {str(e)}")
                raise ValidationError(f"Validation error: {str(e)}")
    
    def save(self, commit=True) -> 'BaseModel':
        """
        Save the model instance to the database.
        
        Args:
            commit (bool): Whether to commit the transaction
            
        Returns:
            BaseModel: The saved model instance
            
        Raises:
            DatabaseError: If save operation fails
        """
        try:
            # Validate before saving
            self.validate()
            
            # Add to session
            db.session.add(self)
            
            # Commit if requested
            if commit:
                db.session.commit()
            
            return self
            
        except IntegrityError as e:
            db.session.rollback()
            logger.error(f"Integrity error saving {self.__class__.__name__}: {str(e)}")
            raise DatabaseError(f"Data integrity violation: {str(e)}")
        except ValidationError:
            db.session.rollback()
            raise
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error saving {self.__class__.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to save model: {str(e)}")
    
    def delete(self, commit=True) -> None:
        """
        Delete the model instance from the database.
        
        Args:
            commit (bool): Whether to commit the transaction
            
        Raises:
            DatabaseError: If delete operation fails
        """
        try:
            db.session.delete(self)
            
            if commit:
                db.session.commit()
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting {self.__class__.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to delete model: {str(e)}")
    
    @classmethod
    def get_by_id(cls, model_id: Union[int, str]) -> Optional['BaseModel']:
        """
        Retrieve a model instance by ID.
        
        Args:
            model_id: The ID of the model to retrieve
            
        Returns:
            Optional[BaseModel]: Model instance if found, None otherwise
        """
        try:
            return cls.query.get(model_id)
        except Exception as e:
            logger.error(f"Error retrieving {cls.__name__} by ID {model_id}: {str(e)}")
            return None
    
    @classmethod
    def get_all(cls, limit=None, offset=None) -> List['BaseModel']:
        """
        Retrieve all instances of the model with optional pagination.
        
        Args:
            limit (int): Maximum number of records to return
            offset (int): Number of records to skip
            
        Returns:
            List[BaseModel]: List of model instances
        """
        try:
            query = cls.query
            
            if offset:
                query = query.offset(offset)
            
            if limit:
                query = query.limit(limit)
            
            return query.all()
            
        except Exception as e:
            logger.error(f"Error retrieving all {cls.__name__}: {str(e)}")
            return []
    
    @classmethod
    def count(cls) -> int:
        """
        Get the total count of records for this model.
        
        Returns:
            int: Total number of records
        """
        try:
            return cls.query.count()
        except Exception as e:
            logger.error(f"Error counting {cls.__name__}: {str(e)}")
            return 0
    
    def __repr__(self) -> str:
        """
        String representation of the model instance.
        
        Returns:
            str: Human-readable representation
        """
        model_id = getattr(self, 'id', 'unknown')
        return f"<{self.__class__.__name__}(id={model_id})>"


# SQLAlchemy Event Hooks for Audit Trail Management

@event.listens_for(db.session, 'before_commit')
def before_commit_audit_hook(session: Session) -> None:
    """
    SQLAlchemy event hook to automatically populate audit fields before commit.
    
    This event listener captures user context from Flask-Login sessions and
    populates audit fields (created_by, updated_by) for all models that
    inherit from AuditMixin.
    
    Args:
        session (Session): SQLAlchemy session about to be committed
    """
    try:
        # Get current user ID from Flask context
        current_user_id = get_current_user_id()
        
        # Process new records (INSERT operations)
        for obj in session.new:
            if hasattr(obj, 'created_by') and obj.created_by is None:
                obj.created_by = current_user_id
            if hasattr(obj, 'updated_by') and obj.updated_by is None:
                obj.updated_by = current_user_id
        
        # Process modified records (UPDATE operations)
        for obj in session.dirty:
            if hasattr(obj, 'updated_by'):
                obj.updated_by = current_user_id
                
    except Exception as e:
        # Log error but don't fail the transaction
        logger.error(f"Error in audit hook: {str(e)}")


@event.listens_for(db.session, 'after_commit')
def after_commit_logging_hook(session: Session) -> None:
    """
    SQLAlchemy event hook for logging database operations after successful commit.
    
    This event listener logs successful database operations for audit trail
    and monitoring purposes.
    
    Args:
        session (Session): SQLAlchemy session that was committed
    """
    try:
        if current_app:
            # Log successful commit operations
            total_operations = len(session.identity_map) if hasattr(session, 'identity_map') else 0
            current_app.logger.info(f"Database commit successful with {total_operations} operations")
            
    except Exception as e:
        # Log error but don't fail since transaction is already committed
        logger.error(f"Error in post-commit logging: {str(e)}")


@event.listens_for(db.session, 'after_rollback')
def after_rollback_logging_hook(session: Session) -> None:
    """
    SQLAlchemy event hook for logging database rollback operations.
    
    This event listener logs rollback operations for debugging and
    monitoring purposes.
    
    Args:
        session (Session): SQLAlchemy session that was rolled back
    """
    try:
        if current_app:
            current_app.logger.warning("Database transaction rolled back")
            
    except Exception as e:
        logger.error(f"Error in rollback logging: {str(e)}")


def init_base_models(app) -> None:
    """
    Initialize base model functionality with Flask application.
    
    This function sets up the base model system including database
    initialization, event listeners, and configuration validation.
    
    Args:
        app: Flask application instance
    """
    try:
        # Initialize SQLAlchemy with the app
        db.init_app(app)
        
        # Validate encryption configuration if models use encryption
        if ENCRYPTION_AVAILABLE:
            try:
                get_encryption_key()
                app.logger.info("Encryption key configuration validated successfully")
            except EncryptionError as e:
                app.logger.warning(f"Encryption configuration issue: {str(e)}")
        else:
            app.logger.warning("SQLAlchemy-Utils not available - encryption features disabled")
        
        # Register additional event listeners if needed
        app.logger.info("Base model system initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Failed to initialize base model system: {str(e)}")
        raise


# Export main classes and functions
__all__ = [
    'db',
    'BaseModel',
    'AuditMixin', 
    'EncryptedMixin',
    'DatabaseError',
    'EncryptionError',
    'ValidationError',
    'init_base_models',
    'get_current_user_id',
    'get_encryption_key'
]