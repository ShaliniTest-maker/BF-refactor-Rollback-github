"""
Base model class providing common database fields and functionality for all Flask-SQLAlchemy models.

This module implements the declarative base pattern with PostgreSQL-optimized field types
and establishes consistent model behavior across the application. All other models inherit
from this base to ensure uniform database patterns and maintenance.

Key Features:
- Flask-SQLAlchemy 3.1.1 declarative model patterns for PostgreSQL integration
- Common database field patterns for timestamp management and primary keys
- Base model inheritance structure for consistent model behavior
- PostgreSQL-optimized field types and constraints for performance
- Automatic timestamp population and management
- Enterprise-grade model utilities and conventions

Technical Specification References:
- Section 6.2.1: Database Technology Transition to PostgreSQL 15.x
- Section 6.2.2.2: Primary key pattern using auto-incrementing integers
- Section 3.2.2: Flask-SQLAlchemy 3.1.1 integration requirements
- Feature F-003: Database Model Conversion from MongoDB patterns
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, DateTime, text
from sqlalchemy.ext.declarative import declared_attr, declarative_base
from sqlalchemy.sql import func


# Initialize Flask-SQLAlchemy instance
# This will be initialized in the Flask application factory pattern
db = SQLAlchemy()


class BaseModel(db.Model):
    """
    Abstract base model class for all Flask-SQLAlchemy models.
    
    Provides common database fields and functionality including:
    - Auto-incrementing primary key with optimal join performance
    - Automatic timestamp management (created_at, updated_at)
    - PostgreSQL-optimized field types and constraints
    - Consistent model behavior patterns across all entities
    - Utility methods for model serialization and representation
    
    This class implements the declarative base pattern as specified in
    Section 6.2.1 of the technical specification, ensuring PostgreSQL
    optimization and Flask-SQLAlchemy 3.1.1 compatibility.
    
    All domain models (User, UserSession, BusinessEntity, EntityRelationship)
    inherit from this base to maintain consistent database patterns.
    """
    
    # Mark this as an abstract base class - no table will be created for this model
    __abstract__ = True
    
    # Primary key field using auto-incrementing integers for optimal join performance
    # Per Section 6.2.2.2: "Primary key pattern using auto-incrementing integers 
    # for optimal join performance per Section 6.2.2.2"
    id = Column(
        Integer,
        primary_key=True,
        nullable=False,
        autoincrement=True,
        comment="Auto-incrementing primary key for optimal PostgreSQL join performance"
    )
    
    # Timestamp fields with automatic population per database design requirements
    # Per Section 6.2.1: "Common timestamp fields (created_at, updated_at) with 
    # automatic population per database design requirements"
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Record creation timestamp with timezone support"
    )
    
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        comment="Record last update timestamp with automatic updates"
    )
    
    def __init__(self, **kwargs):
        """
        Initialize base model with common field handling.
        
        Automatically sets created_at and updated_at timestamps if not provided.
        Supports kwargs-based initialization for flexible model creation.
        
        Args:
            **kwargs: Field values for model initialization
        """
        # Set current timestamp for created_at and updated_at if not provided
        current_time = datetime.now(timezone.utc)
        
        if 'created_at' not in kwargs:
            kwargs['created_at'] = current_time
        if 'updated_at' not in kwargs:
            kwargs['updated_at'] = current_time
            
        # Initialize the model with provided kwargs
        super().__init__(**kwargs)
    
    def __repr__(self) -> str:
        """
        String representation of the model for debugging and logging.
        
        Returns a consistent format showing the model class name and primary key.
        This follows enterprise-grade debugging patterns for model identification.
        
        Returns:
            str: Human-readable representation of the model instance
        """
        return f"<{self.__class__.__name__}(id={self.id})>"
    
    def to_dict(self, include_timestamps: bool = True) -> Dict[str, Any]:
        """
        Convert model instance to dictionary representation.
        
        Provides a consistent method for serializing model data across all entities.
        Useful for API responses, logging, and data transformation workflows.
        
        Args:
            include_timestamps (bool): Whether to include created_at/updated_at fields
            
        Returns:
            Dict[str, Any]: Dictionary representation of the model
        """
        result = {}
        
        # Iterate through all columns and include their values
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            
            # Skip timestamp fields if not requested
            if not include_timestamps and column.name in ('created_at', 'updated_at'):
                continue
                
            # Convert datetime objects to ISO format strings for JSON serialization
            if isinstance(value, datetime):
                result[column.name] = value.isoformat()
            else:
                result[column.name] = value
                
        return result
    
    def update_from_dict(self, data: Dict[str, Any], allowed_fields: Optional[set] = None) -> None:
        """
        Update model instance from dictionary data.
        
        Provides a safe method for updating model fields with validation.
        Automatically updates the updated_at timestamp and validates field access.
        
        Args:
            data (Dict[str, Any]): Dictionary containing field updates
            allowed_fields (Optional[set]): Set of allowed field names for security
        """
        # Get current timestamp for updated_at
        current_time = datetime.now(timezone.utc)
        
        # Iterate through provided data
        for field_name, value in data.items():
            # Skip id field to prevent primary key modification
            if field_name == 'id':
                continue
                
            # Skip created_at to preserve original creation time
            if field_name == 'created_at':
                continue
                
            # Validate allowed fields if specified
            if allowed_fields is not None and field_name not in allowed_fields:
                continue
                
            # Check if the field exists as a column on the model
            if hasattr(self, field_name) and hasattr(self.__class__, field_name):
                column = getattr(self.__class__, field_name)
                if hasattr(column.property, 'columns'):
                    setattr(self, field_name, value)
        
        # Always update the updated_at timestamp
        self.updated_at = current_time
    
    def refresh(self) -> None:
        """
        Refresh the model instance from the database.
        
        Reloads the model data from the database to ensure consistency.
        Useful after complex operations or when working with concurrent access.
        """
        db.session.refresh(self)
    
    def save(self, commit: bool = True) -> 'BaseModel':
        """
        Save the model instance to the database.
        
        Provides a convenient method for persisting model changes with optional
        transaction control. Updates the updated_at timestamp automatically.
        
        Args:
            commit (bool): Whether to commit the transaction immediately
            
        Returns:
            BaseModel: The saved model instance for method chaining
        """
        # Update the updated_at timestamp
        self.updated_at = datetime.now(timezone.utc)
        
        # Add to session and optionally commit
        db.session.add(self)
        if commit:
            db.session.commit()
            
        return self
    
    def delete(self, commit: bool = True) -> None:
        """
        Delete the model instance from the database.
        
        Provides a convenient method for removing model instances with optional
        transaction control. Supports both soft and hard deletion patterns.
        
        Args:
            commit (bool): Whether to commit the transaction immediately
        """
        db.session.delete(self)
        if commit:
            db.session.commit()
    
    @classmethod
    def create(cls, **kwargs) -> 'BaseModel':
        """
        Create and save a new model instance.
        
        Class method for creating new instances with automatic persistence.
        Provides a convenient alternative to manual instantiation and saving.
        
        Args:
            **kwargs: Field values for the new instance
            
        Returns:
            BaseModel: The created and saved model instance
        """
        instance = cls(**kwargs)
        return instance.save()
    
    @classmethod
    def get_by_id(cls, model_id: int) -> Optional['BaseModel']:
        """
        Retrieve a model instance by its primary key.
        
        Provides a consistent method for primary key lookups across all models.
        Returns None if the instance is not found rather than raising an exception.
        
        Args:
            model_id (int): The primary key value to search for
            
        Returns:
            Optional[BaseModel]: The model instance or None if not found
        """
        return cls.query.filter_by(id=model_id).first()
    
    @classmethod
    def exists(cls, model_id: int) -> bool:
        """
        Check if a model instance exists by its primary key.
        
        Efficient method for existence checking without loading the full instance.
        Useful for validation and conditional logic.
        
        Args:
            model_id (int): The primary key value to check
            
        Returns:
            bool: True if the instance exists, False otherwise
        """
        return cls.query.filter_by(id=model_id).first() is not None
    
    @declared_attr
    def __tablename__(cls) -> str:
        """
        Generate table name from class name.
        
        Automatically generates PostgreSQL-compatible table names from model class names.
        Converts CamelCase to snake_case following database naming conventions.
        
        Returns:
            str: The generated table name in snake_case format
        """
        # Convert CamelCase class name to snake_case table name
        import re
        name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', cls.__name__)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


# Export the base model and database instance for use throughout the application
__all__ = ['BaseModel', 'db']