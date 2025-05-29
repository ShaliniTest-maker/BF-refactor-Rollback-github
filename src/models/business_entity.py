"""
BusinessEntity Model Implementation for Core Business Domain Objects.

This module implements the BusinessEntity model using Flask-SQLAlchemy declarative patterns
with PostgreSQL optimization and comprehensive business workflow management. The model
represents core business domain objects with ownership relationships to Users and provides
the foundation for complex business entity associations and relationship mapping.

Key Features:
- Flask-SQLAlchemy 3.1.1 declarative model patterns for PostgreSQL integration
- Foreign key relationship to User model for entity ownership and access control
- Business entity metadata fields (name, description, status) with PostgreSQL optimization
- Foundation for EntityRelationship model associations per ER diagram requirements
- Status field with proper indexing for business workflow management
- Comprehensive business logic preservation from Node.js to Flask migration

Technical Specification References:
- Section 6.2.1: Database Technology Transition to PostgreSQL 15.x
- Section 6.2.2.1: Entity Relationships and Data Models
- Feature F-003: Database Model Conversion from MongoDB patterns
- Feature F-005: Business Logic Preservation during migration
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    Column, Integer, String, Text, ForeignKey, DateTime, Index,
    CheckConstraint, UniqueConstraint, text
)
from sqlalchemy.orm import relationship, validates
from .base import BaseModel, db


class BusinessEntity(BaseModel):
    """
    BusinessEntity model representing core business domain objects with ownership relationships.
    
    This model implements the primary business logic entities with proper foreign key constraints,
    status management, and relationship mapping to support complex business workflows and entity
    relationship patterns. Serves as the foundation for business operations and entity associations.
    
    Inherits from BaseModel for common functionality including:
    - Auto-incrementing primary key (id)
    - Automatic timestamp management (created_at, updated_at)
    - Common utility methods for serialization and persistence
    - PostgreSQL-optimized field patterns
    
    Attributes:
        id (int): Primary key inherited from BaseModel for optimal join performance
        name (str): Business entity name with length constraints and validation
        description (str): Detailed description of the business entity purpose and context
        owner_id (int): Foreign key to User model for entity ownership and access control
        status (str): Business workflow status for entity lifecycle management
        created_at (datetime): Timestamp inherited from BaseModel with automatic population
        updated_at (datetime): Timestamp inherited from BaseModel with automatic updates
        
    Relationships:
        owner (User): Many-to-one relationship with User model for entity ownership
        source_relationships (List[EntityRelationship]): One-to-many as source entity
        target_relationships (List[EntityRelationship]): One-to-many as target entity
    """
    
    __tablename__ = 'business_entities'
    
    # Business entity identification and metadata fields
    # Per Section 6.2.2.1: Business entity metadata fields with PostgreSQL text field optimization
    name = Column(
        String(255),
        nullable=False,
        index=True,
        comment="Business entity name with length constraints and validation"
    )
    
    description = Column(
        Text,
        nullable=True,
        comment="Detailed description of the business entity purpose and context"
    )
    
    # Foreign key relationship to User model for entity ownership per Section 6.2.2.1
    owner_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Foreign key to User model for entity ownership and access control"
    )
    
    # Business workflow status field with indexing per workflow management requirements
    status = Column(
        String(50),
        nullable=False,
        default='active',
        index=True,
        comment="Business workflow status for entity lifecycle management"
    )
    
    # Relationship mapping to User model per Section 6.2.2.1
    owner = relationship(
        'User',
        back_populates='business_entities',
        lazy='select',
        doc="Many-to-one relationship with User model for entity ownership"
    )
    
    # Foundation for EntityRelationship model associations per ER diagram requirements
    # These relationships will be established when EntityRelationship model is available
    source_relationships = relationship(
        'EntityRelationship',
        foreign_keys='[EntityRelationship.source_entity_id]',
        back_populates='source_entity',
        lazy='dynamic',
        cascade='all, delete-orphan',
        passive_deletes=True,
        doc="One-to-many relationship as source entity in business relationships"
    )
    
    target_relationships = relationship(
        'EntityRelationship',
        foreign_keys='[EntityRelationship.target_entity_id]',
        back_populates='target_entity',
        lazy='dynamic',
        cascade='all, delete-orphan',
        passive_deletes=True,
        doc="One-to-many relationship as target entity in business relationships"
    )
    
    # Database constraints and indexes for data integrity and performance per Section 6.2.2.2
    __table_args__ = (
        # Check constraints for data validation and business rules
        CheckConstraint('LENGTH(name) >= 1', name='ck_business_entity_name_length'),
        CheckConstraint('LENGTH(name) <= 255', name='ck_business_entity_name_max_length'),
        CheckConstraint(
            "status IN ('active', 'inactive', 'pending', 'archived', 'deleted')",
            name='ck_business_entity_status_values'
        ),
        
        # Composite indexes for performance optimization per Section 6.2.2.2
        Index('ix_business_entity_owner_status', 'owner_id', 'status'),
        Index('ix_business_entity_name_status', 'name', 'status'),
        Index('ix_business_entity_status_created', 'status', 'created_at'),
        Index('ix_business_entity_owner_created', 'owner_id', 'created_at'),
        
        # Unique constraint for name per owner to prevent duplicates
        UniqueConstraint('owner_id', 'name', name='uq_business_entity_owner_name'),
        
        # Table-level comment for documentation
        {'comment': 'Core business domain objects with ownership and workflow management'}
    )
    
    def __init__(self, name: str, owner_id: int, description: str = None, status: str = 'active', **kwargs) -> None:
        """
        Initialize a new BusinessEntity instance with validation and business rules.
        
        Args:
            name (str): Business entity name (required, 1-255 characters)
            owner_id (int): Foreign key to User model for entity ownership
            description (str, optional): Detailed description of the business entity
            status (str, optional): Business workflow status (default: 'active')
            **kwargs: Additional keyword arguments for model fields
            
        Raises:
            ValueError: If name is empty or owner_id is invalid
            ValueError: If status is not in allowed values
        """
        # Validate required fields and business rules
        if not name or not name.strip():
            raise ValueError("Business entity name is required and cannot be empty")
        
        if len(name.strip()) > 255:
            raise ValueError("Business entity name cannot exceed 255 characters")
        
        if not owner_id or not isinstance(owner_id, int) or owner_id <= 0:
            raise ValueError("Valid owner_id is required for business entity ownership")
        
        # Validate status field against allowed values
        allowed_statuses = {'active', 'inactive', 'pending', 'archived', 'deleted'}
        if status and status not in allowed_statuses:
            raise ValueError(f"Status must be one of: {', '.join(allowed_statuses)}")
        
        # Initialize the model with validated data
        super().__init__(**kwargs)
        self.name = name.strip()
        self.owner_id = owner_id
        self.description = description.strip() if description else None
        self.status = status or 'active'
    
    @validates('name')
    def validate_name(self, key: str, value: str) -> str:
        """
        Validate business entity name field with business rules.
        
        Args:
            key (str): Field name being validated
            value (str): Value being set for the field
            
        Returns:
            str: Validated and normalized name value
            
        Raises:
            ValueError: If name validation fails
        """
        if not value or not value.strip():
            raise ValueError("Business entity name is required and cannot be empty")
        
        if len(value.strip()) > 255:
            raise ValueError("Business entity name cannot exceed 255 characters")
        
        return value.strip()
    
    @validates('status')
    def validate_status(self, key: str, value: str) -> str:
        """
        Validate business entity status field against allowed workflow states.
        
        Args:
            key (str): Field name being validated
            value (str): Value being set for the field
            
        Returns:
            str: Validated status value
            
        Raises:
            ValueError: If status is not in allowed values
        """
        allowed_statuses = {'active', 'inactive', 'pending', 'archived', 'deleted'}
        if value and value not in allowed_statuses:
            raise ValueError(f"Status must be one of: {', '.join(allowed_statuses)}")
        
        return value or 'active'
    
    @validates('owner_id')
    def validate_owner_id(self, key: str, value: int) -> int:
        """
        Validate owner_id field to ensure valid User reference.
        
        Args:
            key (str): Field name being validated
            value (int): Value being set for the field
            
        Returns:
            int: Validated owner_id value
            
        Raises:
            ValueError: If owner_id is invalid
        """
        if not value or not isinstance(value, int) or value <= 0:
            raise ValueError("Valid owner_id is required for business entity ownership")
        
        return value
    
    # Business logic methods for entity management and workflow operations
    
    def is_active(self) -> bool:
        """
        Check if the business entity is in active status.
        
        Returns:
            bool: True if entity status is 'active', False otherwise
        """
        return self.status == 'active'
    
    def is_archived(self) -> bool:
        """
        Check if the business entity is archived.
        
        Returns:
            bool: True if entity status is 'archived', False otherwise
        """
        return self.status == 'archived'
    
    def activate(self) -> None:
        """
        Activate the business entity by setting status to 'active'.
        
        Updates the status field and automatically updates the updated_at timestamp.
        """
        self.status = 'active'
        self.updated_at = datetime.now(timezone.utc)
    
    def deactivate(self) -> None:
        """
        Deactivate the business entity by setting status to 'inactive'.
        
        Updates the status field and automatically updates the updated_at timestamp.
        """
        self.status = 'inactive'
        self.updated_at = datetime.now(timezone.utc)
    
    def archive(self) -> None:
        """
        Archive the business entity by setting status to 'archived'.
        
        Archives the entity for long-term storage while preserving relationships.
        Updates the status field and automatically updates the updated_at timestamp.
        """
        self.status = 'archived'
        self.updated_at = datetime.now(timezone.utc)
    
    def soft_delete(self) -> None:
        """
        Soft delete the business entity by setting status to 'deleted'.
        
        Implements soft deletion pattern to preserve data integrity and relationships.
        Updates the status field and automatically updates the updated_at timestamp.
        """
        self.status = 'deleted'
        self.updated_at = datetime.now(timezone.utc)
    
    def get_all_relationships(self) -> List['EntityRelationship']:
        """
        Retrieve all relationships where this entity is either source or target.
        
        Returns:
            List[EntityRelationship]: Combined list of source and target relationships
        """
        source_rels = list(self.source_relationships.filter_by(is_active=True))
        target_rels = list(self.target_relationships.filter_by(is_active=True))
        return source_rels + target_rels
    
    def get_related_entities(self) -> List['BusinessEntity']:
        """
        Retrieve all business entities related to this entity through relationships.
        
        Returns:
            List[BusinessEntity]: List of related business entities
        """
        related_entities = []
        
        # Get entities where this is the source
        for rel in self.source_relationships.filter_by(is_active=True):
            if rel.target_entity:
                related_entities.append(rel.target_entity)
        
        # Get entities where this is the target
        for rel in self.target_relationships.filter_by(is_active=True):
            if rel.source_entity:
                related_entities.append(rel.source_entity)
        
        return related_entities
    
    def can_be_accessed_by(self, user_id: int) -> bool:
        """
        Check if a user can access this business entity based on ownership.
        
        Args:
            user_id (int): ID of the user to check access for
            
        Returns:
            bool: True if user can access the entity, False otherwise
        """
        return self.owner_id == user_id
    
    def to_dict(self, include_relationships: bool = False, include_owner: bool = False) -> Dict[str, Any]:
        """
        Convert BusinessEntity instance to dictionary representation.
        
        Args:
            include_relationships (bool): Whether to include relationship data
            include_owner (bool): Whether to include owner information
            
        Returns:
            Dict[str, Any]: Dictionary representation of the business entity
        """
        result = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'owner_id': self.owner_id,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        # Include owner information if requested
        if include_owner and self.owner:
            result['owner'] = {
                'id': self.owner.id,
                'username': self.owner.username,
                'email': self.owner.email
            }
        
        # Include relationship data if requested
        if include_relationships:
            result['relationships'] = {
                'source_count': self.source_relationships.count(),
                'target_count': self.target_relationships.count(),
                'total_count': (self.source_relationships.count() + 
                              self.target_relationships.count())
            }
        
        return result
    
    @classmethod
    def find_by_owner(cls, owner_id: int, status: Optional[str] = None) -> List['BusinessEntity']:
        """
        Find all business entities owned by a specific user.
        
        Args:
            owner_id (int): ID of the owner user
            status (Optional[str]): Filter by specific status (optional)
            
        Returns:
            List[BusinessEntity]: List of business entities owned by the user
        """
        query = cls.query.filter_by(owner_id=owner_id)
        
        if status:
            query = query.filter_by(status=status)
        
        return query.order_by(cls.created_at.desc()).all()
    
    @classmethod
    def find_by_name_and_owner(cls, name: str, owner_id: int) -> Optional['BusinessEntity']:
        """
        Find business entity by name and owner (unique constraint).
        
        Args:
            name (str): Name of the business entity
            owner_id (int): ID of the owner user
            
        Returns:
            Optional[BusinessEntity]: Business entity if found, None otherwise
        """
        return cls.query.filter_by(name=name, owner_id=owner_id).first()
    
    @classmethod
    def find_active_entities(cls, limit: Optional[int] = None) -> List['BusinessEntity']:
        """
        Find all active business entities across all users.
        
        Args:
            limit (Optional[int]): Maximum number of entities to return
            
        Returns:
            List[BusinessEntity]: List of active business entities
        """
        query = cls.query.filter_by(status='active').order_by(cls.created_at.desc())
        
        if limit:
            query = query.limit(limit)
        
        return query.all()
    
    @classmethod
    def get_entity_statistics(cls, owner_id: Optional[int] = None) -> Dict[str, int]:
        """
        Get statistics about business entities by status.
        
        Args:
            owner_id (Optional[int]): Filter by specific owner (optional)
            
        Returns:
            Dict[str, int]: Statistics dictionary with counts by status
        """
        query = cls.query
        
        if owner_id:
            query = query.filter_by(owner_id=owner_id)
        
        stats = {
            'total': query.count(),
            'active': query.filter_by(status='active').count(),
            'inactive': query.filter_by(status='inactive').count(),
            'pending': query.filter_by(status='pending').count(),
            'archived': query.filter_by(status='archived').count(),
            'deleted': query.filter_by(status='deleted').count(),
        }
        
        return stats
    
    def __repr__(self) -> str:
        """
        String representation of BusinessEntity instance for debugging and logging.
        
        Returns:
            str: String representation of BusinessEntity instance
        """
        return (
            f"<BusinessEntity(id={self.id}, name='{self.name}', "
            f"owner_id={self.owner_id}, status='{self.status}')>"
        )
    
    def __str__(self) -> str:
        """
        Human-readable string representation of BusinessEntity instance.
        
        Returns:
            str: User-friendly string representation
        """
        return f"BusinessEntity: {self.name} (Status: {self.status})"


# Export the model for use throughout the application
__all__ = ['BusinessEntity']