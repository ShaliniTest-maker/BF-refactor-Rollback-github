"""
BusinessEntity Model

This module implements the BusinessEntity model representing core business domain objects
with ownership relationships to Users and comprehensive metadata management. The model
provides the primary business logic entities with proper foreign key constraints,
status management, and relationship mapping to support complex business workflows
and entity relationship patterns.

Migration Context:
- Converted from MongoDB business entity schemas to Flask-SQLAlchemy declarative model
- Implements PostgreSQL-optimized field types for enhanced performance
- Maintains all existing data relationships and business logic patterns
- Supports complex business workflows through proper indexing and relationship mapping

Dependencies:
- Flask-SQLAlchemy 3.1.1 for declarative model patterns
- PostgreSQL 15.x for relational database backend
- Base model for common fields and functionality
- User model for ownership relationships
"""

from datetime import datetime
from sqlalchemy import Index, Text, String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import relationship, Mapped, mapped_column
from typing import TYPE_CHECKING, List, Optional

# Conditional imports for type checking to avoid circular imports
if TYPE_CHECKING:
    from .user import User
    from .entity_relationship import EntityRelationship

try:
    from .base import BaseModel
except ImportError:
    # Fallback if base model doesn't exist yet - will be replaced once base.py is created
    from flask_sqlalchemy import SQLAlchemy
    from flask_sqlalchemy.model import Model
    
    # Temporary base class until base.py is available
    class BaseModel(Model):
        """Temporary base model class until base.py is available"""
        pass


class BusinessEntity(BaseModel):
    """
    BusinessEntity model representing core business domain objects with comprehensive
    metadata management and ownership relationships.
    
    This model implements the primary business logic entities converted from MongoDB
    schemas to Flask-SQLAlchemy declarative patterns. It provides proper foreign key
    constraints, status management, and relationship mapping to support complex 
    business workflows and entity relationship patterns.
    
    Features:
    - PostgreSQL-optimized field types for enhanced performance
    - Indexed status field for efficient workflow management queries
    - Foreign key relationship to User model for entity ownership
    - Foundation for EntityRelationship model associations
    - Comprehensive metadata fields for business context
    
    Database Design:
    - Implements auto-incrementing integer primary key for optimal join performance
    - Text fields optimized for PostgreSQL storage and indexing
    - Status field indexed for business workflow state management
    - Created/updated timestamp fields for audit tracking
    """
    
    __tablename__ = 'business_entities'
    
    # Primary key - auto-incrementing integer for optimal join performance
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Business metadata fields with PostgreSQL text field optimization
    name: Mapped[str] = mapped_column(
        String(255), 
        nullable=False,
        index=True,  # Index for efficient name-based queries
        comment="Business entity name - indexed for efficient lookup operations"
    )
    
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Detailed description of the business entity purpose and context"
    )
    
    # Foreign key relationship to User model for entity ownership
    owner_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,  # Index for efficient owner-based queries
        comment="Foreign key to User model establishing entity ownership"
    )
    
    # Status field with proper indexing for business workflow management
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default='active',
        index=True,  # Critical index for workflow state queries
        comment="Business entity status for workflow management - indexed for performance"
    )
    
    # Timestamp fields for audit tracking and temporal management
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        comment="Entity creation timestamp with timezone awareness"
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        comment="Entity last modification timestamp with automatic updates"
    )
    
    # Relationship declarations for comprehensive entity associations
    
    # Ownership relationship to User model
    owner: Mapped["User"] = relationship(
        "User",
        back_populates="business_entities",
        lazy="select",  # Explicit loading strategy for performance control
        foreign_keys=[owner_id],
        doc="User who owns this business entity - establishes access control context"
    )
    
    # Foundation for EntityRelationship model associations
    # Source relationships where this entity is the source
    source_relationships: Mapped[List["EntityRelationship"]] = relationship(
        "EntityRelationship",
        foreign_keys="EntityRelationship.source_entity_id",
        back_populates="source_entity",
        lazy="dynamic",  # Dynamic loading for large relationship collections
        cascade="all, delete-orphan",
        doc="Relationships where this entity serves as the source"
    )
    
    # Target relationships where this entity is the target
    target_relationships: Mapped[List["EntityRelationship"]] = relationship(
        "EntityRelationship", 
        foreign_keys="EntityRelationship.target_entity_id",
        back_populates="target_entity",
        lazy="dynamic",  # Dynamic loading for large relationship collections
        cascade="all, delete-orphan",
        doc="Relationships where this entity serves as the target"
    )
    
    # Database indexes for query optimization
    __table_args__ = (
        # Composite index for owner-status queries (common business workflow pattern)
        Index('idx_business_entity_owner_status', 'owner_id', 'status'),
        
        # Composite index for temporal queries with status filtering
        Index('idx_business_entity_status_created', 'status', 'created_at'),
        
        # Index for name-based searches and sorting
        Index('idx_business_entity_name_lower', 'name'),
        
        {'comment': 'Business entities table storing core business domain objects'}
    )
    
    def __repr__(self) -> str:
        """
        String representation of BusinessEntity for debugging and logging.
        
        Returns:
            str: Human-readable representation including ID, name, and status
        """
        return f"<BusinessEntity(id={self.id}, name='{self.name}', status='{self.status}')>"
    
    def __str__(self) -> str:
        """
        User-friendly string representation for display purposes.
        
        Returns:
            str: Business entity name for user interface display
        """
        return self.name
    
    def to_dict(self) -> dict:
        """
        Convert BusinessEntity instance to dictionary representation.
        
        This method provides a standardized way to serialize the model
        for API responses, maintaining consistency with original Node.js
        implementation patterns.
        
        Returns:
            dict: Dictionary containing all model fields and metadata
        """
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'owner_id': self.owner_id,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
    
    @classmethod
    def get_active_entities(cls, owner_id: Optional[int] = None):
        """
        Class method to retrieve active business entities with optional owner filtering.
        
        This method provides a common query pattern for business workflow
        operations that need to work with active entities only.
        
        Args:
            owner_id (Optional[int]): Filter results by owner ID if provided
            
        Returns:
            Query: SQLAlchemy query object for active entities
        """
        from flask_sqlalchemy import db
        
        query = db.session.query(cls).filter(cls.status == 'active')
        
        if owner_id is not None:
            query = query.filter(cls.owner_id == owner_id)
            
        return query.order_by(cls.name)
    
    @classmethod
    def get_by_status(cls, status: str, owner_id: Optional[int] = None):
        """
        Class method to retrieve business entities by status with optional owner filtering.
        
        This method supports business workflow operations that need to query
        entities based on their current workflow state.
        
        Args:
            status (str): Entity status to filter by
            owner_id (Optional[int]): Filter results by owner ID if provided
            
        Returns:
            Query: SQLAlchemy query object for entities with specified status
        """
        from flask_sqlalchemy import db
        
        query = db.session.query(cls).filter(cls.status == status)
        
        if owner_id is not None:
            query = query.filter(cls.owner_id == owner_id)
            
        return query.order_by(cls.created_at.desc())
    
    def update_status(self, new_status: str) -> None:
        """
        Update entity status with automatic timestamp management.
        
        This method provides a controlled way to update entity status
        while ensuring proper audit trail maintenance through automatic
        timestamp updates.
        
        Args:
            new_status (str): New status value for the entity
        """
        self.status = new_status
        self.updated_at = datetime.utcnow()
    
    def get_related_entities(self, relationship_type: Optional[str] = None):
        """
        Retrieve entities related to this business entity through EntityRelationship.
        
        This method provides access to complex business relationship patterns
        by traversing both source and target relationships.
        
        Args:
            relationship_type (Optional[str]): Filter by specific relationship type
            
        Returns:
            List[BusinessEntity]: List of related business entities
        """
        related_entities = []
        
        # Get entities where this is the source
        source_query = self.source_relationships
        if relationship_type:
            source_query = source_query.filter_by(relationship_type=relationship_type)
        
        for rel in source_query.filter_by(is_active=True):
            if rel.target_entity:
                related_entities.append(rel.target_entity)
        
        # Get entities where this is the target  
        target_query = self.target_relationships
        if relationship_type:
            target_query = target_query.filter_by(relationship_type=relationship_type)
            
        for rel in target_query.filter_by(is_active=True):
            if rel.source_entity:
                related_entities.append(rel.source_entity)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_entities = []
        for entity in related_entities:
            if entity.id not in seen:
                seen.add(entity.id)
                unique_entities.append(entity)
                
        return unique_entities


# Export the model for package-level imports
__all__ = ['BusinessEntity']