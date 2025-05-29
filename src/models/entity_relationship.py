"""
EntityRelationship Model

This module implements the EntityRelationship model for complex business entity associations
with source and target entity mapping, relationship type categorization, and temporal management.
The model enables sophisticated business logic workflows through many-to-many entity relationships
with proper referential integrity and relationship state management for complex business rule
implementation.

Migration Context:
- Created EntityRelationship model for complex business entity associations per database design Section 6.2.2.1
- Implements dual foreign key relationships to BusinessEntity model for source and target mapping
- Provides relationship type categorization and temporal state management for business workflow support
- Establishes composite indexing for efficient relationship queries and business logic performance
- Adds is_active field for soft deletion and relationship lifecycle management

Technical Specification References:
- Section 6.2.2.1: Entity Relationships and Data Models
- Feature F-005: Business Logic Preservation for entity association workflows
- Section 5.2.3: Service Layer Implementation for business workflow orchestration
- Section 6.2.2.2: Indexing Strategy for performance optimization

Dependencies:
- Flask-SQLAlchemy 3.1.1 for declarative model patterns
- PostgreSQL 15.x for relational database backend with advanced indexing
- Base model for common fields and functionality  
- BusinessEntity model for dual foreign key relationships
- Service layer integration for business workflow orchestration
"""

from datetime import datetime
from sqlalchemy import Index, String, Integer, DateTime, ForeignKey, Boolean, CheckConstraint
from sqlalchemy.orm import relationship, Mapped, mapped_column, validates
from typing import TYPE_CHECKING, Optional, Dict, Any, List

# Conditional imports for type checking to avoid circular imports
if TYPE_CHECKING:
    from .business_entity import BusinessEntity

from .base import BaseModel


class EntityRelationship(BaseModel):
    """
    EntityRelationship model implementing complex business entity associations with
    source and target entity mapping, relationship type categorization, and temporal management.
    
    This model enables sophisticated business logic workflows through many-to-many entity
    relationships with proper referential integrity and relationship state management.
    It provides the foundation for complex business rule implementation through structured
    entity associations.
    
    Features:
    - Dual foreign key relationships to BusinessEntity for source and target mapping
    - Relationship type categorization for business workflow organization
    - Temporal state management with is_active field for soft deletion
    - Composite indexing for efficient relationship queries and performance optimization
    - Comprehensive validation for business rule enforcement
    - PostgreSQL-optimized field types and constraints
    
    Database Design:
    - Implements auto-incrementing integer primary key for optimal join performance
    - Foreign key constraints ensuring referential integrity with BusinessEntity
    - Composite indexes for efficient relationship traversal and queries
    - Check constraints preventing self-referential relationships
    - Temporal fields for relationship lifecycle management
    
    Business Logic Integration:
    - Supports complex business workflows through relationship type categorization
    - Enables service layer orchestration of entity association patterns
    - Provides foundation for business rule validation and enforcement
    - Maintains audit trail through timestamp and state management
    """
    
    __tablename__ = 'entity_relationships'
    
    # Primary key - auto-incrementing integer for optimal join performance per Section 6.2.2.2
    id: Mapped[int] = mapped_column(
        Integer, 
        primary_key=True, 
        autoincrement=True,
        comment="Auto-incrementing primary key for optimal PostgreSQL join performance"
    )
    
    # Source entity foreign key relationship
    source_entity_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('business_entities.id', ondelete='CASCADE'),
        nullable=False,
        index=True,  # Index for efficient source entity queries
        comment="Foreign key to BusinessEntity serving as the relationship source"
    )
    
    # Target entity foreign key relationship  
    target_entity_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('business_entities.id', ondelete='CASCADE'),
        nullable=False,
        index=True,  # Index for efficient target entity queries
        comment="Foreign key to BusinessEntity serving as the relationship target"
    )
    
    # Relationship type categorization for business workflow organization
    relationship_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,  # Critical index for type-based relationship queries
        comment="Categorization of relationship type for business workflow organization"
    )
    
    # Temporal state management with is_active field for soft deletion per requirements
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,  # Index for efficient active relationship filtering
        comment="Soft deletion flag for relationship lifecycle management"
    )
    
    # Timestamp fields for comprehensive audit trail and temporal management
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        comment="Relationship creation timestamp with timezone awareness"
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        comment="Relationship last modification timestamp with automatic updates"
    )
    
    # Relationship declarations for comprehensive entity associations
    
    # Source entity relationship mapping
    source_entity: Mapped["BusinessEntity"] = relationship(
        "BusinessEntity",
        foreign_keys=[source_entity_id],
        back_populates="source_relationships",
        lazy="select",  # Explicit loading strategy for performance control
        doc="BusinessEntity serving as the source of this relationship"
    )
    
    # Target entity relationship mapping
    target_entity: Mapped["BusinessEntity"] = relationship(
        "BusinessEntity", 
        foreign_keys=[target_entity_id],
        back_populates="target_relationships",
        lazy="select",  # Explicit loading strategy for performance control
        doc="BusinessEntity serving as the target of this relationship"
    )
    
    # Database constraints and indexes for performance optimization and data integrity
    __table_args__ = (
        # Check constraint to prevent self-referential relationships
        CheckConstraint(
            'source_entity_id != target_entity_id',
            name='check_no_self_reference'
        ),
        
        # Composite index for efficient relationship queries per Section 6.2.2.2
        Index(
            'idx_entity_relationship_source_target',
            'source_entity_id', 
            'target_entity_id',
            unique=False  # Allow multiple relationship types between same entities
        ),
        
        # Composite index for relationship type and state queries (critical for business logic)
        Index(
            'idx_entity_relationship_type_active',
            'relationship_type',
            'is_active'
        ),
        
        # Composite index for source entity and relationship type queries
        Index(
            'idx_entity_relationship_source_type',
            'source_entity_id',
            'relationship_type',
            'is_active'
        ),
        
        # Composite index for target entity and relationship type queries
        Index(
            'idx_entity_relationship_target_type',
            'target_entity_id', 
            'relationship_type',
            'is_active'
        ),
        
        # Temporal index for relationship lifecycle queries
        Index(
            'idx_entity_relationship_temporal',
            'created_at',
            'is_active'
        ),
        
        # Unique constraint for specific relationship types that should be singular
        # Note: This can be adjusted based on business requirements
        Index(
            'idx_entity_relationship_unique_active',
            'source_entity_id',
            'target_entity_id', 
            'relationship_type',
            unique=True,
            postgresql_where=(lambda: "is_active = true")  # Partial unique index for active relationships
        ),
        
        {'comment': 'Entity relationships table for complex business entity associations'}
    )
    
    def __repr__(self) -> str:
        """
        String representation of EntityRelationship for debugging and logging.
        
        Returns:
            str: Human-readable representation including relationship details
        """
        return (f"<EntityRelationship(id={self.id}, "
                f"source={self.source_entity_id}, "
                f"target={self.target_entity_id}, "
                f"type='{self.relationship_type}', "
                f"active={self.is_active})>")
    
    def __str__(self) -> str:
        """
        User-friendly string representation for display purposes.
        
        Returns:
            str: Relationship description for user interface display
        """
        return f"{self.relationship_type} relationship"
    
    def to_dict(self, include_entities: bool = False) -> Dict[str, Any]:
        """
        Convert EntityRelationship instance to dictionary representation.
        
        This method provides a standardized way to serialize the model
        for API responses, maintaining consistency with original Node.js
        implementation patterns and supporting service layer integration.
        
        Args:
            include_entities (bool): Whether to include full entity details
            
        Returns:
            Dict[str, Any]: Dictionary containing relationship fields and metadata
        """
        result = {
            'id': self.id,
            'source_entity_id': self.source_entity_id,
            'target_entity_id': self.target_entity_id,
            'relationship_type': self.relationship_type,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        # Optionally include full entity details for comprehensive API responses
        if include_entities:
            result['source_entity'] = self.source_entity.to_dict() if self.source_entity else None
            result['target_entity'] = self.target_entity.to_dict() if self.target_entity else None
        
        return result
    
    @validates('relationship_type')
    def validate_relationship_type(self, key: str, relationship_type: str) -> str:
        """
        Validate relationship type field according to business rules.
        
        This validator ensures relationship types conform to business logic
        requirements and maintain consistency across the application.
        
        Args:
            key (str): Field name being validated
            relationship_type (str): Relationship type value to validate
            
        Returns:
            str: Validated relationship type value
            
        Raises:
            ValueError: If relationship type is invalid
        """
        if not relationship_type or not relationship_type.strip():
            raise ValueError("Relationship type cannot be empty")
        
        # Normalize relationship type to lowercase for consistency
        normalized_type = relationship_type.strip().lower()
        
        # Define allowed relationship types based on business requirements
        # These can be configured based on specific business domain needs
        allowed_types = {
            'parent_child',
            'dependency',
            'association',
            'composition',
            'aggregation',
            'reference',
            'hierarchy',
            'workflow',
            'approval',
            'collaboration'
        }
        
        if normalized_type not in allowed_types:
            raise ValueError(f"Invalid relationship type: {relationship_type}. "
                           f"Allowed types: {', '.join(sorted(allowed_types))}")
        
        return normalized_type
    
    @validates('source_entity_id', 'target_entity_id')
    def validate_entity_ids(self, key: str, entity_id: int) -> int:
        """
        Validate entity ID fields to ensure proper foreign key references.
        
        Args:
            key (str): Field name being validated
            entity_id (int): Entity ID value to validate
            
        Returns:
            int: Validated entity ID value
            
        Raises:
            ValueError: If entity ID is invalid
        """
        if entity_id is None or entity_id <= 0:
            raise ValueError(f"{key} must be a positive integer")
        
        return entity_id
    
    def activate(self) -> None:
        """
        Activate the relationship by setting is_active to True.
        
        This method provides controlled activation of relationships with
        automatic timestamp management for audit trail maintenance.
        """
        self.is_active = True
        self.updated_at = datetime.utcnow()
    
    def deactivate(self) -> None:
        """
        Deactivate the relationship by setting is_active to False (soft deletion).
        
        This method provides controlled deactivation of relationships with
        automatic timestamp management for audit trail maintenance.
        """
        self.is_active = False
        self.updated_at = datetime.utcnow()
    
    def reverse_relationship(self):
        """
        Get the reverse relationship if it exists.
        
        This method supports bidirectional relationship patterns by finding
        relationships with swapped source and target entities.
        
        Returns:
            Optional[EntityRelationship]: Reverse relationship if it exists
        """
        from sqlalchemy import and_
        
        return EntityRelationship.query.filter(
            and_(
                EntityRelationship.source_entity_id == self.target_entity_id,
                EntityRelationship.target_entity_id == self.source_entity_id,
                EntityRelationship.relationship_type == self.relationship_type,
                EntityRelationship.is_active == True
            )
        ).first()
    
    @classmethod
    def get_relationships_by_type(cls, relationship_type: str, active_only: bool = True):
        """
        Class method to retrieve relationships by type with optional active filtering.
        
        This method provides a common query pattern for business workflow
        operations that need to work with specific relationship types.
        
        Args:
            relationship_type (str): Type of relationships to retrieve
            active_only (bool): Whether to filter only active relationships
            
        Returns:
            Query: SQLAlchemy query object for relationships of specified type
        """
        from flask_sqlalchemy import db
        
        query = db.session.query(cls).filter(cls.relationship_type == relationship_type)
        
        if active_only:
            query = query.filter(cls.is_active == True)
            
        return query.order_by(cls.created_at.desc())
    
    @classmethod
    def get_entity_relationships(cls, entity_id: int, as_source: bool = None, 
                               relationship_type: str = None, active_only: bool = True):
        """
        Class method to retrieve relationships for a specific entity.
        
        This method supports complex business workflow queries by finding
        all relationships involving a specific entity with optional filtering.
        
        Args:
            entity_id (int): ID of the entity to find relationships for
            as_source (bool): If True, find relationships where entity is source;
                            if False, find where entity is target; if None, find both
            relationship_type (str): Optional filter by relationship type
            active_only (bool): Whether to filter only active relationships
            
        Returns:
            Query: SQLAlchemy query object for entity relationships
        """
        from flask_sqlalchemy import db
        from sqlalchemy import or_
        
        query = db.session.query(cls)
        
        # Build entity filter based on as_source parameter
        if as_source is True:
            query = query.filter(cls.source_entity_id == entity_id)
        elif as_source is False:
            query = query.filter(cls.target_entity_id == entity_id)
        else:
            # Find relationships where entity is either source or target
            query = query.filter(
                or_(
                    cls.source_entity_id == entity_id,
                    cls.target_entity_id == entity_id
                )
            )
        
        # Apply optional filters
        if relationship_type:
            query = query.filter(cls.relationship_type == relationship_type)
        
        if active_only:
            query = query.filter(cls.is_active == True)
            
        return query.order_by(cls.created_at.desc())
    
    @classmethod
    def create_relationship(cls, source_entity_id: int, target_entity_id: int,
                          relationship_type: str, allow_duplicates: bool = False) -> 'EntityRelationship':
        """
        Class method to create a new entity relationship with validation.
        
        This method provides a controlled way to create relationships with
        business rule validation and duplicate checking.
        
        Args:
            source_entity_id (int): ID of the source entity
            target_entity_id (int): ID of the target entity  
            relationship_type (str): Type of relationship to create
            allow_duplicates (bool): Whether to allow duplicate relationships
            
        Returns:
            EntityRelationship: The created relationship instance
            
        Raises:
            ValueError: If validation fails or duplicate exists when not allowed
        """
        # Validate that entities are different (prevent self-reference)
        if source_entity_id == target_entity_id:
            raise ValueError("Cannot create self-referential relationship")
        
        # Check for existing relationship if duplicates not allowed
        if not allow_duplicates:
            existing = cls.query.filter(
                cls.source_entity_id == source_entity_id,
                cls.target_entity_id == target_entity_id,
                cls.relationship_type == relationship_type,
                cls.is_active == True
            ).first()
            
            if existing:
                raise ValueError(
                    f"Active {relationship_type} relationship already exists "
                    f"between entities {source_entity_id} and {target_entity_id}"
                )
        
        # Create the new relationship
        relationship = cls(
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            relationship_type=relationship_type,
            is_active=True
        )
        
        return relationship
    
    @classmethod
    def get_relationship_statistics(cls, entity_id: int = None) -> Dict[str, Any]:
        """
        Class method to get relationship statistics for analytics and monitoring.
        
        This method provides insights into relationship patterns for business
        intelligence and system monitoring purposes.
        
        Args:
            entity_id (int): Optional entity ID to get statistics for specific entity
            
        Returns:
            Dict[str, Any]: Statistics about relationships
        """
        from flask_sqlalchemy import db
        from sqlalchemy import func, case
        
        query = db.session.query(cls)
        
        if entity_id:
            from sqlalchemy import or_
            query = query.filter(
                or_(
                    cls.source_entity_id == entity_id,
                    cls.target_entity_id == entity_id
                )
            )
        
        # Calculate basic statistics
        total_relationships = query.count()
        active_relationships = query.filter(cls.is_active == True).count()
        inactive_relationships = total_relationships - active_relationships
        
        # Get relationship type distribution
        type_distribution = (
            query.with_entities(
                cls.relationship_type,
                func.count(cls.id).label('count')
            )
            .group_by(cls.relationship_type)
            .all()
        )
        
        return {
            'total_relationships': total_relationships,
            'active_relationships': active_relationships,
            'inactive_relationships': inactive_relationships,
            'type_distribution': {
                row.relationship_type: row.count 
                for row in type_distribution
            }
        }


# Export the model for package-level imports
__all__ = ['EntityRelationship']