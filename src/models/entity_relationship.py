"""
EntityRelationship Model for Complex Business Entity Associations

This module implements the EntityRelationship model for sophisticated business logic
workflows through many-to-many entity relationships with proper referential integrity
and relationship state management for complex business rule implementation.

Key Features:
- Dual foreign key relationships to BusinessEntity model for source and target mapping
- Relationship type categorization for business workflow support
- Temporal state management with automatic timestamp tracking
- Composite indexing for efficient relationship queries and business logic performance
- Soft deletion via is_active field for relationship lifecycle management
- PostgreSQL-optimized field types and constraints for performance

Integration Points:
- Flask-SQLAlchemy 3.1.1 declarative model system
- PostgreSQL 15.x relational database integration
- Service layer integration for business workflow orchestration
- Flask-Migrate 4.1.0 database versioning support

Database Design Compliance:
- Implements complex business entity relationship mapping per Section 6.2.2.1
- Maintains database relationship integrity and referential constraints
- Supports business logic preservation for entity association workflows per Feature F-005
"""

from datetime import datetime
from sqlalchemy import Index, ForeignKey, CheckConstraint
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy instance for model definition
db = SQLAlchemy()


class EntityRelationship(db.Model):
    """
    EntityRelationship Model - Complex Business Entity Association Management
    
    This model implements sophisticated many-to-many business entity relationships
    with comprehensive relationship management capabilities including:
    
    - Source and target entity mapping through dual foreign keys
    - Relationship type categorization for business rule implementation
    - Temporal state management with automatic timestamp tracking
    - Soft deletion lifecycle management via is_active field
    - Performance-optimized composite indexing for query efficiency
    
    Database Schema:
    ---------------
    Table: entity_relationships
    - id: Primary key (auto-incrementing integer)
    - source_entity_id: Foreign key to business_entities table (source entity)
    - target_entity_id: Foreign key to business_entities table (target entity)
    - relationship_type: Business relationship categorization (VARCHAR 100)
    - created_at: Relationship creation timestamp (TIMESTAMP WITH TIME ZONE)
    - updated_at: Last modification timestamp (TIMESTAMP WITH TIME ZONE)  
    - is_active: Soft deletion flag (BOOLEAN, default True)
    
    Constraints:
    -----------
    - Primary key constraint on id field
    - Foreign key constraints with CASCADE behavior for referential integrity
    - Check constraint ensuring source_entity_id != target_entity_id (no self-relationships)
    - Unique constraint on (source_entity_id, target_entity_id, relationship_type) for active relationships
    - NOT NULL constraints on all required fields
    
    Indexes:
    -------
    - Composite index on (source_entity_id, relationship_type, is_active) for source-based queries
    - Composite index on (target_entity_id, relationship_type, is_active) for target-based queries
    - Index on (relationship_type, is_active) for type-based filtering
    - Index on created_at for temporal sorting and filtering
    
    Business Logic Integration:
    -------------------------
    - Supports complex business workflows through relationship type categorization
    - Enables bidirectional entity relationship navigation for business rule implementation
    - Provides temporal tracking for relationship lifecycle management
    - Integrates with Service Layer pattern for workflow orchestration per Section 5.2.3
    """
    
    __tablename__ = 'entity_relationships'
    
    # Primary Key - Auto-incrementing integer for optimal join performance
    id = db.Column(
        db.Integer, 
        primary_key=True, 
        nullable=False,
        comment='Primary key for entity relationship records'
    )
    
    # Source Entity Foreign Key - References BusinessEntity.id
    source_entity_id = db.Column(
        db.Integer,
        ForeignKey('business_entities.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False,
        index=True,
        comment='Foreign key to business entities table (source entity in relationship)'
    )
    
    # Target Entity Foreign Key - References BusinessEntity.id  
    target_entity_id = db.Column(
        db.Integer,
        ForeignKey('business_entities.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False,
        index=True,
        comment='Foreign key to business entities table (target entity in relationship)'
    )
    
    # Relationship Type Categorization - Business workflow classification
    relationship_type = db.Column(
        db.String(100),
        nullable=False,
        index=True,
        comment='Business relationship type categorization for workflow management'
    )
    
    # Temporal Management Fields - Automatic timestamp tracking
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        index=True,
        comment='Relationship creation timestamp with timezone support'
    )
    
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        comment='Last modification timestamp with automatic updates'
    )
    
    # Soft Deletion Management - Relationship lifecycle control
    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        index=True,
        comment='Soft deletion flag for relationship lifecycle management'
    )
    
    # SQLAlchemy Relationship Mappings - ORM navigation support
    
    # Source Entity Relationship - Enables navigation from relationship to source entity
    source_entity = relationship(
        'BusinessEntity',
        foreign_keys=[source_entity_id],
        backref='source_relationships',
        lazy='select',
        cascade='all, delete-orphan',
        doc='Source business entity in the relationship'
    )
    
    # Target Entity Relationship - Enables navigation from relationship to target entity
    target_entity = relationship(
        'BusinessEntity', 
        foreign_keys=[target_entity_id],
        backref='target_relationships',
        lazy='select',
        cascade='all, delete-orphan',
        doc='Target business entity in the relationship'
    )
    
    # Database Constraints - Data integrity enforcement
    
    __table_args__ = (
        # Check Constraint - Prevent self-relationships (source != target)
        CheckConstraint(
            'source_entity_id != target_entity_id',
            name='ck_entity_relationship_no_self_reference'
        ),
        
        # Unique Constraint - Prevent duplicate active relationships of same type
        db.UniqueConstraint(
            'source_entity_id', 
            'target_entity_id', 
            'relationship_type',
            name='uq_entity_relationship_active_unique',
            info={'where': 'is_active = true'}
        ),
        
        # Composite Performance Indexes - Query optimization for business logic
        
        # Source-based relationship queries (most common access pattern)
        Index(
            'idx_entity_relationship_source_type_active',
            'source_entity_id', 
            'relationship_type', 
            'is_active'
        ),
        
        # Target-based relationship queries (reverse navigation)
        Index(
            'idx_entity_relationship_target_type_active',
            'target_entity_id', 
            'relationship_type', 
            'is_active'
        ),
        
        # Relationship type filtering (business workflow queries)
        Index(
            'idx_entity_relationship_type_active',
            'relationship_type', 
            'is_active'
        ),
        
        # Temporal sorting and filtering (audit and reporting)
        Index(
            'idx_entity_relationship_created_at',
            'created_at'
        ),
        
        # Comprehensive constraint and index documentation
        {
            'comment': 'Entity relationships table for complex business entity associations with temporal management and soft deletion support',
            'postgresql_partition_by': 'RANGE (created_at)',  # Future partitioning support
        }
    )
    
    def __init__(self, source_entity_id, target_entity_id, relationship_type, **kwargs):
        """
        Initialize EntityRelationship instance with required parameters
        
        Args:
            source_entity_id (int): ID of the source business entity
            target_entity_id (int): ID of the target business entity  
            relationship_type (str): Business relationship type classification
            **kwargs: Additional optional parameters (is_active, etc.)
        
        Raises:
            ValueError: If source_entity_id equals target_entity_id (self-relationship)
            ValueError: If any required parameter is None or invalid
        """
        # Validate required parameters
        if source_entity_id is None or target_entity_id is None:
            raise ValueError("Source and target entity IDs are required")
            
        if source_entity_id == target_entity_id:
            raise ValueError("Self-relationships are not permitted")
            
        if not relationship_type or not isinstance(relationship_type, str):
            raise ValueError("Relationship type must be a non-empty string")
        
        # Set required attributes
        self.source_entity_id = source_entity_id
        self.target_entity_id = target_entity_id
        self.relationship_type = relationship_type.strip()
        
        # Set optional attributes with defaults
        self.is_active = kwargs.get('is_active', True)
        
        # Timestamps will be set automatically by SQLAlchemy defaults
        super().__init__()
    
    def __repr__(self):
        """
        String representation for debugging and logging
        
        Returns:
            str: Human-readable representation of the relationship
        """
        return (
            f"<EntityRelationship(id={self.id}, "
            f"source={self.source_entity_id}, "
            f"target={self.target_entity_id}, "
            f"type='{self.relationship_type}', "
            f"active={self.is_active})>"
        )
    
    def __str__(self):
        """
        Human-readable string representation
        
        Returns:
            str: Business-friendly description of the relationship
        """
        status = "Active" if self.is_active else "Inactive"
        return (
            f"{status} {self.relationship_type} relationship: "
            f"Entity {self.source_entity_id} → Entity {self.target_entity_id}"
        )
    
    # Class Methods - Business logic support methods
    
    @classmethod
    def create_relationship(cls, source_entity_id, target_entity_id, relationship_type, **kwargs):
        """
        Factory method for creating new entity relationships with validation
        
        Args:
            source_entity_id (int): Source entity identifier
            target_entity_id (int): Target entity identifier  
            relationship_type (str): Business relationship classification
            **kwargs: Additional relationship attributes
        
        Returns:
            EntityRelationship: New relationship instance ready for database persistence
            
        Raises:
            ValueError: If validation fails for any parameter
        """
        return cls(
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            relationship_type=relationship_type,
            **kwargs
        )
    
    @classmethod
    def get_relationships_by_source(cls, source_entity_id, relationship_type=None, active_only=True):
        """
        Query method for retrieving relationships by source entity
        
        Args:
            source_entity_id (int): Source entity identifier
            relationship_type (str, optional): Filter by relationship type
            active_only (bool): Only return active relationships (default: True)
        
        Returns:
            Query: SQLAlchemy query object for further filtering or execution
        """
        query = cls.query.filter(cls.source_entity_id == source_entity_id)
        
        if active_only:
            query = query.filter(cls.is_active == True)
            
        if relationship_type:
            query = query.filter(cls.relationship_type == relationship_type)
            
        return query.order_by(cls.created_at.desc())
    
    @classmethod  
    def get_relationships_by_target(cls, target_entity_id, relationship_type=None, active_only=True):
        """
        Query method for retrieving relationships by target entity
        
        Args:
            target_entity_id (int): Target entity identifier
            relationship_type (str, optional): Filter by relationship type
            active_only (bool): Only return active relationships (default: True)
        
        Returns:
            Query: SQLAlchemy query object for further filtering or execution
        """
        query = cls.query.filter(cls.target_entity_id == target_entity_id)
        
        if active_only:
            query = query.filter(cls.is_active == True)
            
        if relationship_type:
            query = query.filter(cls.relationship_type == relationship_type)
            
        return query.order_by(cls.created_at.desc())
    
    @classmethod
    def get_bidirectional_relationships(cls, entity_id, relationship_type=None, active_only=True):
        """
        Query method for retrieving all relationships where entity is either source or target
        
        Args:
            entity_id (int): Entity identifier to search for in both source and target
            relationship_type (str, optional): Filter by relationship type  
            active_only (bool): Only return active relationships (default: True)
        
        Returns:
            Query: SQLAlchemy query object combining source and target relationships
        """
        from sqlalchemy import or_
        
        query = cls.query.filter(
            or_(
                cls.source_entity_id == entity_id,
                cls.target_entity_id == entity_id
            )
        )
        
        if active_only:
            query = query.filter(cls.is_active == True)
            
        if relationship_type:
            query = query.filter(cls.relationship_type == relationship_type)
            
        return query.order_by(cls.created_at.desc())
    
    # Instance Methods - Relationship lifecycle management
    
    def deactivate(self, commit=True):
        """
        Soft delete the relationship by setting is_active to False
        
        Args:
            commit (bool): Whether to commit the transaction immediately (default: True)
        
        Returns:
            EntityRelationship: Self for method chaining
        """
        self.is_active = False
        self.updated_at = datetime.utcnow()
        
        if commit:
            db.session.commit()
            
        return self
    
    def reactivate(self, commit=True):
        """
        Reactivate a previously deactivated relationship
        
        Args:
            commit (bool): Whether to commit the transaction immediately (default: True)
        
        Returns:
            EntityRelationship: Self for method chaining
        """
        self.is_active = True
        self.updated_at = datetime.utcnow()
        
        if commit:
            db.session.commit()
            
        return self
    
    def update_relationship_type(self, new_type, commit=True):
        """
        Update the relationship type classification
        
        Args:
            new_type (str): New relationship type classification
            commit (bool): Whether to commit the transaction immediately (default: True)
        
        Returns:
            EntityRelationship: Self for method chaining
            
        Raises:
            ValueError: If new_type is invalid
        """
        if not new_type or not isinstance(new_type, str):
            raise ValueError("Relationship type must be a non-empty string")
            
        self.relationship_type = new_type.strip()
        self.updated_at = datetime.utcnow()
        
        if commit:
            db.session.commit()
            
        return self
    
    def is_reverse_of(self, other_relationship):
        """
        Check if this relationship is the reverse of another relationship
        
        Args:
            other_relationship (EntityRelationship): Another relationship to compare
        
        Returns:
            bool: True if relationships are reverses of each other
        """
        if not isinstance(other_relationship, EntityRelationship):
            return False
            
        return (
            self.source_entity_id == other_relationship.target_entity_id and
            self.target_entity_id == other_relationship.source_entity_id and
            self.relationship_type == other_relationship.relationship_type
        )
    
    def to_dict(self, include_entities=False):
        """
        Convert relationship to dictionary representation
        
        Args:
            include_entities (bool): Whether to include related entity data (default: False)
        
        Returns:
            dict: Dictionary representation of the relationship
        """
        result = {
            'id': self.id,
            'source_entity_id': self.source_entity_id,
            'target_entity_id': self.target_entity_id, 
            'relationship_type': self.relationship_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'is_active': self.is_active
        }
        
        # Include related entity data if requested and available
        if include_entities:
            if hasattr(self, 'source_entity') and self.source_entity:
                result['source_entity'] = {
                    'id': self.source_entity.id,
                    'name': getattr(self.source_entity, 'name', None)
                }
                
            if hasattr(self, 'target_entity') and self.target_entity:
                result['target_entity'] = {
                    'id': self.target_entity.id,
                    'name': getattr(self.target_entity, 'name', None)
                }
        
        return result


# Model Registration - Export for Flask application factory pattern
__all__ = ['EntityRelationship']