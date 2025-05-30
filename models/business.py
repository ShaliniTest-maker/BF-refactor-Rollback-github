"""
Business Entity and Relationship Models

This module implements Flask-SQLAlchemy declarative classes for comprehensive business entity
management and relationship tracking. Provides the foundation for business logic operations,
entity interconnections, and hierarchy management throughout the application.

The business system supports:
- Core business entity management with user ownership integration
- Flexible relationship tracking between business entities with type classification
- Cascade deletion policies ensuring referential integrity
- Comprehensive audit trails for all business operations
- Performance-optimized relationship queries with bidirectional navigation
- Validation and constraint enforcement for business rules

Dependencies:
- Flask-SQLAlchemy 3.1.1: ORM functionality and declarative models
- models.base: BaseModel and AuditMixin for common functionality
- models.user: User model for ownership relationships
- SQLAlchemy relationship patterns for efficient data navigation
"""

from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, ForeignKey,
    Index, UniqueConstraint, CheckConstraint, event, and_, or_
)
from sqlalchemy.orm import relationship, validates, backref
from werkzeug.exceptions import ValidationError
import logging

# Import base model components
from .base import BaseModel, db
from .user import User

# Configure logging for business model operations
logger = logging.getLogger(__name__)


class BusinessEntity(BaseModel):
    """
    Business entity model implementing core business object management with user ownership.
    
    Represents fundamental business objects within the application with comprehensive
    relationship tracking, user ownership integration, and flexible status management.
    Provides the foundation for business logic operations and entity management workflows.
    
    Features:
    - User ownership integration with cascade deletion policies
    - Flexible status management system supporting business workflows
    - Comprehensive validation and constraint enforcement
    - Bidirectional relationship navigation for entity interconnections
    - Performance-optimized queries with proper indexing
    - Audit trail integration through BaseModel inheritance
    
    Attributes:
        id: Primary key inherited from BaseModel
        name: Business entity name with uniqueness constraints
        description: Detailed description of the business entity
        owner_id: Foreign key reference to User model for ownership tracking
        status: Entity status supporting business workflow states
        created_at: Creation timestamp from AuditMixin
        updated_at: Last modification timestamp from AuditMixin
        created_by: User who created the entity from AuditMixin
        updated_by: User who last modified the entity from AuditMixin
        
    Relationships:
        owner: Many-to-one relationship with User model
        source_relationships: One-to-many with EntityRelationship (as source)
        target_relationships: One-to-many with EntityRelationship (as target)
        
    Database Indexes:
        - Primary key index on id (inherited)
        - Foreign key index on owner_id
        - Index on name for search operations
        - Index on status for filtering
        - Composite index on (owner_id, status) for owner queries
        - Composite index on (name, owner_id) for uniqueness validation
    """
    
    __tablename__ = 'business_entities'
    
    # Core entity fields
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # User ownership integration with cascade deletion
    owner_id = Column(
        Integer, 
        ForeignKey('users.id', ondelete='CASCADE'), 
        nullable=False, 
        index=True
    )
    
    # Status management for business workflows
    status = Column(
        String(50), 
        nullable=False, 
        default='active', 
        index=True
    )
    
    # Additional entity metadata
    entity_type = Column(String(100), nullable=True)
    priority = Column(Integer, default=0, nullable=False)
    metadata = Column(Text, nullable=True)  # JSON string for flexible metadata storage
    
    # Business entity relationships using back_populates for bidirectional navigation
    owner = relationship(
        'User',
        foreign_keys=[owner_id],
        lazy='select'
    )
    
    # Entity relationship tracking - source relationships (this entity as source)
    source_relationships = relationship(
        'EntityRelationship',
        foreign_keys='EntityRelationship.source_entity_id',
        back_populates='source_entity',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    
    # Entity relationship tracking - target relationships (this entity as target)
    target_relationships = relationship(
        'EntityRelationship',
        foreign_keys='EntityRelationship.target_entity_id',
        back_populates='target_entity',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    
    # Database constraints and indexes for performance optimization
    __table_args__ = (
        # Composite indexes for efficient querying
        Index('idx_business_entities_owner_status', 'owner_id', 'status'),
        Index('idx_business_entities_name_search', 'name', 'owner_id'),
        Index('idx_business_entities_type_status', 'entity_type', 'status'),
        Index('idx_business_entities_priority', 'priority', 'status'),
        
        # Business rule constraints
        CheckConstraint(
            "status IN ('active', 'inactive', 'pending', 'archived', 'deleted')",
            name='ck_business_entity_status_valid'
        ),
        CheckConstraint(
            "priority >= 0 AND priority <= 100",
            name='ck_business_entity_priority_range'
        ),
        CheckConstraint(
            "LENGTH(TRIM(name)) > 0",
            name='ck_business_entity_name_not_empty'
        ),
        
        # Uniqueness constraint for entity name within owner scope
        UniqueConstraint('name', 'owner_id', name='uq_business_entity_name_owner'),
    )
    
    @validates('name')
    def validate_name(self, key, name):
        """
        Validate business entity name format and constraints.
        
        Args:
            key: Field name being validated
            name: Name value to validate
            
        Returns:
            Validated and normalized name
            
        Raises:
            ValueError: If name validation fails
        """
        if not name or not name.strip():
            raise ValueError("Business entity name cannot be empty")
        
        name = name.strip()
        
        if len(name) < 2:
            raise ValueError("Business entity name must be at least 2 characters")
        if len(name) > 200:
            raise ValueError("Business entity name cannot exceed 200 characters")
        
        # Validate name contains meaningful characters
        if name.replace(' ', '').replace('-', '').replace('_', '').replace('.', '').isspace():
            raise ValueError("Business entity name must contain meaningful characters")
        
        return name
    
    @validates('status')
    def validate_status(self, key, status):
        """
        Validate business entity status values.
        
        Args:
            key: Field name being validated
            status: Status value to validate
            
        Returns:
            Validated status value
            
        Raises:
            ValueError: If status validation fails
        """
        valid_statuses = ['active', 'inactive', 'pending', 'archived', 'deleted']
        
        if status not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")
        
        return status
    
    @validates('entity_type')
    def validate_entity_type(self, key, entity_type):
        """
        Validate business entity type if provided.
        
        Args:
            key: Field name being validated
            entity_type: Entity type value to validate
            
        Returns:
            Validated entity type or None
        """
        if entity_type is not None:
            entity_type = entity_type.strip()
            if not entity_type:
                return None
            if len(entity_type) > 100:
                raise ValueError("Entity type cannot exceed 100 characters")
        
        return entity_type
    
    @validates('priority')
    def validate_priority(self, key, priority):
        """
        Validate business entity priority range.
        
        Args:
            key: Field name being validated
            priority: Priority value to validate
            
        Returns:
            Validated priority value
            
        Raises:
            ValueError: If priority validation fails
        """
        if priority is None:
            return 0
        
        if not isinstance(priority, int):
            try:
                priority = int(priority)
            except (ValueError, TypeError):
                raise ValueError("Priority must be an integer")
        
        if priority < 0 or priority > 100:
            raise ValueError("Priority must be between 0 and 100")
        
        return priority
    
    def get_all_relationships(self, include_inactive: bool = False) -> List['EntityRelationship']:
        """
        Get all relationships for this entity (both source and target).
        
        Args:
            include_inactive: Whether to include inactive relationships
            
        Returns:
            List of EntityRelationship objects
        """
        source_query = self.source_relationships
        target_query = self.target_relationships
        
        if not include_inactive:
            source_query = source_query.filter_by(is_active=True)
            target_query = target_query.filter_by(is_active=True)
        
        source_rels = source_query.all()
        target_rels = target_query.all()
        
        return source_rels + target_rels
    
    def get_relationships_by_type(self, relationship_type: str, 
                                 include_inactive: bool = False) -> List['EntityRelationship']:
        """
        Get relationships of a specific type for this entity.
        
        Args:
            relationship_type: Type of relationship to filter by
            include_inactive: Whether to include inactive relationships
            
        Returns:
            List of EntityRelationship objects of the specified type
        """
        filters = [EntityRelationship.relationship_type == relationship_type]
        
        if not include_inactive:
            filters.append(EntityRelationship.is_active == True)
        
        # Query relationships where this entity is either source or target
        source_rels = self.source_relationships.filter(*filters).all()
        target_rels = self.target_relationships.filter(*filters).all()
        
        return source_rels + target_rels
    
    def get_related_entities(self, relationship_type: str = None, 
                           include_inactive: bool = False) -> List['BusinessEntity']:
        """
        Get all entities related to this entity through relationships.
        
        Args:
            relationship_type: Optional filter by relationship type
            include_inactive: Whether to include inactive relationships
            
        Returns:
            List of related BusinessEntity objects
        """
        if relationship_type:
            relationships = self.get_relationships_by_type(relationship_type, include_inactive)
        else:
            relationships = self.get_all_relationships(include_inactive)
        
        related_entities = []
        for rel in relationships:
            if rel.source_entity_id == self.id:
                related_entities.append(rel.target_entity)
            else:
                related_entities.append(rel.source_entity)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_entities = []
        for entity in related_entities:
            if entity.id not in seen:
                seen.add(entity.id)
                unique_entities.append(entity)
        
        return unique_entities
    
    def has_relationship_with(self, other_entity: 'BusinessEntity', 
                            relationship_type: str = None) -> bool:
        """
        Check if this entity has a relationship with another entity.
        
        Args:
            other_entity: The other BusinessEntity to check
            relationship_type: Optional specific relationship type to check
            
        Returns:
            Boolean indicating if relationship exists
        """
        filters = [
            or_(
                and_(
                    EntityRelationship.source_entity_id == self.id,
                    EntityRelationship.target_entity_id == other_entity.id
                ),
                and_(
                    EntityRelationship.source_entity_id == other_entity.id,
                    EntityRelationship.target_entity_id == self.id
                )
            ),
            EntityRelationship.is_active == True
        ]
        
        if relationship_type:
            filters.append(EntityRelationship.relationship_type == relationship_type)
        
        return EntityRelationship.query.filter(*filters).first() is not None
    
    def create_relationship(self, target_entity: 'BusinessEntity', 
                          relationship_type: str, **kwargs) -> 'EntityRelationship':
        """
        Create a new relationship with another entity.
        
        Args:
            target_entity: The target BusinessEntity
            relationship_type: Type of relationship to create
            **kwargs: Additional relationship attributes
            
        Returns:
            New EntityRelationship instance
            
        Raises:
            ValueError: If relationship cannot be created
        """
        if self.id == target_entity.id:
            raise ValueError("Cannot create relationship with self")
        
        if self.has_relationship_with(target_entity, relationship_type):
            raise ValueError(f"Relationship of type '{relationship_type}' already exists")
        
        relationship = EntityRelationship(
            source_entity_id=self.id,
            target_entity_id=target_entity.id,
            relationship_type=relationship_type,
            **kwargs
        )
        
        return relationship
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get entity metadata as dictionary.
        
        Returns:
            Dictionary of entity metadata
        """
        if not self.metadata:
            return {}
        try:
            import json
            return json.loads(self.metadata)
        except (ValueError, TypeError):
            return {}
    
    def set_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        Set entity metadata from dictionary.
        
        Args:
            metadata: Dictionary of metadata to store
        """
        if metadata:
            import json
            self.metadata = json.dumps(metadata)
        else:
            self.metadata = None
    
    def is_owned_by(self, user: Union[User, int]) -> bool:
        """
        Check if entity is owned by the specified user.
        
        Args:
            user: User object or user ID
            
        Returns:
            Boolean indicating ownership
        """
        user_id = user.id if isinstance(user, User) else user
        return self.owner_id == user_id
    
    def can_be_accessed_by(self, user: Union[User, int]) -> bool:
        """
        Check if entity can be accessed by the specified user.
        
        Args:
            user: User object or user ID
            
        Returns:
            Boolean indicating access permission
        """
        # Basic ownership check - can be extended for more complex permissions
        return self.is_owned_by(user)
    
    def to_dict(self, include_relationships: bool = False, 
               include_metadata: bool = True) -> Dict[str, Any]:
        """
        Convert business entity to dictionary representation.
        
        Args:
            include_relationships: Whether to include relationship information
            include_metadata: Whether to include metadata information
            
        Returns:
            Dictionary representation of the business entity
        """
        result = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'owner_id': self.owner_id,
            'status': self.status,
            'entity_type': self.entity_type,
            'priority': self.priority,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by,
            'updated_by': self.updated_by
        }
        
        if include_metadata:
            result['metadata'] = self.get_metadata()
        
        if include_relationships:
            result['relationships'] = {
                'source_count': self.source_relationships.count(),
                'target_count': self.target_relationships.count(),
                'total_count': len(self.get_all_relationships())
            }
        
        return result
    
    @classmethod
    def get_by_owner(cls, owner_id: int, status: str = None, 
                    limit: int = None, offset: int = None) -> List['BusinessEntity']:
        """
        Get business entities by owner with optional filtering.
        
        Args:
            owner_id: Owner user ID
            status: Optional status filter
            limit: Maximum number of records to return
            offset: Number of records to skip
            
        Returns:
            List of BusinessEntity objects
        """
        query = cls.query.filter_by(owner_id=owner_id)
        
        if status:
            query = query.filter_by(status=status)
        
        query = query.order_by(cls.priority.desc(), cls.created_at.desc())
        
        if offset:
            query = query.offset(offset)
        if limit:
            query = query.limit(limit)
        
        return query.all()
    
    @classmethod
    def search_by_name(cls, name_pattern: str, owner_id: int = None, 
                      status: str = 'active') -> List['BusinessEntity']:
        """
        Search business entities by name pattern.
        
        Args:
            name_pattern: Name pattern to search for
            owner_id: Optional owner filter
            status: Optional status filter
            
        Returns:
            List of matching BusinessEntity objects
        """
        query = cls.query.filter(cls.name.ilike(f'%{name_pattern}%'))
        
        if owner_id:
            query = query.filter_by(owner_id=owner_id)
        
        if status:
            query = query.filter_by(status=status)
        
        return query.order_by(cls.name).all()
    
    def __repr__(self):
        return f"<BusinessEntity {self.name} (ID: {self.id}, Owner: {self.owner_id}, Status: {self.status})>"


class EntityRelationship(BaseModel):
    """
    Entity relationship model for tracking relationships between business entities.
    
    Implements flexible relationship tracking system supporting various business entity
    connections with type classification, active status management, and comprehensive
    audit trails. Enables complex business object interconnections and hierarchy management.
    
    Features:
    - Flexible relationship type classification system
    - Active status management for relationship lifecycle
    - Bidirectional relationship navigation with back_populates
    - Comprehensive audit trails through BaseModel inheritance
    - Performance-optimized queries with proper indexing
    - Cascade deletion policies for referential integrity
    
    Attributes:
        id: Primary key inherited from BaseModel
        source_entity_id: Foreign key to source BusinessEntity
        target_entity_id: Foreign key to target BusinessEntity
        relationship_type: Classification of the relationship type
        is_active: Boolean flag for relationship status management
        strength: Numeric strength or weight of the relationship
        metadata: JSON metadata for additional relationship attributes
        created_at: Creation timestamp from AuditMixin
        updated_at: Last modification timestamp from AuditMixin
        created_by: User who created the relationship from AuditMixin
        updated_by: User who last modified the relationship from AuditMixin
        
    Relationships:
        source_entity: Many-to-one relationship with BusinessEntity (source)
        target_entity: Many-to-one relationship with BusinessEntity (target)
        
    Database Indexes:
        - Primary key index on id (inherited)
        - Foreign key indexes on source_entity_id and target_entity_id
        - Index on relationship_type for type filtering
        - Index on is_active for status filtering
        - Composite index on (source_entity_id, target_entity_id) for relationship lookups
        - Composite index on (relationship_type, is_active) for type queries
    """
    
    __tablename__ = 'entity_relationships'
    
    # Relationship entity references with cascade deletion
    source_entity_id = Column(
        Integer,
        ForeignKey('business_entities.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    target_entity_id = Column(
        Integer,
        ForeignKey('business_entities.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    
    # Relationship classification and management
    relationship_type = Column(String(100), nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    
    # Relationship strength and metadata
    strength = Column(Integer, default=1, nullable=False)
    bidirectional = Column(Boolean, default=False, nullable=False)
    metadata = Column(Text, nullable=True)  # JSON string for flexible metadata storage
    
    # Relationship lifecycle management
    activated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    deactivated_at = Column(DateTime, nullable=True)
    deactivated_by = Column(String(100), nullable=True)
    
    # Bidirectional relationships using back_populates for efficient navigation
    source_entity = relationship(
        'BusinessEntity',
        foreign_keys=[source_entity_id],
        back_populates='source_relationships',
        lazy='select'
    )
    
    target_entity = relationship(
        'BusinessEntity',
        foreign_keys=[target_entity_id],
        back_populates='target_relationships',
        lazy='select'
    )
    
    # Database constraints and indexes for performance optimization
    __table_args__ = (
        # Composite indexes for efficient relationship queries
        Index('idx_entity_relationships_source_target', 'source_entity_id', 'target_entity_id'),
        Index('idx_entity_relationships_target_source', 'target_entity_id', 'source_entity_id'),
        Index('idx_entity_relationships_type_active', 'relationship_type', 'is_active'),
        Index('idx_entity_relationships_source_type', 'source_entity_id', 'relationship_type'),
        Index('idx_entity_relationships_target_type', 'target_entity_id', 'relationship_type'),
        Index('idx_entity_relationships_strength', 'strength', 'is_active'),
        
        # Business rule constraints
        CheckConstraint(
            'source_entity_id != target_entity_id',
            name='ck_entity_relationship_no_self_reference'
        ),
        CheckConstraint(
            "relationship_type IN ('parent_child', 'dependency', 'association', 'composition', 'aggregation', 'collaboration', 'inheritance', 'realization', 'uses', 'contains', 'owns', 'manages', 'supports', 'references', 'custom')",
            name='ck_entity_relationship_type_valid'
        ),
        CheckConstraint(
            'strength >= 1 AND strength <= 10',
            name='ck_entity_relationship_strength_range'
        ),
        
        # Prevent duplicate active relationships of the same type
        UniqueConstraint(
            'source_entity_id', 'target_entity_id', 'relationship_type',
            name='uq_entity_relationship_unique_active'
        ),
    )
    
    @validates('relationship_type')
    def validate_relationship_type(self, key, relationship_type):
        """
        Validate relationship type classification.
        
        Args:
            key: Field name being validated
            relationship_type: Relationship type to validate
            
        Returns:
            Validated relationship type
            
        Raises:
            ValueError: If relationship type validation fails
        """
        valid_types = [
            'parent_child', 'dependency', 'association', 'composition',
            'aggregation', 'collaboration', 'inheritance', 'realization',
            'uses', 'contains', 'owns', 'manages', 'supports', 'references', 'custom'
        ]
        
        if not relationship_type or relationship_type not in valid_types:
            raise ValueError(f"Relationship type must be one of: {', '.join(valid_types)}")
        
        return relationship_type
    
    @validates('strength')
    def validate_strength(self, key, strength):
        """
        Validate relationship strength range.
        
        Args:
            key: Field name being validated
            strength: Strength value to validate
            
        Returns:
            Validated strength value
            
        Raises:
            ValueError: If strength validation fails
        """
        if strength is None:
            return 1
        
        if not isinstance(strength, int):
            try:
                strength = int(strength)
            except (ValueError, TypeError):
                raise ValueError("Relationship strength must be an integer")
        
        if strength < 1 or strength > 10:
            raise ValueError("Relationship strength must be between 1 and 10")
        
        return strength
    
    def activate(self, activated_by: str = None) -> None:
        """
        Activate the relationship.
        
        Args:
            activated_by: User who activated the relationship
        """
        self.is_active = True
        self.activated_at = datetime.utcnow()
        self.deactivated_at = None
        self.deactivated_by = None
        
        if activated_by:
            self.updated_by = activated_by
    
    def deactivate(self, deactivated_by: str = None, reason: str = None) -> None:
        """
        Deactivate the relationship.
        
        Args:
            deactivated_by: User who deactivated the relationship
            reason: Optional reason for deactivation
        """
        self.is_active = False
        self.deactivated_at = datetime.utcnow()
        self.deactivated_by = deactivated_by or 'system'
        
        if reason:
            metadata = self.get_metadata()
            metadata['deactivation_reason'] = reason
            self.set_metadata(metadata)
        
        if deactivated_by:
            self.updated_by = deactivated_by
    
    def get_reverse_relationship(self) -> Optional['EntityRelationship']:
        """
        Get the reverse relationship if this is bidirectional.
        
        Returns:
            Reverse EntityRelationship if exists, None otherwise
        """
        if not self.bidirectional:
            return None
        
        return EntityRelationship.query.filter(
            EntityRelationship.source_entity_id == self.target_entity_id,
            EntityRelationship.target_entity_id == self.source_entity_id,
            EntityRelationship.relationship_type == self.relationship_type,
            EntityRelationship.is_active == True
        ).first()
    
    def create_reverse_relationship(self) -> Optional['EntityRelationship']:
        """
        Create a reverse relationship if this is bidirectional.
        
        Returns:
            New reverse EntityRelationship if created, None if not bidirectional
        """
        if not self.bidirectional:
            return None
        
        # Check if reverse relationship already exists
        if self.get_reverse_relationship():
            return None
        
        reverse_rel = EntityRelationship(
            source_entity_id=self.target_entity_id,
            target_entity_id=self.source_entity_id,
            relationship_type=self.relationship_type,
            strength=self.strength,
            bidirectional=True,
            is_active=self.is_active,
            metadata=self.metadata
        )
        
        return reverse_rel
    
    def get_other_entity(self, entity: BusinessEntity) -> Optional[BusinessEntity]:
        """
        Get the other entity in this relationship.
        
        Args:
            entity: One entity in the relationship
            
        Returns:
            The other entity, or None if entity is not part of this relationship
        """
        if entity.id == self.source_entity_id:
            return self.target_entity
        elif entity.id == self.target_entity_id:
            return self.source_entity
        else:
            return None
    
    def get_relationship_direction(self, entity: BusinessEntity) -> Optional[str]:
        """
        Get the direction of the relationship relative to the given entity.
        
        Args:
            entity: Entity to determine direction from
            
        Returns:
            'outgoing' if entity is source, 'incoming' if entity is target, None otherwise
        """
        if entity.id == self.source_entity_id:
            return 'outgoing'
        elif entity.id == self.target_entity_id:
            return 'incoming'
        else:
            return None
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get relationship metadata as dictionary.
        
        Returns:
            Dictionary of relationship metadata
        """
        if not self.metadata:
            return {}
        try:
            import json
            return json.loads(self.metadata)
        except (ValueError, TypeError):
            return {}
    
    def set_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        Set relationship metadata from dictionary.
        
        Args:
            metadata: Dictionary of metadata to store
        """
        if metadata:
            import json
            self.metadata = json.dumps(metadata)
        else:
            self.metadata = None
    
    def to_dict(self, include_entities: bool = False) -> Dict[str, Any]:
        """
        Convert entity relationship to dictionary representation.
        
        Args:
            include_entities: Whether to include entity information
            
        Returns:
            Dictionary representation of the entity relationship
        """
        result = {
            'id': self.id,
            'source_entity_id': self.source_entity_id,
            'target_entity_id': self.target_entity_id,
            'relationship_type': self.relationship_type,
            'is_active': self.is_active,
            'strength': self.strength,
            'bidirectional': self.bidirectional,
            'activated_at': self.activated_at.isoformat() if self.activated_at else None,
            'deactivated_at': self.deactivated_at.isoformat() if self.deactivated_at else None,
            'deactivated_by': self.deactivated_by,
            'metadata': self.get_metadata(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by,
            'updated_by': self.updated_by
        }
        
        if include_entities:
            result['source_entity'] = self.source_entity.to_dict() if self.source_entity else None
            result['target_entity'] = self.target_entity.to_dict() if self.target_entity else None
        
        return result
    
    @classmethod
    def get_relationships_for_entity(cls, entity_id: int, relationship_type: str = None,
                                   direction: str = None, include_inactive: bool = False) -> List['EntityRelationship']:
        """
        Get all relationships for a specific entity.
        
        Args:
            entity_id: BusinessEntity ID
            relationship_type: Optional filter by relationship type
            direction: Optional filter by direction ('incoming', 'outgoing', or None for both)
            include_inactive: Whether to include inactive relationships
            
        Returns:
            List of EntityRelationship objects
        """
        filters = []
        
        # Direction filters
        if direction == 'outgoing':
            filters.append(cls.source_entity_id == entity_id)
        elif direction == 'incoming':
            filters.append(cls.target_entity_id == entity_id)
        else:
            filters.append(
                or_(cls.source_entity_id == entity_id, cls.target_entity_id == entity_id)
            )
        
        # Type filter
        if relationship_type:
            filters.append(cls.relationship_type == relationship_type)
        
        # Active status filter
        if not include_inactive:
            filters.append(cls.is_active == True)
        
        return cls.query.filter(*filters).order_by(cls.strength.desc(), cls.created_at.desc()).all()
    
    @classmethod
    def get_relationship_types(cls) -> List[str]:
        """
        Get all available relationship types.
        
        Returns:
            List of valid relationship type strings
        """
        return [
            'parent_child', 'dependency', 'association', 'composition',
            'aggregation', 'collaboration', 'inheritance', 'realization',
            'uses', 'contains', 'owns', 'manages', 'supports', 'references', 'custom'
        ]
    
    def __repr__(self):
        return f"<EntityRelationship {self.source_entity_id}->{self.target_entity_id} ({self.relationship_type}, Active: {self.is_active})>"


# SQLAlchemy event listeners for relationship management
@event.listens_for(EntityRelationship, 'after_insert')
def create_reverse_relationship_handler(mapper, connection, target):
    """
    Automatically create reverse relationship for bidirectional relationships.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: EntityRelationship instance that was inserted
    """
    if target.bidirectional:
        try:
            # Create reverse relationship if it doesn't exist
            reverse_rel = target.create_reverse_relationship()
            if reverse_rel:
                db.session.add(reverse_rel)
                logger.debug(f"Created reverse relationship for bidirectional relationship {target.id}")
        except Exception as e:
            logger.error(f"Failed to create reverse relationship: {e}")


@event.listens_for(BusinessEntity, 'before_delete')
def cleanup_entity_relationships_handler(mapper, connection, target):
    """
    Clean up related EntityRelationship records before deleting BusinessEntity.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: BusinessEntity instance being deleted
    """
    try:
        # Deactivate all relationships before cascade deletion
        for relationship in target.get_all_relationships(include_inactive=True):
            if relationship.is_active:
                relationship.deactivate(deactivated_by='system', reason='Entity deletion')
        
        logger.info(f"Cleaned up relationships for BusinessEntity {target.id} before deletion")
    except Exception as e:
        logger.error(f"Error cleaning up relationships for BusinessEntity {target.id}: {e}")


# Export models for application use
__all__ = [
    'BusinessEntity',
    'EntityRelationship'
]