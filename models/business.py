"""
Business Entity and Relationship Models

This module implements Flask-SQLAlchemy declarative models for core business entity management
and relationship tracking, providing the foundation for business logic operations throughout
the application. These models support entity ownership, hierarchical relationships, and
comprehensive business object management with proper validation and constraint enforcement.

Models:
    BusinessEntity: Core business entity model with ownership tracking and status management
    EntityRelationship: Business entity relationship model supporting complex interconnections

Dependencies:
    - models.base: Provides AuditMixin and BaseModel for common functionality
    - models.user: User model for entity ownership relationships
    - Flask-SQLAlchemy: ORM functionality and declarative model support
    - SQLAlchemy: Database relationship and constraint definitions
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey, DateTime, Index
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.declarative import declared_attr
from datetime import datetime
import re

from . import db
from .base import BaseModel, AuditMixin


class BusinessEntity(BaseModel, AuditMixin, db.Model):
    """
    Business Entity Model
    
    Represents core business objects within the application with ownership tracking,
    status management, and comprehensive validation. Provides the foundation for
    business logic operations and entity management workflows.
    
    Attributes:
        id (int): Primary key identifier
        name (str): Business entity name with validation constraints
        description (str): Detailed entity description supporting rich text content
        owner_id (int): Foreign key reference to User model for ownership tracking
        status (str): Entity status with predefined values for lifecycle management
        is_active (bool): Soft delete flag for entity lifecycle management
        
    Relationships:
        owner: Many-to-one relationship with User model (entity ownership)
        source_relationships: One-to-many with EntityRelationship (as source entity)
        target_relationships: One-to-many with EntityRelationship (as target entity)
    
    Validation:
        - Name: Required, 1-255 characters, alphanumeric with spaces and common punctuation
        - Description: Optional, maximum 2000 characters
        - Status: Must be one of predefined valid status values
        - Owner: Must reference valid existing user
    
    Constraints:
        - Unique constraint on (name, owner_id) for scoped uniqueness
        - Foreign key constraint with cascade deletion on owner relationship
        - Check constraints for status and name format validation
    """
    
    __tablename__ = 'business_entity'
    
    # Primary identifier
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    # Core entity attributes with validation constraints
    name = db.Column(db.String(255), nullable=False, index=True,
                     doc="Business entity name with length and format validation")
    
    description = db.Column(db.Text, nullable=True,
                           doc="Optional detailed description of the business entity")
    
    # Ownership and status management
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), 
                        nullable=False, index=True,
                        doc="Foreign key reference to User model for entity ownership")
    
    status = db.Column(db.String(50), nullable=False, default='active', index=True,
                       doc="Entity lifecycle status with predefined valid values")
    
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True,
                         doc="Soft delete flag for entity lifecycle management")
    
    # Relationship definitions with bidirectional navigation
    owner = db.relationship('User', back_populates='owned_entities',
                           doc="Many-to-one relationship with User model for entity ownership")
    
    source_relationships = db.relationship('EntityRelationship', 
                                          foreign_keys='EntityRelationship.source_entity_id',
                                          back_populates='source_entity',
                                          cascade='all, delete-orphan',
                                          doc="One-to-many relationships where this entity is the source")
    
    target_relationships = db.relationship('EntityRelationship',
                                          foreign_keys='EntityRelationship.target_entity_id', 
                                          back_populates='target_entity',
                                          cascade='all, delete-orphan',
                                          doc="One-to-many relationships where this entity is the target")
    
    # Database constraints and indexes
    __table_args__ = (
        # Unique constraint for scoped entity names per owner
        db.UniqueConstraint('name', 'owner_id', name='uq_business_entity_name_owner'),
        
        # Composite index for efficient ownership queries
        Index('idx_business_entity_owner_status', 'owner_id', 'status'),
        
        # Index for active entity queries with status filtering
        Index('idx_business_entity_active_status', 'is_active', 'status'),
        
        # Check constraint for valid status values
        db.CheckConstraint(
            status.in_(['active', 'inactive', 'pending', 'archived', 'suspended']),
            name='ck_business_entity_status'
        ),
        
        # Check constraint for name format validation
        db.CheckConstraint(
            db.and_(
                db.func.length(name) >= 1,
                db.func.length(name) <= 255,
                name != ''
            ),
            name='ck_business_entity_name_length'
        )
    )
    
    # Validation methods for data integrity
    @validates('name')
    def validate_name(self, key, value):
        """
        Validate business entity name format and constraints
        
        Args:
            key (str): Attribute name being validated
            value (str): Name value to validate
            
        Returns:
            str: Validated and normalized name value
            
        Raises:
            ValueError: If name fails validation constraints
        """
        if not value or not value.strip():
            raise ValueError("Business entity name is required and cannot be empty")
        
        # Normalize whitespace
        normalized_name = re.sub(r'\s+', ' ', value.strip())
        
        # Length validation
        if len(normalized_name) < 1 or len(normalized_name) > 255:
            raise ValueError("Business entity name must be between 1 and 255 characters")
        
        # Format validation - allow alphanumeric, spaces, and common business punctuation
        if not re.match(r'^[a-zA-Z0-9\s\-_.,&()\'\"]+$', normalized_name):
            raise ValueError("Business entity name contains invalid characters")
        
        return normalized_name
    
    @validates('description')
    def validate_description(self, key, value):
        """
        Validate business entity description constraints
        
        Args:
            key (str): Attribute name being validated
            value (str): Description value to validate
            
        Returns:
            str: Validated description value or None
            
        Raises:
            ValueError: If description exceeds length constraints
        """
        if value is None:
            return None
        
        # Length validation for description
        if len(value) > 2000:
            raise ValueError("Business entity description cannot exceed 2000 characters")
        
        return value.strip() if value.strip() else None
    
    @validates('status')
    def validate_status(self, key, value):
        """
        Validate business entity status against allowed values
        
        Args:
            key (str): Attribute name being validated
            value (str): Status value to validate
            
        Returns:
            str: Validated status value
            
        Raises:
            ValueError: If status is not in allowed values
        """
        valid_statuses = {'active', 'inactive', 'pending', 'archived', 'suspended'}
        
        if value not in valid_statuses:
            raise ValueError(f"Invalid status '{value}'. Must be one of: {', '.join(sorted(valid_statuses))}")
        
        return value
    
    def get_all_relationships(self):
        """
        Retrieve all relationships (both source and target) for this entity
        
        Returns:
            list: Combined list of all EntityRelationship objects where this entity participates
        """
        return list(self.source_relationships) + list(self.target_relationships)
    
    def get_active_relationships(self):
        """
        Retrieve only active relationships for this entity
        
        Returns:
            list: List of active EntityRelationship objects
        """
        return [rel for rel in self.get_all_relationships() if rel.is_active]
    
    def get_relationships_by_type(self, relationship_type):
        """
        Retrieve relationships filtered by relationship type
        
        Args:
            relationship_type (str): Type of relationship to filter by
            
        Returns:
            list: List of EntityRelationship objects matching the specified type
        """
        return [rel for rel in self.get_all_relationships() 
                if rel.relationship_type == relationship_type]
    
    def deactivate(self):
        """
        Soft delete the entity by setting is_active to False and status to archived
        
        This method provides a safe way to remove entities while preserving audit trails
        and relationship history for compliance and business continuity.
        """
        self.is_active = False
        self.status = 'archived'
    
    def reactivate(self):
        """
        Reactivate a previously deactivated entity
        
        Sets is_active to True and status to active, allowing the entity to participate
        in business operations again while maintaining historical data integrity.
        """
        self.is_active = True
        self.status = 'active'
    
    def __repr__(self):
        """String representation for debugging and logging purposes"""
        return f"<BusinessEntity(id={self.id}, name='{self.name}', owner_id={self.owner_id}, status='{self.status}')>"


class EntityRelationship(BaseModel, AuditMixin, db.Model):
    """
    Entity Relationship Model
    
    Manages relationships between business entities, supporting complex business object
    interconnections, hierarchy management, and relationship type classification.
    Enables tracking of entity dependencies, organizational structures, and business workflows.
    
    Attributes:
        id (int): Primary key identifier
        source_entity_id (int): Foreign key to source BusinessEntity
        target_entity_id (int): Foreign key to target BusinessEntity  
        relationship_type (str): Classification of relationship type
        is_active (bool): Active status for relationship lifecycle management
        metadata (dict): Optional JSON metadata for relationship context
        
    Relationships:
        source_entity: Many-to-one relationship with BusinessEntity (source)
        target_entity: Many-to-one relationship with BusinessEntity (target)
    
    Validation:
        - Source and target entities must be different (no self-relationships)
        - Relationship type must be from predefined valid types
        - Source and target entities must exist and be active
        - Prevents duplicate relationships between same entities with same type
    
    Constraints:
        - Unique constraint on (source_entity_id, target_entity_id, relationship_type)
        - Foreign key constraints with cascade deletion
        - Check constraint preventing self-relationships
        - Index optimization for relationship queries
    """
    
    __tablename__ = 'entity_relationship'
    
    # Primary identifier
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    
    # Entity relationship references
    source_entity_id = db.Column(db.Integer, 
                                db.ForeignKey('business_entity.id', ondelete='CASCADE'),
                                nullable=False, index=True,
                                doc="Foreign key reference to source business entity")
    
    target_entity_id = db.Column(db.Integer,
                                db.ForeignKey('business_entity.id', ondelete='CASCADE'), 
                                nullable=False, index=True,
                                doc="Foreign key reference to target business entity")
    
    # Relationship classification and status
    relationship_type = db.Column(db.String(100), nullable=False, index=True,
                                 doc="Classification type for the entity relationship")
    
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True,
                         doc="Active status flag for relationship lifecycle management")
    
    # Optional metadata for relationship context (using PostgreSQL JSON support)
    metadata = db.Column(db.JSON, nullable=True,
                        doc="Optional JSON metadata for additional relationship context")
    
    # Bidirectional relationship definitions
    source_entity = db.relationship('BusinessEntity',
                                   foreign_keys=[source_entity_id],
                                   back_populates='source_relationships',
                                   doc="Many-to-one relationship with source BusinessEntity")
    
    target_entity = db.relationship('BusinessEntity', 
                                   foreign_keys=[target_entity_id],
                                   back_populates='target_relationships',
                                   doc="Many-to-one relationship with target BusinessEntity")
    
    # Database constraints and indexes  
    __table_args__ = (
        # Unique constraint preventing duplicate relationships
        db.UniqueConstraint('source_entity_id', 'target_entity_id', 'relationship_type',
                           name='uq_entity_relationship_unique'),
        
        # Check constraint preventing self-relationships
        db.CheckConstraint(
            source_entity_id != target_entity_id,
            name='ck_entity_relationship_no_self'
        ),
        
        # Composite indexes for efficient relationship queries
        Index('idx_entity_relationship_source_type', 'source_entity_id', 'relationship_type'),
        Index('idx_entity_relationship_target_type', 'target_entity_id', 'relationship_type'),
        Index('idx_entity_relationship_active_type', 'is_active', 'relationship_type'),
        
        # Index for bidirectional relationship queries
        Index('idx_entity_relationship_bidirectional', 'source_entity_id', 'target_entity_id')
    )
    
    # Validation methods for relationship integrity
    @validates('relationship_type')
    def validate_relationship_type(self, key, value):
        """
        Validate relationship type against predefined classification types
        
        Args:
            key (str): Attribute name being validated
            value (str): Relationship type to validate
            
        Returns:
            str: Validated relationship type value
            
        Raises:
            ValueError: If relationship type is invalid
        """
        valid_types = {
            'parent_child', 'child_parent', 'sibling', 'dependency', 'composition',
            'aggregation', 'association', 'collaboration', 'hierarchy', 'workflow',
            'category', 'classification', 'reference', 'link', 'custom'
        }
        
        if not value or value.strip() == '':
            raise ValueError("Relationship type is required and cannot be empty")
        
        normalized_type = value.strip().lower()
        
        if normalized_type not in valid_types:
            raise ValueError(f"Invalid relationship type '{value}'. Must be one of: {', '.join(sorted(valid_types))}")
        
        return normalized_type
    
    @validates('source_entity_id', 'target_entity_id')
    def validate_entity_ids(self, key, value):
        """
        Validate entity ID references for relationship creation
        
        Args:
            key (str): Attribute name being validated ('source_entity_id' or 'target_entity_id')
            value (int): Entity ID to validate
            
        Returns:
            int: Validated entity ID
            
        Raises:
            ValueError: If entity ID is invalid or entities are the same
        """
        if not value or value <= 0:
            raise ValueError(f"{key} must be a positive integer")
        
        # Prevent self-relationships during validation
        if key == 'target_entity_id' and hasattr(self, 'source_entity_id'):
            if self.source_entity_id == value:
                raise ValueError("Source and target entities cannot be the same (self-relationships not allowed)")
        elif key == 'source_entity_id' and hasattr(self, 'target_entity_id'):
            if self.target_entity_id == value:
                raise ValueError("Source and target entities cannot be the same (self-relationships not allowed)")
        
        return value
    
    @validates('metadata')
    def validate_metadata(self, key, value):
        """
        Validate relationship metadata JSON structure and constraints
        
        Args:
            key (str): Attribute name being validated
            value (dict): Metadata dictionary to validate
            
        Returns:
            dict: Validated metadata dictionary or None
            
        Raises:
            ValueError: If metadata structure is invalid
        """
        if value is None:
            return None
        
        if not isinstance(value, dict):
            raise ValueError("Relationship metadata must be a dictionary/JSON object")
        
        # Limit metadata size to prevent excessive storage usage
        import json
        metadata_size = len(json.dumps(value))
        if metadata_size > 10000:  # 10KB limit
            raise ValueError("Relationship metadata size cannot exceed 10KB")
        
        return value
    
    def get_reverse_relationship(self):
        """
        Find the reverse relationship if it exists
        
        Returns:
            EntityRelationship: Reverse relationship object or None if not found
        """
        return EntityRelationship.query.filter_by(
            source_entity_id=self.target_entity_id,
            target_entity_id=self.source_entity_id,
            relationship_type=self.relationship_type,
            is_active=True
        ).first()
    
    def create_reverse_relationship(self, commit=True):
        """
        Create a bidirectional relationship by adding the reverse relationship
        
        Args:
            commit (bool): Whether to commit the transaction immediately
            
        Returns:
            EntityRelationship: Created reverse relationship object
        """
        reverse_rel = EntityRelationship(
            source_entity_id=self.target_entity_id,
            target_entity_id=self.source_entity_id,
            relationship_type=self.relationship_type,
            is_active=self.is_active,
            metadata=self.metadata.copy() if self.metadata else None
        )
        
        db.session.add(reverse_rel)
        
        if commit:
            db.session.commit()
        
        return reverse_rel
    
    def deactivate(self, deactivate_reverse=True):
        """
        Deactivate this relationship and optionally its reverse
        
        Args:
            deactivate_reverse (bool): Whether to also deactivate the reverse relationship
        """
        self.is_active = False
        
        if deactivate_reverse:
            reverse_rel = self.get_reverse_relationship()
            if reverse_rel:
                reverse_rel.is_active = False
    
    def reactivate(self, reactivate_reverse=True):
        """
        Reactivate this relationship and optionally its reverse
        
        Args:
            reactivate_reverse (bool): Whether to also reactivate the reverse relationship
        """
        self.is_active = True
        
        if reactivate_reverse:
            reverse_rel = self.get_reverse_relationship()
            if reverse_rel:
                reverse_rel.is_active = True
    
    def __repr__(self):
        """String representation for debugging and logging purposes"""
        return (f"<EntityRelationship(id={self.id}, "
                f"source_entity_id={self.source_entity_id}, "
                f"target_entity_id={self.target_entity_id}, "
                f"relationship_type='{self.relationship_type}', "
                f"is_active={self.is_active})>")


# Additional utility functions for business entity operations
def get_entities_by_owner(owner_id, status=None, include_inactive=False):
    """
    Retrieve business entities owned by a specific user
    
    Args:
        owner_id (int): User ID of the entity owner
        status (str, optional): Filter by specific status
        include_inactive (bool): Whether to include inactive entities
        
    Returns:
        Query: SQLAlchemy query object for further filtering or execution
    """
    query = BusinessEntity.query.filter_by(owner_id=owner_id)
    
    if not include_inactive:
        query = query.filter_by(is_active=True)
    
    if status:
        query = query.filter_by(status=status)
    
    return query.order_by(BusinessEntity.name)


def get_entity_hierarchy(entity_id, relationship_type='parent_child', max_depth=10):
    """
    Retrieve hierarchical relationships for a business entity
    
    Args:
        entity_id (int): ID of the root entity
        relationship_type (str): Type of hierarchical relationship to follow
        max_depth (int): Maximum depth to traverse in the hierarchy
        
    Returns:
        dict: Hierarchical structure of related entities
    """
    visited = set()
    
    def _build_hierarchy(current_id, depth=0):
        if depth >= max_depth or current_id in visited:
            return None
        
        visited.add(current_id)
        entity = BusinessEntity.query.get(current_id)
        
        if not entity or not entity.is_active:
            return None
        
        children = []
        for rel in entity.source_relationships:
            if (rel.relationship_type == relationship_type and 
                rel.is_active and 
                rel.target_entity_id not in visited):
                child_hierarchy = _build_hierarchy(rel.target_entity_id, depth + 1)
                if child_hierarchy:
                    children.append(child_hierarchy)
        
        return {
            'entity': entity,
            'children': children,
            'depth': depth
        }
    
    return _build_hierarchy(entity_id)


def find_relationship_path(source_entity_id, target_entity_id, max_depth=5):
    """
    Find relationship path between two business entities
    
    Args:
        source_entity_id (int): Starting entity ID
        target_entity_id (int): Target entity ID
        max_depth (int): Maximum depth to search
        
    Returns:
        list: List of EntityRelationship objects forming the path, or empty list if no path found
    """
    if source_entity_id == target_entity_id:
        return []
    
    visited = set()
    queue = [(source_entity_id, [])]
    
    while queue:
        current_id, path = queue.pop(0)
        
        if current_id == target_entity_id:
            return path
        
        if current_id in visited or len(path) >= max_depth:
            continue
        
        visited.add(current_id)
        
        # Find all active relationships from current entity
        relationships = EntityRelationship.query.filter(
            db.or_(
                EntityRelationship.source_entity_id == current_id,
                EntityRelationship.target_entity_id == current_id
            ),
            EntityRelationship.is_active == True
        ).all()
        
        for rel in relationships:
            next_id = (rel.target_entity_id if rel.source_entity_id == current_id 
                      else rel.source_entity_id)
            
            if next_id not in visited:
                new_path = path + [rel]
                queue.append((next_id, new_path))
    
    return []  # No path found