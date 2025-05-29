"""
Business Entity Service Implementation

This module implements the Business Entity Service orchestrating complex business entity
workflows including entity creation, relationship management, lifecycle operations,
and cross-entity business rules. This service implements the core business domain logic
with comprehensive entity relationship coordination while preserving all original
Node.js business logic patterns through the Service Layer pattern.

Key Features:
- Business entity workflow orchestration per Section 5.2.3 Service Layer requirements
- Entity relationship management with complex business logic coordination
- Service Layer pattern implementation for business workflow orchestration
- Entity lifecycle management with comprehensive validation rules
- Cross-entity business rule coordination maintaining functional equivalence
- Transaction boundary management with Flask-SQLAlchemy integration
- Python 3.13.3 business logic implementation preserving Node.js patterns

Migration Context:
- Converted Node.js business entity logic to Python Service Layer pattern per Feature F-005
- Implements comprehensive business workflow orchestration per Section 4.5.3
- Maintains functional equivalence with original Node.js business rules
- Provides Service Layer abstraction for business logic per Feature F-006

Dependencies:
- Flask-SQLAlchemy 3.1.1 for database operations and transaction management
- Python 3.13.3 for modern type hints and dataclass integration
- BaseService for Service Layer pattern implementation
- BusinessEntity and EntityRelationship models for data persistence
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from enum import Enum

from flask import current_app, g
from flask_sqlalchemy import SQLAlchemy
from injector import inject, singleton
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import joinedload, selectinload

from .base import BaseService, ServiceError, ValidationError, TransactionError, retry_on_failure


# Type definitions for business entity operations
EntityID = int
RelationshipID = int
UserID = int


class EntityStatus(str, Enum):
    """
    Business entity status enumeration for workflow management.
    
    Provides consistent status values for entity lifecycle management
    with clear business meaning and workflow progression patterns.
    """
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    ARCHIVED = "archived"
    DELETED = "deleted"


class RelationshipType(str, Enum):
    """
    Business entity relationship type enumeration.
    
    Defines standardized relationship types for complex business
    entity associations and workflow coordination.
    """
    OWNS = "owns"
    DEPENDS_ON = "depends_on"
    CONTAINS = "contains"
    RELATES_TO = "relates_to"
    REPLACES = "replaces"
    REFERENCES = "references"
    MANAGES = "manages"
    COLLABORATES_WITH = "collaborates_with"


@dataclass
class EntityCreationRequest:
    """
    Data class for entity creation requests with comprehensive validation.
    
    Implements Python dataclass pattern for structured data handling
    as specified in Section 4.5.1 for robust data validation and type safety.
    """
    name: str
    description: Optional[str] = None
    owner_id: Optional[int] = None
    status: EntityStatus = EntityStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate entity creation request data after initialization."""
        if not self.name or not self.name.strip():
            raise ValidationError("Entity name is required and cannot be empty")
        
        if len(self.name.strip()) > 255:
            raise ValidationError("Entity name cannot exceed 255 characters")
        
        self.name = self.name.strip()
        
        if self.description and len(self.description) > 5000:
            raise ValidationError("Entity description cannot exceed 5000 characters")


@dataclass
class EntityUpdateRequest:
    """
    Data class for entity update requests with validation support.
    
    Provides structured data representation for entity modification
    operations with automatic validation and type safety.
    """
    entity_id: int
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[EntityStatus] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Validate entity update request data after initialization."""
        if self.entity_id <= 0:
            raise ValidationError("Invalid entity ID provided")
        
        if self.name is not None:
            if not self.name.strip():
                raise ValidationError("Entity name cannot be empty")
            if len(self.name.strip()) > 255:
                raise ValidationError("Entity name cannot exceed 255 characters")
            self.name = self.name.strip()
        
        if self.description is not None and len(self.description) > 5000:
            raise ValidationError("Entity description cannot exceed 5000 characters")


@dataclass
class RelationshipCreationRequest:
    """
    Data class for entity relationship creation requests.
    
    Implements structured relationship data handling with validation
    for complex business entity associations.
    """
    source_entity_id: int
    target_entity_id: int
    relationship_type: RelationshipType
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate relationship creation request data after initialization."""
        if self.source_entity_id <= 0 or self.target_entity_id <= 0:
            raise ValidationError("Invalid entity IDs provided for relationship")
        
        if self.source_entity_id == self.target_entity_id:
            raise ValidationError("Self-relationships are not permitted")
        
        if not isinstance(self.relationship_type, RelationshipType):
            raise ValidationError("Invalid relationship type provided")


@dataclass
class BusinessWorkflowResult:
    """
    Data class for business workflow operation results.
    
    Provides structured result reporting for complex business operations
    with success status, data payload, and metadata tracking.
    """
    success: bool
    entity_id: Optional[int] = None
    relationship_id: Optional[int] = None
    data: Optional[Dict[str, Any]] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_error(self, error: str) -> None:
        """Add error message to result."""
        self.errors.append(error)
        self.success = False
    
    def add_warning(self, warning: str) -> None:
        """Add warning message to result."""
        self.warnings.append(warning)


@singleton
class BusinessEntityService(BaseService):
    """
    Business Entity Service orchestrating complex business entity workflows.
    
    This service implements the core business domain logic with comprehensive
    entity relationship coordination while preserving all original Node.js
    business logic patterns through the Service Layer pattern as specified
    in Section 5.2.3.
    
    Key Responsibilities:
    - Entity creation, modification, and lifecycle management
    - Complex entity relationship management and coordination
    - Business rule enforcement and validation
    - Cross-entity business logic coordination
    - Transaction boundary management for complex operations
    - Service composition for workflow orchestration
    - Comprehensive error handling and retry mechanisms
    
    Business Logic Preservation:
    - Maintains functional equivalence with original Node.js implementation
    - Preserves all existing business rules and validation patterns
    - Implements identical workflow sequences and decision logic
    - Supports all original API contracts and data formats
    
    Service Layer Architecture:
    - Clean separation of business logic from presentation layer
    - Dependency injection support through Flask-Injector
    - Service composition patterns for complex operations
    - Transaction management with Flask-SQLAlchemy integration
    """
    
    @inject
    def __init__(self, db: SQLAlchemy):
        """
        Initialize Business Entity Service with database dependency.
        
        Args:
            db: Flask-SQLAlchemy database instance for transaction management
        """
        super().__init__(db)
        
        # Import models after initialization to avoid circular imports
        self._import_models()
        
        # Business rule configuration
        self._max_relationships_per_entity = 1000
        self._max_relationship_depth = 10
        self._allowed_status_transitions = self._build_status_transition_matrix()
        
        self.logger.info("BusinessEntityService initialized successfully")
    
    def _import_models(self) -> None:
        """Import model classes to avoid circular import issues."""
        try:
            from ..models.business_entity import BusinessEntity
            from ..models.entity_relationship import EntityRelationship
            from ..models.user import User
            
            self.BusinessEntity = BusinessEntity
            self.EntityRelationship = EntityRelationship
            self.User = User
            
        except ImportError as e:
            self.logger.error(f"Failed to import required models: {e}")
            raise ServiceError("Required models not available", original_error=e)
    
    def _build_status_transition_matrix(self) -> Dict[EntityStatus, Set[EntityStatus]]:
        """
        Build valid status transition matrix for business rules enforcement.
        
        Returns:
            Dict mapping current status to allowed next statuses
        """
        return {
            EntityStatus.PENDING: {EntityStatus.ACTIVE, EntityStatus.INACTIVE, EntityStatus.DELETED},
            EntityStatus.ACTIVE: {EntityStatus.INACTIVE, EntityStatus.ARCHIVED, EntityStatus.DELETED},
            EntityStatus.INACTIVE: {EntityStatus.ACTIVE, EntityStatus.ARCHIVED, EntityStatus.DELETED},
            EntityStatus.ARCHIVED: {EntityStatus.ACTIVE, EntityStatus.DELETED},
            EntityStatus.DELETED: set()  # No transitions allowed from deleted state
        }
    
    def validate_business_rules(self, data: Dict[str, Any]) -> bool:
        """
        Validate business rules for entity operations.
        
        Implements comprehensive business rule validation maintaining
        functional equivalence with original Node.js validation patterns.
        
        Args:
            data: Operation data to validate
        
        Returns:
            True if validation passes
        
        Raises:
            ValidationError: When business rules are violated
        """
        if not isinstance(data, dict):
            raise ValidationError("Validation data must be a dictionary")
        
        # Validate entity naming conventions
        if "name" in data:
            name = data["name"]
            if not name or not isinstance(name, str) or not name.strip():
                raise ValidationError("Entity name is required and must be non-empty")
            
            # Business rule: entity names must be unique within owner scope
            if "owner_id" in data and "entity_id" not in data:
                existing_entity = self._check_entity_name_uniqueness(name.strip(), data["owner_id"])
                if existing_entity:
                    raise ValidationError(f"Entity name '{name}' already exists for this owner")
        
        # Validate status transitions
        if "status" in data and "current_status" in data:
            if not self._validate_status_transition(data["current_status"], data["status"]):
                raise ValidationError(
                    f"Invalid status transition from {data['current_status']} to {data['status']}"
                )
        
        # Validate relationship constraints
        if "relationship_type" in data:
            if not self._validate_relationship_type(data["relationship_type"]):
                raise ValidationError(f"Invalid relationship type: {data['relationship_type']}")
        
        return True
    
    def _check_entity_name_uniqueness(self, name: str, owner_id: int) -> Optional[object]:
        """Check if entity name already exists for the given owner."""
        try:
            return self.session.query(self.BusinessEntity).filter(
                self.BusinessEntity.name == name,
                self.BusinessEntity.owner_id == owner_id,
                self.BusinessEntity.status != EntityStatus.DELETED
            ).first()
        except SQLAlchemyError as e:
            self.logger.warning(f"Error checking name uniqueness: {e}")
            return None
    
    def _validate_status_transition(self, current_status: str, new_status: str) -> bool:
        """Validate if status transition is allowed by business rules."""
        try:
            current = EntityStatus(current_status)
            new = EntityStatus(new_status)
            return new in self._allowed_status_transitions.get(current, set())
        except ValueError:
            return False
    
    def _validate_relationship_type(self, relationship_type: str) -> bool:
        """Validate if relationship type is allowed by business rules."""
        try:
            RelationshipType(relationship_type)
            return True
        except ValueError:
            return False
    
    # Core Entity Management Operations
    
    @retry_on_failure(max_retries=3)
    def create_entity(self, request: EntityCreationRequest) -> BusinessWorkflowResult:
        """
        Create a new business entity with comprehensive validation and transaction management.
        
        Implements business entity creation workflow orchestration per Section 5.2.3
        with complete business rule enforcement and error handling.
        
        Args:
            request: EntityCreationRequest with validated entity data
        
        Returns:
            BusinessWorkflowResult with creation status and entity details
        
        Raises:
            ValidationError: When business rules are violated
            TransactionError: When database operations fail
        """
        result = BusinessWorkflowResult(success=False)
        
        try:
            # Resolve owner ID if not provided
            if request.owner_id is None:
                request.owner_id = self.get_current_user_id()
                if request.owner_id is None:
                    result.add_error("Owner ID is required for entity creation")
                    return result
            
            # Validate business rules
            validation_data = {
                "name": request.name,
                "owner_id": request.owner_id,
                "status": request.status
            }
            self.validate_business_rules(validation_data)
            
            # Verify owner exists
            owner = self.session.query(self.User).filter(
                self.User.id == request.owner_id,
                self.User.is_active == True
            ).first()
            
            if not owner:
                result.add_error(f"Owner with ID {request.owner_id} not found or inactive")
                return result
            
            with self.transaction_boundary():
                # Create entity instance
                entity = self.BusinessEntity(
                    name=request.name,
                    description=request.description,
                    owner_id=request.owner_id,
                    status=request.status.value,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
                
                self.session.add(entity)
                self.session.flush()  # Get entity ID without committing
                
                result.success = True
                result.entity_id = entity.id
                result.data = {
                    "entity": entity.to_dict(),
                    "owner": {"id": owner.id, "username": owner.username}
                }
                
                self.log_service_operation(
                    f"Created entity '{request.name}' with ID {entity.id}",
                    {"entity_id": entity.id, "owner_id": request.owner_id}
                )
        
        except IntegrityError as e:
            self.handle_integrity_error(e, "entity creation")
            result.add_error("Entity creation failed due to data integrity constraints")
            
        except ValidationError as e:
            result.add_error(str(e))
            
        except Exception as e:
            self.logger.error(f"Unexpected error in entity creation: {e}", exc_info=True)
            result.add_error("Entity creation failed due to unexpected error")
        
        return result
    
    @retry_on_failure(max_retries=3)
    def update_entity(self, request: EntityUpdateRequest) -> BusinessWorkflowResult:
        """
        Update existing business entity with validation and transaction management.
        
        Implements entity modification workflow with business rule enforcement
        and comprehensive validation per Section 4.12.1.
        
        Args:
            request: EntityUpdateRequest with validated update data
        
        Returns:
            BusinessWorkflowResult with update status and entity details
        """
        result = BusinessWorkflowResult(success=False)
        
        try:
            # Retrieve existing entity
            entity = self.session.query(self.BusinessEntity).filter(
                self.BusinessEntity.id == request.entity_id,
                self.BusinessEntity.status != EntityStatus.DELETED
            ).first()
            
            if not entity:
                result.add_error(f"Entity with ID {request.entity_id} not found")
                return result
            
            # Check ownership permissions
            current_user_id = self.get_current_user_id()
            if current_user_id and entity.owner_id != current_user_id:
                result.add_error("Insufficient permissions to update entity")
                return result
            
            # Validate business rules for updates
            validation_data = {"entity_id": request.entity_id}
            
            if request.name is not None:
                validation_data.update({"name": request.name, "owner_id": entity.owner_id})
            
            if request.status is not None:
                validation_data.update({
                    "status": request.status.value,
                    "current_status": entity.status
                })
            
            self.validate_business_rules(validation_data)
            
            with self.transaction_boundary():
                # Apply updates
                if request.name is not None:
                    entity.name = request.name
                
                if request.description is not None:
                    entity.description = request.description
                
                if request.status is not None:
                    entity.status = request.status.value
                
                entity.updated_at = datetime.now(timezone.utc)
                
                result.success = True
                result.entity_id = entity.id
                result.data = {"entity": entity.to_dict()}
                
                self.log_service_operation(
                    f"Updated entity with ID {entity.id}",
                    {"entity_id": entity.id, "updates": len([x for x in [request.name, request.description, request.status] if x is not None])}
                )
        
        except IntegrityError as e:
            self.handle_integrity_error(e, "entity update")
            result.add_error("Entity update failed due to data integrity constraints")
            
        except ValidationError as e:
            result.add_error(str(e))
            
        except Exception as e:
            self.logger.error(f"Unexpected error in entity update: {e}", exc_info=True)
            result.add_error("Entity update failed due to unexpected error")
        
        return result
    
    def get_entity_by_id(self, entity_id: int, include_relationships: bool = False) -> Optional[Dict[str, Any]]:
        """
        Retrieve business entity by ID with optional relationship data.
        
        Implements entity retrieval with comprehensive data loading
        and relationship mapping per Section 6.2.2.1.
        
        Args:
            entity_id: Entity identifier
            include_relationships: Whether to include relationship data
        
        Returns:
            Entity data dictionary or None if not found
        """
        try:
            query = self.session.query(self.BusinessEntity).filter(
                self.BusinessEntity.id == entity_id,
                self.BusinessEntity.status != EntityStatus.DELETED
            )
            
            if include_relationships:
                query = query.options(
                    selectinload(self.BusinessEntity.source_relationships),
                    selectinload(self.BusinessEntity.target_relationships),
                    joinedload(self.BusinessEntity.owner)
                )
            
            entity = query.first()
            
            if not entity:
                return None
            
            entity_data = entity.to_dict()
            
            if include_relationships:
                entity_data["relationships"] = self._build_relationship_data(entity)
                if entity.owner:
                    entity_data["owner"] = {
                        "id": entity.owner.id,
                        "username": entity.owner.username
                    }
            
            return entity_data
        
        except SQLAlchemyError as e:
            self.logger.error(f"Error retrieving entity {entity_id}: {e}")
            return None
    
    def _build_relationship_data(self, entity) -> Dict[str, List[Dict[str, Any]]]:
        """Build comprehensive relationship data for entity."""
        relationship_data = {
            "source_relationships": [],
            "target_relationships": [],
            "bidirectional_summary": {}
        }
        
        # Process source relationships
        for rel in entity.source_relationships.filter_by(is_active=True):
            relationship_data["source_relationships"].append({
                "id": rel.id,
                "target_entity_id": rel.target_entity_id,
                "relationship_type": rel.relationship_type,
                "created_at": rel.created_at.isoformat() if rel.created_at else None
            })
        
        # Process target relationships
        for rel in entity.target_relationships.filter_by(is_active=True):
            relationship_data["target_relationships"].append({
                "id": rel.id,
                "source_entity_id": rel.source_entity_id,
                "relationship_type": rel.relationship_type,
                "created_at": rel.created_at.isoformat() if rel.created_at else None
            })
        
        # Build relationship type summary
        all_types = set()
        for rel in relationship_data["source_relationships"]:
            all_types.add(rel["relationship_type"])
        for rel in relationship_data["target_relationships"]:
            all_types.add(rel["relationship_type"])
        
        for rel_type in all_types:
            source_count = len([r for r in relationship_data["source_relationships"] if r["relationship_type"] == rel_type])
            target_count = len([r for r in relationship_data["target_relationships"] if r["relationship_type"] == rel_type])
            relationship_data["bidirectional_summary"][rel_type] = {
                "as_source": source_count,
                "as_target": target_count,
                "total": source_count + target_count
            }
        
        return relationship_data
    
    def list_entities(self, owner_id: Optional[int] = None, status: Optional[EntityStatus] = None,
                     limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """
        List business entities with filtering and pagination.
        
        Implements entity listing with comprehensive filtering options
        and performance optimization through pagination.
        
        Args:
            owner_id: Optional owner filter
            status: Optional status filter
            limit: Maximum number of entities to return (default: 100)
            offset: Number of entities to skip (default: 0)
        
        Returns:
            Dictionary with entities list and pagination metadata
        """
        try:
            query = self.session.query(self.BusinessEntity).filter(
                self.BusinessEntity.status != EntityStatus.DELETED
            )
            
            # Apply filters
            if owner_id is not None:
                query = query.filter(self.BusinessEntity.owner_id == owner_id)
            
            if status is not None:
                query = query.filter(self.BusinessEntity.status == status.value)
            
            # Get total count for pagination
            total_count = query.count()
            
            # Apply pagination and ordering
            entities = query.order_by(
                self.BusinessEntity.updated_at.desc()
            ).offset(offset).limit(limit).all()
            
            # Convert to dictionaries
            entity_list = [entity.to_dict() for entity in entities]
            
            return {
                "entities": entity_list,
                "pagination": {
                    "total": total_count,
                    "limit": limit,
                    "offset": offset,
                    "has_more": (offset + limit) < total_count
                }
            }
        
        except SQLAlchemyError as e:
            self.logger.error(f"Error listing entities: {e}")
            return {"entities": [], "pagination": {"total": 0, "limit": limit, "offset": offset, "has_more": False}}
    
    # Entity Relationship Management Operations
    
    @retry_on_failure(max_retries=3)
    def create_relationship(self, request: RelationshipCreationRequest) -> BusinessWorkflowResult:
        """
        Create entity relationship with comprehensive validation and business rule enforcement.
        
        Implements complex entity relationship creation per Section 6.2.2.1
        with transaction management and business logic coordination.
        
        Args:
            request: RelationshipCreationRequest with validated relationship data
        
        Returns:
            BusinessWorkflowResult with creation status and relationship details
        """
        result = BusinessWorkflowResult(success=False)
        
        try:
            # Validate entities exist and are accessible
            source_entity = self.session.query(self.BusinessEntity).filter(
                self.BusinessEntity.id == request.source_entity_id,
                self.BusinessEntity.status != EntityStatus.DELETED
            ).first()
            
            target_entity = self.session.query(self.BusinessEntity).filter(
                self.BusinessEntity.id == request.target_entity_id,
                self.BusinessEntity.status != EntityStatus.DELETED
            ).first()
            
            if not source_entity:
                result.add_error(f"Source entity with ID {request.source_entity_id} not found")
                return result
            
            if not target_entity:
                result.add_error(f"Target entity with ID {request.target_entity_id} not found")
                return result
            
            # Check permissions
            current_user_id = self.get_current_user_id()
            if current_user_id:
                if (source_entity.owner_id != current_user_id and 
                    target_entity.owner_id != current_user_id):
                    result.add_error("Insufficient permissions to create relationship")
                    return result
            
            # Validate business rules
            validation_data = {
                "relationship_type": request.relationship_type.value,
                "source_entity_id": request.source_entity_id,
                "target_entity_id": request.target_entity_id
            }
            self.validate_business_rules(validation_data)
            
            # Check for relationship limit
            if not self._check_relationship_limits(request.source_entity_id):
                result.add_error("Maximum number of relationships exceeded for source entity")
                return result
            
            # Check for duplicate relationships
            existing_rel = self.session.query(self.EntityRelationship).filter(
                self.EntityRelationship.source_entity_id == request.source_entity_id,
                self.EntityRelationship.target_entity_id == request.target_entity_id,
                self.EntityRelationship.relationship_type == request.relationship_type.value,
                self.EntityRelationship.is_active == True
            ).first()
            
            if existing_rel:
                result.add_error("Relationship already exists between these entities")
                return result
            
            with self.transaction_boundary():
                # Create relationship instance
                relationship = self.EntityRelationship(
                    source_entity_id=request.source_entity_id,
                    target_entity_id=request.target_entity_id,
                    relationship_type=request.relationship_type.value,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
                
                self.session.add(relationship)
                self.session.flush()  # Get relationship ID without committing
                
                result.success = True
                result.relationship_id = relationship.id
                result.data = {
                    "relationship": relationship.to_dict(),
                    "source_entity": source_entity.to_dict(),
                    "target_entity": target_entity.to_dict()
                }
                
                self.log_service_operation(
                    f"Created {request.relationship_type.value} relationship between entities {request.source_entity_id} and {request.target_entity_id}",
                    {"relationship_id": relationship.id, "type": request.relationship_type.value}
                )
        
        except IntegrityError as e:
            self.handle_integrity_error(e, "relationship creation")
            result.add_error("Relationship creation failed due to data integrity constraints")
            
        except ValidationError as e:
            result.add_error(str(e))
            
        except Exception as e:
            self.logger.error(f"Unexpected error in relationship creation: {e}", exc_info=True)
            result.add_error("Relationship creation failed due to unexpected error")
        
        return result
    
    def _check_relationship_limits(self, entity_id: int) -> bool:
        """Check if entity has reached maximum relationship limit."""
        try:
            relationship_count = self.session.query(self.EntityRelationship).filter(
                (self.EntityRelationship.source_entity_id == entity_id) |
                (self.EntityRelationship.target_entity_id == entity_id),
                self.EntityRelationship.is_active == True
            ).count()
            
            return relationship_count < self._max_relationships_per_entity
        
        except SQLAlchemyError as e:
            self.logger.warning(f"Error checking relationship limits: {e}")
            return True  # Allow operation if check fails
    
    def remove_relationship(self, relationship_id: int, soft_delete: bool = True) -> BusinessWorkflowResult:
        """
        Remove entity relationship with soft or hard deletion support.
        
        Implements relationship removal with configurable deletion strategy
        and comprehensive validation per business rules.
        
        Args:
            relationship_id: Relationship identifier
            soft_delete: Whether to soft delete (default) or hard delete
        
        Returns:
            BusinessWorkflowResult with removal status
        """
        result = BusinessWorkflowResult(success=False)
        
        try:
            relationship = self.session.query(self.EntityRelationship).filter(
                self.EntityRelationship.id == relationship_id,
                self.EntityRelationship.is_active == True
            ).first()
            
            if not relationship:
                result.add_error(f"Relationship with ID {relationship_id} not found")
                return result
            
            # Check permissions
            current_user_id = self.get_current_user_id()
            if current_user_id:
                source_entity = self.session.query(self.BusinessEntity).get(relationship.source_entity_id)
                target_entity = self.session.query(self.BusinessEntity).get(relationship.target_entity_id)
                
                if (source_entity.owner_id != current_user_id and 
                    target_entity.owner_id != current_user_id):
                    result.add_error("Insufficient permissions to remove relationship")
                    return result
            
            with self.transaction_boundary():
                if soft_delete:
                    relationship.is_active = False
                    relationship.updated_at = datetime.now(timezone.utc)
                    action = "deactivated"
                else:
                    self.session.delete(relationship)
                    action = "deleted"
                
                result.success = True
                result.relationship_id = relationship_id
                result.data = {"action": action}
                
                self.log_service_operation(
                    f"Relationship {relationship_id} {action}",
                    {"relationship_id": relationship_id, "soft_delete": soft_delete}
                )
        
        except Exception as e:
            self.logger.error(f"Unexpected error in relationship removal: {e}", exc_info=True)
            result.add_error("Relationship removal failed due to unexpected error")
        
        return result
    
    def get_entity_relationships(self, entity_id: int, relationship_type: Optional[RelationshipType] = None,
                               include_inactive: bool = False) -> Dict[str, Any]:
        """
        Retrieve all relationships for a business entity with filtering options.
        
        Implements comprehensive relationship retrieval with business logic
        support for complex entity association patterns.
        
        Args:
            entity_id: Entity identifier
            relationship_type: Optional relationship type filter
            include_inactive: Whether to include inactive relationships
        
        Returns:
            Dictionary with relationship data and metadata
        """
        try:
            # Verify entity exists
            entity = self.session.query(self.BusinessEntity).filter(
                self.BusinessEntity.id == entity_id,
                self.BusinessEntity.status != EntityStatus.DELETED
            ).first()
            
            if not entity:
                return {"relationships": [], "summary": {}, "error": "Entity not found"}
            
            # Build query filters
            filters = [
                (self.EntityRelationship.source_entity_id == entity_id) |
                (self.EntityRelationship.target_entity_id == entity_id)
            ]
            
            if not include_inactive:
                filters.append(self.EntityRelationship.is_active == True)
            
            if relationship_type:
                filters.append(self.EntityRelationship.relationship_type == relationship_type.value)
            
            # Execute query with eager loading
            relationships = self.session.query(self.EntityRelationship).filter(
                *filters
            ).options(
                joinedload(self.EntityRelationship.source_entity),
                joinedload(self.EntityRelationship.target_entity)
            ).order_by(self.EntityRelationship.created_at.desc()).all()
            
            # Process relationships
            relationship_data = []
            summary = {"by_type": {}, "total": len(relationships)}
            
            for rel in relationships:
                rel_dict = rel.to_dict(include_entities=True)
                rel_dict["direction"] = "outgoing" if rel.source_entity_id == entity_id else "incoming"
                relationship_data.append(rel_dict)
                
                # Update summary
                rel_type = rel.relationship_type
                if rel_type not in summary["by_type"]:
                    summary["by_type"][rel_type] = {"total": 0, "outgoing": 0, "incoming": 0}
                
                summary["by_type"][rel_type]["total"] += 1
                if rel.source_entity_id == entity_id:
                    summary["by_type"][rel_type]["outgoing"] += 1
                else:
                    summary["by_type"][rel_type]["incoming"] += 1
            
            return {
                "relationships": relationship_data,
                "summary": summary,
                "entity": entity.to_dict()
            }
        
        except SQLAlchemyError as e:
            self.logger.error(f"Error retrieving relationships for entity {entity_id}: {e}")
            return {"relationships": [], "summary": {}, "error": "Database error occurred"}
    
    # Advanced Workflow Orchestration Methods
    
    def execute_bulk_entity_operation(self, operation: str, entity_ids: List[int],
                                    operation_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute bulk operations on multiple entities with transaction management.
        
        Implements advanced workflow orchestration patterns per Section 4.5.3
        with comprehensive error handling and rollback capabilities.
        
        Args:
            operation: Operation type ('update_status', 'bulk_delete', 'bulk_archive')
            entity_ids: List of entity identifiers
            operation_data: Additional operation parameters
        
        Returns:
            Dictionary with operation results and detailed status
        """
        operation_data = operation_data or {}
        results = {
            "operation": operation,
            "total_entities": len(entity_ids),
            "successful": [],
            "failed": [],
            "errors": []
        }
        
        if not entity_ids:
            results["errors"].append("No entity IDs provided")
            return results
        
        try:
            with self.transaction_boundary():
                for entity_id in entity_ids:
                    try:
                        entity = self.session.query(self.BusinessEntity).filter(
                            self.BusinessEntity.id == entity_id,
                            self.BusinessEntity.status != EntityStatus.DELETED
                        ).first()
                        
                        if not entity:
                            results["failed"].append({
                                "entity_id": entity_id,
                                "error": "Entity not found"
                            })
                            continue
                        
                        # Check permissions
                        current_user_id = self.get_current_user_id()
                        if current_user_id and entity.owner_id != current_user_id:
                            results["failed"].append({
                                "entity_id": entity_id,
                                "error": "Insufficient permissions"
                            })
                            continue
                        
                        # Execute operation
                        operation_result = self._execute_single_bulk_operation(
                            operation, entity, operation_data
                        )
                        
                        if operation_result["success"]:
                            results["successful"].append({
                                "entity_id": entity_id,
                                "data": operation_result.get("data", {})
                            })
                        else:
                            results["failed"].append({
                                "entity_id": entity_id,
                                "error": operation_result.get("error", "Unknown error")
                            })
                    
                    except Exception as e:
                        self.logger.error(f"Error in bulk operation for entity {entity_id}: {e}")
                        results["failed"].append({
                            "entity_id": entity_id,
                            "error": str(e)
                        })
                
                self.log_service_operation(
                    f"Bulk operation '{operation}' completed",
                    {
                        "total": results["total_entities"],
                        "successful": len(results["successful"]),
                        "failed": len(results["failed"])
                    }
                )
        
        except Exception as e:
            self.logger.error(f"Critical error in bulk operation: {e}", exc_info=True)
            results["errors"].append(f"Bulk operation failed: {str(e)}")
        
        return results
    
    def _execute_single_bulk_operation(self, operation: str, entity, operation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single operation within a bulk operation context."""
        try:
            if operation == "update_status":
                new_status = operation_data.get("status")
                if not new_status:
                    return {"success": False, "error": "Status not provided"}
                
                # Validate status transition
                if not self._validate_status_transition(entity.status, new_status):
                    return {"success": False, "error": f"Invalid status transition from {entity.status} to {new_status}"}
                
                entity.status = new_status
                entity.updated_at = datetime.now(timezone.utc)
                
                return {"success": True, "data": {"old_status": entity.status, "new_status": new_status}}
            
            elif operation == "bulk_delete":
                entity.status = EntityStatus.DELETED.value
                entity.updated_at = datetime.now(timezone.utc)
                
                return {"success": True, "data": {"action": "deleted"}}
            
            elif operation == "bulk_archive":
                if entity.status != EntityStatus.ACTIVE.value:
                    return {"success": False, "error": "Only active entities can be archived"}
                
                entity.status = EntityStatus.ARCHIVED.value
                entity.updated_at = datetime.now(timezone.utc)
                
                return {"success": True, "data": {"action": "archived"}}
            
            else:
                return {"success": False, "error": f"Unknown operation: {operation}"}
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def analyze_entity_relationship_graph(self, entity_id: int, max_depth: int = 3) -> Dict[str, Any]:
        """
        Analyze entity relationship graph with configurable depth traversal.
        
        Implements complex relationship analysis for business intelligence
        and workflow orchestration with performance optimization.
        
        Args:
            entity_id: Root entity identifier
            max_depth: Maximum traversal depth (default: 3)
        
        Returns:
            Dictionary with relationship graph analysis
        """
        max_depth = min(max_depth, self._max_relationship_depth)  # Enforce business rule
        
        analysis = {
            "root_entity_id": entity_id,
            "max_depth": max_depth,
            "nodes": {},
            "edges": [],
            "statistics": {
                "total_nodes": 0,
                "total_edges": 0,
                "depth_distribution": {},
                "relationship_types": {}
            }
        }
        
        try:
            # Verify root entity exists
            root_entity = self.session.query(self.BusinessEntity).filter(
                self.BusinessEntity.id == entity_id,
                self.BusinessEntity.status != EntityStatus.DELETED
            ).first()
            
            if not root_entity:
                analysis["error"] = "Root entity not found"
                return analysis
            
            # Traverse relationship graph
            visited_entities = set()
            entity_queue = [(entity_id, 0)]  # (entity_id, depth)
            
            while entity_queue and len(visited_entities) < 1000:  # Prevent infinite loops
                current_entity_id, depth = entity_queue.pop(0)
                
                if current_entity_id in visited_entities or depth > max_depth:
                    continue
                
                visited_entities.add(current_entity_id)
                
                # Get entity details
                entity = self.session.query(self.BusinessEntity).get(current_entity_id)
                if entity and entity.status != EntityStatus.DELETED.value:
                    analysis["nodes"][current_entity_id] = {
                        "id": entity.id,
                        "name": entity.name,
                        "status": entity.status,
                        "depth": depth,
                        "owner_id": entity.owner_id
                    }
                    
                    # Update depth distribution
                    depth_key = str(depth)
                    if depth_key not in analysis["statistics"]["depth_distribution"]:
                        analysis["statistics"]["depth_distribution"][depth_key] = 0
                    analysis["statistics"]["depth_distribution"][depth_key] += 1
                
                # Get relationships if not at max depth
                if depth < max_depth:
                    relationships = self.session.query(self.EntityRelationship).filter(
                        (self.EntityRelationship.source_entity_id == current_entity_id) |
                        (self.EntityRelationship.target_entity_id == current_entity_id),
                        self.EntityRelationship.is_active == True
                    ).all()
                    
                    for rel in relationships:
                        # Add edge to analysis
                        analysis["edges"].append({
                            "source": rel.source_entity_id,
                            "target": rel.target_entity_id,
                            "type": rel.relationship_type,
                            "id": rel.id
                        })
                        
                        # Update relationship type statistics
                        rel_type = rel.relationship_type
                        if rel_type not in analysis["statistics"]["relationship_types"]:
                            analysis["statistics"]["relationship_types"][rel_type] = 0
                        analysis["statistics"]["relationship_types"][rel_type] += 1
                        
                        # Add connected entities to queue
                        if rel.source_entity_id == current_entity_id:
                            entity_queue.append((rel.target_entity_id, depth + 1))
                        else:
                            entity_queue.append((rel.source_entity_id, depth + 1))
            
            # Finalize statistics
            analysis["statistics"]["total_nodes"] = len(analysis["nodes"])
            analysis["statistics"]["total_edges"] = len(analysis["edges"])
            
            self.log_service_operation(
                f"Analyzed relationship graph for entity {entity_id}",
                {
                    "nodes": analysis["statistics"]["total_nodes"],
                    "edges": analysis["statistics"]["total_edges"],
                    "max_depth": max_depth
                }
            )
        
        except SQLAlchemyError as e:
            self.logger.error(f"Error analyzing relationship graph: {e}")
            analysis["error"] = "Database error during analysis"
        
        return analysis
    
    def validate_entity_consistency(self, entity_id: int) -> Dict[str, Any]:
        """
        Validate entity data consistency and business rule compliance.
        
        Implements comprehensive validation for business integrity
        and data consistency per Section 4.12.1.
        
        Args:
            entity_id: Entity identifier to validate
        
        Returns:
            Dictionary with validation results and recommendations
        """
        validation_result = {
            "entity_id": entity_id,
            "valid": True,
            "errors": [],
            "warnings": [],
            "recommendations": []
        }
        
        try:
            entity = self.session.query(self.BusinessEntity).filter(
                self.BusinessEntity.id == entity_id
            ).first()
            
            if not entity:
                validation_result["valid"] = False
                validation_result["errors"].append("Entity not found")
                return validation_result
            
            # Validate entity basic properties
            if not entity.name or not entity.name.strip():
                validation_result["valid"] = False
                validation_result["errors"].append("Entity name is missing or empty")
            
            if len(entity.name) > 255:
                validation_result["valid"] = False
                validation_result["errors"].append("Entity name exceeds maximum length")
            
            # Validate owner relationship
            owner = self.session.query(self.User).get(entity.owner_id)
            if not owner:
                validation_result["valid"] = False
                validation_result["errors"].append("Entity owner not found")
            elif not owner.is_active:
                validation_result["warnings"].append("Entity owner is inactive")
            
            # Validate status
            try:
                EntityStatus(entity.status)
            except ValueError:
                validation_result["valid"] = False
                validation_result["errors"].append(f"Invalid entity status: {entity.status}")
            
            # Validate relationships
            relationship_issues = self._validate_entity_relationships(entity)
            validation_result["errors"].extend(relationship_issues["errors"])
            validation_result["warnings"].extend(relationship_issues["warnings"])
            validation_result["recommendations"].extend(relationship_issues["recommendations"])
            
            if relationship_issues["errors"]:
                validation_result["valid"] = False
            
            # Performance recommendations
            if relationship_issues["relationship_count"] > 100:
                validation_result["recommendations"].append(
                    "Consider archiving some relationships for better performance"
                )
            
            self.log_service_operation(
                f"Validated entity {entity_id} consistency",
                {
                    "valid": validation_result["valid"],
                    "errors": len(validation_result["errors"]),
                    "warnings": len(validation_result["warnings"])
                }
            )
        
        except Exception as e:
            self.logger.error(f"Error validating entity consistency: {e}", exc_info=True)
            validation_result["valid"] = False
            validation_result["errors"].append("Validation process failed")
        
        return validation_result
    
    def _validate_entity_relationships(self, entity) -> Dict[str, Any]:
        """Validate entity relationships for consistency and business rules."""
        result = {
            "errors": [],
            "warnings": [],
            "recommendations": [],
            "relationship_count": 0
        }
        
        try:
            # Get all relationships
            relationships = self.session.query(self.EntityRelationship).filter(
                (self.EntityRelationship.source_entity_id == entity.id) |
                (self.EntityRelationship.target_entity_id == entity.id)
            ).all()
            
            result["relationship_count"] = len(relationships)
            
            # Check for orphaned relationships
            for rel in relationships:
                source_exists = self.session.query(self.BusinessEntity).filter(
                    self.BusinessEntity.id == rel.source_entity_id
                ).first()
                target_exists = self.session.query(self.BusinessEntity).filter(
                    self.BusinessEntity.id == rel.target_entity_id
                ).first()
                
                if not source_exists:
                    result["errors"].append(f"Relationship {rel.id} references non-existent source entity")
                
                if not target_exists:
                    result["errors"].append(f"Relationship {rel.id} references non-existent target entity")
                
                # Check for invalid relationship types
                try:
                    RelationshipType(rel.relationship_type)
                except ValueError:
                    result["errors"].append(f"Relationship {rel.id} has invalid type: {rel.relationship_type}")
            
            # Check for duplicate relationships
            seen_relationships = set()
            for rel in relationships:
                if rel.is_active:
                    rel_key = (rel.source_entity_id, rel.target_entity_id, rel.relationship_type)
                    if rel_key in seen_relationships:
                        result["warnings"].append(f"Duplicate active relationship detected: {rel_key}")
                    seen_relationships.add(rel_key)
            
            # Check relationship limits
            if len(relationships) > self._max_relationships_per_entity * 0.8:
                result["warnings"].append("Entity approaching maximum relationship limit")
            
        except Exception as e:
            result["errors"].append(f"Relationship validation failed: {str(e)}")
        
        return result


# Export service for application registration
__all__ = ['BusinessEntityService', 'EntityCreationRequest', 'EntityUpdateRequest', 
           'RelationshipCreationRequest', 'BusinessWorkflowResult', 'EntityStatus', 'RelationshipType']