"""
Business Entity Service

This service orchestrates complex business entity workflows including entity creation,
relationship management, lifecycle operations, and cross-entity business rules.
Implements the Service Layer pattern for business workflow orchestration while
preserving all original Node.js business logic patterns through comprehensive
entity relationship coordination.

Features implemented:
- Business logic preservation for entity management workflows (Feature F-005)
- Complex business entity relationship mapping (Section 6.2.2.1)
- Service Layer pattern implementation (Feature F-006)
- Entity lifecycle management with business rule enforcement (Section 4.12.1)
- Cross-entity business logic coordination (Section 5.2.3)
"""

from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime
import logging
from contextlib import contextmanager

from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, asc

# Import models
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship
from src.models.user import User

# Import utilities
from src.utils.validation import ValidationService
from src.utils.error_handling import BusinessLogicError, ValidationError, DataIntegrityError
from src.utils.logging import get_structured_logger
from src.utils.database import DatabaseTransactionManager
from src.utils.response import ResponseFormatter


@dataclass
class EntityCreationRequest:
    """
    Data class for entity creation requests with type hints for validation.
    Implements Python dataclass pattern per Section 4.5.1 requirements.
    """
    name: str
    description: Optional[str] = None
    owner_id: Optional[int] = None
    status: str = 'active'
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class EntityRelationshipRequest:
    """
    Data class for entity relationship creation with comprehensive validation.
    Supports complex business entity relationship mapping per Section 6.2.2.1.
    """
    source_entity_id: int
    target_entity_id: int
    relationship_type: str
    metadata: Optional[Dict[str, Any]] = None
    is_active: bool = True


@dataclass
class EntityUpdateRequest:
    """
    Data class for entity update operations with selective field updates.
    Maintains business rule enforcement during lifecycle operations.
    """
    entity_id: int
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class BusinessEntityService:
    """
    Core business entity service implementing Service Layer pattern for 
    complex entity workflow orchestration. Provides comprehensive business
    logic abstraction for entity management operations while maintaining
    functional equivalence with original Node.js business rules.
    
    This service coordinates:
    - Entity creation and lifecycle management
    - Complex relationship mapping and validation
    - Cross-entity business rule enforcement
    - Transaction boundary management
    - Workflow orchestration for multi-step operations
    """
    
    def __init__(self, db: SQLAlchemy = None):
        """
        Initialize business entity service with dependency injection support.
        
        Args:
            db: Flask-SQLAlchemy database instance for transaction management
        """
        self.db = db
        self.logger = get_structured_logger(__name__)
        self.validation_service = ValidationService()
        self.db_transaction_manager = DatabaseTransactionManager()
        self.response_formatter = ResponseFormatter()
        
        # Valid entity statuses for lifecycle management
        self.VALID_STATUSES = ['active', 'inactive', 'archived', 'pending']
        
        # Valid relationship types for business logic enforcement
        self.VALID_RELATIONSHIP_TYPES = [
            'parent_child', 'depends_on', 'related_to', 
            'contains', 'references', 'manages', 'owns'
        ]
    
    @contextmanager
    def _get_db_session(self):
        """
        Database session context manager for transaction boundary control.
        Implements Flask-SQLAlchemy session handling per Section 5.2.4.
        """
        if self.db:
            session = self.db.session
        else:
            session = current_app.extensions['sqlalchemy'].db.session
            
        try:
            yield session
        except Exception as e:
            session.rollback()
            self.logger.error(f"Database transaction rolled back: {str(e)}")
            raise
        finally:
            session.close()
    
    def create_entity(self, request: EntityCreationRequest, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Create a new business entity with comprehensive validation and business rule enforcement.
        
        Implements entity creation workflow per Section 5.2.3 Service Layer requirements
        with complete business logic preservation from Node.js implementation.
        
        Args:
            request: EntityCreationRequest with entity details
            user_id: Optional user ID for ownership assignment
            
        Returns:
            Dict containing created entity data and operation metadata
            
        Raises:
            ValidationError: For invalid input data or business rule violations
            BusinessLogicError: For business rule enforcement failures
            DataIntegrityError: For database constraint violations
        """
        try:
            # Input validation with comprehensive schema checking
            self._validate_entity_creation_request(request)
            
            # Business rule validation
            self._enforce_entity_creation_rules(request, user_id)
            
            with self._get_db_session() as session:
                # Determine entity owner
                owner_id = request.owner_id or user_id
                if owner_id:
                    owner = session.query(User).filter_by(id=owner_id).first()
                    if not owner:
                        raise ValidationError(f"Invalid owner_id: {owner_id}")
                
                # Create entity with business logic preservation
                entity = BusinessEntity(
                    name=request.name,
                    description=request.description,
                    owner_id=owner_id,
                    status=request.status,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                
                session.add(entity)
                session.commit()
                
                # Log entity creation for audit trail
                self.logger.info(
                    "Business entity created",
                    extra={
                        "entity_id": entity.id,
                        "entity_name": entity.name,
                        "owner_id": owner_id,
                        "user_id": user_id,
                        "status": entity.status
                    }
                )
                
                return self.response_formatter.format_success_response(
                    data={
                        "entity_id": entity.id,
                        "name": entity.name,
                        "description": entity.description,
                        "owner_id": entity.owner_id,
                        "status": entity.status,
                        "created_at": entity.created_at.isoformat(),
                        "updated_at": entity.updated_at.isoformat()
                    },
                    message="Entity created successfully"
                )
                
        except (ValidationError, BusinessLogicError) as e:
            self.logger.warning(f"Entity creation validation failed: {str(e)}")
            raise
        except IntegrityError as e:
            self.logger.error(f"Entity creation integrity error: {str(e)}")
            raise DataIntegrityError(f"Database constraint violation: {str(e)}")
        except Exception as e:
            self.logger.error(f"Entity creation failed: {str(e)}")
            raise BusinessLogicError(f"Entity creation failed: {str(e)}")
    
    def update_entity(self, request: EntityUpdateRequest, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Update business entity with lifecycle management and business rule enforcement.
        
        Implements entity lifecycle management per Section 4.12.1 with comprehensive
        validation rules and cross-entity business logic coordination.
        
        Args:
            request: EntityUpdateRequest with update parameters
            user_id: Optional user ID for authorization checking
            
        Returns:
            Dict containing updated entity data and operation metadata
            
        Raises:
            ValidationError: For invalid update parameters or business rule violations
            BusinessLogicError: For entity not found or business logic failures
            DataIntegrityError: For database constraint violations
        """
        try:
            # Input validation
            self._validate_entity_update_request(request)
            
            with self._get_db_session() as session:
                # Retrieve entity with existence validation
                entity = session.query(BusinessEntity).filter_by(id=request.entity_id).first()
                if not entity:
                    raise BusinessLogicError(f"Entity not found: {request.entity_id}")
                
                # Authorization validation
                if user_id and entity.owner_id and entity.owner_id != user_id:
                    raise BusinessLogicError("Insufficient permissions to update entity")
                
                # Business rule enforcement for updates
                self._enforce_entity_update_rules(entity, request)
                
                # Apply selective updates with validation
                if request.name is not None:
                    entity.name = request.name
                if request.description is not None:
                    entity.description = request.description
                if request.status is not None:
                    # Validate status transition
                    self._validate_status_transition(entity.status, request.status)
                    entity.status = request.status
                if request.metadata is not None:
                    # Merge metadata with existing data
                    entity.metadata = {**(entity.metadata or {}), **request.metadata}
                
                entity.updated_at = datetime.utcnow()
                session.commit()
                
                # Log entity update for audit trail
                self.logger.info(
                    "Business entity updated",
                    extra={
                        "entity_id": entity.id,
                        "entity_name": entity.name,
                        "user_id": user_id,
                        "updated_fields": [
                            field for field in ['name', 'description', 'status', 'metadata'] 
                            if getattr(request, field) is not None
                        ]
                    }
                )
                
                return self.response_formatter.format_success_response(
                    data={
                        "entity_id": entity.id,
                        "name": entity.name,
                        "description": entity.description,
                        "owner_id": entity.owner_id,
                        "status": entity.status,
                        "created_at": entity.created_at.isoformat(),
                        "updated_at": entity.updated_at.isoformat()
                    },
                    message="Entity updated successfully"
                )
                
        except (ValidationError, BusinessLogicError) as e:
            self.logger.warning(f"Entity update validation failed: {str(e)}")
            raise
        except IntegrityError as e:
            self.logger.error(f"Entity update integrity error: {str(e)}")
            raise DataIntegrityError(f"Database constraint violation: {str(e)}")
        except Exception as e:
            self.logger.error(f"Entity update failed: {str(e)}")
            raise BusinessLogicError(f"Entity update failed: {str(e)}")
    
    def create_relationship(self, request: EntityRelationshipRequest, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Create business entity relationship with complex business logic coordination.
        
        Implements complex business entity relationship mapping per Section 6.2.2.1
        with comprehensive validation and cross-entity business rule enforcement.
        
        Args:
            request: EntityRelationshipRequest with relationship details
            user_id: Optional user ID for authorization checking
            
        Returns:
            Dict containing created relationship data and operation metadata
            
        Raises:
            ValidationError: For invalid relationship parameters or business rule violations
            BusinessLogicError: For entity not found or relationship logic failures
            DataIntegrityError: For database constraint violations
        """
        try:
            # Input validation with relationship-specific rules
            self._validate_relationship_request(request)
            
            with self._get_db_session() as session:
                # Validate source and target entities exist
                source_entity = session.query(BusinessEntity).filter_by(id=request.source_entity_id).first()
                target_entity = session.query(BusinessEntity).filter_by(id=request.target_entity_id).first()
                
                if not source_entity:
                    raise BusinessLogicError(f"Source entity not found: {request.source_entity_id}")
                if not target_entity:
                    raise BusinessLogicError(f"Target entity not found: {request.target_entity_id}")
                
                # Authorization validation for relationship creation
                if user_id:
                    if (source_entity.owner_id and source_entity.owner_id != user_id and
                        target_entity.owner_id and target_entity.owner_id != user_id):
                        raise BusinessLogicError("Insufficient permissions to create relationship")
                
                # Business rule enforcement for relationships
                self._enforce_relationship_creation_rules(source_entity, target_entity, request)
                
                # Check for duplicate relationships
                existing_relationship = session.query(EntityRelationship).filter(
                    and_(
                        EntityRelationship.source_entity_id == request.source_entity_id,
                        EntityRelationship.target_entity_id == request.target_entity_id,
                        EntityRelationship.relationship_type == request.relationship_type,
                        EntityRelationship.is_active == True
                    )
                ).first()
                
                if existing_relationship:
                    raise BusinessLogicError(
                        f"Relationship already exists between entities {request.source_entity_id} "
                        f"and {request.target_entity_id} with type {request.relationship_type}"
                    )
                
                # Create relationship with business logic coordination
                relationship = EntityRelationship(
                    source_entity_id=request.source_entity_id,
                    target_entity_id=request.target_entity_id,
                    relationship_type=request.relationship_type,
                    is_active=request.is_active,
                    created_at=datetime.utcnow()
                )
                
                session.add(relationship)
                session.commit()
                
                # Log relationship creation for audit trail
                self.logger.info(
                    "Entity relationship created",
                    extra={
                        "relationship_id": relationship.id,
                        "source_entity_id": relationship.source_entity_id,
                        "target_entity_id": relationship.target_entity_id,
                        "relationship_type": relationship.relationship_type,
                        "user_id": user_id
                    }
                )
                
                return self.response_formatter.format_success_response(
                    data={
                        "relationship_id": relationship.id,
                        "source_entity_id": relationship.source_entity_id,
                        "target_entity_id": relationship.target_entity_id,
                        "relationship_type": relationship.relationship_type,
                        "is_active": relationship.is_active,
                        "created_at": relationship.created_at.isoformat()
                    },
                    message="Relationship created successfully"
                )
                
        except (ValidationError, BusinessLogicError) as e:
            self.logger.warning(f"Relationship creation validation failed: {str(e)}")
            raise
        except IntegrityError as e:
            self.logger.error(f"Relationship creation integrity error: {str(e)}")
            raise DataIntegrityError(f"Database constraint violation: {str(e)}")
        except Exception as e:
            self.logger.error(f"Relationship creation failed: {str(e)}")
            raise BusinessLogicError(f"Relationship creation failed: {str(e)}")
    
    def get_entity(self, entity_id: int, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Retrieve business entity with relationships and metadata.
        
        Implements comprehensive entity retrieval with relationship mapping
        and authorization checking per Section 5.2.3 requirements.
        
        Args:
            entity_id: ID of the entity to retrieve
            user_id: Optional user ID for authorization checking
            
        Returns:
            Dict containing entity data with relationships and metadata
            
        Raises:
            BusinessLogicError: For entity not found or authorization failures
        """
        try:
            with self._get_db_session() as session:
                # Retrieve entity with relationship loading
                entity = session.query(BusinessEntity).filter_by(id=entity_id).first()
                if not entity:
                    raise BusinessLogicError(f"Entity not found: {entity_id}")
                
                # Authorization validation
                if user_id and entity.owner_id and entity.owner_id != user_id:
                    raise BusinessLogicError("Insufficient permissions to view entity")
                
                # Retrieve entity relationships
                source_relationships = session.query(EntityRelationship).filter(
                    and_(
                        EntityRelationship.source_entity_id == entity_id,
                        EntityRelationship.is_active == True
                    )
                ).all()
                
                target_relationships = session.query(EntityRelationship).filter(
                    and_(
                        EntityRelationship.target_entity_id == entity_id,
                        EntityRelationship.is_active == True
                    )
                ).all()
                
                return self.response_formatter.format_success_response(
                    data={
                        "entity_id": entity.id,
                        "name": entity.name,
                        "description": entity.description,
                        "owner_id": entity.owner_id,
                        "status": entity.status,
                        "created_at": entity.created_at.isoformat(),
                        "updated_at": entity.updated_at.isoformat(),
                        "source_relationships": [
                            {
                                "relationship_id": rel.id,
                                "target_entity_id": rel.target_entity_id,
                                "relationship_type": rel.relationship_type,
                                "created_at": rel.created_at.isoformat()
                            } for rel in source_relationships
                        ],
                        "target_relationships": [
                            {
                                "relationship_id": rel.id,
                                "source_entity_id": rel.source_entity_id,
                                "relationship_type": rel.relationship_type,
                                "created_at": rel.created_at.isoformat()
                            } for rel in target_relationships
                        ]
                    },
                    message="Entity retrieved successfully"
                )
                
        except BusinessLogicError as e:
            self.logger.warning(f"Entity retrieval failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Entity retrieval error: {str(e)}")
            raise BusinessLogicError(f"Entity retrieval failed: {str(e)}")
    
    def list_entities(
        self, 
        user_id: Optional[int] = None,
        status: Optional[str] = None,
        owner_id: Optional[int] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Dict[str, Any]:
        """
        List business entities with filtering and pagination support.
        
        Implements comprehensive entity listing with business rule enforcement
        and performance optimization per Section 6.2.5.1 requirements.
        
        Args:
            user_id: Optional user ID for authorization filtering
            status: Optional status filter
            owner_id: Optional owner filter
            page: Page number for pagination
            per_page: Items per page
            
        Returns:
            Dict containing paginated entity list and metadata
        """
        try:
            with self._get_db_session() as session:
                # Build query with filters
                query = session.query(BusinessEntity)
                
                # Apply filters with business logic
                if user_id and not owner_id:
                    query = query.filter(BusinessEntity.owner_id == user_id)
                elif owner_id:
                    query = query.filter(BusinessEntity.owner_id == owner_id)
                
                if status and status in self.VALID_STATUSES:
                    query = query.filter(BusinessEntity.status == status)
                
                # Apply pagination
                total_count = query.count()
                offset = (page - 1) * per_page
                entities = query.order_by(desc(BusinessEntity.updated_at)).offset(offset).limit(per_page).all()
                
                # Format entity data
                entity_data = []
                for entity in entities:
                    entity_data.append({
                        "entity_id": entity.id,
                        "name": entity.name,
                        "description": entity.description,
                        "owner_id": entity.owner_id,
                        "status": entity.status,
                        "created_at": entity.created_at.isoformat(),
                        "updated_at": entity.updated_at.isoformat()
                    })
                
                return self.response_formatter.format_success_response(
                    data={
                        "entities": entity_data,
                        "pagination": {
                            "page": page,
                            "per_page": per_page,
                            "total_count": total_count,
                            "total_pages": (total_count + per_page - 1) // per_page
                        }
                    },
                    message="Entities retrieved successfully"
                )
                
        except Exception as e:
            self.logger.error(f"Entity listing failed: {str(e)}")
            raise BusinessLogicError(f"Entity listing failed: {str(e)}")
    
    def delete_entity(self, entity_id: int, user_id: Optional[int] = None, soft_delete: bool = True) -> Dict[str, Any]:
        """
        Delete business entity with relationship cleanup and business rule enforcement.
        
        Implements entity lifecycle management with comprehensive cleanup procedures
        and cross-entity business logic coordination per Section 4.12.1 requirements.
        
        Args:
            entity_id: ID of the entity to delete
            user_id: Optional user ID for authorization checking
            soft_delete: Whether to perform soft delete (status change) or hard delete
            
        Returns:
            Dict containing deletion confirmation and operation metadata
            
        Raises:
            ValidationError: For deletion rule violations
            BusinessLogicError: For entity not found or authorization failures
        """
        try:
            with self._get_db_session() as session:
                # Retrieve entity
                entity = session.query(BusinessEntity).filter_by(id=entity_id).first()
                if not entity:
                    raise BusinessLogicError(f"Entity not found: {entity_id}")
                
                # Authorization validation
                if user_id and entity.owner_id and entity.owner_id != user_id:
                    raise BusinessLogicError("Insufficient permissions to delete entity")
                
                # Business rule enforcement for deletion
                self._enforce_entity_deletion_rules(entity, session)
                
                if soft_delete:
                    # Soft delete - change status to archived
                    entity.status = 'archived'
                    entity.updated_at = datetime.utcnow()
                    
                    # Deactivate related relationships
                    session.query(EntityRelationship).filter(
                        or_(
                            EntityRelationship.source_entity_id == entity_id,
                            EntityRelationship.target_entity_id == entity_id
                        )
                    ).update({"is_active": False})
                    
                    session.commit()
                    action = "archived"
                else:
                    # Hard delete - remove entity and relationships
                    session.query(EntityRelationship).filter(
                        or_(
                            EntityRelationship.source_entity_id == entity_id,
                            EntityRelationship.target_entity_id == entity_id
                        )
                    ).delete()
                    
                    session.delete(entity)
                    session.commit()
                    action = "deleted"
                
                # Log entity deletion for audit trail
                self.logger.info(
                    f"Business entity {action}",
                    extra={
                        "entity_id": entity_id,
                        "entity_name": entity.name if soft_delete else "N/A",
                        "user_id": user_id,
                        "action": action
                    }
                )
                
                return self.response_formatter.format_success_response(
                    data={"entity_id": entity_id, "action": action},
                    message=f"Entity {action} successfully"
                )
                
        except (ValidationError, BusinessLogicError) as e:
            self.logger.warning(f"Entity deletion failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Entity deletion error: {str(e)}")
            raise BusinessLogicError(f"Entity deletion failed: {str(e)}")
    
    def get_entity_relationships(
        self, 
        entity_id: int, 
        relationship_type: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Retrieve entity relationships with filtering and metadata.
        
        Implements complex business entity relationship mapping retrieval
        per Section 6.2.2.1 with comprehensive relationship coordination.
        
        Args:
            entity_id: ID of the entity to get relationships for
            relationship_type: Optional filter by relationship type
            user_id: Optional user ID for authorization checking
            
        Returns:
            Dict containing relationship data and metadata
        """
        try:
            with self._get_db_session() as session:
                # Validate entity exists and user has access
                entity = session.query(BusinessEntity).filter_by(id=entity_id).first()
                if not entity:
                    raise BusinessLogicError(f"Entity not found: {entity_id}")
                
                if user_id and entity.owner_id and entity.owner_id != user_id:
                    raise BusinessLogicError("Insufficient permissions to view entity relationships")
                
                # Build relationship query
                query_conditions = [
                    or_(
                        EntityRelationship.source_entity_id == entity_id,
                        EntityRelationship.target_entity_id == entity_id
                    ),
                    EntityRelationship.is_active == True
                ]
                
                if relationship_type and relationship_type in self.VALID_RELATIONSHIP_TYPES:
                    query_conditions.append(EntityRelationship.relationship_type == relationship_type)
                
                relationships = session.query(EntityRelationship).filter(
                    and_(*query_conditions)
                ).order_by(desc(EntityRelationship.created_at)).all()
                
                # Format relationship data with related entity information
                relationship_data = []
                for rel in relationships:
                    # Determine direction and related entity
                    if rel.source_entity_id == entity_id:
                        direction = "outgoing"
                        related_entity_id = rel.target_entity_id
                    else:
                        direction = "incoming"
                        related_entity_id = rel.source_entity_id
                    
                    # Get related entity basic info
                    related_entity = session.query(BusinessEntity).filter_by(id=related_entity_id).first()
                    
                    relationship_data.append({
                        "relationship_id": rel.id,
                        "direction": direction,
                        "relationship_type": rel.relationship_type,
                        "related_entity": {
                            "entity_id": related_entity.id,
                            "name": related_entity.name,
                            "status": related_entity.status
                        } if related_entity else None,
                        "created_at": rel.created_at.isoformat()
                    })
                
                return self.response_formatter.format_success_response(
                    data={
                        "entity_id": entity_id,
                        "relationships": relationship_data,
                        "total_count": len(relationship_data)
                    },
                    message="Entity relationships retrieved successfully"
                )
                
        except BusinessLogicError as e:
            self.logger.warning(f"Relationship retrieval failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Relationship retrieval error: {str(e)}")
            raise BusinessLogicError(f"Relationship retrieval failed: {str(e)}")
    
    def orchestrate_entity_workflow(
        self, 
        workflow_type: str, 
        entity_ids: List[int], 
        workflow_params: Dict[str, Any],
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Orchestrate complex business entity workflows across multiple entities.
        
        Implements advanced workflow orchestration patterns per Section 4.5.3
        with service composition for complex business operations and comprehensive
        transaction boundary management across multiple entities.
        
        Args:
            workflow_type: Type of workflow to execute
            entity_ids: List of entity IDs involved in the workflow
            workflow_params: Parameters specific to the workflow
            user_id: Optional user ID for authorization checking
            
        Returns:
            Dict containing workflow execution results and metadata
            
        Raises:
            ValidationError: For invalid workflow parameters
            BusinessLogicError: For workflow execution failures
        """
        try:
            # Validate workflow parameters
            self._validate_workflow_request(workflow_type, entity_ids, workflow_params)
            
            with self._get_db_session() as session:
                # Validate all entities exist and user has access
                entities = []
                for entity_id in entity_ids:
                    entity = session.query(BusinessEntity).filter_by(id=entity_id).first()
                    if not entity:
                        raise BusinessLogicError(f"Entity not found: {entity_id}")
                    
                    if user_id and entity.owner_id and entity.owner_id != user_id:
                        raise BusinessLogicError(f"Insufficient permissions for entity: {entity_id}")
                    
                    entities.append(entity)
                
                # Execute workflow based on type
                workflow_result = self._execute_workflow(workflow_type, entities, workflow_params, session)
                
                session.commit()
                
                # Log workflow execution for audit trail
                self.logger.info(
                    "Entity workflow executed",
                    extra={
                        "workflow_type": workflow_type,
                        "entity_ids": entity_ids,
                        "user_id": user_id,
                        "workflow_result": workflow_result
                    }
                )
                
                return self.response_formatter.format_success_response(
                    data={
                        "workflow_type": workflow_type,
                        "entity_ids": entity_ids,
                        "workflow_result": workflow_result,
                        "executed_at": datetime.utcnow().isoformat()
                    },
                    message="Workflow executed successfully"
                )
                
        except (ValidationError, BusinessLogicError) as e:
            self.logger.warning(f"Workflow execution failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Workflow execution error: {str(e)}")
            raise BusinessLogicError(f"Workflow execution failed: {str(e)}")
    
    # Private validation and business rule methods
    
    def _validate_entity_creation_request(self, request: EntityCreationRequest) -> None:
        """
        Validate entity creation request with comprehensive input validation.
        
        Implements input validation per Section 4.12.1 validation rules
        with business rule enforcement and security compliance.
        """
        if not request.name or not request.name.strip():
            raise ValidationError("Entity name is required")
        
        if len(request.name) > 255:
            raise ValidationError("Entity name must be 255 characters or less")
        
        if request.status and request.status not in self.VALID_STATUSES:
            raise ValidationError(f"Invalid status. Must be one of: {', '.join(self.VALID_STATUSES)}")
        
        if request.description and len(request.description) > 1000:
            raise ValidationError("Entity description must be 1000 characters or less")
        
        # Validate metadata if provided
        if request.metadata:
            if not isinstance(request.metadata, dict):
                raise ValidationError("Entity metadata must be a dictionary")
            
            # Basic sanitization for security
            self.validation_service.validate_metadata_security(request.metadata)
    
    def _validate_entity_update_request(self, request: EntityUpdateRequest) -> None:
        """
        Validate entity update request with selective field validation.
        
        Implements entity lifecycle validation per Section 4.12.1 requirements
        with comprehensive business rule enforcement.
        """
        if not request.entity_id:
            raise ValidationError("Entity ID is required")
        
        if request.name is not None:
            if not request.name.strip():
                raise ValidationError("Entity name cannot be empty")
            if len(request.name) > 255:
                raise ValidationError("Entity name must be 255 characters or less")
        
        if request.status is not None and request.status not in self.VALID_STATUSES:
            raise ValidationError(f"Invalid status. Must be one of: {', '.join(self.VALID_STATUSES)}")
        
        if request.description is not None and len(request.description) > 1000:
            raise ValidationError("Entity description must be 1000 characters or less")
        
        if request.metadata is not None:
            if not isinstance(request.metadata, dict):
                raise ValidationError("Entity metadata must be a dictionary")
            self.validation_service.validate_metadata_security(request.metadata)
    
    def _validate_relationship_request(self, request: EntityRelationshipRequest) -> None:
        """
        Validate entity relationship request with business logic coordination.
        
        Implements complex business entity relationship validation per Section 6.2.2.1
        with comprehensive constraint checking and business rule enforcement.
        """
        if not request.source_entity_id:
            raise ValidationError("Source entity ID is required")
        
        if not request.target_entity_id:
            raise ValidationError("Target entity ID is required")
        
        if request.source_entity_id == request.target_entity_id:
            raise ValidationError("Source and target entities cannot be the same")
        
        if not request.relationship_type:
            raise ValidationError("Relationship type is required")
        
        if request.relationship_type not in self.VALID_RELATIONSHIP_TYPES:
            raise ValidationError(
                f"Invalid relationship type. Must be one of: {', '.join(self.VALID_RELATIONSHIP_TYPES)}"
            )
        
        if request.metadata is not None:
            if not isinstance(request.metadata, dict):
                raise ValidationError("Relationship metadata must be a dictionary")
            self.validation_service.validate_metadata_security(request.metadata)
    
    def _validate_workflow_request(
        self, 
        workflow_type: str, 
        entity_ids: List[int], 
        workflow_params: Dict[str, Any]
    ) -> None:
        """
        Validate workflow orchestration request parameters.
        
        Implements workflow validation per Section 4.5.3 advanced workflow
        orchestration patterns with comprehensive parameter validation.
        """
        valid_workflow_types = [
            'bulk_status_update', 'relationship_cascade', 'entity_merge', 
            'ownership_transfer', 'dependency_check', 'cleanup_orphaned'
        ]
        
        if not workflow_type:
            raise ValidationError("Workflow type is required")
        
        if workflow_type not in valid_workflow_types:
            raise ValidationError(
                f"Invalid workflow type. Must be one of: {', '.join(valid_workflow_types)}"
            )
        
        if not entity_ids or len(entity_ids) == 0:
            raise ValidationError("At least one entity ID is required")
        
        if len(entity_ids) > 100:
            raise ValidationError("Cannot process more than 100 entities in a single workflow")
        
        if not isinstance(workflow_params, dict):
            raise ValidationError("Workflow parameters must be a dictionary")
        
        # Workflow-specific parameter validation
        if workflow_type == 'bulk_status_update':
            if 'new_status' not in workflow_params:
                raise ValidationError("new_status parameter is required for bulk_status_update workflow")
            if workflow_params['new_status'] not in self.VALID_STATUSES:
                raise ValidationError(f"Invalid new_status. Must be one of: {', '.join(self.VALID_STATUSES)}")
        
        elif workflow_type == 'relationship_cascade':
            if 'relationship_type' not in workflow_params:
                raise ValidationError("relationship_type parameter is required for relationship_cascade workflow")
            if workflow_params['relationship_type'] not in self.VALID_RELATIONSHIP_TYPES:
                raise ValidationError(
                    f"Invalid relationship_type. Must be one of: {', '.join(self.VALID_RELATIONSHIP_TYPES)}"
                )
        
        elif workflow_type == 'ownership_transfer':
            if 'new_owner_id' not in workflow_params:
                raise ValidationError("new_owner_id parameter is required for ownership_transfer workflow")
    
    def _enforce_entity_creation_rules(self, request: EntityCreationRequest, user_id: Optional[int]) -> None:
        """
        Enforce business rules for entity creation.
        
        Implements business rule enforcement per Section 4.12.1 with
        comprehensive business logic preservation from Node.js implementation.
        """
        # Business rule: Entity name must be unique per owner
        with self._get_db_session() as session:
            owner_id = request.owner_id or user_id
            if owner_id:
                existing_entity = session.query(BusinessEntity).filter(
                    and_(
                        BusinessEntity.name == request.name,
                        BusinessEntity.owner_id == owner_id,
                        BusinessEntity.status != 'archived'
                    )
                ).first()
                
                if existing_entity:
                    raise BusinessLogicError(f"Entity with name '{request.name}' already exists for this owner")
        
        # Business rule: Default status validation
        if not request.status:
            request.status = 'pending'  # Default to pending for new entities
    
    def _enforce_entity_update_rules(self, entity: BusinessEntity, request: EntityUpdateRequest) -> None:
        """
        Enforce business rules for entity updates.
        
        Implements entity lifecycle business rule enforcement per Section 4.12.1
        with comprehensive validation and cross-entity coordination.
        """
        # Business rule: Cannot update archived entities
        if entity.status == 'archived':
            raise BusinessLogicError("Cannot update archived entities")
        
        # Business rule: Name uniqueness check for updates
        if request.name and request.name != entity.name:
            with self._get_db_session() as session:
                existing_entity = session.query(BusinessEntity).filter(
                    and_(
                        BusinessEntity.name == request.name,
                        BusinessEntity.owner_id == entity.owner_id,
                        BusinessEntity.id != entity.id,
                        BusinessEntity.status != 'archived'
                    )
                ).first()
                
                if existing_entity:
                    raise BusinessLogicError(f"Entity with name '{request.name}' already exists for this owner")
    
    def _enforce_relationship_creation_rules(
        self, 
        source_entity: BusinessEntity, 
        target_entity: BusinessEntity, 
        request: EntityRelationshipRequest
    ) -> None:
        """
        Enforce business rules for relationship creation.
        
        Implements complex business entity relationship rules per Section 6.2.2.1
        with comprehensive cross-entity business logic coordination.
        """
        # Business rule: Cannot create relationships with archived entities
        if source_entity.status == 'archived' or target_entity.status == 'archived':
            raise BusinessLogicError("Cannot create relationships with archived entities")
        
        # Business rule: Specific relationship type restrictions
        if request.relationship_type == 'parent_child':
            # Check for circular dependencies
            with self._get_db_session() as session:
                circular_check = session.query(EntityRelationship).filter(
                    and_(
                        EntityRelationship.source_entity_id == request.target_entity_id,
                        EntityRelationship.target_entity_id == request.source_entity_id,
                        EntityRelationship.relationship_type == 'parent_child',
                        EntityRelationship.is_active == True
                    )
                ).first()
                
                if circular_check:
                    raise BusinessLogicError("Cannot create circular parent-child relationships")
        
        # Business rule: Ownership validation for certain relationship types
        if request.relationship_type in ['owns', 'manages']:
            if source_entity.owner_id != target_entity.owner_id:
                raise BusinessLogicError(
                    f"'{request.relationship_type}' relationships can only exist between entities with the same owner"
                )
    
    def _enforce_entity_deletion_rules(self, entity: BusinessEntity, session: Session) -> None:
        """
        Enforce business rules for entity deletion.
        
        Implements entity lifecycle deletion rules per Section 4.12.1
        with comprehensive dependency checking and business logic coordination.
        """
        # Business rule: Check for critical relationships before deletion
        critical_relationships = session.query(EntityRelationship).filter(
            and_(
                EntityRelationship.target_entity_id == entity.id,
                EntityRelationship.relationship_type.in_(['depends_on', 'parent_child']),
                EntityRelationship.is_active == True
            )
        ).count()
        
        if critical_relationships > 0:
            raise ValidationError(
                f"Cannot delete entity with {critical_relationships} critical dependencies. "
                "Remove dependencies first."
            )
    
    def _validate_status_transition(self, current_status: str, new_status: str) -> None:
        """
        Validate entity status transitions according to business rules.
        
        Implements entity lifecycle status validation per Section 4.12.1
        with comprehensive state transition management.
        """
        # Define valid status transitions
        valid_transitions = {
            'pending': ['active', 'inactive', 'archived'],
            'active': ['inactive', 'archived'],
            'inactive': ['active', 'archived'],
            'archived': []  # Archived entities cannot transition to other states
        }
        
        if current_status not in valid_transitions:
            raise ValidationError(f"Invalid current status: {current_status}")
        
        if new_status not in valid_transitions[current_status]:
            raise ValidationError(
                f"Invalid status transition from '{current_status}' to '{new_status}'. "
                f"Valid transitions: {', '.join(valid_transitions[current_status])}"
            )
    
    def _execute_workflow(
        self, 
        workflow_type: str, 
        entities: List[BusinessEntity], 
        workflow_params: Dict[str, Any],
        session: Session
    ) -> Dict[str, Any]:
        """
        Execute specific workflow types with comprehensive business logic coordination.
        
        Implements advanced workflow orchestration patterns per Section 4.5.3
        with service composition and transaction boundary management.
        """
        workflow_result = {"processed_entities": [], "errors": [], "summary": {}}
        
        try:
            if workflow_type == 'bulk_status_update':
                return self._execute_bulk_status_update(entities, workflow_params, session)
            
            elif workflow_type == 'relationship_cascade':
                return self._execute_relationship_cascade(entities, workflow_params, session)
            
            elif workflow_type == 'ownership_transfer':
                return self._execute_ownership_transfer(entities, workflow_params, session)
            
            elif workflow_type == 'dependency_check':
                return self._execute_dependency_check(entities, workflow_params, session)
            
            elif workflow_type == 'cleanup_orphaned':
                return self._execute_cleanup_orphaned(entities, workflow_params, session)
            
            else:
                raise BusinessLogicError(f"Unsupported workflow type: {workflow_type}")
                
        except Exception as e:
            self.logger.error(f"Workflow execution failed for {workflow_type}: {str(e)}")
            workflow_result["errors"].append(str(e))
            return workflow_result
    
    def _execute_bulk_status_update(
        self, 
        entities: List[BusinessEntity], 
        workflow_params: Dict[str, Any],
        session: Session
    ) -> Dict[str, Any]:
        """Execute bulk status update workflow with validation."""
        new_status = workflow_params['new_status']
        processed_entities = []
        errors = []
        
        for entity in entities:
            try:
                self._validate_status_transition(entity.status, new_status)
                entity.status = new_status
                entity.updated_at = datetime.utcnow()
                processed_entities.append(entity.id)
            except Exception as e:
                errors.append(f"Entity {entity.id}: {str(e)}")
        
        return {
            "processed_entities": processed_entities,
            "errors": errors,
            "summary": {"total_processed": len(processed_entities), "total_errors": len(errors)}
        }
    
    def _execute_relationship_cascade(
        self, 
        entities: List[BusinessEntity], 
        workflow_params: Dict[str, Any],
        session: Session
    ) -> Dict[str, Any]:
        """Execute relationship cascade workflow with business logic coordination."""
        relationship_type = workflow_params['relationship_type']
        processed_entities = []
        errors = []
        
        # Create relationships between consecutive entities in the list
        for i in range(len(entities) - 1):
            try:
                source_entity = entities[i]
                target_entity = entities[i + 1]
                
                # Check if relationship already exists
                existing_rel = session.query(EntityRelationship).filter(
                    and_(
                        EntityRelationship.source_entity_id == source_entity.id,
                        EntityRelationship.target_entity_id == target_entity.id,
                        EntityRelationship.relationship_type == relationship_type,
                        EntityRelationship.is_active == True
                    )
                ).first()
                
                if not existing_rel:
                    relationship = EntityRelationship(
                        source_entity_id=source_entity.id,
                        target_entity_id=target_entity.id,
                        relationship_type=relationship_type,
                        is_active=True,
                        created_at=datetime.utcnow()
                    )
                    session.add(relationship)
                    processed_entities.append(f"{source_entity.id}->{target_entity.id}")
                
            except Exception as e:
                errors.append(f"Relationship {source_entity.id}->{target_entity.id}: {str(e)}")
        
        return {
            "processed_entities": processed_entities,
            "errors": errors,
            "summary": {"total_processed": len(processed_entities), "total_errors": len(errors)}
        }
    
    def _execute_ownership_transfer(
        self, 
        entities: List[BusinessEntity], 
        workflow_params: Dict[str, Any],
        session: Session
    ) -> Dict[str, Any]:
        """Execute ownership transfer workflow with validation."""
        new_owner_id = workflow_params['new_owner_id']
        processed_entities = []
        errors = []
        
        # Validate new owner exists
        new_owner = session.query(User).filter_by(id=new_owner_id).first()
        if not new_owner:
            return {
                "processed_entities": [],
                "errors": [f"New owner not found: {new_owner_id}"],
                "summary": {"total_processed": 0, "total_errors": 1}
            }
        
        for entity in entities:
            try:
                if entity.status != 'archived':
                    entity.owner_id = new_owner_id
                    entity.updated_at = datetime.utcnow()
                    processed_entities.append(entity.id)
                else:
                    errors.append(f"Entity {entity.id}: Cannot transfer ownership of archived entity")
            except Exception as e:
                errors.append(f"Entity {entity.id}: {str(e)}")
        
        return {
            "processed_entities": processed_entities,
            "errors": errors,
            "summary": {"total_processed": len(processed_entities), "total_errors": len(errors)}
        }
    
    def _execute_dependency_check(
        self, 
        entities: List[BusinessEntity], 
        workflow_params: Dict[str, Any],
        session: Session
    ) -> Dict[str, Any]:
        """Execute dependency check workflow for entities."""
        processed_entities = []
        dependency_report = {}
        
        for entity in entities:
            try:
                # Check incoming dependencies
                incoming_deps = session.query(EntityRelationship).filter(
                    and_(
                        EntityRelationship.target_entity_id == entity.id,
                        EntityRelationship.is_active == True
                    )
                ).count()
                
                # Check outgoing dependencies
                outgoing_deps = session.query(EntityRelationship).filter(
                    and_(
                        EntityRelationship.source_entity_id == entity.id,
                        EntityRelationship.is_active == True
                    )
                ).count()
                
                dependency_report[entity.id] = {
                    "incoming_dependencies": incoming_deps,
                    "outgoing_dependencies": outgoing_deps,
                    "total_dependencies": incoming_deps + outgoing_deps
                }
                
                processed_entities.append(entity.id)
            except Exception as e:
                dependency_report[entity.id] = {"error": str(e)}
        
        return {
            "processed_entities": processed_entities,
            "errors": [],
            "summary": {"total_processed": len(processed_entities), "dependency_report": dependency_report}
        }
    
    def _execute_cleanup_orphaned(
        self, 
        entities: List[BusinessEntity], 
        workflow_params: Dict[str, Any],
        session: Session
    ) -> Dict[str, Any]:
        """Execute cleanup workflow for orphaned entities."""
        processed_entities = []
        cleaned_relationships = 0
        
        for entity in entities:
            try:
                # Clean up inactive relationships
                inactive_rels = session.query(EntityRelationship).filter(
                    and_(
                        or_(
                            EntityRelationship.source_entity_id == entity.id,
                            EntityRelationship.target_entity_id == entity.id
                        ),
                        EntityRelationship.is_active == False
                    )
                ).count()
                
                session.query(EntityRelationship).filter(
                    and_(
                        or_(
                            EntityRelationship.source_entity_id == entity.id,
                            EntityRelationship.target_entity_id == entity.id
                        ),
                        EntityRelationship.is_active == False
                    )
                ).delete()
                
                cleaned_relationships += inactive_rels
                processed_entities.append(entity.id)
                
            except Exception as e:
                self.logger.warning(f"Cleanup failed for entity {entity.id}: {str(e)}")
        
        return {
            "processed_entities": processed_entities,
            "errors": [],
            "summary": {
                "total_processed": len(processed_entities), 
                "cleaned_relationships": cleaned_relationships
            }
        }