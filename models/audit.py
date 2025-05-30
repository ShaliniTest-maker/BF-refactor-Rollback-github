"""
Comprehensive Audit Logging and Security Event Models

This module implements Flask-SQLAlchemy declarative classes for complete audit trail management
and security monitoring. Provides detailed tracking of all database operations, user activities,
and security events throughout the application for compliance requirements and security analysis.

The audit system supports:
- Flask-SQLAlchemy 3.1.1 declarative model architecture
- PostgreSQL JSON column utilization for flexible audit data storage
- Comprehensive DML operation tracking (INSERT, UPDATE, DELETE)
- Security event monitoring with severity classification and context storage
- SQLAlchemy event hook integration for automatic audit trail generation
- User context tracking from Flask-Login sessions with timestamp accuracy
- Performance-optimized indexing for efficient audit queries
- Compliance-ready audit retention and archival procedures

Dependencies:
- Flask-SQLAlchemy 3.1.1: ORM functionality and declarative models
- PostgreSQL 14.12+: JSON column support and advanced indexing capabilities
- Flask-Login: User context capture for audit attribution
- models.base: BaseModel, AuditMixin, and database utilities
- models.user: User model integration for audit attribution
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from enum import Enum

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, JSON, Index,
    ForeignKey, CheckConstraint, event, text, UniqueConstraint
)
from sqlalchemy.orm import relationship, validates, backref
from sqlalchemy.dialects.postgresql import JSONB, INET
from flask import request, g
from flask_login import current_user
from werkzeug.exceptions import ValidationError

from .base import BaseModel, db, DatabaseManager
from .user import User


# Configure logging for audit operations
logger = logging.getLogger(__name__)


class AuditOperationType(Enum):
    """Enumeration of database operation types for audit logging"""
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    SELECT = "SELECT"
    BULK_INSERT = "BULK_INSERT"
    BULK_UPDATE = "BULK_UPDATE"
    BULK_DELETE = "BULK_DELETE"


class SecurityEventSeverity(Enum):
    """Enumeration of security event severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEventType(Enum):
    """Enumeration of security event types for classification"""
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    AUTHENTICATION_SUCCESS = "AUTHENTICATION_SUCCESS"
    AUTHORIZATION_VIOLATION = "AUTHORIZATION_VIOLATION"
    SESSION_ANOMALY = "SESSION_ANOMALY"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    DATA_ACCESS_VIOLATION = "DATA_ACCESS_VIOLATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    BRUTE_FORCE_ATTEMPT = "BRUTE_FORCE_ATTEMPT"
    ACCOUNT_LOCKOUT = "ACCOUNT_LOCKOUT"
    PASSWORD_POLICY_VIOLATION = "PASSWORD_POLICY_VIOLATION"
    CSRF_ATTEMPT = "CSRF_ATTEMPT"
    XSS_ATTEMPT = "XSS_ATTEMPT"
    SQL_INJECTION_ATTEMPT = "SQL_INJECTION_ATTEMPT"
    MALICIOUS_FILE_UPLOAD = "MALICIOUS_FILE_UPLOAD"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    SECURITY_CONFIGURATION_CHANGE = "SECURITY_CONFIGURATION_CHANGE"
    SYSTEM_INTEGRITY_VIOLATION = "SYSTEM_INTEGRITY_VIOLATION"


class AuditLog(BaseModel):
    """
    Comprehensive audit log model for tracking all database operations and data modifications.
    
    Provides complete audit trail functionality including:
    - DML operation tracking (INSERT, UPDATE, DELETE) with before/after change data
    - User attribution through Flask-Login session integration
    - PostgreSQL JSON column utilization for flexible change data storage
    - Performance-optimized indexing for efficient audit queries
    - Compliance-ready audit retention and query capabilities
    
    Database Design:
    - Primary key: Auto-incrementing integer for optimal performance
    - Foreign key: user_id references users.id for audit attribution
    - JSON columns: change_data stores before/after values with JSONB indexing
    - Indexes: Optimized for common audit query patterns
    
    Attributes:
        id: Primary key for audit log identification
        table_name: Name of the database table that was modified
        record_id: Primary key of the modified record
        operation_type: Type of database operation (INSERT, UPDATE, DELETE)
        user_id: Foreign key reference to User model for attribution
        session_id: Session identifier for request correlation
        change_data: JSON column storing before/after values and metadata
        ip_address: Client IP address for security correlation
        user_agent: Client user agent for request identification
        request_url: URL endpoint that triggered the database operation
        request_method: HTTP method (GET, POST, PUT, DELETE) for operation context
        execution_time_ms: Query execution time in milliseconds for performance monitoring
        transaction_id: Database transaction identifier for operation grouping
        
    Relationships:
        user: Many-to-one relationship with User model for audit attribution
        
    Database Indexes:
        - Primary key index on id for optimal join performance
        - Composite index on (table_name, record_id) for record-specific audit queries
        - Index on user_id for user-specific audit trail queries
        - Index on created_at for time-based audit queries and archival
        - Index on operation_type for filtering by operation type
        - GIN index on change_data JSONB for efficient JSON queries
        - Composite index on (table_name, created_at) for table-specific time queries
    """
    
    __tablename__ = 'audit_logs'
    
    # Core audit identification fields
    table_name = Column(String(100), nullable=False, index=True,
                       doc="Name of the database table that was modified")
    record_id = Column(String(50), nullable=True, index=True,
                      doc="Primary key of the modified record (stored as string for flexibility)")
    operation_type = Column(String(20), nullable=False, index=True,
                           doc="Type of database operation (INSERT, UPDATE, DELETE)")
    
    # User attribution and session tracking
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True,
                    doc="Foreign key reference to User model for audit attribution")
    session_id = Column(String(255), nullable=True,
                       doc="Session identifier for request correlation")
    
    # Comprehensive change data storage using PostgreSQL JSONB
    change_data = Column(JSONB, nullable=True,
                        doc="JSON column storing before/after values, metadata, and context")
    
    # Request context and security information
    ip_address = Column(INET, nullable=True,
                       doc="Client IP address for security correlation and geo-location")
    user_agent = Column(Text, nullable=True,
                       doc="Client user agent for request identification and device tracking")
    request_url = Column(String(500), nullable=True,
                        doc="URL endpoint that triggered the database operation")
    request_method = Column(String(10), nullable=True,
                           doc="HTTP method (GET, POST, PUT, DELETE) for operation context")
    
    # Performance and technical metadata
    execution_time_ms = Column(Integer, nullable=True,
                              doc="Query execution time in milliseconds for performance monitoring")
    transaction_id = Column(String(100), nullable=True,
                           doc="Database transaction identifier for operation grouping")
    
    # Additional audit metadata
    application_version = Column(String(50), nullable=True,
                                doc="Application version for change tracking across releases")
    environment = Column(String(20), nullable=True,
                        doc="Environment identifier (development, staging, production)")
    
    # Relationship with User model for audit attribution
    user = relationship('User', backref=backref('audit_logs', lazy='dynamic'),
                       doc="Many-to-one relationship with User model for audit attribution")
    
    # Database constraints and indexes for optimal performance
    __table_args__ = (
        # Composite indexes for common audit query patterns
        Index('idx_audit_table_record', 'table_name', 'record_id'),
        Index('idx_audit_table_time', 'table_name', 'created_at'),
        Index('idx_audit_user_time', 'user_id', 'created_at'),
        Index('idx_audit_operation_time', 'operation_type', 'created_at'),
        
        # GIN index for JSONB change_data queries
        Index('idx_audit_change_data_gin', 'change_data', postgresql_using='gin'),
        
        # Performance optimization indexes
        Index('idx_audit_session_time', 'session_id', 'created_at'),
        Index('idx_audit_ip_time', 'ip_address', 'created_at'),
        
        # Check constraints for data validation
        CheckConstraint(
            operation_type.in_(['INSERT', 'UPDATE', 'DELETE', 'SELECT', 'BULK_INSERT', 'BULK_UPDATE', 'BULK_DELETE']),
            name='ck_audit_operation_type_valid'
        ),
        CheckConstraint(
            "request_method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')",
            name='ck_audit_request_method_valid'
        ),
        CheckConstraint(
            'execution_time_ms >= 0',
            name='ck_audit_execution_time_positive'
        ),
        
        # Unique constraint for preventing duplicate audit entries
        UniqueConstraint('table_name', 'record_id', 'operation_type', 'created_at', 'user_id',
                        name='uq_audit_operation_uniqueness')
    )
    
    @validates('table_name')
    def validate_table_name(self, key, table_name):
        """Validate table name format and constraints"""
        if not table_name or len(table_name.strip()) == 0:
            raise ValueError("Table name cannot be empty")
        if len(table_name) > 100:
            raise ValueError("Table name cannot exceed 100 characters")
        if not table_name.replace('_', '').isalnum():
            raise ValueError("Table name can only contain alphanumeric characters and underscores")
        return table_name.strip().lower()
    
    @validates('operation_type')
    def validate_operation_type(self, key, operation_type):
        """Validate operation type against allowed values"""
        if operation_type not in [op.value for op in AuditOperationType]:
            raise ValueError(f"Invalid operation type: {operation_type}")
        return operation_type.upper()
    
    @validates('change_data')
    def validate_change_data(self, key, change_data):
        """Validate change data JSON structure"""
        if change_data is not None:
            if not isinstance(change_data, dict):
                raise ValueError("Change data must be a dictionary")
            
            # Validate required structure for UPDATE operations
            if self.operation_type == 'UPDATE' and change_data:
                if 'before' not in change_data and 'after' not in change_data:
                    raise ValueError("UPDATE operations must include 'before' and/or 'after' data")
        
        return change_data
    
    @classmethod
    def create_audit_entry(cls, table_name: str, record_id: Union[int, str], operation_type: str,
                          change_data: Optional[Dict[str, Any]] = None, user_id: Optional[int] = None,
                          additional_context: Optional[Dict[str, Any]] = None) -> 'AuditLog':
        """
        Create comprehensive audit log entry with automatic context capture.
        
        Args:
            table_name: Name of the database table that was modified
            record_id: Primary key of the modified record
            operation_type: Type of database operation (INSERT, UPDATE, DELETE)
            change_data: Dictionary containing before/after values and metadata
            user_id: User ID for audit attribution (auto-detected if not provided)
            additional_context: Additional context data to include in audit log
            
        Returns:
            Created AuditLog instance
            
        Raises:
            ValueError: If required parameters are invalid or missing
        """
        try:
            # Auto-detect user context if not provided
            if user_id is None:
                user_id = cls._get_current_user_id()
            
            # Capture request context
            request_context = cls._capture_request_context()
            
            # Build comprehensive change data
            comprehensive_change_data = {
                'operation_metadata': {
                    'timestamp': datetime.utcnow().isoformat(),
                    'operation_type': operation_type,
                    'table_name': table_name,
                    'record_id': str(record_id)
                }
            }
            
            if change_data:
                comprehensive_change_data['data_changes'] = change_data
            
            if additional_context:
                comprehensive_change_data['additional_context'] = additional_context
            
            # Create audit log entry
            audit_entry = cls(
                table_name=table_name,
                record_id=str(record_id),
                operation_type=operation_type,
                user_id=user_id,
                session_id=request_context.get('session_id'),
                change_data=comprehensive_change_data,
                ip_address=request_context.get('ip_address'),
                user_agent=request_context.get('user_agent'),
                request_url=request_context.get('request_url'),
                request_method=request_context.get('request_method'),
                application_version=os.environ.get('APP_VERSION', 'unknown'),
                environment=os.environ.get('FLASK_ENV', 'unknown')
            )
            
            db.session.add(audit_entry)
            logger.info(f"Created audit entry: {operation_type} on {table_name}#{record_id} by user {user_id}")
            
            return audit_entry
            
        except Exception as e:
            logger.error(f"Failed to create audit entry: {e}")
            raise ValueError(f"Failed to create audit entry: {str(e)}")
    
    @staticmethod
    def _get_current_user_id() -> Optional[int]:
        """Get current user ID from Flask-Login session or Flask g object"""
        try:
            # Try Flask-Login current_user
            if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
                return current_user.id
        except (RuntimeError, AttributeError):
            pass
        
        # Try Flask g object
        if hasattr(g, 'current_user_id'):
            return g.current_user_id
        
        return None
    
    @staticmethod
    def _capture_request_context() -> Dict[str, Optional[str]]:
        """Capture request context for audit logging"""
        context = {
            'session_id': None,
            'ip_address': None,
            'user_agent': None,
            'request_url': None,
            'request_method': None
        }
        
        try:
            if request:
                context.update({
                    'session_id': request.cookies.get('session'),
                    'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                    'user_agent': request.headers.get('User-Agent'),
                    'request_url': request.url,
                    'request_method': request.method
                })
        except RuntimeError:
            # Outside of request context
            pass
        
        return context
    
    def get_change_summary(self) -> Dict[str, Any]:
        """
        Get human-readable summary of changes from audit log entry.
        
        Returns:
            Dictionary containing change summary and metadata
        """
        summary = {
            'operation': self.operation_type,
            'table': self.table_name,
            'record': self.record_id,
            'timestamp': self.created_at.isoformat() if self.created_at else None,
            'user': self.user.username if self.user else 'system',
            'changes': []
        }
        
        if self.change_data and 'data_changes' in self.change_data:
            changes = self.change_data['data_changes']
            
            if self.operation_type == 'UPDATE' and 'before' in changes and 'after' in changes:
                before = changes['before']
                after = changes['after']
                
                for field, new_value in after.items():
                    old_value = before.get(field)
                    if old_value != new_value:
                        summary['changes'].append({
                            'field': field,
                            'old_value': old_value,
                            'new_value': new_value
                        })
            elif self.operation_type == 'INSERT' and 'after' in changes:
                summary['changes'] = [{'field': 'record_created', 'new_value': changes['after']}]
            elif self.operation_type == 'DELETE' and 'before' in changes:
                summary['changes'] = [{'field': 'record_deleted', 'old_value': changes['before']}]
        
        return summary
    
    @classmethod
    def get_audit_trail(cls, table_name: Optional[str] = None, record_id: Optional[str] = None,
                       user_id: Optional[int] = None, start_date: Optional[datetime] = None,
                       end_date: Optional[datetime] = None, operation_types: Optional[List[str]] = None,
                       limit: int = 100, offset: int = 0) -> List['AuditLog']:
        """
        Retrieve comprehensive audit trail with flexible filtering options.
        
        Args:
            table_name: Filter by specific table name
            record_id: Filter by specific record ID
            user_id: Filter by specific user ID
            start_date: Filter entries after this date
            end_date: Filter entries before this date
            operation_types: Filter by specific operation types
            limit: Maximum number of records to return
            offset: Number of records to skip for pagination
            
        Returns:
            List of AuditLog instances matching filter criteria
        """
        query = cls.query
        
        # Apply filters
        if table_name:
            query = query.filter(cls.table_name == table_name)
        if record_id:
            query = query.filter(cls.record_id == str(record_id))
        if user_id:
            query = query.filter(cls.user_id == user_id)
        if start_date:
            query = query.filter(cls.created_at >= start_date)
        if end_date:
            query = query.filter(cls.created_at <= end_date)
        if operation_types:
            query = query.filter(cls.operation_type.in_(operation_types))
        
        # Order by most recent first
        query = query.order_by(cls.created_at.desc())
        
        # Apply pagination
        query = query.offset(offset).limit(limit)
        
        return query.all()
    
    @classmethod
    def cleanup_old_audit_logs(cls, retention_days: int = 2555) -> int:
        """
        Clean up audit logs older than retention period.
        
        Args:
            retention_days: Number of days to retain audit logs (default: 7 years)
            
        Returns:
            Number of audit logs deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        try:
            deleted_count = cls.query.filter(cls.created_at < cutoff_date).delete()
            db.session.commit()
            
            logger.info(f"Cleaned up {deleted_count} audit logs older than {retention_days} days")
            return deleted_count
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to cleanup audit logs: {e}")
            raise
    
    def to_dict(self, include_sensitive: bool = False, include_change_data: bool = True) -> Dict[str, Any]:
        """
        Convert audit log to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive information
            include_change_data: Whether to include detailed change data
            
        Returns:
            Dictionary representation of the audit log
        """
        result = {
            'id': self.id,
            'table_name': self.table_name,
            'record_id': self.record_id,
            'operation_type': self.operation_type,
            'user_id': self.user_id,
            'user_name': self.user.username if self.user else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'request_method': self.request_method,
            'execution_time_ms': self.execution_time_ms,
            'environment': self.environment
        }
        
        if include_sensitive:
            result.update({
                'session_id': self.session_id,
                'ip_address': str(self.ip_address) if self.ip_address else None,
                'user_agent': self.user_agent,
                'request_url': self.request_url,
                'transaction_id': self.transaction_id,
                'application_version': self.application_version
            })
        
        if include_change_data and self.change_data:
            result['change_data'] = self.change_data
            result['change_summary'] = self.get_change_summary()
        
        return result
    
    def __repr__(self):
        """String representation of the audit log entry"""
        return (f"<AuditLog(id={self.id}, table={self.table_name}, "
                f"record={self.record_id}, operation={self.operation_type}, "
                f"user={self.user_id}, timestamp={self.created_at})>")


class SecurityEvent(BaseModel):
    """
    Security event model for comprehensive security monitoring and incident tracking.
    
    Provides complete security event management including:
    - Authentication failure and success tracking with context
    - Authorization violation monitoring with detailed incident data
    - Suspicious activity detection and pattern analysis
    - Security incident classification with severity levels
    - Real-time security monitoring integration with alerting systems
    - Compliance-ready security event retention and reporting
    
    Database Design:
    - Primary key: Auto-incrementing integer for optimal performance
    - Foreign key: user_id references users.id for security attribution
    - JSON columns: event_context stores detailed security event data
    - Indexes: Optimized for security monitoring and incident response queries
    
    Attributes:
        id: Primary key for security event identification
        event_type: Type of security event for classification and filtering
        severity: Security event severity level (LOW, MEDIUM, HIGH, CRITICAL)
        user_id: Foreign key reference to User model for attribution
        session_id: Session identifier for incident correlation
        event_context: JSON column storing detailed security event data and metadata
        ip_address: Client IP address for geo-location and threat analysis
        user_agent: Client user agent for device identification and analysis
        request_url: URL endpoint where security event occurred
        request_method: HTTP method for security context analysis
        threat_indicators: JSON array of threat indicators and IOCs
        response_action: Action taken in response to the security event
        resolved_at: Timestamp when security incident was resolved
        resolved_by: User who resolved the security incident
        incident_id: Reference to related security incident for correlation
        
    Relationships:
        user: Many-to-one relationship with User model for security attribution
        
    Database Indexes:
        - Primary key index on id for optimal join performance
        - Index on event_type for security event classification queries
        - Index on severity for filtering by threat level
        - Index on user_id for user-specific security event analysis
        - Index on created_at for time-based security analysis
        - Index on ip_address for geo-location and threat tracking
        - GIN index on event_context JSONB for efficient security data queries
        - Composite index on (event_type, severity, created_at) for security monitoring
    """
    
    __tablename__ = 'security_events'
    
    # Security event classification and severity
    event_type = Column(String(50), nullable=False, index=True,
                       doc="Type of security event for classification and filtering")
    severity = Column(String(20), nullable=False, index=True,
                     doc="Security event severity level (LOW, MEDIUM, HIGH, CRITICAL)")
    
    # User attribution and session tracking
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True,
                    doc="Foreign key reference to User model for security attribution")
    session_id = Column(String(255), nullable=True,
                       doc="Session identifier for incident correlation")
    
    # Comprehensive security event context using PostgreSQL JSONB
    event_context = Column(JSONB, nullable=True,
                          doc="JSON column storing detailed security event data and metadata")
    
    # Request context and threat analysis
    ip_address = Column(INET, nullable=True, index=True,
                       doc="Client IP address for geo-location and threat analysis")
    user_agent = Column(Text, nullable=True,
                       doc="Client user agent for device identification and analysis")
    request_url = Column(String(500), nullable=True,
                        doc="URL endpoint where security event occurred")
    request_method = Column(String(10), nullable=True,
                           doc="HTTP method for security context analysis")
    
    # Threat intelligence and indicators
    threat_indicators = Column(JSONB, nullable=True,
                              doc="JSON array of threat indicators and IOCs")
    risk_score = Column(Integer, nullable=True,
                       doc="Calculated risk score for the security event (0-100)")
    
    # Incident response and resolution
    response_action = Column(String(100), nullable=True,
                            doc="Action taken in response to the security event")
    resolved_at = Column(DateTime, nullable=True,
                        doc="Timestamp when security incident was resolved")
    resolved_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True,
                        doc="User who resolved the security incident")
    incident_id = Column(String(100), nullable=True,
                        doc="Reference to related security incident for correlation")
    
    # Additional security metadata
    detection_method = Column(String(50), nullable=True,
                             doc="Method used to detect the security event")
    false_positive = Column(Boolean, default=False, nullable=False,
                           doc="Flag indicating if event was determined to be false positive")
    
    # Relationship with User model for security attribution
    user = relationship('User', foreign_keys=[user_id],
                       backref=backref('security_events', lazy='dynamic'),
                       doc="Many-to-one relationship with User model for security attribution")
    resolver = relationship('User', foreign_keys=[resolved_by],
                           doc="User who resolved the security incident")
    
    # Database constraints and indexes for optimal security monitoring
    __table_args__ = (
        # Composite indexes for security monitoring queries
        Index('idx_security_type_severity_time', 'event_type', 'severity', 'created_at'),
        Index('idx_security_user_time', 'user_id', 'created_at'),
        Index('idx_security_ip_time', 'ip_address', 'created_at'),
        Index('idx_security_severity_time', 'severity', 'created_at'),
        
        # GIN index for JSONB security context queries
        Index('idx_security_context_gin', 'event_context', postgresql_using='gin'),
        Index('idx_security_threats_gin', 'threat_indicators', postgresql_using='gin'),
        
        # Security monitoring optimization indexes
        Index('idx_security_incident_correlation', 'incident_id', 'created_at'),
        Index('idx_security_response_tracking', 'response_action', 'resolved_at'),
        
        # Check constraints for data validation
        CheckConstraint(
            severity.in_(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
            name='ck_security_severity_valid'
        ),
        CheckConstraint(
            'risk_score >= 0 AND risk_score <= 100',
            name='ck_security_risk_score_range'
        ),
        CheckConstraint(
            '(resolved_at IS NULL AND resolved_by IS NULL) OR (resolved_at IS NOT NULL)',
            name='ck_security_resolution_consistency'
        ),
        
        # Performance optimization constraints
        CheckConstraint(
            "request_method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')",
            name='ck_security_request_method_valid'
        )
    )
    
    @validates('event_type')
    def validate_event_type(self, key, event_type):
        """Validate security event type against allowed values"""
        if event_type not in [event.value for event in SecurityEventType]:
            raise ValueError(f"Invalid security event type: {event_type}")
        return event_type.upper()
    
    @validates('severity')
    def validate_severity(self, key, severity):
        """Validate security event severity against allowed values"""
        if severity not in [sev.value for sev in SecurityEventSeverity]:
            raise ValueError(f"Invalid security event severity: {severity}")
        return severity.upper()
    
    @validates('risk_score')
    def validate_risk_score(self, key, risk_score):
        """Validate risk score range"""
        if risk_score is not None:
            if not isinstance(risk_score, int) or risk_score < 0 or risk_score > 100:
                raise ValueError("Risk score must be an integer between 0 and 100")
        return risk_score
    
    @validates('event_context')
    def validate_event_context(self, key, event_context):
        """Validate security event context JSON structure"""
        if event_context is not None:
            if not isinstance(event_context, dict):
                raise ValueError("Event context must be a dictionary")
            
            # Validate required security context fields
            required_fields = ['timestamp', 'event_description']
            for field in required_fields:
                if field not in event_context:
                    logger.warning(f"Security event context missing recommended field: {field}")
        
        return event_context
    
    @classmethod
    def create_security_event(cls, event_type: str, severity: str, description: str,
                             user_id: Optional[int] = None, event_context: Optional[Dict[str, Any]] = None,
                             threat_indicators: Optional[List[str]] = None,
                             risk_score: Optional[int] = None) -> 'SecurityEvent':
        """
        Create comprehensive security event with automatic context capture.
        
        Args:
            event_type: Type of security event (from SecurityEventType enum)
            severity: Security event severity level (from SecurityEventSeverity enum)
            description: Human-readable description of the security event
            user_id: User ID for security attribution (auto-detected if not provided)
            event_context: Additional context data for the security event
            threat_indicators: List of threat indicators and IOCs
            risk_score: Calculated risk score for the event (0-100)
            
        Returns:
            Created SecurityEvent instance
            
        Raises:
            ValueError: If required parameters are invalid or missing
        """
        try:
            # Auto-detect user context if not provided
            if user_id is None:
                user_id = cls._get_current_user_id()
            
            # Capture request context
            request_context = cls._capture_request_context()
            
            # Build comprehensive event context
            comprehensive_context = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_description': description,
                'detection_timestamp': datetime.utcnow().isoformat(),
                'source': 'flask_application'
            }
            
            if event_context:
                comprehensive_context.update(event_context)
            
            # Add request context to event data
            if request_context:
                comprehensive_context['request_context'] = request_context
            
            # Calculate risk score if not provided
            if risk_score is None:
                risk_score = cls._calculate_risk_score(event_type, severity, threat_indicators)
            
            # Create security event entry
            security_event = cls(
                event_type=event_type,
                severity=severity,
                user_id=user_id,
                session_id=request_context.get('session_id'),
                event_context=comprehensive_context,
                ip_address=request_context.get('ip_address'),
                user_agent=request_context.get('user_agent'),
                request_url=request_context.get('request_url'),
                request_method=request_context.get('request_method'),
                threat_indicators=threat_indicators,
                risk_score=risk_score,
                detection_method='automated'
            )
            
            db.session.add(security_event)
            logger.warning(f"Created security event: {event_type} ({severity}) for user {user_id}")
            
            # Trigger real-time alerting for high-severity events
            if severity in ['HIGH', 'CRITICAL']:
                cls._trigger_security_alert(security_event)
            
            return security_event
            
        except Exception as e:
            logger.error(f"Failed to create security event: {e}")
            raise ValueError(f"Failed to create security event: {str(e)}")
    
    @staticmethod
    def _get_current_user_id() -> Optional[int]:
        """Get current user ID from Flask-Login session or Flask g object"""
        try:
            # Try Flask-Login current_user
            if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
                return current_user.id
        except (RuntimeError, AttributeError):
            pass
        
        # Try Flask g object
        if hasattr(g, 'current_user_id'):
            return g.current_user_id
        
        return None
    
    @staticmethod
    def _capture_request_context() -> Dict[str, Optional[str]]:
        """Capture request context for security event logging"""
        context = {
            'session_id': None,
            'ip_address': None,
            'user_agent': None,
            'request_url': None,
            'request_method': None
        }
        
        try:
            if request:
                context.update({
                    'session_id': request.cookies.get('session'),
                    'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                    'user_agent': request.headers.get('User-Agent'),
                    'request_url': request.url,
                    'request_method': request.method
                })
        except RuntimeError:
            # Outside of request context
            pass
        
        return context
    
    @staticmethod
    def _calculate_risk_score(event_type: str, severity: str, threat_indicators: Optional[List[str]] = None) -> int:
        """Calculate risk score based on event characteristics"""
        base_scores = {
            'LOW': 20,
            'MEDIUM': 40,
            'HIGH': 70,
            'CRITICAL': 90
        }
        
        risk_score = base_scores.get(severity, 20)
        
        # Adjust score based on event type
        high_risk_events = [
            'AUTHENTICATION_FAILURE',
            'AUTHORIZATION_VIOLATION',
            'PRIVILEGE_ESCALATION',
            'SQL_INJECTION_ATTEMPT',
            'SYSTEM_INTEGRITY_VIOLATION'
        ]
        
        if event_type in high_risk_events:
            risk_score = min(100, risk_score + 15)
        
        # Adjust score based on threat indicators
        if threat_indicators:
            risk_score = min(100, risk_score + len(threat_indicators) * 5)
        
        return risk_score
    
    @staticmethod
    def _trigger_security_alert(security_event: 'SecurityEvent') -> None:
        """Trigger real-time security alert for high-severity events"""
        try:
            # Log immediate alert
            logger.critical(f"HIGH-SEVERITY SECURITY EVENT: {security_event.event_type} "
                           f"({security_event.severity}) - Risk Score: {security_event.risk_score}")
            
            # Here you would integrate with your alerting system
            # Examples: Send to Slack, PagerDuty, email notifications, etc.
            
        except Exception as e:
            logger.error(f"Failed to trigger security alert: {e}")
    
    def resolve_event(self, resolved_by_user_id: int, resolution_notes: Optional[str] = None,
                     false_positive: bool = False) -> None:
        """
        Mark security event as resolved with resolution tracking.
        
        Args:
            resolved_by_user_id: ID of user resolving the security event
            resolution_notes: Optional notes about the resolution
            false_positive: Whether the event was determined to be a false positive
        """
        self.resolved_at = datetime.utcnow()
        self.resolved_by = resolved_by_user_id
        self.false_positive = false_positive
        
        # Add resolution notes to event context
        if not self.event_context:
            self.event_context = {}
        
        self.event_context['resolution'] = {
            'resolved_at': self.resolved_at.isoformat(),
            'resolved_by': resolved_by_user_id,
            'notes': resolution_notes,
            'false_positive': false_positive
        }
        
        logger.info(f"Security event {self.id} resolved by user {resolved_by_user_id}")
    
    @classmethod
    def get_security_dashboard_data(cls, start_date: Optional[datetime] = None,
                                   end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Get comprehensive security dashboard data for monitoring and analysis.
        
        Args:
            start_date: Start date for analysis period
            end_date: End date for analysis period
            
        Returns:
            Dictionary containing security metrics and analysis data
        """
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()
        
        query = cls.query.filter(cls.created_at >= start_date, cls.created_at <= end_date)
        
        # Event counts by severity
        severity_counts = db.session.query(
            cls.severity, db.func.count(cls.id)
        ).filter(cls.created_at >= start_date, cls.created_at <= end_date).group_by(cls.severity).all()
        
        # Event counts by type
        type_counts = db.session.query(
            cls.event_type, db.func.count(cls.id)
        ).filter(cls.created_at >= start_date, cls.created_at <= end_date).group_by(cls.event_type).all()
        
        # Top threat IPs
        ip_counts = db.session.query(
            cls.ip_address, db.func.count(cls.id)
        ).filter(
            cls.created_at >= start_date,
            cls.created_at <= end_date,
            cls.ip_address.isnot(None)
        ).group_by(cls.ip_address).order_by(db.func.count(cls.id).desc()).limit(10).all()
        
        return {
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'total_events': query.count(),
            'unresolved_events': query.filter(cls.resolved_at.is_(None)).count(),
            'high_severity_events': query.filter(cls.severity.in_(['HIGH', 'CRITICAL'])).count(),
            'severity_distribution': dict(severity_counts),
            'event_type_distribution': dict(type_counts),
            'top_threat_ips': [{'ip': str(ip), 'count': count} for ip, count in ip_counts],
            'average_risk_score': db.session.query(db.func.avg(cls.risk_score)).filter(
                cls.created_at >= start_date, cls.created_at <= end_date
            ).scalar() or 0
        }
    
    @classmethod
    def cleanup_old_security_events(cls, retention_days: int = 2555) -> int:
        """
        Clean up security events older than retention period.
        
        Args:
            retention_days: Number of days to retain security events (default: 7 years)
            
        Returns:
            Number of security events deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        try:
            # Only delete resolved events or low-severity events
            deleted_count = cls.query.filter(
                cls.created_at < cutoff_date,
                db.or_(
                    cls.resolved_at.isnot(None),
                    cls.severity == 'LOW'
                )
            ).delete()
            
            db.session.commit()
            
            logger.info(f"Cleaned up {deleted_count} security events older than {retention_days} days")
            return deleted_count
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to cleanup security events: {e}")
            raise
    
    def to_dict(self, include_sensitive: bool = False, include_context: bool = True) -> Dict[str, Any]:
        """
        Convert security event to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive information
            include_context: Whether to include detailed event context
            
        Returns:
            Dictionary representation of the security event
        """
        result = {
            'id': self.id,
            'event_type': self.event_type,
            'severity': self.severity,
            'user_id': self.user_id,
            'user_name': self.user.username if self.user else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'risk_score': self.risk_score,
            'detection_method': self.detection_method,
            'false_positive': self.false_positive,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolved_by': self.resolved_by,
            'incident_id': self.incident_id
        }
        
        if include_sensitive:
            result.update({
                'session_id': self.session_id,
                'ip_address': str(self.ip_address) if self.ip_address else None,
                'user_agent': self.user_agent,
                'request_url': self.request_url,
                'request_method': self.request_method,
                'threat_indicators': self.threat_indicators
            })
        
        if include_context and self.event_context:
            result['event_context'] = self.event_context
        
        return result
    
    def __repr__(self):
        """String representation of the security event"""
        return (f"<SecurityEvent(id={self.id}, type={self.event_type}, "
                f"severity={self.severity}, user={self.user_id}, "
                f"risk_score={self.risk_score}, timestamp={self.created_at})>")


# SQLAlchemy event listeners for automatic audit trail generation
@event.listens_for(db.session, 'before_commit')
def capture_audit_changes(session):
    """
    SQLAlchemy event hook for automatic audit trail generation.
    
    Captures all database changes (INSERT, UPDATE, DELETE) and creates corresponding
    audit log entries with user context, change data, and request information.
    
    Args:
        session: SQLAlchemy session about to commit
    """
    try:
        # Skip audit logging for audit tables to prevent recursion
        audit_tables = {'audit_logs', 'security_events'}
        
        # Capture user context
        user_id = AuditLog._get_current_user_id()
        request_context = AuditLog._capture_request_context()
        
        # Process new objects (INSERT operations)
        for obj in session.new:
            if obj.__tablename__ not in audit_tables:
                try:
                    change_data = {
                        'after': {column.name: getattr(obj, column.name, None) 
                                for column in obj.__table__.columns}
                    }
                    
                    # Create audit entry (will be added to session after current commit)
                    audit_entry_data = {
                        'table_name': obj.__tablename__,
                        'record_id': str(getattr(obj, 'id', 'unknown')),
                        'operation_type': 'INSERT',
                        'user_id': user_id,
                        'session_id': request_context.get('session_id'),
                        'change_data': change_data,
                        'ip_address': request_context.get('ip_address'),
                        'user_agent': request_context.get('user_agent'),
                        'request_url': request_context.get('request_url'),
                        'request_method': request_context.get('request_method'),
                        'application_version': os.environ.get('APP_VERSION', 'unknown'),
                        'environment': os.environ.get('FLASK_ENV', 'unknown')
                    }
                    
                    # Store for post-commit processing
                    if not hasattr(session, '_audit_entries'):
                        session._audit_entries = []
                    session._audit_entries.append(audit_entry_data)
                    
                except Exception as e:
                    logger.error(f"Error capturing INSERT audit for {obj.__tablename__}: {e}")
        
        # Process modified objects (UPDATE operations)
        for obj in session.dirty:
            if obj.__tablename__ not in audit_tables:
                try:
                    # Get original values
                    original_values = {}
                    for attr in session.identity_map.all_states():
                        if attr.object is obj:
                            for column in obj.__table__.columns:
                                original_values[column.name] = attr.committed_state.get(column.name)
                            break
                    
                    # Get current values
                    current_values = {column.name: getattr(obj, column.name, None) 
                                    for column in obj.__table__.columns}
                    
                    # Only log if there are actual changes
                    changes_detected = any(original_values.get(k) != v for k, v in current_values.items())
                    
                    if changes_detected:
                        change_data = {
                            'before': original_values,
                            'after': current_values
                        }
                        
                        # Create audit entry (will be added to session after current commit)
                        audit_entry_data = {
                            'table_name': obj.__tablename__,
                            'record_id': str(getattr(obj, 'id', 'unknown')),
                            'operation_type': 'UPDATE',
                            'user_id': user_id,
                            'session_id': request_context.get('session_id'),
                            'change_data': change_data,
                            'ip_address': request_context.get('ip_address'),
                            'user_agent': request_context.get('user_agent'),
                            'request_url': request_context.get('request_url'),
                            'request_method': request_context.get('request_method'),
                            'application_version': os.environ.get('APP_VERSION', 'unknown'),
                            'environment': os.environ.get('FLASK_ENV', 'unknown')
                        }
                        
                        # Store for post-commit processing
                        if not hasattr(session, '_audit_entries'):
                            session._audit_entries = []
                        session._audit_entries.append(audit_entry_data)
                        
                except Exception as e:
                    logger.error(f"Error capturing UPDATE audit for {obj.__tablename__}: {e}")
        
        # Process deleted objects (DELETE operations)
        for obj in session.deleted:
            if obj.__tablename__ not in audit_tables:
                try:
                    change_data = {
                        'before': {column.name: getattr(obj, column.name, None) 
                                 for column in obj.__table__.columns}
                    }
                    
                    # Create audit entry (will be added to session after current commit)
                    audit_entry_data = {
                        'table_name': obj.__tablename__,
                        'record_id': str(getattr(obj, 'id', 'unknown')),
                        'operation_type': 'DELETE',
                        'user_id': user_id,
                        'session_id': request_context.get('session_id'),
                        'change_data': change_data,
                        'ip_address': request_context.get('ip_address'),
                        'user_agent': request_context.get('user_agent'),
                        'request_url': request_context.get('request_url'),
                        'request_method': request_context.get('request_method'),
                        'application_version': os.environ.get('APP_VERSION', 'unknown'),
                        'environment': os.environ.get('FLASK_ENV', 'unknown')
                    }
                    
                    # Store for post-commit processing
                    if not hasattr(session, '_audit_entries'):
                        session._audit_entries = []
                    session._audit_entries.append(audit_entry_data)
                    
                except Exception as e:
                    logger.error(f"Error capturing DELETE audit for {obj.__tablename__}: {e}")
                    
    except Exception as e:
        logger.error(f"Error in audit capture event hook: {e}")


@event.listens_for(db.session, 'after_commit')
def process_audit_entries(session):
    """
    SQLAlchemy event hook for processing audit entries after successful commit.
    
    Creates audit log entries in a separate transaction to avoid interfering
    with the main business transaction.
    
    Args:
        session: SQLAlchemy session that was committed
    """
    try:
        if hasattr(session, '_audit_entries'):
            audit_entries = session._audit_entries
            
            # Create new session for audit entries
            with DatabaseManager.transaction():
                for audit_data in audit_entries:
                    try:
                        audit_entry = AuditLog(**audit_data)
                        db.session.add(audit_entry)
                    except Exception as e:
                        logger.error(f"Failed to create audit entry: {e}")
                        continue
            
            # Clean up
            delattr(session, '_audit_entries')
            
            logger.debug(f"Processed {len(audit_entries)} audit entries")
            
    except Exception as e:
        logger.error(f"Error processing audit entries: {e}")


@event.listens_for(db.session, 'after_rollback')
def cleanup_audit_entries(session):
    """
    SQLAlchemy event hook for cleaning up audit entries after rollback.
    
    Args:
        session: SQLAlchemy session that was rolled back
    """
    try:
        if hasattr(session, '_audit_entries'):
            delattr(session, '_audit_entries')
            logger.debug("Cleaned up audit entries after rollback")
    except Exception as e:
        logger.error(f"Error cleaning up audit entries: {e}")


# Utility functions for audit and security event management
class AuditManager:
    """
    Utility class for comprehensive audit and security event management.
    
    Provides high-level methods for audit trail analysis, security monitoring,
    and compliance reporting functionality.
    """
    
    @staticmethod
    def get_comprehensive_audit_report(start_date: datetime, end_date: datetime,
                                     include_security_events: bool = True) -> Dict[str, Any]:
        """
        Generate comprehensive audit report for specified time period.
        
        Args:
            start_date: Start date for audit report
            end_date: End date for audit report
            include_security_events: Whether to include security events in report
            
        Returns:
            Dictionary containing comprehensive audit report data
        """
        # Audit log statistics
        audit_stats = {
            'total_operations': AuditLog.query.filter(
                AuditLog.created_at >= start_date,
                AuditLog.created_at <= end_date
            ).count(),
            'operations_by_type': dict(
                db.session.query(AuditLog.operation_type, db.func.count(AuditLog.id))
                .filter(AuditLog.created_at >= start_date, AuditLog.created_at <= end_date)
                .group_by(AuditLog.operation_type).all()
            ),
            'operations_by_table': dict(
                db.session.query(AuditLog.table_name, db.func.count(AuditLog.id))
                .filter(AuditLog.created_at >= start_date, AuditLog.created_at <= end_date)
                .group_by(AuditLog.table_name).all()
            ),
            'unique_users': db.session.query(AuditLog.user_id).filter(
                AuditLog.created_at >= start_date,
                AuditLog.created_at <= end_date,
                AuditLog.user_id.isnot(None)
            ).distinct().count()
        }
        
        report = {
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'audit_statistics': audit_stats
        }
        
        # Include security events if requested
        if include_security_events:
            report['security_statistics'] = SecurityEvent.get_security_dashboard_data(
                start_date, end_date
            )
        
        return report
    
    @staticmethod
    def detect_anomalous_activity(user_id: Optional[int] = None,
                                 lookback_hours: int = 24) -> List[Dict[str, Any]]:
        """
        Detect anomalous activity patterns in audit logs.
        
        Args:
            user_id: Specific user ID to analyze (None for all users)
            lookback_hours: Hours to look back for anomaly detection
            
        Returns:
            List of detected anomalies with details
        """
        start_time = datetime.utcnow() - timedelta(hours=lookback_hours)
        anomalies = []
        
        # Query for suspicious patterns
        query = AuditLog.query.filter(AuditLog.created_at >= start_time)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        
        # Detect high-frequency operations
        operation_counts = db.session.query(
            AuditLog.user_id, AuditLog.operation_type, db.func.count(AuditLog.id)
        ).filter(AuditLog.created_at >= start_time).group_by(
            AuditLog.user_id, AuditLog.operation_type
        ).having(db.func.count(AuditLog.id) > 100).all()
        
        for user_id, operation_type, count in operation_counts:
            anomalies.append({
                'type': 'high_frequency_operations',
                'user_id': user_id,
                'operation_type': operation_type,
                'count': count,
                'threshold': 100,
                'severity': 'MEDIUM'
            })
        
        # Detect unusual table access patterns
        table_counts = db.session.query(
            AuditLog.user_id, AuditLog.table_name, db.func.count(AuditLog.id)
        ).filter(AuditLog.created_at >= start_time).group_by(
            AuditLog.user_id, AuditLog.table_name
        ).having(db.func.count(AuditLog.id) > 50).all()
        
        for user_id, table_name, count in table_counts:
            if table_name in ['users', 'security_events', 'audit_logs']:  # Sensitive tables
                anomalies.append({
                    'type': 'unusual_sensitive_table_access',
                    'user_id': user_id,
                    'table_name': table_name,
                    'count': count,
                    'threshold': 50,
                    'severity': 'HIGH'
                })
        
        return anomalies
    
    @staticmethod
    def ensure_audit_compliance() -> Dict[str, Any]:
        """
        Ensure audit system compliance and data integrity.
        
        Returns:
            Dictionary containing compliance status and recommendations
        """
        compliance_status = {
            'audit_coverage': True,
            'retention_compliance': True,
            'data_integrity': True,
            'recommendations': []
        }
        
        # Check audit coverage
        tables_with_audit = db.session.query(AuditLog.table_name).distinct().all()
        tables_with_audit = [table[0] for table in tables_with_audit]
        
        # Check for tables that should have audit coverage
        expected_tables = ['users', 'business_entities', 'user_sessions']
        missing_coverage = [table for table in expected_tables if table not in tables_with_audit]
        
        if missing_coverage:
            compliance_status['audit_coverage'] = False
            compliance_status['recommendations'].append(
                f"Enable audit coverage for tables: {', '.join(missing_coverage)}"
            )
        
        # Check retention compliance (should have logs from at least 1 year ago)
        one_year_ago = datetime.utcnow() - timedelta(days=365)
        old_logs_count = AuditLog.query.filter(AuditLog.created_at < one_year_ago).count()
        
        if old_logs_count == 0:
            compliance_status['recommendations'].append(
                "Consider implementing audit log archival for long-term retention"
            )
        
        # Check for audit log gaps
        latest_log = AuditLog.query.order_by(AuditLog.created_at.desc()).first()
        if latest_log:
            hours_since_last_log = (datetime.utcnow() - latest_log.created_at).total_seconds() / 3600
            if hours_since_last_log > 24:
                compliance_status['data_integrity'] = False
                compliance_status['recommendations'].append(
                    f"No audit logs in last {hours_since_last_log:.1f} hours - investigate audit system"
                )
        
        return compliance_status


# Export models and utilities for application use
__all__ = [
    'AuditLog',
    'SecurityEvent',
    'AuditOperationType',
    'SecurityEventSeverity',
    'SecurityEventType',
    'AuditManager'
]