"""
Comprehensive audit logging and security event models implementing Flask-SQLAlchemy declarative classes 
for complete audit trail management and security monitoring.

This module provides:
- AuditLog model for comprehensive DML operation tracking (INSERT, UPDATE, DELETE)
- SecurityEvent model for tracking authentication failures, authorization violations, and security incidents
- SQLAlchemy event hooks for automatic audit trail generation with user context tracking
- PostgreSQL JSON column utilization for flexible audit data storage with proper indexing
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional, Union
from sqlalchemy import Column, Integer, String, DateTime, Text, Index, event, text
from sqlalchemy.dialects.postgresql import JSON, JSONB
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import Session
from flask import request, g, has_request_context
from flask_sqlalchemy import SQLAlchemy
from werkzeug.user_agent import UserAgent

# Import base components (these would be defined in base.py)
try:
    from .base import db, AuditMixin
except ImportError:
    # Fallback for standalone testing - define minimal base components
    from flask_sqlalchemy import SQLAlchemy
    from sqlalchemy.ext.declarative import declarative_base
    
    db = SQLAlchemy()
    
    class AuditMixin:
        """Base audit mixin providing common audit fields"""
        
        @declared_attr
        def created_at(cls):
            return db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
        
        @declared_attr
        def updated_at(cls):
            return db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
        
        @declared_attr
        def created_by(cls):
            return db.Column(db.String(255), nullable=True)
        
        @declared_attr
        def updated_by(cls):
            return db.Column(db.String(255), nullable=True)

# Configure logger for audit operations
audit_logger = logging.getLogger('audit')


class AuditLog(db.Model, AuditMixin):
    """
    Comprehensive audit logging model for tracking all database operations (DML events).
    
    Provides detailed tracking of INSERT, UPDATE, and DELETE operations with:
    - Complete change data capture using PostgreSQL JSON columns
    - User attribution from Flask-Login sessions
    - Timestamp accuracy and operation context
    - Optimized indexing for efficient audit queries
    """
    
    __tablename__ = 'audit_logs'
    
    # Primary identification fields
    id = db.Column(db.Integer, primary_key=True)
    
    # Core audit tracking fields
    table_name = db.Column(db.String(100), nullable=False, index=True)
    record_id = db.Column(db.String(50), nullable=True, index=True)  # String to handle various ID types
    operation_type = db.Column(db.String(10), nullable=False, index=True)  # INSERT, UPDATE, DELETE
    
    # User and session context
    user_id = db.Column(db.String(255), nullable=True, index=True)
    username = db.Column(db.String(255), nullable=True)
    session_id = db.Column(db.String(255), nullable=True)
    
    # Request context information
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.Text, nullable=True)
    request_method = db.Column(db.String(10), nullable=True)
    request_path = db.Column(db.String(500), nullable=True)
    
    # Change data capture using PostgreSQL JSONB for performance
    # JSONB provides better query performance and indexing compared to JSON
    old_values = db.Column(JSONB, nullable=True)
    new_values = db.Column(JSONB, nullable=True)
    changes = db.Column(JSONB, nullable=True)  # Computed diff of old vs new values
    
    # Additional audit metadata
    operation_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    transaction_id = db.Column(db.String(255), nullable=True)
    
    # Error handling for failed operations
    error_message = db.Column(db.Text, nullable=True)
    
    # Composite indexes for efficient audit queries
    __table_args__ = (
        # Primary audit query patterns
        Index('idx_audit_table_operation_time', 'table_name', 'operation_type', 'operation_timestamp'),
        Index('idx_audit_user_time', 'user_id', 'operation_timestamp'),
        Index('idx_audit_record_tracking', 'table_name', 'record_id', 'operation_timestamp'),
        
        # Security monitoring indexes
        Index('idx_audit_ip_time', 'ip_address', 'operation_timestamp'),
        Index('idx_audit_session_tracking', 'session_id', 'operation_timestamp'),
        
        # JSONB GIN indexes for efficient JSON queries
        Index('idx_audit_changes_gin', 'changes', postgresql_using='gin'),
        Index('idx_audit_new_values_gin', 'new_values', postgresql_using='gin'),
    )
    
    def __init__(self, **kwargs):
        """Initialize audit log entry with automatic context capture"""
        super().__init__(**kwargs)
        self._capture_request_context()
    
    def _capture_request_context(self):
        """Capture Flask request context for audit trail"""
        if has_request_context():
            self.ip_address = self._get_client_ip()
            self.user_agent = request.headers.get('User-Agent', '')[:1000]  # Truncate long user agents
            self.request_method = request.method
            self.request_path = request.path[:500]  # Truncate long paths
            
            # Capture session ID if available
            if hasattr(g, 'session_id'):
                self.session_id = g.session_id
            
            # Capture user context from Flask-Login or custom auth
            if hasattr(g, 'current_user_id'):
                self.user_id = str(g.current_user_id)
            if hasattr(g, 'current_username'):
                self.username = g.current_username
    
    def _get_client_ip(self) -> Optional[str]:
        """Extract client IP address handling proxy headers"""
        if request:
            # Check for forwarded IP (load balancer/proxy)
            forwarded_for = request.headers.get('X-Forwarded-For')
            if forwarded_for:
                return forwarded_for.split(',')[0].strip()
            
            # Check for real IP header
            real_ip = request.headers.get('X-Real-IP')
            if real_ip:
                return real_ip.strip()
            
            # Fallback to remote address
            return request.remote_addr
        
        return None
    
    def compute_changes(self):
        """Compute change diff between old and new values"""
        if self.old_values and self.new_values:
            changes = {}
            
            # Find changed fields
            for key, new_value in self.new_values.items():
                old_value = self.old_values.get(key)
                if old_value != new_value:
                    changes[key] = {
                        'old': old_value,
                        'new': new_value
                    }
            
            # Find removed fields (present in old but not in new)
            for key, old_value in self.old_values.items():
                if key not in self.new_values:
                    changes[key] = {
                        'old': old_value,
                        'new': None
                    }
            
            self.changes = changes if changes else None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit log to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'table_name': self.table_name,
            'record_id': self.record_id,
            'operation_type': self.operation_type,
            'user_id': self.user_id,
            'username': self.username,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'request_method': self.request_method,
            'request_path': self.request_path,
            'old_values': self.old_values,
            'new_values': self.new_values,
            'changes': self.changes,
            'operation_timestamp': self.operation_timestamp.isoformat() if self.operation_timestamp else None,
            'transaction_id': self.transaction_id,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by
        }
    
    @classmethod
    def create_audit_entry(cls, table_name: str, record_id: Union[str, int], operation_type: str,
                          old_values: Optional[Dict] = None, new_values: Optional[Dict] = None,
                          error_message: Optional[str] = None) -> 'AuditLog':
        """
        Create a new audit log entry with comprehensive change tracking.
        
        Args:
            table_name: Name of the table being modified
            record_id: ID of the record being modified
            operation_type: Type of operation (INSERT, UPDATE, DELETE)
            old_values: Previous values (for UPDATE/DELETE)
            new_values: New values (for INSERT/UPDATE)
            error_message: Error message if operation failed
            
        Returns:
            AuditLog: Created audit log entry
        """
        audit_entry = cls(
            table_name=table_name,
            record_id=str(record_id) if record_id is not None else None,
            operation_type=operation_type.upper(),
            old_values=old_values,
            new_values=new_values,
            error_message=error_message
        )
        
        # Compute changes for UPDATE operations
        if operation_type.upper() == 'UPDATE' and old_values and new_values:
            audit_entry.compute_changes()
        
        return audit_entry
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, table='{self.table_name}', operation='{self.operation_type}', record_id='{self.record_id}')>"


class SecurityEvent(db.Model, AuditMixin):
    """
    Security event model for tracking authentication failures, authorization violations,
    suspicious activities, and security incidents.
    
    Provides comprehensive security monitoring with:
    - Severity classification for threat assessment
    - Context storage for incident analysis
    - Integration with security monitoring systems
    - Real-time alerting capabilities
    """
    
    __tablename__ = 'security_events'
    
    # Primary identification
    id = db.Column(db.Integer, primary_key=True)
    
    # Event classification
    event_type = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Event description and details
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    
    # Security context
    user_id = db.Column(db.String(255), nullable=True, index=True)
    username = db.Column(db.String(255), nullable=True)
    session_id = db.Column(db.String(255), nullable=True)
    
    # Request and network context
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    user_agent = db.Column(db.Text, nullable=True)
    request_method = db.Column(db.String(10), nullable=True)
    request_path = db.Column(db.String(500), nullable=True)
    
    # Event metadata and context
    event_data = db.Column(JSONB, nullable=True)  # Flexible storage for event-specific data
    additional_context = db.Column(JSONB, nullable=True)  # Additional security context
    
    # Event timing
    event_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Incident tracking
    incident_id = db.Column(db.String(255), nullable=True, index=True)
    correlation_id = db.Column(db.String(255), nullable=True, index=True)
    
    # Response tracking
    resolved = db.Column(db.Boolean, default=False, nullable=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.String(255), nullable=True)
    resolution_notes = db.Column(db.Text, nullable=True)
    
    # Risk assessment
    risk_score = db.Column(db.Integer, nullable=True)  # 0-100 risk score
    threat_indicators = db.Column(JSONB, nullable=True)  # Array of threat indicators
    
    # Composite indexes for security monitoring
    __table_args__ = (
        # Primary security monitoring patterns
        Index('idx_security_severity_time', 'severity', 'event_timestamp'),
        Index('idx_security_type_time', 'event_type', 'event_timestamp'),
        Index('idx_security_user_time', 'user_id', 'event_timestamp'),
        
        # Incident response indexes
        Index('idx_security_unresolved', 'resolved', 'severity', 'event_timestamp'),
        Index('idx_security_incident_tracking', 'incident_id', 'event_timestamp'),
        Index('idx_security_correlation', 'correlation_id', 'event_timestamp'),
        
        # Network security monitoring
        Index('idx_security_ip_time', 'ip_address', 'event_timestamp'),
        Index('idx_security_ip_type', 'ip_address', 'event_type'),
        
        # JSONB indexes for flexible querying
        Index('idx_security_event_data_gin', 'event_data', postgresql_using='gin'),
        Index('idx_security_threat_indicators_gin', 'threat_indicators', postgresql_using='gin'),
    )
    
    # Security event type constants
    EVENT_TYPES = {
        'AUTHENTICATION_FAILURE': 'authentication_failure',
        'AUTHORIZATION_VIOLATION': 'authorization_violation',
        'SUSPICIOUS_ACTIVITY': 'suspicious_activity',
        'BRUTE_FORCE_ATTEMPT': 'brute_force_attempt',
        'ACCOUNT_LOCKOUT': 'account_lockout',
        'PRIVILEGE_ESCALATION': 'privilege_escalation',
        'DATA_ACCESS_VIOLATION': 'data_access_violation',
        'SESSION_ANOMALY': 'session_anomaly',
        'MALICIOUS_REQUEST': 'malicious_request',
        'SECURITY_BREACH': 'security_breach'
    }
    
    # Severity levels
    SEVERITY_LEVELS = {
        'LOW': 'LOW',
        'MEDIUM': 'MEDIUM', 
        'HIGH': 'HIGH',
        'CRITICAL': 'CRITICAL'
    }
    
    def __init__(self, **kwargs):
        """Initialize security event with automatic context capture"""
        super().__init__(**kwargs)
        self._capture_security_context()
    
    def _capture_security_context(self):
        """Capture comprehensive security context"""
        if has_request_context():
            self.ip_address = self._get_client_ip()
            self.user_agent = request.headers.get('User-Agent', '')[:1000]
            self.request_method = request.method
            self.request_path = request.path[:500]
            
            # Capture session and user context
            if hasattr(g, 'session_id'):
                self.session_id = g.session_id
            if hasattr(g, 'current_user_id'):
                self.user_id = str(g.current_user_id)
            if hasattr(g, 'current_username'):
                self.username = g.current_username
            
            # Capture additional security context
            security_context = {
                'headers': dict(request.headers),
                'referrer': request.referrer,
                'endpoint': request.endpoint,
                'remote_addr': request.remote_addr
            }
            
            # Remove sensitive headers
            security_context['headers'].pop('Authorization', None)
            security_context['headers'].pop('Cookie', None)
            
            self.additional_context = security_context
    
    def _get_client_ip(self) -> Optional[str]:
        """Extract client IP address handling proxy headers"""
        if request:
            # Check for forwarded IP (load balancer/proxy)
            forwarded_for = request.headers.get('X-Forwarded-For')
            if forwarded_for:
                return forwarded_for.split(',')[0].strip()
            
            # Check for real IP header
            real_ip = request.headers.get('X-Real-IP')
            if real_ip:
                return real_ip.strip()
            
            # Fallback to remote address
            return request.remote_addr
        
        return None
    
    def calculate_risk_score(self) -> int:
        """Calculate risk score based on severity and event type"""
        base_scores = {
            'CRITICAL': 90,
            'HIGH': 70,
            'MEDIUM': 40,
            'LOW': 10
        }
        
        base_score = base_scores.get(self.severity, 10)
        
        # Adjust based on event type
        high_risk_events = [
            'SECURITY_BREACH', 'PRIVILEGE_ESCALATION', 'BRUTE_FORCE_ATTEMPT'
        ]
        
        if self.event_type in high_risk_events:
            base_score = min(100, base_score + 20)
        
        # Adjust for repeat offenders
        if self.user_id:
            recent_events = SecurityEvent.query.filter(
                SecurityEvent.user_id == self.user_id,
                SecurityEvent.event_timestamp >= datetime.utcnow().replace(hour=0, minute=0, second=0),
                SecurityEvent.id != self.id
            ).count()
            
            if recent_events > 5:
                base_score = min(100, base_score + 15)
        
        self.risk_score = base_score
        return base_score
    
    def resolve_event(self, resolved_by: str, resolution_notes: str = None):
        """Mark security event as resolved"""
        self.resolved = True
        self.resolved_at = datetime.utcnow()
        self.resolved_by = resolved_by
        self.resolution_notes = resolution_notes
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert security event to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'event_type': self.event_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'user_id': self.user_id,
            'username': self.username,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'request_method': self.request_method,
            'request_path': self.request_path,
            'event_data': self.event_data,
            'additional_context': self.additional_context,
            'event_timestamp': self.event_timestamp.isoformat() if self.event_timestamp else None,
            'incident_id': self.incident_id,
            'correlation_id': self.correlation_id,
            'resolved': self.resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolved_by': self.resolved_by,
            'resolution_notes': self.resolution_notes,
            'risk_score': self.risk_score,
            'threat_indicators': self.threat_indicators,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by
        }
    
    @classmethod
    def create_security_event(cls, event_type: str, severity: str, title: str, description: str,
                             event_data: Optional[Dict] = None, incident_id: Optional[str] = None,
                             correlation_id: Optional[str] = None) -> 'SecurityEvent':
        """
        Create a new security event with comprehensive context capture.
        
        Args:
            event_type: Type of security event
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            title: Brief title describing the event
            description: Detailed description of the security event
            event_data: Additional event-specific data
            incident_id: Related incident ID for correlation
            correlation_id: Correlation ID for related events
            
        Returns:
            SecurityEvent: Created security event
        """
        security_event = cls(
            event_type=event_type,
            severity=severity.upper(),
            title=title,
            description=description,
            event_data=event_data,
            incident_id=incident_id,
            correlation_id=correlation_id
        )
        
        # Calculate initial risk score
        security_event.calculate_risk_score()
        
        return security_event
    
    def __repr__(self):
        return f"<SecurityEvent(id={self.id}, type='{self.event_type}', severity='{self.severity}', resolved={self.resolved})>"


# SQLAlchemy Event Hooks for Automatic Audit Trail Generation
class AuditEventHandler:
    """
    SQLAlchemy event hooks for automatic audit trail generation with user context tracking.
    
    Provides comprehensive DML auditing by capturing:
    - All INSERT, UPDATE, DELETE operations
    - User context from Flask-Login sessions
    - Complete change data with before/after values
    - Transaction context and timing
    """
    
    @staticmethod
    def get_current_user_context() -> Dict[str, Optional[str]]:
        """Extract current user context from Flask-Login or Flask globals"""
        user_context = {
            'user_id': None,
            'username': None,
            'session_id': None
        }
        
        if has_request_context():
            # Try to get from Flask-Login current_user
            try:
                from flask_login import current_user
                if current_user and hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
                    user_context['user_id'] = str(getattr(current_user, 'id', None))
                    user_context['username'] = getattr(current_user, 'username', None)
            except ImportError:
                pass
            
            # Fallback to Flask globals
            if hasattr(g, 'current_user_id'):
                user_context['user_id'] = str(g.current_user_id)
            if hasattr(g, 'current_username'):
                user_context['username'] = g.current_username
            if hasattr(g, 'session_id'):
                user_context['session_id'] = g.session_id
        
        return user_context
    
    @staticmethod
    def serialize_model_data(obj) -> Dict[str, Any]:
        """Serialize SQLAlchemy model instance to dictionary for audit storage"""
        if obj is None:
            return None
        
        data = {}
        for column in obj.__table__.columns:
            value = getattr(obj, column.name)
            
            # Handle different data types for JSON serialization
            if isinstance(value, datetime):
                data[column.name] = value.isoformat()
            elif hasattr(value, 'isoformat'):  # Handle other datetime-like objects
                data[column.name] = value.isoformat()
            elif value is not None:
                try:
                    # Ensure value is JSON serializable
                    json.dumps(value)
                    data[column.name] = value
                except (TypeError, ValueError):
                    # Convert non-serializable values to string
                    data[column.name] = str(value)
            else:
                data[column.name] = None
        
        return data
    
    @staticmethod
    @event.listens_for(Session, 'before_commit')
    def capture_audit_data(session):
        """Capture audit data before committing transactions"""
        # Skip audit logging for audit tables to prevent recursion
        audit_tables = {'audit_logs', 'security_events'}
        
        # Get current user context
        user_context = AuditEventHandler.get_current_user_context()
        
        # Collect audit entries for batch processing
        audit_entries = []
        
        try:
            # Process new objects (INSERT operations)
            for obj in session.new:
                if hasattr(obj, '__tablename__') and obj.__tablename__ not in audit_tables:
                    new_values = AuditEventHandler.serialize_model_data(obj)
                    record_id = getattr(obj, 'id', None)
                    
                    audit_entry = AuditLog.create_audit_entry(
                        table_name=obj.__tablename__,
                        record_id=record_id,
                        operation_type='INSERT',
                        new_values=new_values
                    )
                    
                    # Set user context
                    audit_entry.user_id = user_context['user_id']
                    audit_entry.username = user_context['username']
                    audit_entry.session_id = user_context['session_id']
                    
                    audit_entries.append(audit_entry)
            
            # Process modified objects (UPDATE operations)
            for obj in session.dirty:
                if hasattr(obj, '__tablename__') and obj.__tablename__ not in audit_tables:
                    # Get current (new) values
                    new_values = AuditEventHandler.serialize_model_data(obj)
                    
                    # Get original (old) values from session history
                    old_values = {}
                    history = session.get_history(obj, obj.__class__.id.key) if hasattr(obj.__class__, 'id') else None
                    
                    # Build old values from attribute history
                    for column in obj.__table__.columns:
                        attr_history = session.get_history(obj, column.name)
                        if attr_history.has_changes():
                            # Use the original value from history
                            old_values[column.name] = attr_history.deleted[0] if attr_history.deleted else new_values.get(column.name)
                        else:
                            old_values[column.name] = new_values.get(column.name)
                    
                    record_id = getattr(obj, 'id', None)
                    
                    audit_entry = AuditLog.create_audit_entry(
                        table_name=obj.__tablename__,
                        record_id=record_id,
                        operation_type='UPDATE',
                        old_values=old_values,
                        new_values=new_values
                    )
                    
                    # Set user context
                    audit_entry.user_id = user_context['user_id']
                    audit_entry.username = user_context['username']
                    audit_entry.session_id = user_context['session_id']
                    
                    audit_entries.append(audit_entry)
            
            # Process deleted objects (DELETE operations)
            for obj in session.deleted:
                if hasattr(obj, '__tablename__') and obj.__tablename__ not in audit_tables:
                    old_values = AuditEventHandler.serialize_model_data(obj)
                    record_id = getattr(obj, 'id', None)
                    
                    audit_entry = AuditLog.create_audit_entry(
                        table_name=obj.__tablename__,
                        record_id=record_id,
                        operation_type='DELETE',
                        old_values=old_values
                    )
                    
                    # Set user context
                    audit_entry.user_id = user_context['user_id']
                    audit_entry.username = user_context['username']
                    audit_entry.session_id = user_context['session_id']
                    
                    audit_entries.append(audit_entry)
            
            # Bulk add all audit entries
            if audit_entries:
                session.add_all(audit_entries)
                
                # Log audit activity
                audit_logger.info(f"Created {len(audit_entries)} audit log entries for user {user_context.get('username', 'unknown')}")
        
        except Exception as e:
            # Log audit error but don't fail the transaction
            audit_logger.error(f"Error creating audit logs: {str(e)}")


# Utility functions for audit and security event management
class AuditQueryHelper:
    """Helper class for common audit and security event queries"""
    
    @staticmethod
    def get_user_activity(user_id: str, start_date: datetime = None, end_date: datetime = None) -> Dict[str, Any]:
        """Get comprehensive user activity summary"""
        query_filter = AuditLog.user_id == user_id
        
        if start_date:
            query_filter = query_filter & (AuditLog.operation_timestamp >= start_date)
        if end_date:
            query_filter = query_filter & (AuditLog.operation_timestamp <= end_date)
        
        audit_logs = AuditLog.query.filter(query_filter).order_by(AuditLog.operation_timestamp.desc()).all()
        
        # Get security events for the same period
        security_filter = SecurityEvent.user_id == user_id
        if start_date:
            security_filter = security_filter & (SecurityEvent.event_timestamp >= start_date)
        if end_date:
            security_filter = security_filter & (SecurityEvent.event_timestamp <= end_date)
        
        security_events = SecurityEvent.query.filter(security_filter).order_by(SecurityEvent.event_timestamp.desc()).all()
        
        return {
            'user_id': user_id,
            'audit_logs': [log.to_dict() for log in audit_logs],
            'security_events': [event.to_dict() for event in security_events],
            'summary': {
                'total_operations': len(audit_logs),
                'security_events_count': len(security_events),
                'high_risk_events': len([e for e in security_events if e.severity in ['HIGH', 'CRITICAL']]),
                'unresolved_events': len([e for e in security_events if not e.resolved])
            }
        }
    
    @staticmethod
    def get_table_audit_trail(table_name: str, record_id: str = None) -> Dict[str, Any]:
        """Get complete audit trail for a table or specific record"""
        query = AuditLog.query.filter(AuditLog.table_name == table_name)
        
        if record_id:
            query = query.filter(AuditLog.record_id == str(record_id))
        
        audit_logs = query.order_by(AuditLog.operation_timestamp.desc()).all()
        
        return {
            'table_name': table_name,
            'record_id': record_id,
            'audit_trail': [log.to_dict() for log in audit_logs],
            'summary': {
                'total_changes': len(audit_logs),
                'insert_count': len([log for log in audit_logs if log.operation_type == 'INSERT']),
                'update_count': len([log for log in audit_logs if log.operation_type == 'UPDATE']),
                'delete_count': len([log for log in audit_logs if log.operation_type == 'DELETE'])
            }
        }
    
    @staticmethod
    def get_security_dashboard_data(time_period_hours: int = 24) -> Dict[str, Any]:
        """Get security dashboard data for monitoring"""
        start_time = datetime.utcnow().replace(minute=0, second=0, microsecond=0) - \
                    datetime.timedelta(hours=time_period_hours)
        
        # Get recent security events
        security_events = SecurityEvent.query.filter(
            SecurityEvent.event_timestamp >= start_time
        ).order_by(SecurityEvent.event_timestamp.desc()).all()
        
        # Get audit activity summary
        audit_activity = db.session.query(
            AuditLog.table_name,
            AuditLog.operation_type,
            db.func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.operation_timestamp >= start_time
        ).group_by(
            AuditLog.table_name,
            AuditLog.operation_type
        ).all()
        
        # Aggregate security metrics
        security_metrics = {
            'total_events': len(security_events),
            'critical_events': len([e for e in security_events if e.severity == 'CRITICAL']),
            'high_events': len([e for e in security_events if e.severity == 'HIGH']),
            'unresolved_events': len([e for e in security_events if not e.resolved]),
            'unique_users_affected': len(set([e.user_id for e in security_events if e.user_id])),
            'unique_ips': len(set([e.ip_address for e in security_events if e.ip_address]))
        }
        
        return {
            'time_period_hours': time_period_hours,
            'start_time': start_time.isoformat(),
            'security_events': [event.to_dict() for event in security_events[:50]],  # Latest 50 events
            'security_metrics': security_metrics,
            'audit_activity': [
                {
                    'table_name': activity.table_name,
                    'operation_type': activity.operation_type,
                    'count': activity.count
                }
                for activity in audit_activity
            ]
        }


# Export main components
__all__ = [
    'AuditLog',
    'SecurityEvent', 
    'AuditEventHandler',
    'AuditQueryHelper'
]