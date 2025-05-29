"""
AuthenticationLog Model Implementation for Comprehensive Security Audit Logging.

This module implements the AuthenticationLog model using Flask-SQLAlchemy declarative patterns
with PostgreSQL optimization for comprehensive authentication event tracking and security
monitoring integration. The model captures detailed authentication attempts, session activities,
and security events for compliance reporting and anomaly detection, integrating with Prometheus
metrics and AWS CloudWatch for real-time security monitoring.

Key Features:
- Comprehensive authentication audit logging for security compliance per Section 6.4.2.5
- Structured JSON logging integration with Python structlog for machine-readable audit trails
- Security event tracking for real-time monitoring and anomaly detection per Section 6.4.6.1
- Audit trail preservation for GDPR and compliance requirements per Section 6.2.4.1
- Integration with AWS CloudWatch Logs for centralized security monitoring per Section 6.4.2.5
- Foreign key relationships to User model for audit trail attribution and compliance tracking
- Prometheus metrics collection integration points for performance monitoring
- Log retention policies and automated data archival for compliance requirements
- PostgreSQL-optimized indexing for security query performance and pattern analysis
- Anomaly detection support through structured event classification and pattern tracking
- GDPR Article 32 compliance with automated audit trail preservation and anonymization

Technical Specification References:
- Section 6.4.2.5: Enhanced Audit Framework with Structured Logging
- Section 6.4.6.1: Real-Time Security Monitoring with Python Observability Integration
- Section 6.4.6.2: Automated Security Incident Detection and Classification
- Section 6.2.4.1: Data Retention and Privacy Controls with GDPR compliance
- Section 6.2.4.3: Audit Mechanisms and Access Controls with centralized logging
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Union, Tuple
from enum import Enum
from ipaddress import ip_address, AddressValueError

from flask import request, g, current_app
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, JSON, Index,
    CheckConstraint, ForeignKey, event, func, text, desc, asc
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB

# Import base model and database instance for inheritance pattern consistency
from src.models.base import BaseModel, db


class AuthenticationEventType(Enum):
    """
    Enumeration of authentication event types for structured logging.
    
    Provides comprehensive categorization of authentication and security events
    for consistent logging, monitoring, and analysis across the application.
    """
    # Authentication Events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    SESSION_CREATED = "session_created"
    SESSION_INVALIDATED = "session_invalidated"
    
    # Token Events
    TOKEN_ISSUED = "token_issued"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_EXPIRED = "token_expired"
    
    # Security Events
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    
    # Password Events
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    PASSWORD_CHANGED = "password_changed"
    
    # Account Events
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_ACTIVATED = "account_activated"
    ACCOUNT_DEACTIVATED = "account_deactivated"
    EMAIL_VERIFIED = "email_verified"
    
    # Access Control Events
    AUTHORIZATION_GRANTED = "authorization_granted"
    AUTHORIZATION_DENIED = "authorization_denied"
    PERMISSION_CHANGED = "permission_changed"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"


class AuthenticationMethod(Enum):
    """
    Enumeration of authentication methods for audit tracking.
    
    Categorizes different authentication mechanisms used throughout
    the application for security analysis and compliance reporting.
    """
    PASSWORD = "password"
    TOKEN = "token"
    JWT = "jwt"
    SESSION = "session"
    API_KEY = "api_key"
    OAUTH = "oauth"
    SSO = "sso"
    MFA = "mfa"
    BIOMETRIC = "biometric"


class SecurityClassification(Enum):
    """
    Security classification levels for event prioritization.
    
    Provides hierarchical classification of security events for
    automated response coordination and incident management.
    """
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECURITY_RELEVANT = "security_relevant"
    SECURITY_CRITICAL = "security_critical"


class EventSeverity(Enum):
    """
    Event severity levels for monitoring and alerting.
    
    Standardized severity classification for security events
    enabling consistent monitoring and automated response procedures.
    """
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthenticationLog(BaseModel):
    """
    AuthenticationLog model implementing comprehensive audit logging for authentication events.
    
    This model captures detailed authentication attempts, session activities, and security events
    for compliance reporting and anomaly detection, integrating with Prometheus metrics and AWS
    CloudWatch for real-time security monitoring. Implements structured JSON data storage with
    comprehensive audit trail preservation for GDPR and compliance requirements.
    
    Inherits from BaseModel for common functionality:
    - Auto-incrementing primary key (id)
    - Automatic timestamp management (created_at, updated_at)
    - Common utility methods for serialization and persistence
    - PostgreSQL-optimized field patterns
    
    Attributes:
        id (int): Primary key inherited from BaseModel for optimal join performance
        event_id (str): Unique UUID identifier for event correlation across systems
        user_id (int, optional): Foreign key to User model for audit trail attribution
        event_type (AuthenticationEventType): Categorized authentication event type
        authentication_method (AuthenticationMethod): Method used for authentication
        success (bool): Authentication success or failure status
        client_ip (str): Client IP address for security tracking and geo-analysis
        user_agent (str): Client user agent for device and browser identification
        request_id (str): Unique request identifier for correlation across logs
        session_id (str, optional): User session identifier for session tracking
        endpoint (str, optional): API endpoint accessed during authentication
        http_method (str, optional): HTTP method used for the request
        blueprint_name (str, optional): Flask blueprint name for module identification
        event_details (dict): Structured JSON data for detailed event information
        security_classification (SecurityClassification): Security level classification
        severity (EventSeverity): Event severity for monitoring and alerting
        risk_score (int): Calculated risk score for anomaly detection (0-100)
        correlation_id (str, optional): Cross-system correlation identifier
        geolocation_data (dict, optional): IP geolocation information for analysis
        device_fingerprint (str, optional): Device fingerprint for tracking
        metadata (dict): Additional metadata for extensibility and custom fields
        archived_at (datetime, optional): Timestamp for compliance archival tracking
        retention_expires_at (datetime): Calculated retention expiration for GDPR
        created_at (datetime): Timestamp inherited from BaseModel
        updated_at (datetime): Timestamp inherited from BaseModel
        
    Relationships:
        user (User, optional): Many-to-one relationship with User model for attribution
    """
    
    __tablename__ = 'authentication_logs'
    
    # Unique event identifier for correlation across distributed systems
    event_id = Column(
        UUID(as_uuid=True),
        unique=True,
        nullable=False,
        default=uuid.uuid4,
        index=True,
        comment="Unique UUID identifier for event correlation across systems"
    )
    
    # Optional foreign key to User model for audit trail attribution
    # Nullable to support failed authentication attempts where user may not exist
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
        comment="Foreign key to User model for audit trail attribution (nullable for failed auth)"
    )
    
    # Authentication event classification and method tracking
    event_type = Column(
        String(50),
        nullable=False,
        index=True,
        comment="Categorized authentication event type from AuthenticationEventType enum"
    )
    
    authentication_method = Column(
        String(20),
        nullable=False,
        index=True,
        comment="Method used for authentication from AuthenticationMethod enum"
    )
    
    # Authentication result and status tracking
    success = Column(
        Boolean,
        nullable=False,
        index=True,
        comment="Authentication success or failure status for security analysis"
    )
    
    # Client information for security tracking and geo-analysis
    client_ip = Column(
        INET,
        nullable=True,
        index=True,
        comment="Client IP address for security tracking and geo-analysis"
    )
    
    user_agent = Column(
        Text,
        nullable=True,
        comment="Client user agent for device and browser identification"
    )
    
    # Request correlation and session tracking
    request_id = Column(
        String(128),
        nullable=True,
        index=True,
        comment="Unique request identifier for correlation across application logs"
    )
    
    session_id = Column(
        String(128),
        nullable=True,
        index=True,
        comment="User session identifier for session lifecycle tracking"
    )
    
    # Flask application context information
    endpoint = Column(
        String(200),
        nullable=True,
        index=True,
        comment="API endpoint accessed during authentication for context analysis"
    )
    
    http_method = Column(
        String(10),
        nullable=True,
        comment="HTTP method used for the request (GET, POST, etc.)"
    )
    
    blueprint_name = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Flask blueprint name for module identification and analysis"
    )
    
    # Structured JSON data for detailed event information per Section 6.4.2.5
    event_details = Column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Structured JSON data for detailed event information and context"
    )
    
    # Security classification and severity for monitoring integration
    security_classification = Column(
        String(30),
        nullable=False,
        default=SecurityClassification.INTERNAL.value,
        index=True,
        comment="Security level classification for automated response coordination"
    )
    
    severity = Column(
        String(20),
        nullable=False,
        default=EventSeverity.INFO.value,
        index=True,
        comment="Event severity for monitoring and alerting integration"
    )
    
    # Risk assessment for anomaly detection per Section 6.4.6.1
    risk_score = Column(
        Integer,
        nullable=False,
        default=0,
        index=True,
        comment="Calculated risk score for anomaly detection (0-100 scale)"
    )
    
    # Cross-system correlation for distributed security monitoring
    correlation_id = Column(
        String(128),
        nullable=True,
        index=True,
        comment="Cross-system correlation identifier for distributed monitoring"
    )
    
    # Geolocation and device tracking for security analysis
    geolocation_data = Column(
        JSONB,
        nullable=True,
        comment="IP geolocation information for geographic security analysis"
    )
    
    device_fingerprint = Column(
        String(128),
        nullable=True,
        index=True,
        comment="Device fingerprint hash for device tracking and analysis"
    )
    
    # Extensible metadata for custom fields and integration requirements
    metadata = Column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Additional metadata for extensibility and custom integration fields"
    )
    
    # GDPR compliance and data retention tracking per Section 6.2.4.1
    archived_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp for compliance archival tracking and GDPR requirements"
    )
    
    retention_expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Calculated retention expiration for GDPR compliance and automated cleanup"
    )
    
    # Relationship to User model for audit trail attribution
    user = relationship(
        'User',
        foreign_keys=[user_id],
        back_populates=None,  # User model doesn't define back reference to avoid circular imports
        lazy='select',
        doc="Many-to-one relationship with User model for audit trail attribution"
    )
    
    # Database constraints and indexes for performance optimization per Section 6.2.2.2
    __table_args__ = (
        # Check constraints for data validation and security
        CheckConstraint('risk_score >= 0 AND risk_score <= 100', name='ck_auth_log_risk_score_range'),
        CheckConstraint("event_type != ''", name='ck_auth_log_event_type_not_empty'),
        CheckConstraint("authentication_method != ''", name='ck_auth_log_auth_method_not_empty'),
        CheckConstraint("security_classification != ''", name='ck_auth_log_security_class_not_empty'),
        CheckConstraint("severity != ''", name='ck_auth_log_severity_not_empty'),
        CheckConstraint('retention_expires_at > created_at', name='ck_auth_log_retention_future'),
        
        # Composite indexes for security queries and performance optimization
        Index('ix_auth_log_user_success_time', 'user_id', 'success', 'created_at'),
        Index('ix_auth_log_ip_time', 'client_ip', 'created_at'),
        Index('ix_auth_log_event_type_time', 'event_type', 'created_at'),
        Index('ix_auth_log_success_severity_time', 'success', 'severity', 'created_at'),
        Index('ix_auth_log_security_class_time', 'security_classification', 'created_at'),
        Index('ix_auth_log_risk_score_time', 'risk_score', 'created_at'),
        Index('ix_auth_log_blueprint_endpoint', 'blueprint_name', 'endpoint'),
        Index('ix_auth_log_correlation_time', 'correlation_id', 'created_at'),
        Index('ix_auth_log_session_time', 'session_id', 'created_at'),
        Index('ix_auth_log_retention_archive', 'retention_expires_at', 'archived_at'),
        Index('ix_auth_log_device_time', 'device_fingerprint', 'created_at'),
        
        # Partial indexes for active monitoring and cleanup
        Index('ix_auth_log_failed_auth_recent', 'client_ip', 'created_at', 
              postgresql_where=(text("success = false AND created_at > NOW() - INTERVAL '1 hour'"))),
        Index('ix_auth_log_high_risk_recent', 'risk_score', 'created_at',
              postgresql_where=(text("risk_score >= 70 AND created_at > NOW() - INTERVAL '24 hours'"))),
        Index('ix_auth_log_expired_retention', 'retention_expires_at',
              postgresql_where=(text("retention_expires_at <= NOW() AND archived_at IS NULL"))),
        
        # Table-level comment for documentation
        {'comment': 'Comprehensive authentication audit logging with structured JSON and security monitoring'}
    )
    
    def __init__(
        self,
        event_type: Union[AuthenticationEventType, str],
        authentication_method: Union[AuthenticationMethod, str],
        success: bool,
        user_id: Optional[int] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        http_method: Optional[str] = None,
        blueprint_name: Optional[str] = None,
        event_details: Optional[Dict[str, Any]] = None,
        security_classification: Union[SecurityClassification, str] = SecurityClassification.INTERNAL,
        severity: Union[EventSeverity, str] = EventSeverity.INFO,
        risk_score: int = 0,
        correlation_id: Optional[str] = None,
        geolocation_data: Optional[Dict[str, Any]] = None,
        device_fingerprint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        retention_days: Optional[int] = None,
        **kwargs
    ) -> None:
        """
        Initialize a new AuthenticationLog instance with comprehensive event tracking.
        
        Args:
            event_type: Type of authentication event from AuthenticationEventType enum
            authentication_method: Authentication method from AuthenticationMethod enum
            success: Whether the authentication was successful
            user_id: Optional foreign key to User model for attribution
            client_ip: Client IP address for security tracking
            user_agent: Client user agent string for device identification
            request_id: Unique request identifier for correlation
            session_id: User session identifier for session tracking
            endpoint: API endpoint accessed during authentication
            http_method: HTTP method used for the request
            blueprint_name: Flask blueprint name for module identification
            event_details: Structured event details as dictionary
            security_classification: Security level from SecurityClassification enum
            severity: Event severity from EventSeverity enum
            risk_score: Risk assessment score (0-100)
            correlation_id: Cross-system correlation identifier
            geolocation_data: IP geolocation information as dictionary
            device_fingerprint: Device fingerprint for tracking
            metadata: Additional metadata as dictionary
            retention_days: Custom retention period in days (uses default if None)
            **kwargs: Additional keyword arguments for model fields
            
        Raises:
            ValueError: If required parameters are invalid or missing
        """
        super().__init__(**kwargs)
        
        # Generate unique event identifier
        self.event_id = uuid.uuid4()
        
        # Set event classification
        self.event_type = event_type.value if isinstance(event_type, AuthenticationEventType) else event_type
        self.authentication_method = authentication_method.value if isinstance(authentication_method, AuthenticationMethod) else authentication_method
        self.success = success
        
        # Set user attribution
        self.user_id = user_id
        
        # Set client information with validation
        self.client_ip = self._validate_ip_address(client_ip)
        self.user_agent = user_agent[:2000] if user_agent else None  # Limit length
        
        # Set request correlation information
        self.request_id = request_id or self._generate_request_id()
        self.session_id = session_id
        
        # Set Flask application context
        self.endpoint = endpoint[:200] if endpoint else None  # Limit length
        self.http_method = http_method[:10] if http_method else None
        self.blueprint_name = blueprint_name[:100] if blueprint_name else None
        
        # Set structured event details
        self.event_details = event_details or {}
        
        # Set security classification and severity
        self.security_classification = security_classification.value if isinstance(security_classification, SecurityClassification) else security_classification
        self.severity = severity.value if isinstance(severity, EventSeverity) else severity
        
        # Set risk assessment
        self.risk_score = max(0, min(100, risk_score))  # Clamp to 0-100 range
        
        # Set correlation and tracking information
        self.correlation_id = correlation_id
        self.geolocation_data = geolocation_data or {}
        self.device_fingerprint = device_fingerprint
        self.metadata = metadata or {}
        
        # Set retention policy per Section 6.2.4.1
        self._set_retention_policy(retention_days)
        
        # Initialize archival tracking
        self.archived_at = None
    
    @staticmethod
    def _validate_ip_address(ip_str: Optional[str]) -> Optional[str]:
        """
        Validate and normalize IP address format.
        
        Args:
            ip_str: IP address string to validate
            
        Returns:
            str: Validated IP address or None if invalid
        """
        if not ip_str:
            return None
        
        try:
            # Validate using ipaddress module
            ip_obj = ip_address(ip_str.strip())
            return str(ip_obj)
        except (AddressValueError, ValueError):
            # Return original string if validation fails (for logging purposes)
            return ip_str.strip()[:45]  # Limit to IPv6 length
    
    @staticmethod
    def _generate_request_id() -> str:
        """
        Generate unique request identifier for correlation.
        
        Returns:
            str: Unique request identifier
        """
        return str(uuid.uuid4())
    
    def _set_retention_policy(self, retention_days: Optional[int] = None) -> None:
        """
        Set data retention policy based on GDPR and compliance requirements.
        
        Args:
            retention_days: Custom retention period in days
        """
        if retention_days is None:
            # Default retention based on event severity and classification
            if self.severity in [EventSeverity.CRITICAL.value, EventSeverity.HIGH.value]:
                retention_days = current_app.config.get('SECURITY_LOG_RETENTION_DAYS', 2555)  # ~7 years
            elif self.security_classification == SecurityClassification.SECURITY_CRITICAL.value:
                retention_days = current_app.config.get('CRITICAL_LOG_RETENTION_DAYS', 1826)  # ~5 years
            else:
                retention_days = current_app.config.get('DEFAULT_LOG_RETENTION_DAYS', 365)  # 1 year
        
        self.retention_expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)
    
    @validates('event_type')
    def validate_event_type(self, key: str, value: str) -> str:
        """
        Validate event type against allowed values.
        
        Args:
            key: Field name being validated
            value: Event type value being set
            
        Returns:
            str: Validated event type
            
        Raises:
            ValueError: If event type is invalid
        """
        if isinstance(value, AuthenticationEventType):
            return value.value
        
        if value not in [e.value for e in AuthenticationEventType]:
            raise ValueError(f"Invalid event type: {value}")
        
        return value
    
    @validates('authentication_method')
    def validate_authentication_method(self, key: str, value: str) -> str:
        """
        Validate authentication method against allowed values.
        
        Args:
            key: Field name being validated
            value: Authentication method value being set
            
        Returns:
            str: Validated authentication method
            
        Raises:
            ValueError: If authentication method is invalid
        """
        if isinstance(value, AuthenticationMethod):
            return value.value
        
        if value not in [m.value for m in AuthenticationMethod]:
            raise ValueError(f"Invalid authentication method: {value}")
        
        return value
    
    @validates('security_classification')
    def validate_security_classification(self, key: str, value: str) -> str:
        """
        Validate security classification against allowed values.
        
        Args:
            key: Field name being validated
            value: Security classification value being set
            
        Returns:
            str: Validated security classification
            
        Raises:
            ValueError: If security classification is invalid
        """
        if isinstance(value, SecurityClassification):
            return value.value
        
        if value not in [c.value for c in SecurityClassification]:
            raise ValueError(f"Invalid security classification: {value}")
        
        return value
    
    @validates('severity')
    def validate_severity(self, key: str, value: str) -> str:
        """
        Validate event severity against allowed values.
        
        Args:
            key: Field name being validated
            value: Event severity value being set
            
        Returns:
            str: Validated event severity
            
        Raises:
            ValueError: If event severity is invalid
        """
        if isinstance(value, EventSeverity):
            return value.value
        
        if value not in [s.value for s in EventSeverity]:
            raise ValueError(f"Invalid event severity: {value}")
        
        return value
    
    @hybrid_property
    def is_security_relevant(self) -> bool:
        """
        Check if the event is security-relevant for monitoring.
        
        Returns:
            bool: True if event requires security attention
        """
        return (
            self.security_classification in [
                SecurityClassification.SECURITY_RELEVANT.value,
                SecurityClassification.SECURITY_CRITICAL.value
            ] or
            self.severity in [EventSeverity.HIGH.value, EventSeverity.CRITICAL.value] or
            self.risk_score >= 70 or
            not self.success
        )
    
    @hybrid_property
    def is_anomaly(self) -> bool:
        """
        Check if the event represents an anomaly for detection.
        
        Returns:
            bool: True if event is classified as anomalous
        """
        return (
            self.risk_score >= 80 or
            self.event_type in [
                AuthenticationEventType.BRUTE_FORCE_ATTEMPT.value,
                AuthenticationEventType.SUSPICIOUS_ACTIVITY.value,
                AuthenticationEventType.PRIVILEGE_ESCALATION.value
            ]
        )
    
    @hybrid_property
    def needs_immediate_attention(self) -> bool:
        """
        Check if the event requires immediate security attention.
        
        Returns:
            bool: True if event requires immediate response
        """
        return (
            self.severity == EventSeverity.CRITICAL.value or
            self.security_classification == SecurityClassification.SECURITY_CRITICAL.value or
            self.risk_score >= 90
        )
    
    def add_event_detail(self, key: str, value: Any) -> None:
        """
        Add detail to the event_details JSON field.
        
        Args:
            key: Detail key name
            value: Detail value (must be JSON serializable)
        """
        if self.event_details is None:
            self.event_details = {}
        
        self.event_details[key] = value
        # Mark as modified for SQLAlchemy change tracking
        flag_modified(self, 'event_details')
    
    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata to the metadata JSON field.
        
        Args:
            key: Metadata key name
            value: Metadata value (must be JSON serializable)
        """
        if self.metadata is None:
            self.metadata = {}
        
        self.metadata[key] = value
        # Mark as modified for SQLAlchemy change tracking
        flag_modified(self, 'metadata')
    
    def set_geolocation(self, country: str = None, region: str = None, 
                       city: str = None, latitude: float = None, 
                       longitude: float = None, **kwargs) -> None:
        """
        Set geolocation data for the authentication event.
        
        Args:
            country: Country name or code
            region: Region or state name
            city: City name
            latitude: Geographic latitude
            longitude: Geographic longitude
            **kwargs: Additional geolocation fields
        """
        geo_data = {
            'country': country,
            'region': region,
            'city': city,
            'latitude': latitude,
            'longitude': longitude
        }
        
        # Add any additional fields
        geo_data.update(kwargs)
        
        # Remove None values
        self.geolocation_data = {k: v for k, v in geo_data.items() if v is not None}
        
        # Mark as modified for SQLAlchemy change tracking
        flag_modified(self, 'geolocation_data')
    
    def mark_archived(self) -> None:
        """
        Mark the log entry as archived for compliance tracking.
        
        Sets the archived_at timestamp for GDPR compliance and audit purposes.
        """
        self.archived_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
    
    def should_be_archived(self) -> bool:
        """
        Check if the log entry should be archived based on retention policy.
        
        Returns:
            bool: True if entry should be archived
        """
        if self.archived_at is not None:
            return False  # Already archived
        
        current_time = datetime.now(timezone.utc)
        return current_time >= self.retention_expires_at
    
    def to_structured_log(self) -> Dict[str, Any]:
        """
        Convert to structured log format for external logging systems.
        
        Returns structured log data compatible with Python structlog and
        AWS CloudWatch Logs for centralized security monitoring.
        
        Returns:
            Dict[str, Any]: Structured log representation
        """
        return {
            'event_id': str(self.event_id),
            'timestamp': self.created_at.isoformat(),
            'event_type': self.event_type,
            'authentication_method': self.authentication_method,
            'success': self.success,
            'user_id': self.user_id,
            'client_ip': str(self.client_ip) if self.client_ip else None,
            'user_agent': self.user_agent,
            'request_id': self.request_id,
            'session_id': self.session_id,
            'endpoint': self.endpoint,
            'http_method': self.http_method,
            'blueprint_name': self.blueprint_name,
            'security_classification': self.security_classification,
            'severity': self.severity,
            'risk_score': self.risk_score,
            'correlation_id': self.correlation_id,
            'device_fingerprint': self.device_fingerprint,
            'is_security_relevant': self.is_security_relevant,
            'is_anomaly': self.is_anomaly,
            'needs_immediate_attention': self.needs_immediate_attention,
            'event_details': self.event_details,
            'geolocation_data': self.geolocation_data,
            'metadata': self.metadata
        }
    
    def to_prometheus_metrics(self) -> Dict[str, Any]:
        """
        Convert to metrics format for Prometheus integration.
        
        Returns metrics data suitable for Prometheus collection and
        monitoring dashboard integration per Section 6.4.6.1.
        
        Returns:
            Dict[str, Any]: Prometheus-compatible metrics
        """
        return {
            'auth_event_total': 1,
            'auth_success_total': 1 if self.success else 0,
            'auth_failure_total': 0 if self.success else 1,
            'auth_risk_score': self.risk_score,
            'labels': {
                'event_type': self.event_type,
                'authentication_method': self.authentication_method,
                'blueprint_name': self.blueprint_name or 'unknown',
                'endpoint': self.endpoint or 'unknown',
                'security_classification': self.security_classification,
                'severity': self.severity,
                'success': str(self.success).lower()
            }
        }
    
    @classmethod
    def log_authentication_event(
        cls,
        event_type: Union[AuthenticationEventType, str],
        authentication_method: Union[AuthenticationMethod, str],
        success: bool,
        user_id: Optional[int] = None,
        auto_capture_context: bool = True,
        **kwargs
    ) -> 'AuthenticationLog':
        """
        Create and save an authentication log entry with automatic context capture.
        
        Convenience method for creating authentication log entries with automatic
        capture of Flask request context and security information.
        
        Args:
            event_type: Type of authentication event
            authentication_method: Authentication method used
            success: Whether authentication was successful
            user_id: Optional user ID for attribution
            auto_capture_context: Whether to automatically capture Flask request context
            **kwargs: Additional parameters for AuthenticationLog constructor
            
        Returns:
            AuthenticationLog: Created and saved log entry
        """
        # Capture Flask request context if available and requested
        if auto_capture_context and request:
            kwargs.setdefault('client_ip', request.remote_addr)
            kwargs.setdefault('user_agent', request.headers.get('User-Agent'))
            kwargs.setdefault('endpoint', request.endpoint)
            kwargs.setdefault('http_method', request.method)
            kwargs.setdefault('request_id', getattr(g, 'request_id', None))
            kwargs.setdefault('session_id', getattr(g, 'session_id', None))
            kwargs.setdefault('blueprint_name', request.blueprint)
            kwargs.setdefault('correlation_id', getattr(g, 'correlation_id', None))
        
        # Create log entry
        log_entry = cls(
            event_type=event_type,
            authentication_method=authentication_method,
            success=success,
            user_id=user_id,
            **kwargs
        )
        
        # Save to database
        log_entry.save()
        
        return log_entry
    
    @classmethod
    def get_failed_attempts_by_ip(
        cls,
        ip_address: str,
        time_window_hours: int = 1,
        max_attempts: Optional[int] = None
    ) -> List['AuthenticationLog']:
        """
        Get failed authentication attempts from specific IP within time window.
        
        Used for brute force detection and IP-based security analysis.
        
        Args:
            ip_address: IP address to search for
            time_window_hours: Time window in hours to search (default: 1)
            max_attempts: Maximum number of attempts to return
            
        Returns:
            List[AuthenticationLog]: Failed authentication attempts
        """
        time_threshold = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)
        
        query = cls.query.filter(
            cls.client_ip == ip_address,
            cls.success == False,
            cls.created_at >= time_threshold
        ).order_by(desc(cls.created_at))
        
        if max_attempts:
            query = query.limit(max_attempts)
        
        return query.all()
    
    @classmethod
    def get_user_authentication_history(
        cls,
        user_id: int,
        limit: int = 50,
        include_failed: bool = True
    ) -> List['AuthenticationLog']:
        """
        Get authentication history for a specific user.
        
        Args:
            user_id: User ID to search for
            limit: Maximum number of entries to return
            include_failed: Whether to include failed attempts
            
        Returns:
            List[AuthenticationLog]: User authentication history
        """
        query = cls.query.filter(cls.user_id == user_id)
        
        if not include_failed:
            query = query.filter(cls.success == True)
        
        return query.order_by(desc(cls.created_at)).limit(limit).all()
    
    @classmethod
    def get_security_events(
        cls,
        hours_back: int = 24,
        min_risk_score: int = 70,
        include_successful: bool = False
    ) -> List['AuthenticationLog']:
        """
        Get security-relevant events for monitoring and analysis.
        
        Args:
            hours_back: Hours to look back from current time
            min_risk_score: Minimum risk score to include
            include_successful: Whether to include successful authentications
            
        Returns:
            List[AuthenticationLog]: Security events
        """
        time_threshold = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        
        query = cls.query.filter(
            cls.created_at >= time_threshold,
            cls.risk_score >= min_risk_score
        )
        
        if not include_successful:
            query = query.filter(cls.success == False)
        
        return query.order_by(desc(cls.created_at)).all()
    
    @classmethod
    def get_anomalous_events(
        cls,
        hours_back: int = 24,
        min_severity: str = EventSeverity.MEDIUM.value
    ) -> List['AuthenticationLog']:
        """
        Get anomalous events for security analysis.
        
        Args:
            hours_back: Hours to look back from current time
            min_severity: Minimum severity level to include
            
        Returns:
            List[AuthenticationLog]: Anomalous events
        """
        time_threshold = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        
        severity_levels = [s.value for s in EventSeverity]
        min_index = severity_levels.index(min_severity)
        relevant_severities = severity_levels[min_index:]
        
        return cls.query.filter(
            cls.created_at >= time_threshold,
            cls.severity.in_(relevant_severities),
            cls.risk_score >= 80
        ).order_by(desc(cls.created_at)).all()
    
    @classmethod
    def get_authentication_statistics(
        cls,
        hours_back: int = 24,
        group_by_hour: bool = True
    ) -> Dict[str, Any]:
        """
        Get authentication statistics for monitoring dashboards.
        
        Args:
            hours_back: Hours to look back from current time
            group_by_hour: Whether to group statistics by hour
            
        Returns:
            Dict[str, Any]: Authentication statistics
        """
        time_threshold = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        
        # Base query for time period
        base_query = cls.query.filter(cls.created_at >= time_threshold)
        
        # Overall statistics
        total_attempts = base_query.count()
        successful_attempts = base_query.filter(cls.success == True).count()
        failed_attempts = base_query.filter(cls.success == False).count()
        unique_users = base_query.filter(cls.user_id.isnot(None)).distinct(cls.user_id).count()
        unique_ips = base_query.filter(cls.client_ip.isnot(None)).distinct(cls.client_ip).count()
        
        # Security statistics
        high_risk_events = base_query.filter(cls.risk_score >= 70).count()
        security_relevant = base_query.filter(
            cls.security_classification.in_([
                SecurityClassification.SECURITY_RELEVANT.value,
                SecurityClassification.SECURITY_CRITICAL.value
            ])
        ).count()
        
        statistics = {
            'period': {
                'hours_back': hours_back,
                'start_time': time_threshold.isoformat(),
                'end_time': datetime.now(timezone.utc).isoformat()
            },
            'totals': {
                'total_attempts': total_attempts,
                'successful_attempts': successful_attempts,
                'failed_attempts': failed_attempts,
                'success_rate': (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0,
                'unique_users': unique_users,
                'unique_ips': unique_ips,
                'high_risk_events': high_risk_events,
                'security_relevant_events': security_relevant
            }
        }
        
        # Group by hour if requested
        if group_by_hour:
            hourly_stats = db.session.query(
                func.date_trunc('hour', cls.created_at).label('hour'),
                func.count(cls.id).label('total'),
                func.sum(func.cast(cls.success, Integer)).label('successful'),
                func.avg(cls.risk_score).label('avg_risk_score')
            ).filter(
                cls.created_at >= time_threshold
            ).group_by(
                func.date_trunc('hour', cls.created_at)
            ).order_by('hour').all()
            
            statistics['hourly'] = [
                {
                    'hour': stat.hour.isoformat(),
                    'total_attempts': stat.total,
                    'successful_attempts': stat.successful,
                    'failed_attempts': stat.total - stat.successful,
                    'average_risk_score': float(stat.avg_risk_score) if stat.avg_risk_score else 0
                }
                for stat in hourly_stats
            ]
        
        return statistics
    
    @classmethod
    def cleanup_expired_logs(cls, batch_size: int = 1000) -> int:
        """
        Clean up expired log entries based on retention policy.
        
        Implements automated data archival for compliance requirements per Section 6.2.4.1.
        
        Args:
            batch_size: Number of records to process in each batch
            
        Returns:
            int: Number of records cleaned up
        """
        current_time = datetime.now(timezone.utc)
        
        # Find expired logs that haven't been archived
        expired_logs = cls.query.filter(
            cls.retention_expires_at <= current_time,
            cls.archived_at.is_(None)
        ).limit(batch_size).all()
        
        count = 0
        for log_entry in expired_logs:
            # Mark as archived instead of deleting for compliance
            log_entry.mark_archived()
            count += 1
        
        if count > 0:
            db.session.commit()
        
        return count
    
    @classmethod
    def anonymize_user_data(cls, user_id: int) -> int:
        """
        Anonymize authentication logs for a specific user (GDPR compliance).
        
        Removes personally identifiable information while preserving
        security and analytics value of the logs.
        
        Args:
            user_id: User ID to anonymize data for
            
        Returns:
            int: Number of records anonymized
        """
        logs = cls.query.filter(cls.user_id == user_id).all()
        count = 0
        
        for log_entry in logs:
            # Clear user attribution
            log_entry.user_id = None
            
            # Anonymize IP address (keep network portion for geo-analysis)
            if log_entry.client_ip:
                try:
                    ip_obj = ip_address(str(log_entry.client_ip))
                    if ip_obj.version == 4:
                        # IPv4: Keep first 3 octets, zero last octet
                        parts = str(ip_obj).split('.')
                        parts[3] = '0'
                        log_entry.client_ip = '.'.join(parts)
                    else:
                        # IPv6: Keep first 64 bits, zero the rest
                        log_entry.client_ip = str(ip_obj)[:19] + '::0'
                except (AddressValueError, ValueError):
                    log_entry.client_ip = None
            
            # Clear session ID
            log_entry.session_id = None
            
            # Remove PII from event details and metadata
            if log_entry.event_details:
                # Remove common PII fields
                pii_fields = ['email', 'phone', 'name', 'username']
                for field in pii_fields:
                    log_entry.event_details.pop(field, None)
                flag_modified(log_entry, 'event_details')
            
            if log_entry.metadata:
                # Remove PII from metadata
                for field in pii_fields:
                    log_entry.metadata.pop(field, None)
                flag_modified(log_entry, 'metadata')
            
            # Add anonymization marker
            log_entry.add_metadata('anonymized_at', datetime.now(timezone.utc).isoformat())
            log_entry.add_metadata('anonymized_for_gdpr', True)
            
            count += 1
        
        if count > 0:
            db.session.commit()
        
        return count
    
    def __repr__(self) -> str:
        """
        String representation of AuthenticationLog instance for debugging.
        
        Returns:
            str: String representation showing key event information
        """
        return (
            f"<AuthenticationLog(id={self.id}, event_id='{self.event_id}', "
            f"event_type='{self.event_type}', success={self.success}, "
            f"user_id={self.user_id}, client_ip='{self.client_ip}', "
            f"created_at='{self.created_at}')>"
        )
    
    def __str__(self) -> str:
        """
        Human-readable string representation of AuthenticationLog instance.
        
        Returns:
            str: User-friendly string representation
        """
        status = "SUCCESS" if self.success else "FAILURE"
        return f"{self.event_type} {status} from {self.client_ip} at {self.created_at}"


# Database event listeners for additional functionality per Section 6.2.4.3
@event.listens_for(AuthenticationLog, 'before_insert')
def auth_log_before_insert(mapper, connection, target):
    """
    Database event listener for AuthenticationLog creation processing.
    
    Args:
        mapper: SQLAlchemy mapper object
        connection: Database connection
        target: AuthenticationLog instance being inserted
    """
    # Ensure event_id is set
    if not target.event_id:
        target.event_id = uuid.uuid4()
    
    # Set timestamps if not already set
    current_time = datetime.now(timezone.utc)
    if not target.created_at:
        target.created_at = current_time
    target.updated_at = current_time
    
    # Set retention policy if not set
    if not target.retention_expires_at:
        target._set_retention_policy()


@event.listens_for(AuthenticationLog, 'after_insert')
def auth_log_after_insert(mapper, connection, target):
    """
    Database event listener for post-creation processing.
    
    Args:
        mapper: SQLAlchemy mapper object
        connection: Database connection
        target: AuthenticationLog instance that was inserted
    """
    # This could trigger additional processing like:
    # - Sending to external SIEM systems
    # - Updating real-time metrics
    # - Triggering security alerts
    # Implementation would depend on specific monitoring requirements
    pass


# Required import for SQLAlchemy flag_modified function
from sqlalchemy.orm.attributes import flag_modified


# Export the AuthenticationLog model and enums for use throughout the application
__all__ = [
    'AuthenticationLog',
    'AuthenticationEventType',
    'AuthenticationMethod',
    'SecurityClassification',
    'EventSeverity'
]