"""
AuthenticationLog Model Implementation for Comprehensive Security Audit Logging.

This module implements the AuthenticationLog model using Flask-SQLAlchemy declarative patterns
with PostgreSQL optimization and structured JSON logging integration. The model provides
comprehensive audit logging for authentication events, security monitoring, and compliance
reporting while integrating with Prometheus metrics and AWS CloudWatch for real-time security analysis.

Key Features:
- Comprehensive authentication event logging with structured JSON data storage
- Foreign key relationships to User model for audit trail attribution
- Integration with Python structlog for machine-readable audit trails
- Security event tracking for real-time monitoring and anomaly detection
- GDPR and compliance-ready audit trail preservation
- AWS CloudWatch Logs integration for centralized security monitoring
- Prometheus metrics integration for performance monitoring
- Automated log retention policies for compliance requirements

Technical Specification References:
- Section 6.4.2.5: Enhanced Audit Framework with Structured Logging
- Section 6.4.6.1: Real-Time Security Monitoring Integration
- Section 6.2.4.1: Data Retention and Privacy Controls
- Section 6.2.2.1: Entity Relationships and Data Models
- Section 3.2.2: Flask-SQLAlchemy 3.1.1 integration requirements
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Union
from enum import Enum
import json
import uuid
import structlog
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, JSON,
    ForeignKey, Index, CheckConstraint, UniqueConstraint, 
    Enum as SQLEnum, event
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import func

# Import base model and User model for relationships
from src.models.base import BaseModel, db
from src.models.user import User

# Configure structured logging for security audit trails per Section 6.4.2.5
logger = structlog.get_logger("authentication_audit")


class AuthenticationEventType(Enum):
    """
    Enumeration of authentication event types for structured logging and monitoring.
    
    Provides standardized event categorization for security analysis and compliance reporting.
    Each event type corresponds to specific security monitoring and alerting requirements.
    """
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_REVOCATION = "token_revocation"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_COMPLETE = "password_reset_complete"
    SESSION_CREATION = "session_creation"
    SESSION_EXPIRATION = "session_expiration"
    SESSION_INVALIDATION = "session_invalidation"
    ACCOUNT_LOCKOUT = "account_lockout"
    ACCOUNT_UNLOCK = "account_unlock"
    ROLE_ASSIGNMENT = "role_assignment"
    ROLE_REVOCATION = "role_revocation"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_VIOLATION = "security_violation"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    API_KEY_CREATION = "api_key_creation"
    API_KEY_REVOCATION = "api_key_revocation"


class SecuritySeverityLevel(Enum):
    """
    Security event severity levels for alerting and incident response coordination.
    
    Aligns with Section 6.4.6.2 incident classification and automated response procedures.
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuthenticationMethod(Enum):
    """
    Authentication method types for comprehensive audit tracking.
    
    Supports various authentication mechanisms per Section 6.4.1 authentication framework.
    """
    PASSWORD = "password"
    TOKEN = "token"
    REFRESH_TOKEN = "refresh_token"
    API_KEY = "api_key"
    SESSION = "session"
    SSO = "sso"
    MFA = "mfa"
    OAUTH = "oauth"


class AuthenticationLog(BaseModel):
    """
    Comprehensive authentication audit logging model for security monitoring and compliance.
    
    This model captures detailed authentication events, security violations, and user activities
    for compliance reporting, anomaly detection, and real-time security monitoring. Integrates
    with structured logging frameworks, Prometheus metrics, and AWS CloudWatch for comprehensive
    security observability.
    
    Attributes:
        id (int): Primary key with auto-incrementing integer for optimal join performance
        correlation_id (UUID): Unique correlation identifier for request tracking across systems
        user_id (int): Foreign key reference to User model for audit trail attribution
        event_type (AuthenticationEventType): Standardized authentication event categorization
        authentication_method (AuthenticationMethod): Method used for authentication attempt
        severity_level (SecuritySeverityLevel): Security severity for alerting and response
        event_timestamp (datetime): Precise timestamp of authentication event occurrence
        source_ip_address (str): Client IP address for geographic and network analysis
        user_agent (str): Client user agent string for device and browser identification
        session_id (str): Session identifier for correlation with session management
        request_id (str): Request correlation ID for distributed system tracking
        blueprint_name (str): Flask blueprint context for endpoint-specific analysis
        endpoint_name (str): Specific API endpoint for detailed security monitoring
        http_method (str): HTTP method for request pattern analysis
        success (bool): Authentication attempt success status for failure pattern analysis
        failure_reason (str): Detailed failure reason for security investigation
        event_details (JSONB): Structured event data in PostgreSQL JSONB format
        security_context (JSONB): Additional security metadata and threat intelligence
        compliance_data (JSONB): GDPR and regulatory compliance tracking information
        anomaly_score (float): ML-based anomaly detection score for behavioral analysis
        geo_location (JSONB): Geographic location data for threat analysis
        device_fingerprint (str): Device identification for fraud detection
        risk_assessment (JSONB): Real-time risk assessment data and threat indicators
        retention_until (datetime): Data retention expiration for automated compliance
        archived (bool): Archive status for data lifecycle management
        created_at (datetime): Record creation timestamp with timezone support
        updated_at (datetime): Record modification timestamp with automatic updates
        
    Relationships:
        user (User): Many-to-one relationship with User model for audit attribution
    """
    
    __tablename__ = 'authentication_logs'
    
    # Unique correlation identifier for request tracking per Section 6.4.2.5
    correlation_id = Column(
        UUID(as_uuid=True),
        nullable=False,
        default=uuid.uuid4,
        unique=True,
        index=True,
        comment="Unique correlation identifier for end-to-end audit trail tracking"
    )
    
    # Foreign key relationship to User model for audit trail attribution
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,  # Allow null for failed authentication attempts
        index=True,
        comment="Foreign key reference to User model for audit trail attribution"
    )
    
    # Authentication event categorization using PostgreSQL Enum per Section 6.4.2.5
    event_type = Column(
        SQLEnum(AuthenticationEventType),
        nullable=False,
        index=True,
        comment="Standardized authentication event type for security analysis"
    )
    
    # Authentication method tracking for comprehensive audit analysis
    authentication_method = Column(
        SQLEnum(AuthenticationMethod),
        nullable=True,
        index=True,
        comment="Authentication method used for security pattern analysis"
    )
    
    # Security severity level for automated alerting per Section 6.4.6.2
    severity_level = Column(
        SQLEnum(SecuritySeverityLevel),
        nullable=False,
        default=SecuritySeverityLevel.INFO,
        index=True,
        comment="Security severity level for incident response and alerting"
    )
    
    # Precise event timestamp with timezone support for accurate audit trails
    event_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
        comment="Precise timestamp of authentication event with timezone support"
    )
    
    # Source IP address for network-based threat analysis per Section 6.4.6.1
    source_ip_address = Column(
        String(45),  # Supports both IPv4 and IPv6 addresses
        nullable=True,
        index=True,
        comment="Client IP address for geographic and network-based threat analysis"
    )
    
    # User agent string for device and browser identification
    user_agent = Column(
        Text,
        nullable=True,
        comment="Client user agent string for device identification and analysis"
    )
    
    # Session management correlation for Flask session tracking
    session_id = Column(
        String(255),
        nullable=True,
        index=True,
        comment="Session identifier for correlation with Flask session management"
    )
    
    # Request correlation ID for distributed system tracking per Section 6.4.2.5
    request_id = Column(
        String(255),
        nullable=True,
        index=True,
        comment="Request correlation ID for distributed system audit trail tracking"
    )
    
    # Flask blueprint context for endpoint-specific security analysis
    blueprint_name = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Flask blueprint name for modular security monitoring and analysis"
    )
    
    # Specific endpoint name for granular security monitoring
    endpoint_name = Column(
        String(200),
        nullable=True,
        index=True,
        comment="Specific API endpoint for detailed security pattern analysis"
    )
    
    # HTTP method for request pattern analysis and security monitoring
    http_method = Column(
        String(10),
        nullable=True,
        index=True,
        comment="HTTP method for request pattern analysis and security monitoring"
    )
    
    # Authentication success status for failure pattern analysis
    success = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Authentication attempt success status for security pattern analysis"
    )
    
    # Detailed failure reason for security investigation and analysis
    failure_reason = Column(
        String(500),
        nullable=True,
        comment="Detailed authentication failure reason for security investigation"
    )
    
    # Structured event data using PostgreSQL JSONB for flexible schema per Section 6.4.2.5
    event_details = Column(
        JSONB,
        nullable=True,
        comment="Structured authentication event data in machine-readable JSON format"
    )
    
    # Security context and threat intelligence metadata
    security_context = Column(
        JSONB,
        nullable=True,
        comment="Security metadata including threat intelligence and risk indicators"
    )
    
    # GDPR and regulatory compliance tracking per Section 6.2.4.1
    compliance_data = Column(
        JSONB,
        nullable=True,
        comment="GDPR and regulatory compliance tracking information and metadata"
    )
    
    # ML-based anomaly detection score for behavioral analysis per Section 6.4.6.1
    anomaly_score = Column(
        db.Numeric(5, 4),  # Precision 5, scale 4 for scores like 0.9999
        nullable=True,
        default=0.0,
        index=True,
        comment="Machine learning anomaly detection score for behavioral analysis"
    )
    
    # Geographic location data for threat analysis and fraud detection
    geo_location = Column(
        JSONB,
        nullable=True,
        comment="Geographic location data for threat analysis and fraud detection"
    )
    
    # Device fingerprint for fraud detection and device tracking
    device_fingerprint = Column(
        String(255),
        nullable=True,
        index=True,
        comment="Device fingerprint hash for fraud detection and device correlation"
    )
    
    # Real-time risk assessment data and threat indicators
    risk_assessment = Column(
        JSONB,
        nullable=True,
        comment="Real-time risk assessment data and security threat indicators"
    )
    
    # Data retention management for automated compliance per Section 6.2.4.1
    retention_until = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Data retention expiration timestamp for automated compliance management"
    )
    
    # Archive status for data lifecycle management
    archived = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Archive status for data lifecycle management and compliance"
    )
    
    # Relationship to User model for audit trail attribution per Section 6.2.2.1
    user = relationship(
        'User',
        back_populates=None,  # User model doesn't need back_populates for logs
        lazy='select',
        foreign_keys=[user_id],
        doc="Many-to-one relationship with User model for comprehensive audit attribution"
    )
    
    # Database constraints and indexes for performance optimization per Section 6.2.2.2
    __table_args__ = (
        # Check constraints for data validation and integrity
        CheckConstraint(
            "anomaly_score >= 0.0 AND anomaly_score <= 1.0",
            name='ck_auth_log_anomaly_score_range'
        ),
        CheckConstraint(
            "LENGTH(source_ip_address) >= 7",  # Minimum valid IP: "1.1.1.1"
            name='ck_auth_log_ip_address_format'
        ),
        CheckConstraint(
            "http_method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS')",
            name='ck_auth_log_http_method_valid'
        ),
        
        # Composite indexes for performance optimization per Section 6.2.2.2
        Index('ix_auth_log_user_event_timestamp', 'user_id', 'event_timestamp'),
        Index('ix_auth_log_event_type_timestamp', 'event_type', 'event_timestamp'),
        Index('ix_auth_log_severity_timestamp', 'severity_level', 'event_timestamp'),
        Index('ix_auth_log_success_timestamp', 'success', 'event_timestamp'),
        Index('ix_auth_log_ip_timestamp', 'source_ip_address', 'event_timestamp'),
        Index('ix_auth_log_retention_archived', 'retention_until', 'archived'),
        Index('ix_auth_log_blueprint_endpoint', 'blueprint_name', 'endpoint_name'),
        Index('ix_auth_log_anomaly_score_timestamp', 'anomaly_score', 'event_timestamp'),
        Index('ix_auth_log_device_timestamp', 'device_fingerprint', 'event_timestamp'),
        
        # GIN indexes for JSONB columns to support complex queries
        Index('ix_auth_log_event_details_gin', 'event_details', postgresql_using='gin'),
        Index('ix_auth_log_security_context_gin', 'security_context', postgresql_using='gin'),
        Index('ix_auth_log_compliance_data_gin', 'compliance_data', postgresql_using='gin'),
        Index('ix_auth_log_geo_location_gin', 'geo_location', postgresql_using='gin'),
        Index('ix_auth_log_risk_assessment_gin', 'risk_assessment', postgresql_using='gin'),
        
        # Table-level comment for documentation
        {'comment': 'Comprehensive authentication audit logging for security monitoring and compliance'}
    )
    
    def __init__(self, **kwargs) -> None:
        """
        Initialize AuthenticationLog instance with comprehensive security context.
        
        Automatically generates correlation ID, sets retention policy, and configures
        structured logging context for security monitoring and compliance tracking.
        
        Args:
            **kwargs: Field values for authentication log initialization
        """
        # Generate unique correlation ID if not provided
        if 'correlation_id' not in kwargs:
            kwargs['correlation_id'] = uuid.uuid4()
        
        # Set default retention period based on event type per Section 6.2.4.1
        if 'retention_until' not in kwargs and 'event_type' in kwargs:
            kwargs['retention_until'] = self._calculate_retention_period(kwargs['event_type'])
        
        # Set default severity level if not provided
        if 'severity_level' not in kwargs:
            kwargs['severity_level'] = self._determine_default_severity(kwargs.get('event_type'))
        
        # Initialize with structured logging context
        super().__init__(**kwargs)
        
        # Log the audit event creation for monitoring per Section 6.4.2.5
        logger.info(
            "Authentication audit log created",
            correlation_id=str(self.correlation_id),
            event_type=self.event_type.value if self.event_type else None,
            user_id=self.user_id,
            severity=self.severity_level.value if self.severity_level else None,
            timestamp=self.event_timestamp.isoformat() if self.event_timestamp else None
        )
    
    @validates('source_ip_address')
    def validate_ip_address(self, key, address):
        """
        Validate IP address format for security monitoring accuracy.
        
        Args:
            key (str): Field name being validated
            address (str): IP address to validate
            
        Returns:
            str: Validated IP address
            
        Raises:
            ValueError: If IP address format is invalid
        """
        if address is None:
            return address
        
        import ipaddress
        try:
            # Validate IPv4 or IPv6 address format
            ipaddress.ip_address(address)
            return address
        except ValueError:
            # Log invalid IP address for security analysis
            logger.warning(
                "Invalid IP address format in authentication log",
                ip_address=address,
                correlation_id=str(self.correlation_id) if hasattr(self, 'correlation_id') else None
            )
            raise ValueError(f"Invalid IP address format: {address}")
    
    @validates('event_details', 'security_context', 'compliance_data', 'geo_location', 'risk_assessment')
    def validate_json_fields(self, key, value):
        """
        Validate JSON field structure and security content.
        
        Args:
            key (str): Field name being validated
            value: JSON data to validate
            
        Returns:
            dict: Validated JSON data
        """
        if value is None:
            return value
        
        # Ensure value is a dictionary for consistent JSON structure
        if not isinstance(value, dict):
            try:
                value = json.loads(value) if isinstance(value, str) else dict(value)
            except (ValueError, TypeError) as e:
                logger.error(
                    "Invalid JSON structure in authentication log",
                    field=key,
                    error=str(e),
                    correlation_id=str(self.correlation_id) if hasattr(self, 'correlation_id') else None
                )
                raise ValueError(f"Invalid JSON structure for field {key}: {e}")
        
        return value
    
    def _calculate_retention_period(self, event_type: AuthenticationEventType) -> datetime:
        """
        Calculate data retention period based on event type and compliance requirements.
        
        Implements GDPR and regulatory compliance retention policies per Section 6.2.4.1.
        
        Args:
            event_type (AuthenticationEventType): Type of authentication event
            
        Returns:
            datetime: Retention expiration timestamp
        """
        current_time = datetime.now(timezone.utc)
        
        # Define retention periods by event type per compliance requirements
        retention_periods = {
            AuthenticationEventType.LOGIN_SUCCESS: timedelta(days=365),  # 1 year for audit trails
            AuthenticationEventType.LOGIN_FAILURE: timedelta(days=2555),  # 7 years for security incidents
            AuthenticationEventType.SUSPICIOUS_ACTIVITY: timedelta(days=2555),  # 7 years for security
            AuthenticationEventType.SECURITY_VIOLATION: timedelta(days=2555),  # 7 years for security
            AuthenticationEventType.PASSWORD_CHANGE: timedelta(days=2555),  # 7 years for compliance
            AuthenticationEventType.ROLE_ASSIGNMENT: timedelta(days=2555),  # 7 years for audit trails
            AuthenticationEventType.ROLE_REVOCATION: timedelta(days=2555),  # 7 years for audit trails
        }
        
        # Default retention period for other events
        default_retention = timedelta(days=730)  # 2 years default
        
        retention_period = retention_periods.get(event_type, default_retention)
        return current_time + retention_period
    
    def _determine_default_severity(self, event_type: Optional[AuthenticationEventType]) -> SecuritySeverityLevel:
        """
        Determine default security severity level based on event type.
        
        Args:
            event_type (Optional[AuthenticationEventType]): Authentication event type
            
        Returns:
            SecuritySeverityLevel: Default severity level for the event type
        """
        if not event_type:
            return SecuritySeverityLevel.INFO
        
        # Map event types to default severity levels
        severity_mapping = {
            AuthenticationEventType.LOGIN_SUCCESS: SecuritySeverityLevel.INFO,
            AuthenticationEventType.LOGIN_FAILURE: SecuritySeverityLevel.MEDIUM,
            AuthenticationEventType.LOGOUT: SecuritySeverityLevel.INFO,
            AuthenticationEventType.SUSPICIOUS_ACTIVITY: SecuritySeverityLevel.HIGH,
            AuthenticationEventType.SECURITY_VIOLATION: SecuritySeverityLevel.CRITICAL,
            AuthenticationEventType.ACCOUNT_LOCKOUT: SecuritySeverityLevel.HIGH,
            AuthenticationEventType.PASSWORD_CHANGE: SecuritySeverityLevel.MEDIUM,
            AuthenticationEventType.ROLE_ASSIGNMENT: SecuritySeverityLevel.MEDIUM,
            AuthenticationEventType.PERMISSION_DENIED: SecuritySeverityLevel.MEDIUM,
            AuthenticationEventType.MFA_FAILURE: SecuritySeverityLevel.HIGH,
        }
        
        return severity_mapping.get(event_type, SecuritySeverityLevel.INFO)
    
    def to_structured_log(self) -> Dict[str, Any]:
        """
        Convert authentication log to structured logging format per Section 6.4.2.5.
        
        Generates machine-readable log entry for integration with AWS CloudWatch,
        ELK stack, and other centralized logging systems.
        
        Returns:
            Dict[str, Any]: Structured log data for external logging systems
        """
        return {
            'correlation_id': str(self.correlation_id),
            'event_type': self.event_type.value if self.event_type else None,
            'authentication_method': self.authentication_method.value if self.authentication_method else None,
            'severity_level': self.severity_level.value if self.severity_level else None,
            'event_timestamp': self.event_timestamp.isoformat() if self.event_timestamp else None,
            'user_id': self.user_id,
            'source_ip_address': self.source_ip_address,
            'user_agent': self.user_agent,
            'session_id': self.session_id,
            'request_id': self.request_id,
            'blueprint_name': self.blueprint_name,
            'endpoint_name': self.endpoint_name,
            'http_method': self.http_method,
            'success': self.success,
            'failure_reason': self.failure_reason,
            'anomaly_score': float(self.anomaly_score) if self.anomaly_score else None,
            'device_fingerprint': self.device_fingerprint,
            'event_details': self.event_details,
            'security_context': self.security_context,
            'compliance_data': self.compliance_data,
            'geo_location': self.geo_location,
            'risk_assessment': self.risk_assessment,
            'archived': self.archived,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def to_prometheus_metrics(self) -> Dict[str, Union[int, float, str]]:
        """
        Convert authentication log to Prometheus metrics format per Section 6.4.6.1.
        
        Generates metrics data for real-time monitoring, alerting, and anomaly detection
        integration with Prometheus monitoring infrastructure.
        
        Returns:
            Dict[str, Union[int, float, str]]: Prometheus metrics data
        """
        return {
            'auth_event_total': 1,
            'auth_success_total': 1 if self.success else 0,
            'auth_failure_total': 0 if self.success else 1,
            'auth_anomaly_score': float(self.anomaly_score) if self.anomaly_score else 0.0,
            'event_type': self.event_type.value if self.event_type else 'unknown',
            'severity_level': self.severity_level.value if self.severity_level else 'info',
            'authentication_method': self.authentication_method.value if self.authentication_method else 'unknown',
            'blueprint_name': self.blueprint_name or 'unknown',
            'endpoint_name': self.endpoint_name or 'unknown',
            'http_method': self.http_method or 'unknown',
            'source_ip': self.source_ip_address or 'unknown',
            'user_id': str(self.user_id) if self.user_id else 'anonymous'
        }
    
    def mark_for_archival(self, archive_reason: str = None) -> None:
        """
        Mark authentication log for archival per data lifecycle management.
        
        Implements automated data archival for compliance requirements per Section 6.2.4.1
        and prepares record for migration to long-term storage systems.
        
        Args:
            archive_reason (str): Optional reason for archival action
        """
        self.archived = True
        self.updated_at = datetime.now(timezone.utc)
        
        # Update compliance data with archival information
        if not self.compliance_data:
            self.compliance_data = {}
        
        self.compliance_data.update({
            'archived_at': datetime.now(timezone.utc).isoformat(),
            'archive_reason': archive_reason or 'automated_retention_policy',
            'archival_triggered_by': 'system_automated_process'
        })
        
        # Log archival action for audit trail
        logger.info(
            "Authentication log marked for archival",
            correlation_id=str(self.correlation_id),
            user_id=self.user_id,
            archive_reason=archive_reason,
            retention_until=self.retention_until.isoformat() if self.retention_until else None
        )
    
    def update_anomaly_score(self, score: float, detection_method: str = None) -> None:
        """
        Update anomaly detection score for security monitoring per Section 6.4.6.1.
        
        Integrates with ML-based anomaly detection systems for behavioral analysis
        and automated threat detection capabilities.
        
        Args:
            score (float): Anomaly score between 0.0 and 1.0
            detection_method (str): Method used for anomaly detection
            
        Raises:
            ValueError: If anomaly score is outside valid range
        """
        if not (0.0 <= score <= 1.0):
            raise ValueError(f"Anomaly score must be between 0.0 and 1.0, got {score}")
        
        self.anomaly_score = score
        self.updated_at = datetime.now(timezone.utc)
        
        # Update risk assessment with anomaly detection data
        if not self.risk_assessment:
            self.risk_assessment = {}
        
        self.risk_assessment.update({
            'anomaly_score': score,
            'detection_method': detection_method or 'ml_behavioral_analysis',
            'score_updated_at': datetime.now(timezone.utc).isoformat(),
            'risk_level': self._calculate_risk_level(score)
        })
        
        # Log anomaly score update for security monitoring
        logger.warning(
            "Anomaly score updated for authentication log",
            correlation_id=str(self.correlation_id),
            user_id=self.user_id,
            anomaly_score=score,
            detection_method=detection_method,
            risk_level=self._calculate_risk_level(score)
        )
    
    def _calculate_risk_level(self, anomaly_score: float) -> str:
        """
        Calculate risk level based on anomaly score for threat assessment.
        
        Args:
            anomaly_score (float): ML-based anomaly detection score
            
        Returns:
            str: Risk level classification for security response
        """
        if anomaly_score >= 0.9:
            return 'critical'
        elif anomaly_score >= 0.7:
            return 'high'
        elif anomaly_score >= 0.5:
            return 'medium'
        elif anomaly_score >= 0.3:
            return 'low'
        else:
            return 'minimal'
    
    @classmethod
    def create_authentication_event(
        cls,
        event_type: AuthenticationEventType,
        user_id: Optional[int] = None,
        success: bool = False,
        authentication_method: Optional[AuthenticationMethod] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        blueprint_name: Optional[str] = None,
        endpoint_name: Optional[str] = None,
        http_method: Optional[str] = None,
        failure_reason: Optional[str] = None,
        event_details: Optional[Dict[str, Any]] = None,
        security_context: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> 'AuthenticationLog':
        """
        Factory method for creating authentication log entries with comprehensive context.
        
        Provides a convenient interface for creating structured authentication logs
        with automatic validation, correlation ID generation, and structured logging.
        
        Args:
            event_type (AuthenticationEventType): Type of authentication event
            user_id (Optional[int]): User ID for audit trail attribution
            success (bool): Authentication attempt success status
            authentication_method (Optional[AuthenticationMethod]): Authentication method used
            source_ip (Optional[str]): Client IP address
            user_agent (Optional[str]): Client user agent string
            session_id (Optional[str]): Session identifier
            request_id (Optional[str]): Request correlation ID
            blueprint_name (Optional[str]): Flask blueprint name
            endpoint_name (Optional[str]): API endpoint name
            http_method (Optional[str]): HTTP method
            failure_reason (Optional[str]): Authentication failure reason
            event_details (Optional[Dict[str, Any]]): Additional event data
            security_context (Optional[Dict[str, Any]]): Security metadata
            **kwargs: Additional authentication log fields
            
        Returns:
            AuthenticationLog: Created and saved authentication log instance
        """
        # Create authentication log instance
        auth_log = cls(
            event_type=event_type,
            user_id=user_id,
            success=success,
            authentication_method=authentication_method,
            source_ip_address=source_ip,
            user_agent=user_agent,
            session_id=session_id,
            request_id=request_id,
            blueprint_name=blueprint_name,
            endpoint_name=endpoint_name,
            http_method=http_method,
            failure_reason=failure_reason,
            event_details=event_details or {},
            security_context=security_context or {},
            **kwargs
        )
        
        # Save to database and return instance
        return auth_log.save()
    
    @classmethod
    def get_user_authentication_history(
        cls,
        user_id: int,
        limit: int = 100,
        event_types: Optional[List[AuthenticationEventType]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List['AuthenticationLog']:
        """
        Retrieve user authentication history for security analysis and audit trails.
        
        Args:
            user_id (int): User ID for history retrieval
            limit (int): Maximum number of records to return
            event_types (Optional[List[AuthenticationEventType]]): Filter by event types
            start_date (Optional[datetime]): Start date for history range
            end_date (Optional[datetime]): End date for history range
            
        Returns:
            List[AuthenticationLog]: User authentication history records
        """
        query = cls.query.filter(cls.user_id == user_id)
        
        # Apply event type filter if specified
        if event_types:
            query = query.filter(cls.event_type.in_(event_types))
        
        # Apply date range filter if specified
        if start_date:
            query = query.filter(cls.event_timestamp >= start_date)
        if end_date:
            query = query.filter(cls.event_timestamp <= end_date)
        
        # Order by timestamp and limit results
        return query.order_by(cls.event_timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_security_events_by_severity(
        cls,
        severity_level: SecuritySeverityLevel,
        hours: int = 24,
        limit: int = 1000
    ) -> List['AuthenticationLog']:
        """
        Retrieve security events by severity level for incident response per Section 6.4.6.2.
        
        Args:
            severity_level (SecuritySeverityLevel): Minimum severity level to retrieve
            hours (int): Time window in hours for event retrieval
            limit (int): Maximum number of records to return
            
        Returns:
            List[AuthenticationLog]: Security events matching criteria
        """
        # Calculate time window
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Define severity level ordering for filtering
        severity_order = {
            SecuritySeverityLevel.INFO: 0,
            SecuritySeverityLevel.LOW: 1,
            SecuritySeverityLevel.MEDIUM: 2,
            SecuritySeverityLevel.HIGH: 3,
            SecuritySeverityLevel.CRITICAL: 4
        }
        
        # Get severity levels to include (current level and higher)
        min_severity_value = severity_order[severity_level]
        included_severities = [
            level for level, value in severity_order.items()
            if value >= min_severity_value
        ]
        
        return cls.query.filter(
            cls.severity_level.in_(included_severities),
            cls.event_timestamp >= start_time,
            cls.archived == False
        ).order_by(cls.event_timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_anomalous_events(
        cls,
        anomaly_threshold: float = 0.7,
        hours: int = 24,
        limit: int = 500
    ) -> List['AuthenticationLog']:
        """
        Retrieve anomalous authentication events for security analysis per Section 6.4.6.1.
        
        Args:
            anomaly_threshold (float): Minimum anomaly score threshold
            hours (int): Time window in hours for event retrieval
            limit (int): Maximum number of records to return
            
        Returns:
            List[AuthenticationLog]: Anomalous authentication events
        """
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        return cls.query.filter(
            cls.anomaly_score >= anomaly_threshold,
            cls.event_timestamp >= start_time,
            cls.archived == False
        ).order_by(cls.anomaly_score.desc(), cls.event_timestamp.desc()).limit(limit).all()
    
    @classmethod
    def archive_expired_logs(cls) -> int:
        """
        Archive expired authentication logs per data retention policies.
        
        Implements automated data archival for compliance requirements per Section 6.2.4.1
        and returns the number of logs marked for archival.
        
        Returns:
            int: Number of logs marked for archival
        """
        current_time = datetime.now(timezone.utc)
        
        # Find logs that have exceeded their retention period
        expired_logs = cls.query.filter(
            cls.retention_until <= current_time,
            cls.archived == False
        ).all()
        
        # Mark logs for archival
        archived_count = 0
        for log in expired_logs:
            log.mark_for_archival("automated_retention_policy_expiration")
            archived_count += 1
        
        # Commit changes to database
        db.session.commit()
        
        # Log archival operation for audit trail
        logger.info(
            "Automated authentication log archival completed",
            archived_count=archived_count,
            execution_time=current_time.isoformat()
        )
        
        return archived_count
    
    def __repr__(self) -> str:
        """
        String representation of AuthenticationLog for debugging and logging.
        
        Returns:
            str: Human-readable representation of authentication log
        """
        return (
            f"<AuthenticationLog(id={self.id}, correlation_id='{self.correlation_id}', "
            f"event_type='{self.event_type.value if self.event_type else None}', "
            f"user_id={self.user_id}, success={self.success}, "
            f"timestamp='{self.event_timestamp}')>"
        )


# SQLAlchemy event listeners for automated logging and monitoring per Section 6.4.2.5

@event.listens_for(AuthenticationLog, 'after_insert')
def log_authentication_event_created(mapper, connection, target):
    """
    SQLAlchemy event listener for logging authentication event creation.
    
    Automatically generates structured logs for new authentication events
    to support real-time monitoring and security analysis.
    """
    logger.info(
        "Authentication log record created",
        correlation_id=str(target.correlation_id),
        event_type=target.event_type.value if target.event_type else None,
        user_id=target.user_id,
        success=target.success,
        severity=target.severity_level.value if target.severity_level else None,
        source_ip=target.source_ip_address,
        anomaly_score=float(target.anomaly_score) if target.anomaly_score else None
    )


@event.listens_for(AuthenticationLog, 'after_update')
def log_authentication_event_updated(mapper, connection, target):
    """
    SQLAlchemy event listener for logging authentication event updates.
    
    Captures changes to authentication log records for audit trail integrity
    and security monitoring purposes.
    """
    logger.info(
        "Authentication log record updated",
        correlation_id=str(target.correlation_id),
        event_type=target.event_type.value if target.event_type else None,
        user_id=target.user_id,
        anomaly_score=float(target.anomaly_score) if target.anomaly_score else None,
        archived=target.archived,
        updated_at=target.updated_at.isoformat() if target.updated_at else None
    )


# Export the model and enums for use throughout the authentication module
__all__ = [
    'AuthenticationLog',
    'AuthenticationEventType',
    'SecuritySeverityLevel',
    'AuthenticationMethod'
]