"""
SecurityIncident Model Implementation for Automated Security Incident Tracking.

This module implements the SecurityIncident model for comprehensive threat detection,
incident classification, and automated response coordination. The model captures
security violations, authentication anomalies, and potential threats with integrated
incident management capabilities for real-time security response.

Key Features:
- Automated security incident detection and tracking per Section 6.4.6.2
- Incident classification system with severity levels and response prioritization
- Containment action coordination and automated response procedures
- Evidence collection and storage for security investigations
- Integration with monitoring systems for real-time incident response
- Flask incident response system integration for automated threat containment
- JSON-based evidence storage for comprehensive incident documentation
- Temporal incident management with status tracking and resolution workflows

Technical Specification References:
- Section 6.4.6.2: Incident Response Procedures with Python-Specific Response Capabilities
- Section 6.4.6.1: Real-Time Security Monitoring with Python Observability Integration
- Section 6.4.1.4: Token Handling for security incident token revocation procedures
- Section 6.2.2.1: Database relationship integrity with proper foreign key constraints
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import uuid
import json

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, ForeignKey,
    Index, CheckConstraint, UniqueConstraint, Enum as SQLEnum
)
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import relationship, validates
from sqlalchemy.sql import func

from src.models.base import BaseModel, db


class IncidentType(Enum):
    """
    Enumeration of security incident types for classification and response automation.
    
    These incident types align with the Flask security architecture and provide
    comprehensive coverage of authentication, authorization, and runtime security
    threats as specified in Section 6.4.6.2.
    """
    # Authentication and Authorization Incidents
    AUTHENTICATION_BREACH = "auth_breach"
    AUTHORIZATION_BYPASS = "authz_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    BRUTE_FORCE = "brute_force"
    
    # Application Security Incidents
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    CSRF_VIOLATION = "csrf_violation"
    DATA_EXFILTRATION = "data_exfiltration"
    
    # Python Runtime and Flask-Specific Incidents
    PYTHON_RUNTIME_ERROR = "python_runtime_error"
    FLASK_SECURITY_VIOLATION = "flask_security_violation"
    BLUEPRINT_ANOMALY = "blueprint_anomaly"
    SESSION_HIJACKING = "session_hijacking"
    
    # Infrastructure and Network Security
    SUSPICIOUS_NETWORK_ACTIVITY = "suspicious_network_activity"
    CONTAINER_SECURITY_VIOLATION = "container_security_violation"
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
    
    # Monitoring and Compliance
    AUDIT_LOG_TAMPERING = "audit_log_tampering"
    COMPLIANCE_VIOLATION = "compliance_violation"
    ANOMALY_DETECTION = "anomaly_detection"


class IncidentSeverity(Enum):
    """
    Enumeration of incident severity levels for response prioritization.
    
    Severity levels determine automated response procedures and escalation
    workflows as specified in Section 6.4.6.2 incident response procedures.
    """
    CRITICAL = "critical"    # Immediate response required, potential data breach
    HIGH = "high"           # Urgent response required, security compromise likely
    MEDIUM = "medium"       # Timely response required, security risk present
    LOW = "low"            # Standard response timeframe, minimal security impact
    INFO = "info"          # Informational, monitoring and logging purposes


class IncidentStatus(Enum):
    """
    Enumeration of incident lifecycle status values for workflow management.
    
    Status values track incident progression through detection, response,
    containment, and resolution phases.
    """
    DETECTED = "detected"               # Initial detection, automated analysis pending
    ANALYZING = "analyzing"             # Automated analysis in progress
    CONFIRMED = "confirmed"             # Incident validated, response initiated
    CONTAINED = "contained"             # Threat contained, recovery in progress
    INVESTIGATING = "investigating"     # Manual investigation ongoing
    RESOLVED = "resolved"               # Incident fully resolved
    FALSE_POSITIVE = "false_positive"   # Determined to be false alarm
    ESCALATED = "escalated"            # Escalated to security team or external responders


class SecurityIncident(BaseModel):
    """
    SecurityIncident model implementing automated security incident tracking with
    comprehensive threat detection and response coordination.
    
    This model captures security violations, authentication anomalies, and potential
    threats with automated incident classification, containment action tracking,
    and integration with the Flask incident response system for real-time security
    management.
    
    Attributes:
        id (int): Auto-incrementing primary key for optimal PostgreSQL join performance
        incident_uuid (UUID): Unique identifier for cross-system incident correlation
        incident_type (IncidentType): Classification of incident type for response automation
        severity (IncidentSeverity): Severity level for response prioritization
        status (IncidentStatus): Current incident lifecycle status
        title (str): Human-readable incident title for dashboard display
        description (Text): Detailed incident description and initial analysis
        
        # Attribution and Source Information
        user_id (int): Foreign key to User model for incident attribution
        source_ip (str): Source IP address of the incident trigger
        user_agent (str): User agent string for client identification
        session_id (str): Associated session identifier for authentication incidents
        
        # Flask Application Context
        blueprint_name (str): Flask blueprint where incident occurred
        endpoint_name (str): Specific endpoint associated with the incident
        request_method (str): HTTP method of the incident-triggering request
        request_url (str): Full URL of the incident-triggering request
        
        # Evidence and Metadata Storage
        evidence (JSON): Comprehensive evidence collection as JSON document
        request_data (JSON): Request payload and parameters for analysis
        python_traceback (Text): Python exception traceback for runtime errors
        
        # Response and Containment Tracking
        containment_actions (JSON): List of executed containment actions
        automated_response (JSON): Automated response details and outcomes
        escalation_reason (Text): Reason for manual escalation if applicable
        
        # Temporal Management
        detection_time (DateTime): Timestamp of initial incident detection
        first_response_time (DateTime): Timestamp of first automated response
        resolution_time (DateTime): Timestamp of incident resolution
        
        # Assignment and Workflow
        assigned_to (str): Security analyst or team assigned to incident
        priority_score (int): Calculated priority score for response ordering
        false_positive_reason (Text): Explanation if marked as false positive
        
        # Audit and Compliance
        compliance_impact (JSON): Impact assessment for regulatory compliance
        audit_trail (JSON): Complete audit trail of incident handling actions
        
    Relationships:
        user (User): Many-to-one relationship with User model for attribution
        related_incidents (List[SecurityIncident]): Self-referential relationship for incident correlation
    """
    
    __tablename__ = 'security_incidents'
    
    # Unique incident identifier for cross-system correlation
    incident_uuid = Column(
        UUID(as_uuid=True),
        unique=True,
        nullable=False,
        default=uuid.uuid4,
        index=True,
        comment="Unique identifier for cross-system incident correlation and tracking"
    )
    
    # Incident Classification Fields
    incident_type = Column(
        SQLEnum(IncidentType),
        nullable=False,
        index=True,
        comment="Classification of incident type for automated response procedures"
    )
    
    severity = Column(
        SQLEnum(IncidentSeverity),
        nullable=False,
        index=True,
        comment="Severity level for response prioritization and escalation workflows"
    )
    
    status = Column(
        SQLEnum(IncidentStatus),
        nullable=False,
        default=IncidentStatus.DETECTED,
        index=True,
        comment="Current incident lifecycle status for workflow management"
    )
    
    # Incident Identification and Description
    title = Column(
        String(255),
        nullable=False,
        comment="Human-readable incident title for dashboard display and reporting"
    )
    
    description = Column(
        Text,
        nullable=False,
        comment="Detailed incident description and initial automated analysis"
    )
    
    # Attribution and Source Information
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,  # Some incidents may not be attributable to specific users
        index=True,
        comment="Foreign key to User model for incident attribution and user-based analysis"
    )
    
    source_ip = Column(
        String(45),  # Support IPv6 addresses
        nullable=True,
        index=True,
        comment="Source IP address of the incident trigger for network-based analysis"
    )
    
    user_agent = Column(
        Text,
        nullable=True,
        comment="User agent string for client identification and automated threat analysis"
    )
    
    session_id = Column(
        String(128),
        nullable=True,
        index=True,
        comment="Associated session identifier for authentication and session-based incidents"
    )
    
    # Flask Application Context Information
    blueprint_name = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Flask blueprint where incident occurred for application context analysis"
    )
    
    endpoint_name = Column(
        String(200),
        nullable=True,
        index=True,
        comment="Specific endpoint associated with the incident for route-based analysis"
    )
    
    request_method = Column(
        String(10),
        nullable=True,
        comment="HTTP method of the incident-triggering request for request pattern analysis"
    )
    
    request_url = Column(
        Text,
        nullable=True,
        comment="Full URL of the incident-triggering request for forensic analysis"
    )
    
    # Evidence and Metadata Storage (JSON fields for flexibility)
    evidence = Column(
        JSON,
        nullable=False,
        default=dict,
        comment="Comprehensive evidence collection as JSON document for incident analysis"
    )
    
    request_data = Column(
        JSON,
        nullable=True,
        comment="Request payload and parameters for detailed forensic analysis"
    )
    
    python_traceback = Column(
        Text,
        nullable=True,
        comment="Python exception traceback for runtime error incidents and debugging"
    )
    
    # Response and Containment Tracking
    containment_actions = Column(
        JSON,
        nullable=False,
        default=list,
        comment="List of executed containment actions for response tracking and audit"
    )
    
    automated_response = Column(
        JSON,
        nullable=True,
        comment="Automated response details and outcomes for response effectiveness analysis"
    )
    
    escalation_reason = Column(
        Text,
        nullable=True,
        comment="Reason for manual escalation if automated response insufficient"
    )
    
    # Temporal Management Fields
    detection_time = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
        comment="Timestamp of initial incident detection for response time analysis"
    )
    
    first_response_time = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp of first automated response for response time metrics"
    )
    
    resolution_time = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp of incident resolution for closure metrics and SLA tracking"
    )
    
    # Assignment and Workflow Management
    assigned_to = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Security analyst or team assigned to incident for workflow management"
    )
    
    priority_score = Column(
        Integer,
        nullable=False,
        default=0,
        index=True,
        comment="Calculated priority score for response ordering and resource allocation"
    )
    
    false_positive_reason = Column(
        Text,
        nullable=True,
        comment="Explanation if incident marked as false positive for tuning improvement"
    )
    
    # Audit and Compliance Fields
    compliance_impact = Column(
        JSON,
        nullable=True,
        comment="Impact assessment for regulatory compliance and reporting requirements"
    )
    
    audit_trail = Column(
        JSON,
        nullable=False,
        default=list,
        comment="Complete audit trail of incident handling actions for compliance"
    )
    
    # Relationship to User model for incident attribution
    user = relationship(
        'User',
        backref='security_incidents',
        lazy='select',
        foreign_keys=[user_id],
        doc="Many-to-one relationship with User model for incident attribution"
    )
    
    # Self-referential relationship for incident correlation
    related_incident_id = Column(
        Integer,
        ForeignKey('security_incidents.id', ondelete='SET NULL'),
        nullable=True,
        comment="Foreign key for incident correlation and relationship tracking"
    )
    
    related_incidents = relationship(
        'SecurityIncident',
        backref='parent_incident',
        remote_side='SecurityIncident.id',
        lazy='dynamic',
        doc="Self-referential relationship for incident correlation and grouping"
    )
    
    # Database constraints and indexes for performance optimization
    __table_args__ = (
        # Unique constraints
        UniqueConstraint('incident_uuid', name='uq_security_incident_uuid'),
        
        # Check constraints for data validation
        CheckConstraint('LENGTH(title) >= 5', name='ck_security_incident_title_length'),
        CheckConstraint('LENGTH(description) >= 10', name='ck_security_incident_description_length'),
        CheckConstraint('priority_score >= 0 AND priority_score <= 100', name='ck_security_incident_priority_range'),
        CheckConstraint(
            "source_ip IS NULL OR (source_ip ~ '^([0-9]{1,3}\\.){3}[0-9]{1,3}$' OR source_ip ~ '^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')",
            name='ck_security_incident_ip_format'
        ),
        
        # Composite indexes for query optimization
        Index('ix_security_incident_severity_status', 'severity', 'status'),
        Index('ix_security_incident_type_severity', 'incident_type', 'severity'),
        Index('ix_security_incident_detection_severity', 'detection_time', 'severity'),
        Index('ix_security_incident_user_detection', 'user_id', 'detection_time'),
        Index('ix_security_incident_source_detection', 'source_ip', 'detection_time'),
        Index('ix_security_incident_blueprint_endpoint', 'blueprint_name', 'endpoint_name'),
        Index('ix_security_incident_status_assigned', 'status', 'assigned_to'),
        Index('ix_security_incident_priority_detection', 'priority_score', 'detection_time'),
        
        # Performance indexes for common queries
        Index('ix_security_incident_unresolved', 'status', 'detection_time', 
              postgresql_where="status NOT IN ('resolved', 'false_positive')"),
        Index('ix_security_incident_critical_unresolved', 'severity', 'status', 'detection_time',
              postgresql_where="severity = 'critical' AND status NOT IN ('resolved', 'false_positive')"),
        
        # Table-level comment for documentation
        {'comment': 'Security incidents for automated threat detection and response coordination'}
    )
    
    def __init__(self, **kwargs) -> None:
        """
        Initialize a new SecurityIncident instance with validation and defaults.
        
        Args:
            **kwargs: Field values for incident initialization
            
        Raises:
            ValueError: If required fields are missing or invalid
        """
        # Set default values if not provided
        if 'incident_uuid' not in kwargs:
            kwargs['incident_uuid'] = uuid.uuid4()
        
        if 'detection_time' not in kwargs:
            kwargs['detection_time'] = datetime.now(timezone.utc)
        
        if 'evidence' not in kwargs:
            kwargs['evidence'] = {}
        
        if 'containment_actions' not in kwargs:
            kwargs['containment_actions'] = []
        
        if 'audit_trail' not in kwargs:
            kwargs['audit_trail'] = []
        
        # Calculate initial priority score if not provided
        if 'priority_score' not in kwargs and 'severity' in kwargs:
            kwargs['priority_score'] = self._calculate_priority_score(
                kwargs.get('severity'),
                kwargs.get('incident_type')
            )
        
        super().__init__(**kwargs)
    
    @staticmethod
    def _calculate_priority_score(severity: IncidentSeverity, incident_type: IncidentType) -> int:
        """
        Calculate incident priority score based on severity and type.
        
        Args:
            severity (IncidentSeverity): Incident severity level
            incident_type (IncidentType): Type of security incident
            
        Returns:
            int: Priority score from 0-100 for response ordering
        """
        # Base priority by severity
        severity_scores = {
            IncidentSeverity.CRITICAL: 90,
            IncidentSeverity.HIGH: 70,
            IncidentSeverity.MEDIUM: 50,
            IncidentSeverity.LOW: 30,
            IncidentSeverity.INFO: 10
        }
        
        # Type-specific modifiers
        type_modifiers = {
            IncidentType.AUTHENTICATION_BREACH: 10,
            IncidentType.AUTHORIZATION_BYPASS: 8,
            IncidentType.SQL_INJECTION: 10,
            IncidentType.DATA_EXFILTRATION: 10,
            IncidentType.PRIVILEGE_ESCALATION: 8,
            IncidentType.PYTHON_RUNTIME_ERROR: 5,
            IncidentType.BRUTE_FORCE: 6,
        }
        
        base_score = severity_scores.get(severity, 30)
        modifier = type_modifiers.get(incident_type, 0)
        
        return min(100, base_score + modifier)
    
    @validates('source_ip')
    def validate_source_ip(self, key: str, address: str) -> Optional[str]:
        """
        Validate source IP address format for IPv4 and IPv6.
        
        Args:
            key (str): Field name being validated
            address (str): IP address to validate
            
        Returns:
            Optional[str]: Validated IP address or None if invalid
        """
        if not address:
            return None
        
        import ipaddress
        try:
            ipaddress.ip_address(address)
            return address
        except ValueError:
            # Log validation error but don't raise exception to allow incident creation
            return address  # Store as-is for forensic analysis
    
    @validates('evidence', 'request_data', 'containment_actions', 'automated_response', 'compliance_impact', 'audit_trail')
    def validate_json_fields(self, key: str, value: Any) -> Any:
        """
        Validate JSON fields can be serialized and contain valid data.
        
        Args:
            key (str): Field name being validated
            value (Any): Value to validate
            
        Returns:
            Any: Validated value
            
        Raises:
            ValueError: If value cannot be JSON serialized
        """
        if value is None:
            return None
        
        try:
            # Ensure value can be JSON serialized
            json.dumps(value)
            return value
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid JSON data for field {key}: {str(e)}")
    
    def add_evidence(self, key: str, value: Any) -> None:
        """
        Add evidence to the incident with timestamp.
        
        Args:
            key (str): Evidence key for organization
            value (Any): Evidence value (must be JSON serializable)
        """
        if self.evidence is None:
            self.evidence = {}
        
        self.evidence[key] = {
            'value': value,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'manual_addition'
        }
        
        # Mark the JSON field as modified for SQLAlchemy
        self.evidence = self.evidence.copy()
    
    def add_containment_action(self, action: str, result: str = None, metadata: Dict = None) -> None:
        """
        Record a containment action taken for the incident.
        
        Args:
            action (str): Description of the containment action
            result (str): Result or outcome of the action
            metadata (Dict): Additional metadata about the action
        """
        action_entry = {
            'action': action,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'result': result,
            'metadata': metadata or {}
        }
        
        if self.containment_actions is None:
            self.containment_actions = []
        
        self.containment_actions.append(action_entry)
        
        # Mark the JSON field as modified for SQLAlchemy
        self.containment_actions = self.containment_actions.copy()
    
    def add_audit_entry(self, action: str, actor: str, details: Dict = None) -> None:
        """
        Add entry to the incident audit trail.
        
        Args:
            action (str): Action performed on the incident
            actor (str): Person or system that performed the action
            details (Dict): Additional details about the action
        """
        audit_entry = {
            'action': action,
            'actor': actor,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'details': details or {}
        }
        
        if self.audit_trail is None:
            self.audit_trail = []
        
        self.audit_trail.append(audit_entry)
        
        # Mark the JSON field as modified for SQLAlchemy
        self.audit_trail = self.audit_trail.copy()
    
    def escalate(self, reason: str, assigned_to: str = None) -> None:
        """
        Escalate the incident to manual investigation.
        
        Args:
            reason (str): Reason for escalation
            assigned_to (str): Security analyst or team to assign
        """
        self.status = IncidentStatus.ESCALATED
        self.escalation_reason = reason
        
        if assigned_to:
            self.assigned_to = assigned_to
        
        self.add_audit_entry(
            action='escalated',
            actor='system',
            details={
                'reason': reason,
                'assigned_to': assigned_to,
                'escalation_time': datetime.now(timezone.utc).isoformat()
            }
        )
    
    def resolve(self, resolution_notes: str, actor: str = 'system') -> None:
        """
        Mark the incident as resolved.
        
        Args:
            resolution_notes (str): Notes about the resolution
            actor (str): Who resolved the incident
        """
        self.status = IncidentStatus.RESOLVED
        self.resolution_time = datetime.now(timezone.utc)
        
        self.add_audit_entry(
            action='resolved',
            actor=actor,
            details={
                'resolution_notes': resolution_notes,
                'resolution_time': self.resolution_time.isoformat()
            }
        )
    
    def mark_false_positive(self, reason: str, actor: str = 'system') -> None:
        """
        Mark the incident as a false positive.
        
        Args:
            reason (str): Reason for false positive classification
            actor (str): Who made the determination
        """
        self.status = IncidentStatus.FALSE_POSITIVE
        self.false_positive_reason = reason
        self.resolution_time = datetime.now(timezone.utc)
        
        self.add_audit_entry(
            action='marked_false_positive',
            actor=actor,
            details={
                'reason': reason,
                'classification_time': self.resolution_time.isoformat()
            }
        )
    
    def get_response_time_seconds(self) -> Optional[int]:
        """
        Calculate response time in seconds from detection to first response.
        
        Returns:
            Optional[int]: Response time in seconds, None if not yet responded
        """
        if not self.first_response_time:
            return None
        
        delta = self.first_response_time - self.detection_time
        return int(delta.total_seconds())
    
    def get_resolution_time_seconds(self) -> Optional[int]:
        """
        Calculate total resolution time in seconds from detection to resolution.
        
        Returns:
            Optional[int]: Resolution time in seconds, None if not yet resolved
        """
        if not self.resolution_time:
            return None
        
        delta = self.resolution_time - self.detection_time
        return int(delta.total_seconds())
    
    def is_active(self) -> bool:
        """
        Check if the incident is still active and requires attention.
        
        Returns:
            bool: True if incident is active, False if resolved or false positive
        """
        return self.status not in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE)
    
    def is_critical(self) -> bool:
        """
        Check if the incident is critical severity.
        
        Returns:
            bool: True if incident is critical severity
        """
        return self.severity == IncidentSeverity.CRITICAL
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert SecurityIncident instance to dictionary representation.
        
        Args:
            include_sensitive (bool): Whether to include sensitive evidence data
            
        Returns:
            Dict[str, Any]: Dictionary representation of the incident
        """
        result = {
            'id': self.id,
            'incident_uuid': str(self.incident_uuid),
            'incident_type': self.incident_type.value,
            'severity': self.severity.value,
            'status': self.status.value,
            'title': self.title,
            'description': self.description,
            'user_id': self.user_id,
            'source_ip': self.source_ip,
            'session_id': self.session_id,
            'blueprint_name': self.blueprint_name,
            'endpoint_name': self.endpoint_name,
            'request_method': self.request_method,
            'detection_time': self.detection_time.isoformat() if self.detection_time else None,
            'first_response_time': self.first_response_time.isoformat() if self.first_response_time else None,
            'resolution_time': self.resolution_time.isoformat() if self.resolution_time else None,
            'assigned_to': self.assigned_to,
            'priority_score': self.priority_score,
            'containment_actions': self.containment_actions or [],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_sensitive:
            result.update({
                'evidence': self.evidence or {},
                'request_data': self.request_data,
                'python_traceback': self.python_traceback,
                'user_agent': self.user_agent,
                'request_url': self.request_url,
                'automated_response': self.automated_response,
                'audit_trail': self.audit_trail or [],
                'compliance_impact': self.compliance_impact,
                'escalation_reason': self.escalation_reason,
                'false_positive_reason': self.false_positive_reason
            })
        
        return result
    
    @classmethod
    def find_by_uuid(cls, incident_uuid: Union[str, uuid.UUID]) -> Optional['SecurityIncident']:
        """
        Find incident by UUID with efficient query.
        
        Args:
            incident_uuid (Union[str, uuid.UUID]): UUID to search for
            
        Returns:
            Optional[SecurityIncident]: Incident if found, None otherwise
        """
        if isinstance(incident_uuid, str):
            try:
                incident_uuid = uuid.UUID(incident_uuid)
            except ValueError:
                return None
        
        return cls.query.filter_by(incident_uuid=incident_uuid).first()
    
    @classmethod
    def find_active_incidents(cls, severity: IncidentSeverity = None, limit: int = 100) -> List['SecurityIncident']:
        """
        Find active incidents with optional severity filtering.
        
        Args:
            severity (IncidentSeverity): Optional severity filter
            limit (int): Maximum number of incidents to return
            
        Returns:
            List[SecurityIncident]: List of active incidents
        """
        query = cls.query.filter(
            cls.status.notin_([IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE])
        )
        
        if severity:
            query = query.filter_by(severity=severity)
        
        return query.order_by(
            cls.priority_score.desc(),
            cls.detection_time.desc()
        ).limit(limit).all()
    
    @classmethod
    def find_by_user(cls, user_id: int, limit: int = 50) -> List['SecurityIncident']:
        """
        Find incidents associated with a specific user.
        
        Args:
            user_id (int): User ID to search for
            limit (int): Maximum number of incidents to return
            
        Returns:
            List[SecurityIncident]: List of user-associated incidents
        """
        return cls.query.filter_by(user_id=user_id).order_by(
            cls.detection_time.desc()
        ).limit(limit).all()
    
    @classmethod
    def find_by_source_ip(cls, source_ip: str, limit: int = 50) -> List['SecurityIncident']:
        """
        Find incidents from a specific source IP address.
        
        Args:
            source_ip (str): Source IP address to search for
            limit (int): Maximum number of incidents to return
            
        Returns:
            List[SecurityIncident]: List of incidents from the IP address
        """
        return cls.query.filter_by(source_ip=source_ip).order_by(
            cls.detection_time.desc()
        ).limit(limit).all()
    
    @classmethod
    def get_incident_statistics(cls, days: int = 30) -> Dict[str, Any]:
        """
        Get incident statistics for the specified time period.
        
        Args:
            days (int): Number of days to include in statistics
            
        Returns:
            Dict[str, Any]: Statistics about incidents
        """
        start_time = datetime.now(timezone.utc) - timedelta(days=days)
        
        incidents = cls.query.filter(cls.detection_time >= start_time).all()
        
        stats = {
            'total_incidents': len(incidents),
            'by_severity': {},
            'by_type': {},
            'by_status': {},
            'avg_response_time_seconds': 0,
            'avg_resolution_time_seconds': 0,
            'active_incidents': 0,
            'false_positive_rate': 0
        }
        
        response_times = []
        resolution_times = []
        
        for incident in incidents:
            # Count by severity
            severity = incident.severity.value
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Count by type
            incident_type = incident.incident_type.value
            stats['by_type'][incident_type] = stats['by_type'].get(incident_type, 0) + 1
            
            # Count by status
            status = incident.status.value
            stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
            
            # Collect timing data
            response_time = incident.get_response_time_seconds()
            if response_time:
                response_times.append(response_time)
            
            resolution_time = incident.get_resolution_time_seconds()
            if resolution_time:
                resolution_times.append(resolution_time)
            
            # Count active incidents
            if incident.is_active():
                stats['active_incidents'] += 1
        
        # Calculate averages
        if response_times:
            stats['avg_response_time_seconds'] = sum(response_times) / len(response_times)
        
        if resolution_times:
            stats['avg_resolution_time_seconds'] = sum(resolution_times) / len(resolution_times)
        
        # Calculate false positive rate
        false_positives = stats['by_status'].get('false_positive', 0)
        if stats['total_incidents'] > 0:
            stats['false_positive_rate'] = false_positives / stats['total_incidents']
        
        return stats
    
    def __repr__(self) -> str:
        """
        String representation of SecurityIncident for debugging and logging.
        
        Returns:
            str: String representation of the incident
        """
        return (
            f"<SecurityIncident(id={self.id}, uuid={self.incident_uuid}, "
            f"type={self.incident_type.value}, severity={self.severity.value}, "
            f"status={self.status.value})>"
        )
    
    def __str__(self) -> str:
        """
        Human-readable string representation of SecurityIncident.
        
        Returns:
            str: User-friendly string representation
        """
        return f"Security Incident: {self.title} ({self.severity.value.upper()})"


# Export the model and enums for use throughout the application
__all__ = [
    'SecurityIncident',
    'IncidentType',
    'IncidentSeverity', 
    'IncidentStatus'
]