"""
SecurityIncident Model Implementation for Automated Security Incident Tracking and Response.

This module implements the SecurityIncident model using Flask-SQLAlchemy declarative patterns
with PostgreSQL optimization and comprehensive security incident management capabilities. The model
provides automated threat detection, incident classification, containment action tracking, and
integration with the Flask incident response system for real-time security management.

Key Features:
- Comprehensive security incident tracking with automated threat detection
- Incident classification system with severity levels and response procedures
- Containment action coordination and automated response procedures
- Evidence collection and storage for security investigations using JSONB
- Integration with monitoring systems for real-time incident response
- Threat intelligence correlation and risk assessment capabilities
- GDPR and compliance-ready incident documentation and audit trails
- Automated escalation and notification workflows
- Integration with Flask incident response system per Section 6.4.6.2

Technical Specification References:
- Section 6.4.6.2: Incident Response Procedures with Python-Specific Response Capabilities
- Section 6.4.6.1: Real-Time Security Monitoring with Enhanced Security Monitoring Framework
- Section 6.4.2.5: Enhanced Audit Framework with Structured Logging
- Section 6.2.2.1: Entity Relationships and Data Models
- Section 3.2.2: Flask-SQLAlchemy 3.1.1 integration requirements
- Section 6.4.5.2: Security Testing Framework for incident validation
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
    Enum as SQLEnum, event, Float
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.dialects.postgresql import JSONB, UUID, INET
from sqlalchemy.sql import func

# Import base model and User model for relationships
from src.models.base import BaseModel, db
from src.models.user import User

# Configure structured logging for security incident tracking per Section 6.4.6.2
logger = structlog.get_logger("security_incident")


class IncidentSeverity(Enum):
    """
    Security incident severity levels for alerting and automated response coordination.
    
    Aligns with Section 6.4.6.2 incident classification and automated response procedures.
    Each severity level triggers specific containment actions and escalation workflows.
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentType(Enum):
    """
    Security incident types for comprehensive threat categorization and response procedures.
    
    Provides standardized incident classification for automated threat detection and
    response coordination per Section 6.4.6.2 incident response procedures.
    """
    AUTHENTICATION_BREACH = "auth_breach"
    AUTHORIZATION_BYPASS = "authz_bypass"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    CSRF_ATTACK = "csrf_attack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    BRUTE_FORCE = "brute_force"
    ACCOUNT_TAKEOVER = "account_takeover"
    MALWARE_DETECTION = "malware_detection"
    PYTHON_RUNTIME_ERROR = "python_runtime_error"
    FLASK_SECURITY_VIOLATION = "flask_security_violation"
    API_ABUSE = "api_abuse"
    RATE_LIMIT_VIOLATION = "rate_limit_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    INSIDER_THREAT = "insider_threat"
    PHISHING_ATTEMPT = "phishing_attempt"
    SOCIAL_ENGINEERING = "social_engineering"
    NETWORK_INTRUSION = "network_intrusion"
    CONTAINER_BREACH = "container_breach"
    INFRASTRUCTURE_ATTACK = "infrastructure_attack"


class IncidentStatus(Enum):
    """
    Security incident lifecycle status for workflow management and response tracking.
    
    Supports automated incident response workflows and escalation procedures
    per Section 6.4.6.2 incident response framework.
    """
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    TRIAGING = "triaging"
    CONFIRMED = "confirmed"
    CONTAINED = "contained"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class ContainmentActionType(Enum):
    """
    Automated containment action types for incident response procedures.
    
    Defines available containment actions per Section 6.4.6.2 automated response orchestration.
    """
    USER_SESSION_REVOCATION = "user_session_revocation"
    IP_BLOCKING = "ip_blocking"
    ENDPOINT_RATE_LIMITING = "endpoint_rate_limiting"
    ACCOUNT_LOCKOUT = "account_lockout"
    TOKEN_REVOCATION = "token_revocation"
    BLUEPRINT_DISABLING = "blueprint_disabling"
    CONTAINER_ISOLATION = "container_isolation"
    NETWORK_SEGMENTATION = "network_segmentation"
    DATABASE_CONNECTION_MONITORING = "database_connection_monitoring"
    ENHANCED_LOGGING = "enhanced_logging"
    SECURITY_TEAM_NOTIFICATION = "security_team_notification"
    AUTOMATED_ROLLBACK = "automated_rollback"
    TRAFFIC_ROUTING_MODIFICATION = "traffic_routing_modification"
    ENCRYPTION_KEY_ROTATION = "encryption_key_rotation"
    CERTIFICATE_REVOCATION = "certificate_revocation"


class ThreatIntelligenceSource(Enum):
    """
    Threat intelligence source types for evidence correlation and threat assessment.
    
    Supports threat intelligence integration per Section 6.4.6.1 enhanced security monitoring.
    """
    INTERNAL_DETECTION = "internal_detection"
    THREAT_INTELLIGENCE_FEED = "threat_intelligence_feed"
    HONEYPOT = "honeypot"
    IDS_IPS = "ids_ips"
    SIEM_CORRELATION = "siem_correlation"
    ML_ANOMALY_DETECTION = "ml_anomaly_detection"
    USER_REPORT = "user_report"
    EXTERNAL_NOTIFICATION = "external_notification"
    AUTOMATED_SCANNING = "automated_scanning"
    FLASK_SECURITY_FRAMEWORK = "flask_security_framework"


class SecurityIncident(BaseModel):
    """
    Comprehensive security incident model for automated threat detection and response coordination.
    
    This model captures security violations, authentication anomalies, and potential threats
    with automated incident classification, containment action tracking, and integration with
    the Flask incident response system for real-time security management per Section 6.4.6.2.
    
    Attributes:
        id (int): Primary key with auto-incrementing integer for optimal join performance
        correlation_id (UUID): Unique correlation identifier for incident tracking across systems
        incident_title (str): Human-readable incident title for identification and reporting
        incident_description (text): Detailed incident description for investigation and analysis
        incident_type (IncidentType): Standardized incident categorization for response procedures
        severity (IncidentSeverity): Security severity level for automated response and escalation
        status (IncidentStatus): Current incident workflow status for lifecycle management
        detection_time (datetime): Precise timestamp of initial incident detection
        last_activity_time (datetime): Timestamp of most recent incident activity or update
        resolution_time (datetime): Timestamp of incident resolution for SLA tracking
        affected_user_id (int): Foreign key to affected User for incident attribution
        reporter_user_id (int): Foreign key to reporting User for incident accountability
        assigned_to_user_id (int): Foreign key to assigned User for incident response ownership
        source_ip_address (INET): Client IP address for network-based threat analysis
        target_resource (str): Affected system resource or endpoint for impact assessment
        attack_vector (str): Identified attack vector or exploitation method
        threat_actor (str): Suspected threat actor or attack attribution information
        threat_intelligence_sources (JSONB): Threat intelligence correlation data and sources
        detection_method (str): Method used for incident detection and discovery
        confidence_score (float): ML-based confidence score for incident validity assessment
        risk_score (float): Risk assessment score for incident prioritization and response
        impact_assessment (JSONB): Detailed impact analysis and business consequence evaluation
        evidence_data (JSONB): Comprehensive evidence collection for security investigation
        containment_actions (JSONB): Automated and manual containment actions performed
        investigation_notes (JSONB): Investigation progress, findings, and analyst observations
        compliance_implications (JSONB): Regulatory compliance impact and reporting requirements
        related_incidents (JSONB): Related incident correlation and pattern analysis
        automated_response_triggered (bool): Flag indicating if automated response was executed
        escalation_required (bool): Flag indicating if manual escalation is required
        false_positive_likelihood (float): ML-based false positive assessment score
        timeline_data (JSONB): Detailed incident timeline for forensic analysis
        forensic_artifacts (JSONB): Digital forensic evidence and artifact collection
        communication_log (JSONB): Incident communication history and stakeholder notifications
        lessons_learned (JSONB): Post-incident analysis and improvement recommendations
        external_case_id (str): External ticketing system or case management reference
        tags (JSONB): Flexible tagging system for incident categorization and search
        archived (bool): Archive status for incident lifecycle management
        retention_until (datetime): Data retention expiration for compliance management
        created_at (datetime): Record creation timestamp with timezone support
        updated_at (datetime): Record modification timestamp with automatic updates
        
    Relationships:
        affected_user (User): Many-to-one relationship with affected User for attribution
        reporter_user (User): Many-to-one relationship with reporting User for accountability
        assigned_to_user (User): Many-to-one relationship with assigned User for ownership
    """
    
    __tablename__ = 'security_incidents'
    
    # Unique correlation identifier for incident tracking per Section 6.4.6.2
    correlation_id = Column(
        UUID(as_uuid=True),
        nullable=False,
        default=uuid.uuid4,
        unique=True,
        index=True,
        comment="Unique correlation identifier for end-to-end incident tracking"
    )
    
    # Human-readable incident identification and description
    incident_title = Column(
        String(500),
        nullable=False,
        index=True,
        comment="Human-readable incident title for identification and reporting"
    )
    
    incident_description = Column(
        Text,
        nullable=False,
        comment="Detailed incident description for investigation and analysis"
    )
    
    # Incident classification using PostgreSQL Enum per Section 6.4.6.2
    incident_type = Column(
        SQLEnum(IncidentType),
        nullable=False,
        index=True,
        comment="Standardized incident type for automated response procedures"
    )
    
    # Security severity level for automated response per Section 6.4.6.2
    severity = Column(
        SQLEnum(IncidentSeverity),
        nullable=False,
        index=True,
        comment="Security severity level for automated response and escalation"
    )
    
    # Incident workflow status for lifecycle management
    status = Column(
        SQLEnum(IncidentStatus),
        nullable=False,
        default=IncidentStatus.DETECTED,
        index=True,
        comment="Current incident workflow status for lifecycle management"
    )
    
    # Temporal fields for incident lifecycle tracking
    detection_time = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
        comment="Precise timestamp of initial incident detection"
    )
    
    last_activity_time = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp of most recent incident activity or update"
    )
    
    resolution_time = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp of incident resolution for SLA tracking"
    )
    
    # User relationships for incident attribution and ownership per Section 6.2.2.1
    affected_user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
        comment="Foreign key to affected User for incident attribution"
    )
    
    reporter_user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
        comment="Foreign key to reporting User for incident accountability"
    )
    
    assigned_to_user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
        comment="Foreign key to assigned User for incident response ownership"
    )
    
    # Network and system context for threat analysis per Section 6.4.6.1
    source_ip_address = Column(
        INET,
        nullable=True,
        index=True,
        comment="Client IP address for network-based threat analysis and blocking"
    )
    
    target_resource = Column(
        String(500),
        nullable=True,
        index=True,
        comment="Affected system resource or endpoint for impact assessment"
    )
    
    # Threat analysis and attribution fields
    attack_vector = Column(
        String(200),
        nullable=True,
        index=True,
        comment="Identified attack vector or exploitation method for threat analysis"
    )
    
    threat_actor = Column(
        String(200),
        nullable=True,
        index=True,
        comment="Suspected threat actor or attack attribution information"
    )
    
    # Threat intelligence correlation using PostgreSQL JSONB per Section 6.4.6.1
    threat_intelligence_sources = Column(
        JSONB,
        nullable=True,
        comment="Threat intelligence correlation data and external intelligence sources"
    )
    
    detection_method = Column(
        String(200),
        nullable=True,
        index=True,
        comment="Method used for incident detection and discovery"
    )
    
    # ML-based scoring for incident assessment per Section 6.4.6.1
    confidence_score = Column(
        Float,
        nullable=True,
        default=0.0,
        index=True,
        comment="ML-based confidence score for incident validity assessment"
    )
    
    risk_score = Column(
        Float,
        nullable=True,
        default=0.0,
        index=True,
        comment="Risk assessment score for incident prioritization and response"
    )
    
    false_positive_likelihood = Column(
        Float,
        nullable=True,
        default=0.0,
        index=True,
        comment="ML-based false positive assessment score for incident validation"
    )
    
    # Comprehensive incident documentation using JSONB per Section 6.4.6.2
    impact_assessment = Column(
        JSONB,
        nullable=True,
        comment="Detailed impact analysis and business consequence evaluation"
    )
    
    evidence_data = Column(
        JSONB,
        nullable=True,
        comment="Comprehensive evidence collection for security investigation"
    )
    
    containment_actions = Column(
        JSONB,
        nullable=True,
        comment="Automated and manual containment actions performed during response"
    )
    
    investigation_notes = Column(
        JSONB,
        nullable=True,
        comment="Investigation progress, findings, and analyst observations"
    )
    
    compliance_implications = Column(
        JSONB,
        nullable=True,
        comment="Regulatory compliance impact and reporting requirements"
    )
    
    related_incidents = Column(
        JSONB,
        nullable=True,
        comment="Related incident correlation and pattern analysis"
    )
    
    timeline_data = Column(
        JSONB,
        nullable=True,
        comment="Detailed incident timeline for forensic analysis"
    )
    
    forensic_artifacts = Column(
        JSONB,
        nullable=True,
        comment="Digital forensic evidence and artifact collection"
    )
    
    communication_log = Column(
        JSONB,
        nullable=True,
        comment="Incident communication history and stakeholder notifications"
    )
    
    lessons_learned = Column(
        JSONB,
        nullable=True,
        comment="Post-incident analysis and improvement recommendations"
    )
    
    # Workflow and escalation flags for automated response
    automated_response_triggered = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Flag indicating if automated response was executed"
    )
    
    escalation_required = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Flag indicating if manual escalation is required"
    )
    
    # External system integration and categorization
    external_case_id = Column(
        String(200),
        nullable=True,
        index=True,
        comment="External ticketing system or case management reference"
    )
    
    tags = Column(
        JSONB,
        nullable=True,
        comment="Flexible tagging system for incident categorization and search"
    )
    
    # Data lifecycle management per Section 6.2.4.1
    archived = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Archive status for incident lifecycle management"
    )
    
    retention_until = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Data retention expiration for compliance management"
    )
    
    # Relationships to User model for comprehensive incident attribution per Section 6.2.2.1
    affected_user = relationship(
        'User',
        foreign_keys=[affected_user_id],
        back_populates=None,
        lazy='select',
        doc="Many-to-one relationship with affected User for incident attribution"
    )
    
    reporter_user = relationship(
        'User',
        foreign_keys=[reporter_user_id],
        back_populates=None,
        lazy='select',
        doc="Many-to-one relationship with reporting User for accountability"
    )
    
    assigned_to_user = relationship(
        'User',
        foreign_keys=[assigned_to_user_id],
        back_populates=None,
        lazy='select',
        doc="Many-to-one relationship with assigned User for response ownership"
    )
    
    # Database constraints and indexes for performance optimization per Section 6.2.2.2
    __table_args__ = (
        # Check constraints for data validation and integrity
        CheckConstraint(
            "confidence_score >= 0.0 AND confidence_score <= 1.0",
            name='ck_security_incident_confidence_score_range'
        ),
        CheckConstraint(
            "risk_score >= 0.0 AND risk_score <= 1.0",
            name='ck_security_incident_risk_score_range'
        ),
        CheckConstraint(
            "false_positive_likelihood >= 0.0 AND false_positive_likelihood <= 1.0",
            name='ck_security_incident_false_positive_range'
        ),
        CheckConstraint(
            "LENGTH(incident_title) >= 5",
            name='ck_security_incident_title_length'
        ),
        CheckConstraint(
            "LENGTH(incident_description) >= 10",
            name='ck_security_incident_description_length'
        ),
        
        # Composite indexes for performance optimization per Section 6.2.2.2
        Index('ix_security_incident_type_severity_status', 'incident_type', 'severity', 'status'),
        Index('ix_security_incident_detection_status', 'detection_time', 'status'),
        Index('ix_security_incident_severity_detection', 'severity', 'detection_time'),
        Index('ix_security_incident_affected_user_time', 'affected_user_id', 'detection_time'),
        Index('ix_security_incident_assigned_status', 'assigned_to_user_id', 'status'),
        Index('ix_security_incident_ip_detection', 'source_ip_address', 'detection_time'),
        Index('ix_security_incident_risk_confidence', 'risk_score', 'confidence_score'),
        Index('ix_security_incident_archived_retention', 'archived', 'retention_until'),
        Index('ix_security_incident_escalation_status', 'escalation_required', 'status'),
        Index('ix_security_incident_automated_response', 'automated_response_triggered', 'detection_time'),
        Index('ix_security_incident_external_case', 'external_case_id'),
        Index('ix_security_incident_attack_vector', 'attack_vector'),
        Index('ix_security_incident_threat_actor', 'threat_actor'),
        Index('ix_security_incident_detection_method', 'detection_method'),
        
        # GIN indexes for JSONB columns to support complex queries per PostgreSQL optimization
        Index('ix_security_incident_evidence_gin', 'evidence_data', postgresql_using='gin'),
        Index('ix_security_incident_containment_gin', 'containment_actions', postgresql_using='gin'),
        Index('ix_security_incident_impact_gin', 'impact_assessment', postgresql_using='gin'),
        Index('ix_security_incident_intelligence_gin', 'threat_intelligence_sources', postgresql_using='gin'),
        Index('ix_security_incident_investigation_gin', 'investigation_notes', postgresql_using='gin'),
        Index('ix_security_incident_timeline_gin', 'timeline_data', postgresql_using='gin'),
        Index('ix_security_incident_forensic_gin', 'forensic_artifacts', postgresql_using='gin'),
        Index('ix_security_incident_tags_gin', 'tags', postgresql_using='gin'),
        Index('ix_security_incident_compliance_gin', 'compliance_implications', postgresql_using='gin'),
        Index('ix_security_incident_related_gin', 'related_incidents', postgresql_using='gin'),
        Index('ix_security_incident_communication_gin', 'communication_log', postgresql_using='gin'),
        
        # Table-level comment for documentation
        {'comment': 'Comprehensive security incident tracking for automated threat detection and response'}
    )
    
    def __init__(self, **kwargs) -> None:
        """
        Initialize SecurityIncident instance with comprehensive security context.
        
        Automatically generates correlation ID, sets retention policy, configures detection time,
        and establishes structured logging context for security incident tracking per Section 6.4.6.2.
        
        Args:
            **kwargs: Field values for security incident initialization
        """
        # Generate unique correlation ID if not provided
        if 'correlation_id' not in kwargs:
            kwargs['correlation_id'] = uuid.uuid4()
        
        # Set detection time to current timestamp if not provided
        if 'detection_time' not in kwargs:
            kwargs['detection_time'] = datetime.now(timezone.utc)
        
        # Set last activity time to detection time if not provided
        if 'last_activity_time' not in kwargs:
            kwargs['last_activity_time'] = kwargs.get('detection_time', datetime.now(timezone.utc))
        
        # Set default retention period based on incident type and severity
        if 'retention_until' not in kwargs:
            kwargs['retention_until'] = self._calculate_retention_period(
                kwargs.get('incident_type'), 
                kwargs.get('severity', IncidentSeverity.MEDIUM)
            )
        
        # Initialize JSONB fields as empty dictionaries if not provided
        jsonb_fields = [
            'evidence_data', 'containment_actions', 'investigation_notes', 
            'compliance_implications', 'related_incidents', 'timeline_data',
            'forensic_artifacts', 'communication_log', 'impact_assessment',
            'threat_intelligence_sources', 'tags', 'lessons_learned'
        ]
        
        for field in jsonb_fields:
            if field not in kwargs:
                kwargs[field] = {}
        
        # Initialize with structured logging context
        super().__init__(**kwargs)
        
        # Log incident creation for monitoring per Section 6.4.6.2
        logger.error(
            "Security incident created",
            correlation_id=str(self.correlation_id),
            incident_type=self.incident_type.value if self.incident_type else None,
            severity=self.severity.value if self.severity else None,
            title=self.incident_title,
            affected_user_id=self.affected_user_id,
            source_ip=str(self.source_ip_address) if self.source_ip_address else None,
            detection_time=self.detection_time.isoformat() if self.detection_time else None
        )
    
    @validates('source_ip_address')
    def validate_ip_address(self, key, address):
        """
        Validate IP address format for accurate threat analysis.
        
        Args:
            key (str): Field name being validated
            address: IP address to validate (can be string or IPv4/IPv6 object)
            
        Returns:
            Valid IP address object
            
        Raises:
            ValueError: If IP address format is invalid
        """
        if address is None:
            return address
        
        import ipaddress
        try:
            # Convert string to IP address object for validation
            if isinstance(address, str):
                return ipaddress.ip_address(address)
            return address
        except ValueError:
            logger.warning(
                "Invalid IP address format in security incident",
                ip_address=str(address),
                correlation_id=str(self.correlation_id) if hasattr(self, 'correlation_id') else None
            )
            raise ValueError(f"Invalid IP address format: {address}")
    
    @validates('evidence_data', 'containment_actions', 'investigation_notes', 'compliance_implications',
              'related_incidents', 'timeline_data', 'forensic_artifacts', 'communication_log',
              'impact_assessment', 'threat_intelligence_sources', 'tags', 'lessons_learned')
    def validate_jsonb_fields(self, key, value):
        """
        Validate JSONB field structure and security content.
        
        Args:
            key (str): Field name being validated
            value: JSON data to validate
            
        Returns:
            dict: Validated JSON data
        """
        if value is None:
            return {}
        
        # Ensure value is a dictionary for consistent JSON structure
        if not isinstance(value, dict):
            try:
                value = json.loads(value) if isinstance(value, str) else dict(value)
            except (ValueError, TypeError) as e:
                logger.error(
                    "Invalid JSONB structure in security incident",
                    field=key,
                    error=str(e),
                    correlation_id=str(self.correlation_id) if hasattr(self, 'correlation_id') else None
                )
                raise ValueError(f"Invalid JSONB structure for field {key}: {e}")
        
        return value
    
    @validates('confidence_score', 'risk_score', 'false_positive_likelihood')
    def validate_score_ranges(self, key, value):
        """
        Validate ML-based score ranges for incident assessment.
        
        Args:
            key (str): Field name being validated
            value (float): Score value to validate
            
        Returns:
            float: Validated score value
            
        Raises:
            ValueError: If score is outside valid range
        """
        if value is None:
            return 0.0
        
        if not (0.0 <= value <= 1.0):
            raise ValueError(f"{key} must be between 0.0 and 1.0, got {value}")
        
        return float(value)
    
    def _calculate_retention_period(
        self, 
        incident_type: Optional[IncidentType], 
        severity: IncidentSeverity
    ) -> datetime:
        """
        Calculate data retention period based on incident type and severity per Section 6.2.4.1.
        
        Args:
            incident_type (Optional[IncidentType]): Type of security incident
            severity (IncidentSeverity): Incident severity level
            
        Returns:
            datetime: Retention expiration timestamp
        """
        current_time = datetime.now(timezone.utc)
        
        # Base retention periods by severity level
        severity_retention = {
            IncidentSeverity.CRITICAL: timedelta(days=2555),  # 7 years for critical incidents
            IncidentSeverity.HIGH: timedelta(days=1825),      # 5 years for high severity
            IncidentSeverity.MEDIUM: timedelta(days=1095),    # 3 years for medium severity
            IncidentSeverity.LOW: timedelta(days=730),        # 2 years for low severity
            IncidentSeverity.INFO: timedelta(days=365),       # 1 year for informational
        }
        
        # Extended retention for specific incident types
        extended_retention_types = {
            IncidentType.AUTHENTICATION_BREACH,
            IncidentType.DATA_EXFILTRATION,
            IncidentType.PRIVILEGE_ESCALATION,
            IncidentType.ACCOUNT_TAKEOVER,
            IncidentType.INSIDER_THREAT,
            IncidentType.NETWORK_INTRUSION
        }
        
        base_retention = severity_retention.get(severity, timedelta(days=1095))
        
        # Extend retention for high-risk incident types
        if incident_type in extended_retention_types:
            base_retention = max(base_retention, timedelta(days=2555))  # Minimum 7 years
        
        return current_time + base_retention
    
    def update_status(self, new_status: IncidentStatus, notes: str = None) -> None:
        """
        Update incident status with timeline tracking and automated workflows.
        
        Args:
            new_status (IncidentStatus): New incident status
            notes (str): Optional status change notes
        """
        old_status = self.status
        self.status = new_status
        self.last_activity_time = datetime.now(timezone.utc)
        
        # Set resolution time if incident is resolved or closed
        if new_status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
            self.resolution_time = self.last_activity_time
        
        # Update timeline data with status change
        if not self.timeline_data:
            self.timeline_data = {}
        
        if 'status_changes' not in self.timeline_data:
            self.timeline_data['status_changes'] = []
        
        self.timeline_data['status_changes'].append({
            'timestamp': self.last_activity_time.isoformat(),
            'old_status': old_status.value if old_status else None,
            'new_status': new_status.value,
            'notes': notes,
            'changed_by': 'system'  # Could be enhanced to track actual user
        })
        
        # Log status change for monitoring
        logger.info(
            "Security incident status updated",
            correlation_id=str(self.correlation_id),
            old_status=old_status.value if old_status else None,
            new_status=new_status.value,
            incident_type=self.incident_type.value if self.incident_type else None,
            severity=self.severity.value if self.severity else None
        )
    
    def add_containment_action(
        self, 
        action_type: ContainmentActionType, 
        action_details: Dict[str, Any], 
        automated: bool = False
    ) -> None:
        """
        Add containment action to incident tracking per Section 6.4.6.2.
        
        Args:
            action_type (ContainmentActionType): Type of containment action performed
            action_details (Dict[str, Any]): Detailed action information and results
            automated (bool): Whether action was automated or manual
        """
        if not self.containment_actions:
            self.containment_actions = {}
        
        if 'actions' not in self.containment_actions:
            self.containment_actions['actions'] = []
        
        action_record = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action_type': action_type.value,
            'automated': automated,
            'details': action_details,
            'success': action_details.get('success', True),
            'error_message': action_details.get('error_message', None)
        }
        
        self.containment_actions['actions'].append(action_record)
        self.last_activity_time = datetime.now(timezone.utc)
        
        # Update automated response flag if applicable
        if automated:
            self.automated_response_triggered = True
        
        # Log containment action for monitoring
        logger.info(
            "Containment action added to security incident",
            correlation_id=str(self.correlation_id),
            action_type=action_type.value,
            automated=automated,
            success=action_record['success'],
            incident_type=self.incident_type.value if self.incident_type else None
        )
    
    def add_evidence(
        self, 
        evidence_type: str, 
        evidence_data: Dict[str, Any], 
        source: str = None
    ) -> None:
        """
        Add evidence data to incident for security investigation per Section 6.4.6.2.
        
        Args:
            evidence_type (str): Type of evidence being collected
            evidence_data (Dict[str, Any]): Detailed evidence information
            source (str): Source of evidence collection
        """
        if not self.evidence_data:
            self.evidence_data = {}
        
        if 'evidence_items' not in self.evidence_data:
            self.evidence_data['evidence_items'] = []
        
        evidence_record = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'evidence_type': evidence_type,
            'source': source or 'automated_collection',
            'data': evidence_data,
            'evidence_id': str(uuid.uuid4())
        }
        
        self.evidence_data['evidence_items'].append(evidence_record)
        self.last_activity_time = datetime.now(timezone.utc)
        
        # Log evidence collection for audit trail
        logger.info(
            "Evidence added to security incident",
            correlation_id=str(self.correlation_id),
            evidence_type=evidence_type,
            source=source,
            evidence_id=evidence_record['evidence_id'],
            incident_type=self.incident_type.value if self.incident_type else None
        )
    
    def add_investigation_note(
        self, 
        note: str, 
        analyst: str = None, 
        note_type: str = "general"
    ) -> None:
        """
        Add investigation note for incident analysis and documentation.
        
        Args:
            note (str): Investigation note content
            analyst (str): Analyst or system adding the note
            note_type (str): Type or category of the note
        """
        if not self.investigation_notes:
            self.investigation_notes = {}
        
        if 'notes' not in self.investigation_notes:
            self.investigation_notes['notes'] = []
        
        note_record = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'note_type': note_type,
            'content': note,
            'analyst': analyst or 'automated_system',
            'note_id': str(uuid.uuid4())
        }
        
        self.investigation_notes['notes'].append(note_record)
        self.last_activity_time = datetime.now(timezone.utc)
        
        # Log investigation note addition
        logger.info(
            "Investigation note added to security incident",
            correlation_id=str(self.correlation_id),
            note_type=note_type,
            analyst=analyst,
            note_id=note_record['note_id']
        )
    
    def correlate_related_incident(self, related_incident_id: int, relationship_type: str) -> None:
        """
        Correlate with related security incidents for pattern analysis.
        
        Args:
            related_incident_id (int): ID of related security incident
            relationship_type (str): Type of relationship between incidents
        """
        if not self.related_incidents:
            self.related_incidents = {}
        
        if 'correlations' not in self.related_incidents:
            self.related_incidents['correlations'] = []
        
        correlation_record = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'related_incident_id': related_incident_id,
            'relationship_type': relationship_type,
            'correlation_confidence': 0.8,  # Could be ML-based
            'correlation_id': str(uuid.uuid4())
        }
        
        self.related_incidents['correlations'].append(correlation_record)
        self.last_activity_time = datetime.now(timezone.utc)
        
        # Log incident correlation
        logger.info(
            "Related incident correlation added",
            correlation_id=str(self.correlation_id),
            related_incident_id=related_incident_id,
            relationship_type=relationship_type
        )
    
    def calculate_risk_score(self) -> float:
        """
        Calculate comprehensive risk score based on incident characteristics.
        
        Returns:
            float: Calculated risk score between 0.0 and 1.0
        """
        # Base risk scores by incident type
        type_risk_scores = {
            IncidentType.AUTHENTICATION_BREACH: 0.9,
            IncidentType.DATA_EXFILTRATION: 0.95,
            IncidentType.PRIVILEGE_ESCALATION: 0.85,
            IncidentType.ACCOUNT_TAKEOVER: 0.9,
            IncidentType.SQL_INJECTION: 0.8,
            IncidentType.NETWORK_INTRUSION: 0.85,
            IncidentType.INSIDER_THREAT: 0.9,
            IncidentType.BRUTE_FORCE: 0.6,
            IncidentType.API_ABUSE: 0.5,
            IncidentType.SUSPICIOUS_ACTIVITY: 0.4,
        }
        
        # Severity multipliers
        severity_multipliers = {
            IncidentSeverity.CRITICAL: 1.0,
            IncidentSeverity.HIGH: 0.8,
            IncidentSeverity.MEDIUM: 0.6,
            IncidentSeverity.LOW: 0.4,
            IncidentSeverity.INFO: 0.2,
        }
        
        base_risk = type_risk_scores.get(self.incident_type, 0.5)
        severity_multiplier = severity_multipliers.get(self.severity, 0.6)
        
        # Factor in confidence score
        confidence_factor = self.confidence_score or 0.5
        
        # Calculate composite risk score
        risk_score = min(1.0, base_risk * severity_multiplier * (0.5 + 0.5 * confidence_factor))
        
        # Update the risk score field
        self.risk_score = risk_score
        
        return risk_score
    
    def to_structured_log(self) -> Dict[str, Any]:
        """
        Convert security incident to structured logging format per Section 6.4.6.2.
        
        Returns:
            Dict[str, Any]: Structured log data for external monitoring systems
        """
        return {
            'correlation_id': str(self.correlation_id),
            'incident_type': self.incident_type.value if self.incident_type else None,
            'severity': self.severity.value if self.severity else None,
            'status': self.status.value if self.status else None,
            'title': self.incident_title,
            'detection_time': self.detection_time.isoformat() if self.detection_time else None,
            'last_activity_time': self.last_activity_time.isoformat() if self.last_activity_time else None,
            'resolution_time': self.resolution_time.isoformat() if self.resolution_time else None,
            'affected_user_id': self.affected_user_id,
            'source_ip_address': str(self.source_ip_address) if self.source_ip_address else None,
            'target_resource': self.target_resource,
            'attack_vector': self.attack_vector,
            'threat_actor': self.threat_actor,
            'detection_method': self.detection_method,
            'confidence_score': self.confidence_score,
            'risk_score': self.risk_score,
            'false_positive_likelihood': self.false_positive_likelihood,
            'automated_response_triggered': self.automated_response_triggered,
            'escalation_required': self.escalation_required,
            'external_case_id': self.external_case_id,
            'archived': self.archived,
            'containment_actions_count': len(self.containment_actions.get('actions', [])) if self.containment_actions else 0,
            'evidence_items_count': len(self.evidence_data.get('evidence_items', [])) if self.evidence_data else 0,
            'investigation_notes_count': len(self.investigation_notes.get('notes', [])) if self.investigation_notes else 0,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def to_prometheus_metrics(self) -> Dict[str, Union[int, float, str]]:
        """
        Convert security incident to Prometheus metrics format per Section 6.4.6.1.
        
        Returns:
            Dict[str, Union[int, float, str]]: Prometheus metrics data
        """
        return {
            'security_incident_total': 1,
            'security_incident_by_type': self.incident_type.value if self.incident_type else 'unknown',
            'security_incident_by_severity': self.severity.value if self.severity else 'unknown',
            'security_incident_by_status': self.status.value if self.status else 'unknown',
            'security_incident_risk_score': self.risk_score or 0.0,
            'security_incident_confidence_score': self.confidence_score or 0.0,
            'security_incident_false_positive_likelihood': self.false_positive_likelihood or 0.0,
            'security_incident_automated_response': 1 if self.automated_response_triggered else 0,
            'security_incident_escalation_required': 1 if self.escalation_required else 0,
            'security_incident_containment_actions': len(self.containment_actions.get('actions', [])) if self.containment_actions else 0,
            'security_incident_evidence_items': len(self.evidence_data.get('evidence_items', [])) if self.evidence_data else 0,
            'correlation_id': str(self.correlation_id),
            'affected_user_id': str(self.affected_user_id) if self.affected_user_id else 'unknown',
            'source_ip': str(self.source_ip_address) if self.source_ip_address else 'unknown'
        }
    
    @classmethod
    def create_incident(
        cls,
        incident_type: IncidentType,
        severity: IncidentSeverity,
        title: str,
        description: str,
        affected_user_id: Optional[int] = None,
        reporter_user_id: Optional[int] = None,
        source_ip: Optional[str] = None,
        target_resource: Optional[str] = None,
        attack_vector: Optional[str] = None,
        detection_method: Optional[str] = None,
        evidence_data: Optional[Dict[str, Any]] = None,
        automated_detection: bool = True,
        **kwargs
    ) -> 'SecurityIncident':
        """
        Factory method for creating security incidents with comprehensive context.
        
        Args:
            incident_type (IncidentType): Type of security incident
            severity (IncidentSeverity): Incident severity level
            title (str): Human-readable incident title
            description (str): Detailed incident description
            affected_user_id (Optional[int]): ID of affected user
            reporter_user_id (Optional[int]): ID of reporting user
            source_ip (Optional[str]): Source IP address
            target_resource (Optional[str]): Affected resource
            attack_vector (Optional[str]): Attack vector used
            detection_method (Optional[str]): Detection method
            evidence_data (Optional[Dict[str, Any]]): Initial evidence
            automated_detection (bool): Whether detection was automated
            **kwargs: Additional incident fields
            
        Returns:
            SecurityIncident: Created and saved security incident instance
        """
        # Create security incident instance
        incident = cls(
            incident_type=incident_type,
            severity=severity,
            incident_title=title,
            incident_description=description,
            affected_user_id=affected_user_id,
            reporter_user_id=reporter_user_id,
            source_ip_address=source_ip,
            target_resource=target_resource,
            attack_vector=attack_vector,
            detection_method=detection_method,
            evidence_data=evidence_data or {},
            automated_response_triggered=automated_detection,
            **kwargs
        )
        
        # Calculate initial risk score
        incident.calculate_risk_score()
        
        # Save to database and return instance
        return incident.save()
    
    @classmethod
    def get_active_incidents(
        cls,
        severity_filter: Optional[IncidentSeverity] = None,
        incident_type_filter: Optional[IncidentType] = None,
        limit: int = 100
    ) -> List['SecurityIncident']:
        """
        Retrieve active security incidents for incident response dashboard.
        
        Args:
            severity_filter (Optional[IncidentSeverity]): Filter by minimum severity
            incident_type_filter (Optional[IncidentType]): Filter by incident type
            limit (int): Maximum number of incidents to return
            
        Returns:
            List[SecurityIncident]: Active security incidents
        """
        # Define active statuses
        active_statuses = [
            IncidentStatus.DETECTED,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.TRIAGING,
            IncidentStatus.CONFIRMED,
            IncidentStatus.CONTAINED,
            IncidentStatus.MITIGATING
        ]
        
        query = cls.query.filter(
            cls.status.in_(active_statuses),
            cls.archived == False
        )
        
        # Apply severity filter if specified
        if severity_filter:
            # Define severity hierarchy for filtering
            severity_levels = [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH, IncidentSeverity.MEDIUM, IncidentSeverity.LOW, IncidentSeverity.INFO]
            min_index = severity_levels.index(severity_filter)
            included_severities = severity_levels[:min_index + 1]
            query = query.filter(cls.severity.in_(included_severities))
        
        # Apply incident type filter if specified
        if incident_type_filter:
            query = query.filter(cls.incident_type == incident_type_filter)
        
        # Order by risk score and detection time
        return query.order_by(cls.risk_score.desc(), cls.detection_time.desc()).limit(limit).all()
    
    @classmethod
    def get_incidents_requiring_escalation(cls, limit: int = 50) -> List['SecurityIncident']:
        """
        Retrieve incidents requiring manual escalation per Section 6.4.6.2.
        
        Args:
            limit (int): Maximum number of incidents to return
            
        Returns:
            List[SecurityIncident]: Incidents requiring escalation
        """
        return cls.query.filter(
            cls.escalation_required == True,
            cls.status.in_([IncidentStatus.DETECTED, IncidentStatus.INVESTIGATING, IncidentStatus.TRIAGING]),
            cls.archived == False
        ).order_by(cls.severity.desc(), cls.detection_time.asc()).limit(limit).all()
    
    @classmethod
    def get_incidents_by_ip(
        cls,
        ip_address: str,
        hours: int = 24,
        limit: int = 100
    ) -> List['SecurityIncident']:
        """
        Retrieve incidents from specific IP address for threat analysis.
        
        Args:
            ip_address (str): IP address to search for
            hours (int): Time window in hours
            limit (int): Maximum number of incidents to return
            
        Returns:
            List[SecurityIncident]: Incidents from the specified IP
        """
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        return cls.query.filter(
            cls.source_ip_address == ip_address,
            cls.detection_time >= start_time,
            cls.archived == False
        ).order_by(cls.detection_time.desc()).limit(limit).all()
    
    @classmethod
    def get_high_risk_incidents(
        cls,
        risk_threshold: float = 0.7,
        hours: int = 24,
        limit: int = 100
    ) -> List['SecurityIncident']:
        """
        Retrieve high-risk incidents for priority response per Section 6.4.6.2.
        
        Args:
            risk_threshold (float): Minimum risk score threshold
            hours (int): Time window in hours
            limit (int): Maximum number of incidents to return
            
        Returns:
            List[SecurityIncident]: High-risk security incidents
        """
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        return cls.query.filter(
            cls.risk_score >= risk_threshold,
            cls.detection_time >= start_time,
            cls.archived == False
        ).order_by(cls.risk_score.desc(), cls.detection_time.desc()).limit(limit).all()
    
    def __repr__(self) -> str:
        """
        String representation of SecurityIncident for debugging and logging.
        
        Returns:
            str: Human-readable representation of security incident
        """
        return (
            f"<SecurityIncident(id={self.id}, correlation_id='{self.correlation_id}', "
            f"type='{self.incident_type.value if self.incident_type else None}', "
            f"severity='{self.severity.value if self.severity else None}', "
            f"status='{self.status.value if self.status else None}', "
            f"title='{self.incident_title[:50]}...' if len(self.incident_title) > 50 else '{self.incident_title}', "
            f"detection_time='{self.detection_time}')>"
        )


# SQLAlchemy event listeners for automated incident management per Section 6.4.6.2

@event.listens_for(SecurityIncident, 'after_insert')
def trigger_incident_response(mapper, connection, target):
    """
    SQLAlchemy event listener for triggering automated incident response.
    
    Automatically initiates incident response procedures based on severity and type
    according to Section 6.4.6.2 automated response orchestration.
    """
    logger.error(
        "Security incident detected - automated response triggered",
        correlation_id=str(target.correlation_id),
        incident_type=target.incident_type.value if target.incident_type else None,
        severity=target.severity.value if target.severity else None,
        title=target.incident_title,
        affected_user_id=target.affected_user_id,
        source_ip=str(target.source_ip_address) if target.source_ip_address else None,
        risk_score=target.risk_score,
        automated_response=target.automated_response_triggered
    )


@event.listens_for(SecurityIncident, 'after_update')
def log_incident_changes(mapper, connection, target):
    """
    SQLAlchemy event listener for logging incident status changes.
    
    Captures all changes to security incidents for comprehensive audit trail
    and incident lifecycle tracking.
    """
    logger.info(
        "Security incident updated",
        correlation_id=str(target.correlation_id),
        incident_type=target.incident_type.value if target.incident_type else None,
        severity=target.severity.value if target.severity else None,
        status=target.status.value if target.status else None,
        last_activity=target.last_activity_time.isoformat() if target.last_activity_time else None,
        risk_score=target.risk_score,
        escalation_required=target.escalation_required,
        archived=target.archived
    )


# Export the model and enums for use throughout the security incident module
__all__ = [
    'SecurityIncident',
    'IncidentSeverity',
    'IncidentType',
    'IncidentStatus',
    'ContainmentActionType',
    'ThreatIntelligenceSource'
]