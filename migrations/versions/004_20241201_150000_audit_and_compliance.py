"""
Audit and Compliance Migration for GDPR/CCPA Data Protection and Security Monitoring.

This migration implements comprehensive audit and compliance features including:
- Audit tables for complete DML operation tracking (Section 6.2.4.3)
- SQLAlchemy event listeners for automated audit trail generation
- Field-level PII encryption using Python cryptography Fernet (Section 6.2.4.1)
- GDPR/CCPA automated data retention and purging capabilities
- PostgreSQL database triggers for critical table auditing
- Automated user data rights fulfillment infrastructure

Revision ID: 004_20241201_150000
Revises: 003_20241201_140000
Create Date: 2024-12-01 15:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import text
from datetime import datetime, timedelta
import json
import os
from cryptography.fernet import Fernet
import logging

# Revision identifiers used by Alembic
revision = '004_20241201_150000'
down_revision = '003_20241201_140000'
branch_labels = None
depends_on = None

# Configure logging for migration execution
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def upgrade():
    """
    Implement comprehensive audit and compliance infrastructure.
    
    This upgrade function creates:
    1. Audit tables for DML operation tracking per Section 6.2.4.3
    2. Field-level encryption infrastructure per Section 6.2.4.1
    3. GDPR/CCPA compliance tables and procedures
    4. PostgreSQL audit triggers and functions
    5. Data retention and purging automation
    """
    logger.info("Starting audit and compliance migration upgrade")
    
    # Step 1: Create audit tables for comprehensive DML tracking
    create_audit_tables()
    
    # Step 2: Implement field-level PII encryption infrastructure
    create_encryption_infrastructure()
    
    # Step 3: Create GDPR/CCPA compliance tables
    create_compliance_tables()
    
    # Step 4: Add encrypted fields to existing tables
    add_encrypted_fields_to_existing_tables()
    
    # Step 5: Create PostgreSQL audit triggers and functions
    create_postgresql_audit_triggers()
    
    # Step 6: Create data retention and purging procedures
    create_data_retention_procedures()
    
    # Step 7: Create user data rights fulfillment infrastructure
    create_user_data_rights_infrastructure()
    
    # Step 8: Insert initial encryption keys and compliance settings
    initialize_compliance_configuration()
    
    logger.info("Audit and compliance migration upgrade completed successfully")


def downgrade():
    """
    Remove audit and compliance infrastructure.
    
    This downgrade function removes all audit and compliance features
    while preserving data integrity and ensuring safe rollback procedures.
    """
    logger.info("Starting audit and compliance migration downgrade")
    
    # Remove in reverse order of creation
    remove_user_data_rights_infrastructure()
    remove_data_retention_procedures()
    remove_postgresql_audit_triggers()
    remove_encrypted_fields_from_existing_tables()
    remove_compliance_tables()
    remove_encryption_infrastructure()
    remove_audit_tables()
    
    logger.info("Audit and compliance migration downgrade completed successfully")


def create_audit_tables():
    """
    Create comprehensive audit tables for DML operation tracking per Section 6.2.4.3.
    
    Implements audit logging for all database modifications with complete change tracking,
    user attribution, and temporal data management for compliance requirements.
    """
    logger.info("Creating audit tables for DML operation tracking")
    
    # Generic audit log table for all database operations
    op.create_table(
        'audit_log',
        sa.Column('id', sa.BigInteger, primary_key=True, autoincrement=True,
                 comment='Auto-incrementing primary key for audit log entries'),
        sa.Column('table_name', sa.String(100), nullable=False, index=True,
                 comment='Name of the table being audited'),
        sa.Column('record_id', sa.String(100), nullable=False, index=True,
                 comment='Primary key of the audited record'),
        sa.Column('operation', sa.String(10), nullable=False, index=True,
                 comment='Type of operation: INSERT, UPDATE, DELETE'),
        sa.Column('old_values', postgresql.JSONB, nullable=True,
                 comment='Previous values before the operation (for UPDATE/DELETE)'),
        sa.Column('new_values', postgresql.JSONB, nullable=True,
                 comment='New values after the operation (for INSERT/UPDATE)'),
        sa.Column('changed_fields', postgresql.ARRAY(sa.String), nullable=True,
                 comment='List of fields that were modified in UPDATE operations'),
        sa.Column('user_id', sa.Integer, nullable=True, index=True,
                 comment='ID of the user who performed the operation'),
        sa.Column('session_id', sa.String(255), nullable=True, index=True,
                 comment='Session ID associated with the operation'),
        sa.Column('ip_address', sa.String(45), nullable=True, index=True,
                 comment='IP address of the client performing the operation'),
        sa.Column('user_agent', sa.Text, nullable=True,
                 comment='User agent string of the client'),
        sa.Column('request_id', sa.String(36), nullable=True, index=True,
                 comment='Unique request ID for correlation across systems'),
        sa.Column('blueprint_name', sa.String(100), nullable=True, index=True,
                 comment='Flask blueprint name where the operation originated'),
        sa.Column('endpoint_name', sa.String(200), nullable=True, index=True,
                 comment='Flask endpoint name where the operation originated'),
        sa.Column('operation_timestamp', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(), index=True,
                 comment='Timestamp when the operation was performed'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(),
                 comment='Timestamp when the audit log entry was created'),
        
        # Constraints and indexes for performance and data integrity
        sa.Index('ix_audit_log_table_record', 'table_name', 'record_id'),
        sa.Index('ix_audit_log_user_timestamp', 'user_id', 'operation_timestamp'),
        sa.Index('ix_audit_log_operation_timestamp', 'operation', 'operation_timestamp'),
        sa.Index('ix_audit_log_request_correlation', 'request_id', 'session_id'),
        
        # Check constraints for data validation
        sa.CheckConstraint("operation IN ('INSERT', 'UPDATE', 'DELETE')", 
                          name='ck_audit_log_operation'),
        sa.CheckConstraint('LENGTH(table_name) > 0', name='ck_audit_log_table_name'),
        sa.CheckConstraint('LENGTH(record_id) > 0', name='ck_audit_log_record_id'),
        
        comment='Comprehensive audit log for all database operations and changes'
    )
    
    # Security-specific audit table for authentication and authorization events
    op.create_table(
        'security_audit_log',
        sa.Column('id', sa.BigInteger, primary_key=True, autoincrement=True,
                 comment='Auto-incrementing primary key for security audit entries'),
        sa.Column('event_type', sa.String(50), nullable=False, index=True,
                 comment='Type of security event: AUTH_SUCCESS, AUTH_FAILURE, AUTHZ_DENIED, etc.'),
        sa.Column('severity', sa.String(20), nullable=False, index=True,
                 comment='Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO'),
        sa.Column('user_id', sa.Integer, nullable=True, index=True,
                 comment='ID of the user associated with the security event'),
        sa.Column('target_user_id', sa.Integer, nullable=True, index=True,
                 comment='ID of the target user for privilege escalation attempts'),
        sa.Column('resource_type', sa.String(100), nullable=True, index=True,
                 comment='Type of resource being accessed or modified'),
        sa.Column('resource_id', sa.String(100), nullable=True, index=True,
                 comment='ID of the specific resource being accessed'),
        sa.Column('permission_required', sa.String(100), nullable=True,
                 comment='Permission that was required for the operation'),
        sa.Column('permission_granted', sa.Boolean, nullable=True, index=True,
                 comment='Whether the required permission was granted'),
        sa.Column('authentication_method', sa.String(50), nullable=True, index=True,
                 comment='Method used for authentication: password, jwt, oauth, etc.'),
        sa.Column('session_id', sa.String(255), nullable=True, index=True,
                 comment='Session ID associated with the security event'),
        sa.Column('ip_address', sa.String(45), nullable=True, index=True,
                 comment='IP address of the client'),
        sa.Column('user_agent', sa.Text, nullable=True,
                 comment='User agent string of the client'),
        sa.Column('request_path', sa.String(500), nullable=True,
                 comment='HTTP request path that triggered the security event'),
        sa.Column('request_method', sa.String(10), nullable=True,
                 comment='HTTP request method: GET, POST, PUT, DELETE, etc.'),
        sa.Column('request_id', sa.String(36), nullable=True, index=True,
                 comment='Unique request ID for correlation'),
        sa.Column('blueprint_name', sa.String(100), nullable=True, index=True,
                 comment='Flask blueprint name where the event occurred'),
        sa.Column('endpoint_name', sa.String(200), nullable=True, index=True,
                 comment='Flask endpoint name where the event occurred'),
        sa.Column('additional_data', postgresql.JSONB, nullable=True,
                 comment='Additional security event data in JSON format'),
        sa.Column('event_timestamp', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(), index=True,
                 comment='Timestamp when the security event occurred'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(),
                 comment='Timestamp when the audit entry was created'),
        
        # Indexes for security monitoring and analysis
        sa.Index('ix_security_audit_event_severity', 'event_type', 'severity'),
        sa.Index('ix_security_audit_user_timestamp', 'user_id', 'event_timestamp'),
        sa.Index('ix_security_audit_ip_timestamp', 'ip_address', 'event_timestamp'),
        sa.Index('ix_security_audit_failure_analysis', 'event_type', 'permission_granted', 'event_timestamp'),
        
        # Check constraints for data validation
        sa.CheckConstraint("event_type IN ('AUTH_SUCCESS', 'AUTH_FAILURE', 'AUTHZ_SUCCESS', 'AUTHZ_DENIED', 'SESSION_CREATE', 'SESSION_DESTROY', 'PRIVILEGE_ESCALATION', 'SUSPICIOUS_ACTIVITY', 'SECURITY_VIOLATION')",
                          name='ck_security_audit_event_type'),
        sa.CheckConstraint("severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
                          name='ck_security_audit_severity'),
        
        comment='Security-specific audit log for authentication and authorization events'
    )
    
    # Data access audit table for GDPR compliance and privacy tracking
    op.create_table(
        'data_access_audit',
        sa.Column('id', sa.BigInteger, primary_key=True, autoincrement=True,
                 comment='Auto-incrementing primary key for data access audit entries'),
        sa.Column('user_id', sa.Integer, nullable=True, index=True,
                 comment='ID of the user accessing the data'),
        sa.Column('data_subject_id', sa.Integer, nullable=True, index=True,
                 comment='ID of the user whose data is being accessed'),
        sa.Column('data_type', sa.String(100), nullable=False, index=True,
                 comment='Type of personal data accessed: PII, FINANCIAL, HEALTH, etc.'),
        sa.Column('data_fields', postgresql.ARRAY(sa.String), nullable=True,
                 comment='Specific fields of personal data that were accessed'),
        sa.Column('access_purpose', sa.String(200), nullable=True,
                 comment='Business purpose for accessing the personal data'),
        sa.Column('legal_basis', sa.String(100), nullable=True,
                 comment='Legal basis for data processing under GDPR'),
        sa.Column('consent_id', sa.String(36), nullable=True, index=True,
                 comment='ID of the consent record if consent-based processing'),
        sa.Column('data_classification', sa.String(50), nullable=False, index=True,
                 comment='Data classification level: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED'),
        sa.Column('operation_type', sa.String(20), nullable=False, index=True,
                 comment='Type of data operation: READ, EXPORT, MODIFY, DELETE'),
        sa.Column('record_count', sa.Integer, nullable=True,
                 comment='Number of records accessed in bulk operations'),
        sa.Column('session_id', sa.String(255), nullable=True, index=True,
                 comment='Session ID associated with the data access'),
        sa.Column('ip_address', sa.String(45), nullable=True, index=True,
                 comment='IP address of the client accessing the data'),
        sa.Column('user_agent', sa.Text, nullable=True,
                 comment='User agent string of the client'),
        sa.Column('request_id', sa.String(36), nullable=True, index=True,
                 comment='Unique request ID for correlation'),
        sa.Column('blueprint_name', sa.String(100), nullable=True, index=True,
                 comment='Flask blueprint name where the access occurred'),
        sa.Column('endpoint_name', sa.String(200), nullable=True, index=True,
                 comment='Flask endpoint name where the access occurred'),
        sa.Column('access_timestamp', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(), index=True,
                 comment='Timestamp when the data access occurred'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(),
                 comment='Timestamp when the audit entry was created'),
        
        # Indexes for GDPR compliance reporting and privacy analysis
        sa.Index('ix_data_access_subject_timestamp', 'data_subject_id', 'access_timestamp'),
        sa.Index('ix_data_access_type_purpose', 'data_type', 'access_purpose'),
        sa.Index('ix_data_access_legal_basis', 'legal_basis', 'access_timestamp'),
        sa.Index('ix_data_access_consent_tracking', 'consent_id', 'data_subject_id'),
        
        # Check constraints for data validation
        sa.CheckConstraint("data_type IN ('PII', 'FINANCIAL', 'HEALTH', 'BEHAVIORAL', 'BIOMETRIC', 'LOCATION', 'COMMUNICATION')",
                          name='ck_data_access_data_type'),
        sa.CheckConstraint("data_classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')",
                          name='ck_data_access_classification'),
        sa.CheckConstraint("operation_type IN ('READ', 'EXPORT', 'MODIFY', 'DELETE')",
                          name='ck_data_access_operation_type'),
        
        comment='Data access audit log for GDPR compliance and privacy tracking'
    )


def create_encryption_infrastructure():
    """
    Create field-level PII encryption infrastructure per Section 6.2.4.1.
    
    Implements Python cryptography library Fernet symmetric encryption for
    sensitive personal data fields with key management and encryption utilities.
    """
    logger.info("Creating field-level PII encryption infrastructure")
    
    # Encryption keys management table
    op.create_table(
        'encryption_keys',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True,
                 comment='Auto-incrementing primary key for encryption keys'),
        sa.Column('key_id', sa.String(36), nullable=False, unique=True, index=True,
                 comment='Unique identifier for the encryption key'),
        sa.Column('key_purpose', sa.String(100), nullable=False, index=True,
                 comment='Purpose of the encryption key: PII, FINANCIAL, HEALTH, etc.'),
        sa.Column('key_algorithm', sa.String(50), nullable=False, default='FERNET',
                 comment='Encryption algorithm used: FERNET, AES-GCM, etc.'),
        sa.Column('encrypted_key_material', sa.Text, nullable=False,
                 comment='Encrypted key material (encrypted with master key)'),
        sa.Column('key_derivation_salt', sa.String(64), nullable=True,
                 comment='Salt used for key derivation (if applicable)'),
        sa.Column('key_version', sa.Integer, nullable=False, default=1,
                 comment='Version number for key rotation tracking'),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True, index=True,
                 comment='Whether this key is currently active for encryption'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(),
                 comment='Timestamp when the key was created'),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True,
                 comment='Timestamp when the key was activated'),
        sa.Column('deactivated_at', sa.DateTime(timezone=True), nullable=True,
                 comment='Timestamp when the key was deactivated'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True, index=True,
                 comment='Timestamp when the key expires'),
        
        # Indexes for key management and rotation
        sa.Index('ix_encryption_keys_purpose_active', 'key_purpose', 'is_active'),
        sa.Index('ix_encryption_keys_version_purpose', 'key_version', 'key_purpose'),
        sa.Index('ix_encryption_keys_expiration', 'expires_at', 'is_active'),
        
        # Check constraints for data validation
        sa.CheckConstraint("key_purpose IN ('PII', 'FINANCIAL', 'HEALTH', 'COMMUNICATION', 'BIOMETRIC', 'LOCATION')",
                          name='ck_encryption_keys_purpose'),
        sa.CheckConstraint("key_algorithm IN ('FERNET', 'AES_GCM', 'CHACHA20_POLY1305')",
                          name='ck_encryption_keys_algorithm'),
        sa.CheckConstraint('key_version > 0', name='ck_encryption_keys_version'),
        
        comment='Encryption key management for field-level PII data protection'
    )
    
    # Field-level encryption mapping table
    op.create_table(
        'encrypted_field_mapping',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True,
                 comment='Auto-incrementing primary key for field mapping'),
        sa.Column('table_name', sa.String(100), nullable=False, index=True,
                 comment='Name of the table containing encrypted fields'),
        sa.Column('field_name', sa.String(100), nullable=False, index=True,
                 comment='Name of the encrypted field'),
        sa.Column('encryption_key_id', sa.String(36), nullable=False, index=True,
                 comment='ID of the encryption key used for this field'),
        sa.Column('data_classification', sa.String(50), nullable=False, index=True,
                 comment='Classification of data in this field'),
        sa.Column('pii_category', sa.String(100), nullable=True,
                 comment='Category of PII data: NAME, EMAIL, PHONE, SSN, etc.'),
        sa.Column('encryption_algorithm', sa.String(50), nullable=False, default='FERNET',
                 comment='Encryption algorithm used for this field'),
        sa.Column('is_searchable', sa.Boolean, nullable=False, default=False,
                 comment='Whether encrypted field supports searchable encryption'),
        sa.Column('retention_period_days', sa.Integer, nullable=True,
                 comment='Data retention period in days for GDPR compliance'),
        sa.Column('requires_consent', sa.Boolean, nullable=False, default=True,
                 comment='Whether this field requires user consent for processing'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(),
                 comment='Timestamp when the mapping was created'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(), onupdate=sa.func.now(),
                 comment='Timestamp when the mapping was last updated'),
        
        # Unique constraint for table-field combination
        sa.UniqueConstraint('table_name', 'field_name', name='uq_encrypted_field_mapping'),
        
        # Indexes for encryption management
        sa.Index('ix_encrypted_field_classification', 'data_classification', 'pii_category'),
        sa.Index('ix_encrypted_field_retention', 'retention_period_days', 'requires_consent'),
        
        # Check constraints for data validation
        sa.CheckConstraint("data_classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')",
                          name='ck_encrypted_field_classification'),
        sa.CheckConstraint("pii_category IN ('NAME', 'EMAIL', 'PHONE', 'ADDRESS', 'SSN', 'FINANCIAL_ACCOUNT', 'BIOMETRIC', 'HEALTH', 'LOCATION')",
                          name='ck_encrypted_field_pii_category'),
        sa.CheckConstraint('retention_period_days > 0', name='ck_encrypted_field_retention'),
        
        comment='Mapping of encrypted fields to encryption keys and classification'
    )


def create_compliance_tables():
    """
    Create GDPR/CCPA compliance tables for data subject rights and consent management.
    
    Implements automated data subject rights fulfillment infrastructure with
    comprehensive consent tracking and privacy management capabilities.
    """
    logger.info("Creating GDPR/CCPA compliance tables")
    
    # Data subject consent tracking table
    op.create_table(
        'data_subject_consent',
        sa.Column('id', sa.String(36), primary_key=True,
                 comment='UUID primary key for consent records'),
        sa.Column('user_id', sa.Integer, nullable=False, index=True,
                 comment='ID of the user who provided consent'),
        sa.Column('consent_type', sa.String(100), nullable=False, index=True,
                 comment='Type of consent: PROCESSING, MARKETING, ANALYTICS, etc.'),
        sa.Column('consent_purpose', sa.String(200), nullable=False,
                 comment='Specific purpose for which consent was given'),
        sa.Column('legal_basis', sa.String(100), nullable=False, index=True,
                 comment='Legal basis for data processing under GDPR'),
        sa.Column('data_categories', postgresql.ARRAY(sa.String), nullable=False,
                 comment='Categories of personal data covered by this consent'),
        sa.Column('processing_activities', postgresql.ARRAY(sa.String), nullable=False,
                 comment='Specific processing activities covered by consent'),
        sa.Column('consent_granted', sa.Boolean, nullable=False, index=True,
                 comment='Whether consent was granted or denied'),
        sa.Column('consent_method', sa.String(50), nullable=False,
                 comment='Method of consent collection: WEB_FORM, EMAIL, PHONE, etc.'),
        sa.Column('consent_evidence', postgresql.JSONB, nullable=True,
                 comment='Evidence of consent collection (form data, timestamps, etc.)'),
        sa.Column('ip_address', sa.String(45), nullable=True,
                 comment='IP address when consent was provided'),
        sa.Column('user_agent', sa.Text, nullable=True,
                 comment='User agent when consent was provided'),
        sa.Column('consent_timestamp', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(), index=True,
                 comment='Timestamp when consent was provided'),
        sa.Column('expiry_date', sa.DateTime(timezone=True), nullable=True, index=True,
                 comment='Expiry date of the consent (if applicable)'),
        sa.Column('withdrawal_timestamp', sa.DateTime(timezone=True), nullable=True, index=True,
                 comment='Timestamp when consent was withdrawn'),
        sa.Column('withdrawal_method', sa.String(50), nullable=True,
                 comment='Method used to withdraw consent'),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True, index=True,
                 comment='Whether the consent is currently active'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(),
                 comment='Timestamp when the record was created'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(), onupdate=sa.func.now(),
                 comment='Timestamp when the record was last updated'),
        
        # Foreign key to users table
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_consent_user_id'),
        
        # Indexes for consent management and compliance reporting
        sa.Index('ix_consent_user_type', 'user_id', 'consent_type'),
        sa.Index('ix_consent_legal_basis', 'legal_basis', 'consent_granted'),
        sa.Index('ix_consent_expiry_active', 'expiry_date', 'is_active'),
        sa.Index('ix_consent_withdrawal_tracking', 'withdrawal_timestamp', 'user_id'),
        
        # Check constraints for data validation
        sa.CheckConstraint("consent_type IN ('PROCESSING', 'MARKETING', 'ANALYTICS', 'PROFILING', 'SHARING', 'COOKIES')",
                          name='ck_consent_type'),
        sa.CheckConstraint("legal_basis IN ('CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'VITAL_INTERESTS', 'PUBLIC_TASK', 'LEGITIMATE_INTERESTS')",
                          name='ck_consent_legal_basis'),
        sa.CheckConstraint("consent_method IN ('WEB_FORM', 'EMAIL', 'PHONE', 'PAPER', 'API', 'IMPORT')",
                          name='ck_consent_method'),
        
        comment='GDPR/CCPA consent tracking for data subject rights management'
    )
    
    # Data subject access requests table
    op.create_table(
        'data_subject_requests',
        sa.Column('id', sa.String(36), primary_key=True,
                 comment='UUID primary key for data subject requests'),
        sa.Column('user_id', sa.Integer, nullable=False, index=True,
                 comment='ID of the user making the request'),
        sa.Column('request_type', sa.String(50), nullable=False, index=True,
                 comment='Type of request: ACCESS, RECTIFICATION, ERASURE, PORTABILITY, etc.'),
        sa.Column('request_status', sa.String(50), nullable=False, index=True, default='PENDING',
                 comment='Status of the request: PENDING, IN_PROGRESS, COMPLETED, REJECTED'),
        sa.Column('request_description', sa.Text, nullable=True,
                 comment='Detailed description of the data subject request'),
        sa.Column('data_categories_requested', postgresql.ARRAY(sa.String), nullable=True,
                 comment='Specific categories of data requested'),
        sa.Column('verification_method', sa.String(50), nullable=True,
                 comment='Method used to verify the identity of the data subject'),
        sa.Column('verification_status', sa.String(50), nullable=False, default='PENDING',
                 comment='Status of identity verification: PENDING, VERIFIED, FAILED'),
        sa.Column('verification_data', postgresql.JSONB, nullable=True,
                 comment='Verification data and evidence'),
        sa.Column('processing_notes', sa.Text, nullable=True,
                 comment='Internal notes about request processing'),
        sa.Column('fulfillment_data', postgresql.JSONB, nullable=True,
                 comment='Data provided to fulfill the request'),
        sa.Column('rejection_reason', sa.String(200), nullable=True,
                 comment='Reason for request rejection (if applicable)'),
        sa.Column('legal_basis_assessment', sa.Text, nullable=True,
                 comment='Assessment of legal basis for the request'),
        sa.Column('impact_assessment', sa.Text, nullable=True,
                 comment='Assessment of impact on other individuals or business'),
        sa.Column('automated_fulfillment', sa.Boolean, nullable=False, default=False,
                 comment='Whether the request was fulfilled automatically'),
        sa.Column('assigned_to_user_id', sa.Integer, nullable=True,
                 comment='ID of the user assigned to process the request'),
        sa.Column('request_timestamp', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(), index=True,
                 comment='Timestamp when the request was submitted'),
        sa.Column('due_date', sa.DateTime(timezone=True), nullable=False, index=True,
                 comment='Due date for request fulfillment (30 days from submission)'),
        sa.Column('completed_timestamp', sa.DateTime(timezone=True), nullable=True, index=True,
                 comment='Timestamp when the request was completed'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(),
                 comment='Timestamp when the record was created'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(), onupdate=sa.func.now(),
                 comment='Timestamp when the record was last updated'),
        
        # Foreign keys
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_requests_user_id'),
        sa.ForeignKeyConstraint(['assigned_to_user_id'], ['users.id'], name='fk_requests_assigned_user_id'),
        
        # Indexes for request management and SLA tracking
        sa.Index('ix_requests_user_type_status', 'user_id', 'request_type', 'request_status'),
        sa.Index('ix_requests_due_date_status', 'due_date', 'request_status'),
        sa.Index('ix_requests_assigned_status', 'assigned_to_user_id', 'request_status'),
        sa.Index('ix_requests_completion_tracking', 'completed_timestamp', 'request_type'),
        
        # Check constraints for data validation
        sa.CheckConstraint("request_type IN ('ACCESS', 'RECTIFICATION', 'ERASURE', 'PORTABILITY', 'RESTRICTION', 'OBJECTION')",
                          name='ck_requests_type'),
        sa.CheckConstraint("request_status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'REJECTED', 'EXPIRED')",
                          name='ck_requests_status'),
        sa.CheckConstraint("verification_status IN ('PENDING', 'VERIFIED', 'FAILED')",
                          name='ck_requests_verification_status'),
        
        comment='Data subject access requests for GDPR/CCPA compliance'
    )
    
    # Data retention policy table
    op.create_table(
        'data_retention_policies',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True,
                 comment='Auto-incrementing primary key for retention policies'),
        sa.Column('policy_name', sa.String(100), nullable=False, unique=True,
                 comment='Unique name for the retention policy'),
        sa.Column('data_category', sa.String(100), nullable=False, index=True,
                 comment='Category of data covered by this policy'),
        sa.Column('table_name', sa.String(100), nullable=False, index=True,
                 comment='Database table covered by this policy'),
        sa.Column('retention_period_days', sa.Integer, nullable=False,
                 comment='Number of days to retain data'),
        sa.Column('grace_period_days', sa.Integer, nullable=False, default=30,
                 comment='Grace period before permanent deletion'),
        sa.Column('purge_conditions', postgresql.JSONB, nullable=True,
                 comment='Additional conditions for data purging'),
        sa.Column('legal_basis', sa.String(100), nullable=False,
                 comment='Legal basis for the retention period'),
        sa.Column('business_justification', sa.Text, nullable=True,
                 comment='Business justification for the retention period'),
        sa.Column('archival_required', sa.Boolean, nullable=False, default=False,
                 comment='Whether data should be archived before deletion'),
        sa.Column('archival_location', sa.String(200), nullable=True,
                 comment='Location for data archival'),
        sa.Column('automated_purging', sa.Boolean, nullable=False, default=True,
                 comment='Whether purging is automated or requires manual approval'),
        sa.Column('notification_required', sa.Boolean, nullable=False, default=True,
                 comment='Whether to notify data subjects before purging'),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True, index=True,
                 comment='Whether the policy is currently active'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(),
                 comment='Timestamp when the policy was created'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(), onupdate=sa.func.now(),
                 comment='Timestamp when the policy was last updated'),
        
        # Indexes for policy management and enforcement
        sa.Index('ix_retention_category_table', 'data_category', 'table_name'),
        sa.Index('ix_retention_automated_active', 'automated_purging', 'is_active'),
        
        # Check constraints for data validation
        sa.CheckConstraint('retention_period_days > 0', name='ck_retention_period_positive'),
        sa.CheckConstraint('grace_period_days >= 0', name='ck_grace_period_non_negative'),
        
        comment='Data retention policies for automated GDPR/CCPA compliance'
    )


def add_encrypted_fields_to_existing_tables():
    """
    Add encrypted PII fields to existing tables per Section 6.2.4.1.
    
    Implements field-level encryption for sensitive personal data in User and
    related tables using Fernet symmetric encryption.
    """
    logger.info("Adding encrypted fields to existing tables")
    
    # Add encrypted fields to users table
    op.add_column('users', 
        sa.Column('email_encrypted', sa.Text, nullable=True,
                 comment='Encrypted email address using Fernet encryption'))
    
    op.add_column('users', 
        sa.Column('phone_number_encrypted', sa.Text, nullable=True,
                 comment='Encrypted phone number using Fernet encryption'))
    
    op.add_column('users', 
        sa.Column('full_name_encrypted', sa.Text, nullable=True,
                 comment='Encrypted full name using Fernet encryption'))
    
    op.add_column('users', 
        sa.Column('date_of_birth_encrypted', sa.Text, nullable=True,
                 comment='Encrypted date of birth using Fernet encryption'))
    
    op.add_column('users', 
        sa.Column('address_encrypted', sa.Text, nullable=True,
                 comment='Encrypted address information using Fernet encryption'))
    
    op.add_column('users', 
        sa.Column('identification_number_encrypted', sa.Text, nullable=True,
                 comment='Encrypted identification number (SSN, etc.) using Fernet encryption'))
    
    # Add encryption metadata to users table
    op.add_column('users', 
        sa.Column('encryption_key_version', sa.Integer, nullable=True, default=1,
                 comment='Version of encryption key used for PII fields'))
    
    op.add_column('users', 
        sa.Column('pii_encrypted_at', sa.DateTime(timezone=True), nullable=True,
                 comment='Timestamp when PII fields were encrypted'))
    
    op.add_column('users', 
        sa.Column('last_pii_access', sa.DateTime(timezone=True), nullable=True,
                 comment='Timestamp of last PII data access for retention tracking'))
    
    # Create PII access tracking table for users
    op.create_table(
        'user_pii_access_log',
        sa.Column('id', sa.BigInteger, primary_key=True, autoincrement=True,
                 comment='Auto-incrementing primary key for PII access log'),
        sa.Column('user_id', sa.Integer, nullable=False, index=True,
                 comment='ID of the user whose PII was accessed'),
        sa.Column('accessor_user_id', sa.Integer, nullable=True, index=True,
                 comment='ID of the user who accessed the PII'),
        sa.Column('pii_fields_accessed', postgresql.ARRAY(sa.String), nullable=False,
                 comment='List of PII fields that were accessed'),
        sa.Column('access_purpose', sa.String(200), nullable=False,
                 comment='Business purpose for accessing the PII'),
        sa.Column('legal_basis', sa.String(100), nullable=False,
                 comment='Legal basis for PII access'),
        sa.Column('consent_id', sa.String(36), nullable=True,
                 comment='ID of consent record if consent-based access'),
        sa.Column('session_id', sa.String(255), nullable=True, index=True,
                 comment='Session ID when PII was accessed'),
        sa.Column('ip_address', sa.String(45), nullable=True,
                 comment='IP address of the accessor'),
        sa.Column('user_agent', sa.Text, nullable=True,
                 comment='User agent of the accessor'),
        sa.Column('request_id', sa.String(36), nullable=True,
                 comment='Request ID for correlation'),
        sa.Column('decryption_successful', sa.Boolean, nullable=False, default=True,
                 comment='Whether PII decryption was successful'),
        sa.Column('access_timestamp', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(), index=True,
                 comment='Timestamp when PII was accessed'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                 default=sa.func.now(),
                 comment='Timestamp when the log entry was created'),
        
        # Foreign keys
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_pii_access_user_id'),
        sa.ForeignKeyConstraint(['accessor_user_id'], ['users.id'], name='fk_pii_access_accessor_id'),
        
        # Indexes for PII access monitoring
        sa.Index('ix_pii_access_user_timestamp', 'user_id', 'access_timestamp'),
        sa.Index('ix_pii_access_purpose_basis', 'access_purpose', 'legal_basis'),
        sa.Index('ix_pii_access_consent_tracking', 'consent_id', 'user_id'),
        
        comment='PII access logging for enhanced privacy protection and compliance'
    )


def create_postgresql_audit_triggers():
    """
    Create PostgreSQL database triggers for critical table auditing per Section 6.2.4.3.
    
    Implements PL/pgSQL functions and triggers for comprehensive audit logging
    as a backup to SQLAlchemy event listeners.
    """
    logger.info("Creating PostgreSQL audit triggers and functions")
    
    # Create audit function for generic table auditing
    audit_function_sql = """
    CREATE OR REPLACE FUNCTION audit_table_changes()
    RETURNS TRIGGER AS $$
    DECLARE
        old_values JSONB;
        new_values JSONB;
        changed_fields TEXT[];
        field_name TEXT;
    BEGIN
        -- Initialize variables
        old_values := NULL;
        new_values := NULL;
        changed_fields := ARRAY[]::TEXT[];
        
        -- Handle different trigger operations
        IF TG_OP = 'DELETE' THEN
            old_values := to_jsonb(OLD);
            
            INSERT INTO audit_log (
                table_name, record_id, operation, old_values, new_values,
                changed_fields, operation_timestamp, created_at
            ) VALUES (
                TG_TABLE_NAME, OLD.id::TEXT, TG_OP, old_values, NULL,
                NULL, NOW(), NOW()
            );
            
            RETURN OLD;
            
        ELSIF TG_OP = 'INSERT' THEN
            new_values := to_jsonb(NEW);
            
            INSERT INTO audit_log (
                table_name, record_id, operation, old_values, new_values,
                changed_fields, operation_timestamp, created_at
            ) VALUES (
                TG_TABLE_NAME, NEW.id::TEXT, TG_OP, NULL, new_values,
                NULL, NOW(), NOW()
            );
            
            RETURN NEW;
            
        ELSIF TG_OP = 'UPDATE' THEN
            old_values := to_jsonb(OLD);
            new_values := to_jsonb(NEW);
            
            -- Identify changed fields
            FOR field_name IN SELECT key FROM jsonb_each(old_values) LOOP
                IF old_values->>field_name IS DISTINCT FROM new_values->>field_name THEN
                    changed_fields := array_append(changed_fields, field_name);
                END IF;
            END LOOP;
            
            -- Only log if there are actual changes
            IF array_length(changed_fields, 1) > 0 THEN
                INSERT INTO audit_log (
                    table_name, record_id, operation, old_values, new_values,
                    changed_fields, operation_timestamp, created_at
                ) VALUES (
                    TG_TABLE_NAME, NEW.id::TEXT, TG_OP, old_values, new_values,
                    changed_fields, NOW(), NOW()
                );
            END IF;
            
            RETURN NEW;
        END IF;
        
        RETURN NULL;
    END;
    $$ LANGUAGE plpgsql;
    """
    
    op.execute(text(audit_function_sql))
    
    # Create audit triggers for critical tables
    critical_tables = ['users', 'user_sessions', 'business_entities', 'entity_relationships']
    
    for table_name in critical_tables:
        trigger_sql = f"""
        CREATE TRIGGER audit_trigger_{table_name}
            AFTER INSERT OR UPDATE OR DELETE ON {table_name}
            FOR EACH ROW EXECUTE FUNCTION audit_table_changes();
        """
        op.execute(text(trigger_sql))
    
    # Create function for PII access logging
    pii_access_function_sql = """
    CREATE OR REPLACE FUNCTION log_pii_access(
        p_user_id INTEGER,
        p_accessor_user_id INTEGER,
        p_pii_fields TEXT[],
        p_access_purpose TEXT,
        p_legal_basis TEXT,
        p_session_id TEXT DEFAULT NULL,
        p_ip_address TEXT DEFAULT NULL
    ) RETURNS VOID AS $$
    BEGIN
        INSERT INTO user_pii_access_log (
            user_id, accessor_user_id, pii_fields_accessed, access_purpose,
            legal_basis, session_id, ip_address, access_timestamp, created_at
        ) VALUES (
            p_user_id, p_accessor_user_id, p_pii_fields, p_access_purpose,
            p_legal_basis, p_session_id, p_ip_address, NOW(), NOW()
        );
    END;
    $$ LANGUAGE plpgsql;
    """
    
    op.execute(text(pii_access_function_sql))
    
    # Create function for automated consent expiry checking
    consent_expiry_function_sql = """
    CREATE OR REPLACE FUNCTION check_consent_expiry()
    RETURNS VOID AS $$
    BEGIN
        -- Mark expired consents as inactive
        UPDATE data_subject_consent
        SET is_active = FALSE,
            updated_at = NOW()
        WHERE expiry_date < NOW()
          AND is_active = TRUE
          AND withdrawal_timestamp IS NULL;
          
        -- Log consent expiry events
        INSERT INTO security_audit_log (
            event_type, severity, additional_data, event_timestamp, created_at
        ) 
        SELECT 
            'CONSENT_EXPIRED',
            'MEDIUM',
            jsonb_build_object(
                'expired_consents', COUNT(*),
                'check_timestamp', NOW()
            ),
            NOW(),
            NOW()
        FROM data_subject_consent
        WHERE expiry_date < NOW()
          AND is_active = FALSE
          AND updated_at::DATE = NOW()::DATE;
    END;
    $$ LANGUAGE plpgsql;
    """
    
    op.execute(text(consent_expiry_function_sql))


def create_data_retention_procedures():
    """
    Create automated data retention and purging procedures per Section 6.2.4.1.
    
    Implements GDPR/CCPA automated data retention enforcement with referential
    integrity preservation and comprehensive audit logging.
    """
    logger.info("Creating data retention and purging procedures")
    
    # Create function for automated data retention enforcement
    retention_enforcement_function_sql = """
    CREATE OR REPLACE FUNCTION enforce_data_retention()
    RETURNS TEXT AS $$
    DECLARE
        policy_record RECORD;
        purge_count INTEGER := 0;
        total_purged INTEGER := 0;
        result_message TEXT;
    BEGIN
        -- Loop through active retention policies
        FOR policy_record IN 
            SELECT * FROM data_retention_policies 
            WHERE is_active = TRUE AND automated_purging = TRUE
        LOOP
            -- Calculate purge date based on retention period
            DECLARE
                purge_date TIMESTAMP := NOW() - INTERVAL '1 day' * policy_record.retention_period_days;
                grace_date TIMESTAMP := NOW() - INTERVAL '1 day' * (policy_record.retention_period_days + policy_record.grace_period_days);
            BEGIN
                -- Mark records for purging (soft delete first)
                EXECUTE format(
                    'UPDATE %I SET deleted_at = NOW(), updated_at = NOW() 
                     WHERE created_at < $1 AND deleted_at IS NULL',
                    policy_record.table_name
                ) USING purge_date;
                
                GET DIAGNOSTICS purge_count = ROW_COUNT;
                
                -- Permanently delete records after grace period
                IF policy_record.grace_period_days > 0 THEN
                    EXECUTE format(
                        'DELETE FROM %I WHERE deleted_at < $1',
                        policy_record.table_name
                    ) USING grace_date;
                END IF;
                
                total_purged := total_purged + purge_count;
                
                -- Log retention enforcement
                INSERT INTO audit_log (
                    table_name, record_id, operation, new_values,
                    operation_timestamp, created_at
                ) VALUES (
                    'data_retention_enforcement',
                    policy_record.id::TEXT,
                    'RETENTION_PURGE',
                    jsonb_build_object(
                        'policy_name', policy_record.policy_name,
                        'table_name', policy_record.table_name,
                        'records_marked', purge_count,
                        'purge_date', purge_date,
                        'grace_date', grace_date
                    ),
                    NOW(),
                    NOW()
                );
            END;
        END LOOP;
        
        result_message := format('Data retention enforcement completed. Total records processed: %s', total_purged);
        
        -- Log overall enforcement summary
        INSERT INTO security_audit_log (
            event_type, severity, additional_data, event_timestamp, created_at
        ) VALUES (
            'DATA_RETENTION_ENFORCEMENT',
            'INFO',
            jsonb_build_object(
                'total_records_processed', total_purged,
                'enforcement_timestamp', NOW(),
                'policies_processed', (SELECT COUNT(*) FROM data_retention_policies WHERE is_active = TRUE)
            ),
            NOW(),
            NOW()
        );
        
        RETURN result_message;
    END;
    $$ LANGUAGE plpgsql;
    """
    
    op.execute(text(retention_enforcement_function_sql))
    
    # Create function for GDPR data subject erasure
    gdpr_erasure_function_sql = """
    CREATE OR REPLACE FUNCTION execute_gdpr_erasure(p_user_id INTEGER)
    RETURNS TEXT AS $$
    DECLARE
        erasure_count INTEGER := 0;
        total_erased INTEGER := 0;
        result_message TEXT;
    BEGIN
        -- Start transaction for data erasure
        BEGIN
            -- Anonymize or delete user PII data
            UPDATE users 
            SET 
                email_encrypted = NULL,
                phone_number_encrypted = NULL,
                full_name_encrypted = NULL,
                date_of_birth_encrypted = NULL,
                address_encrypted = NULL,
                identification_number_encrypted = NULL,
                email = 'anonymized_' || id || '@deleted.local',
                username = 'anonymized_user_' || id,
                password_hash = 'ERASED',
                is_active = FALSE,
                updated_at = NOW()
            WHERE id = p_user_id;
            
            GET DIAGNOSTICS erasure_count = ROW_COUNT;
            total_erased := total_erased + erasure_count;
            
            -- Mark related records for anonymization
            UPDATE audit_log 
            SET 
                old_values = CASE 
                    WHEN old_values IS NOT NULL THEN 
                        jsonb_set(old_values, '{email}', '"[ERASED]"'::jsonb)
                    ELSE NULL 
                END,
                new_values = CASE 
                    WHEN new_values IS NOT NULL THEN 
                        jsonb_set(new_values, '{email}', '"[ERASED]"'::jsonb)
                    ELSE NULL 
                END,
                updated_at = NOW()
            WHERE user_id = p_user_id;
            
            -- Anonymize consent records (keep for legal compliance)
            UPDATE data_subject_consent
            SET 
                consent_evidence = jsonb_build_object('erased', true, 'erasure_date', NOW()),
                ip_address = '[ERASED]',
                user_agent = '[ERASED]',
                updated_at = NOW()
            WHERE user_id = p_user_id;
            
            -- Log the erasure action
            INSERT INTO audit_log (
                table_name, record_id, operation, new_values,
                user_id, operation_timestamp, created_at
            ) VALUES (
                'gdpr_erasure',
                p_user_id::TEXT,
                'GDPR_ERASURE',
                jsonb_build_object(
                    'user_id', p_user_id,
                    'erasure_timestamp', NOW(),
                    'records_anonymized', total_erased,
                    'legal_basis', 'GDPR Article 17 - Right to Erasure'
                ),
                p_user_id,
                NOW(),
                NOW()
            );
            
            -- Log security event
            INSERT INTO security_audit_log (
                event_type, severity, user_id, additional_data, event_timestamp, created_at
            ) VALUES (
                'GDPR_ERASURE_EXECUTED',
                'HIGH',
                p_user_id,
                jsonb_build_object(
                    'user_id', p_user_id,
                    'erasure_timestamp', NOW(),
                    'records_affected', total_erased
                ),
                NOW(),
                NOW()
            );
            
            result_message := format('GDPR erasure completed for user %s. Records affected: %s', p_user_id, total_erased);
            
        EXCEPTION 
            WHEN OTHERS THEN
                -- Log erasure failure
                INSERT INTO security_audit_log (
                    event_type, severity, user_id, additional_data, event_timestamp, created_at
                ) VALUES (
                    'GDPR_ERASURE_FAILED',
                    'CRITICAL',
                    p_user_id,
                    jsonb_build_object(
                        'user_id', p_user_id,
                        'error_message', SQLERRM,
                        'error_timestamp', NOW()
                    ),
                    NOW(),
                    NOW()
                );
                
                RAISE EXCEPTION 'GDPR erasure failed for user %: %', p_user_id, SQLERRM;
        END;
        
        RETURN result_message;
    END;
    $$ LANGUAGE plpgsql;
    """
    
    op.execute(text(gdpr_erasure_function_sql))


def create_user_data_rights_infrastructure():
    """
    Create infrastructure for automated user data rights fulfillment.
    
    Implements GDPR/CCPA data subject rights automation including data export,
    rectification, and automated request processing capabilities.
    """
    logger.info("Creating user data rights fulfillment infrastructure")
    
    # Create function for automated data export (GDPR Article 20)
    data_export_function_sql = """
    CREATE OR REPLACE FUNCTION generate_user_data_export(p_user_id INTEGER)
    RETURNS JSONB AS $$
    DECLARE
        user_data JSONB;
        export_data JSONB;
    BEGIN
        -- Collect user data from various tables
        SELECT to_jsonb(u) INTO user_data
        FROM (
            SELECT 
                id,
                username,
                email,
                is_active,
                created_at,
                updated_at,
                -- Decrypt PII fields for export
                CASE 
                    WHEN email_encrypted IS NOT NULL THEN '[ENCRYPTED PII - Contact support for decryption]'
                    ELSE email
                END as email_status,
                CASE 
                    WHEN phone_number_encrypted IS NOT NULL THEN '[ENCRYPTED PII - Contact support for decryption]'
                    ELSE NULL
                END as phone_status
            FROM users 
            WHERE id = p_user_id
        ) u;
        
        -- Build comprehensive export data
        export_data := jsonb_build_object(
            'user_profile', user_data,
            'consent_records', (
                SELECT jsonb_agg(to_jsonb(c))
                FROM (
                    SELECT 
                        consent_type,
                        consent_purpose,
                        legal_basis,
                        consent_granted,
                        consent_timestamp,
                        withdrawal_timestamp,
                        is_active
                    FROM data_subject_consent 
                    WHERE user_id = p_user_id
                ) c
            ),
            'access_requests', (
                SELECT jsonb_agg(to_jsonb(r))
                FROM (
                    SELECT 
                        request_type,
                        request_status,
                        request_timestamp,
                        completed_timestamp
                    FROM data_subject_requests 
                    WHERE user_id = p_user_id
                ) r
            ),
            'business_entities', (
                SELECT jsonb_agg(to_jsonb(b))
                FROM (
                    SELECT 
                        name,
                        description,
                        status,
                        created_at,
                        updated_at
                    FROM business_entities 
                    WHERE owner_id = p_user_id
                ) b
            ),
            'export_metadata', jsonb_build_object(
                'export_timestamp', NOW(),
                'export_format', 'JSON',
                'legal_basis', 'GDPR Article 20 - Right to Data Portability',
                'retention_notice', 'This export contains personal data. Please handle according to applicable privacy laws.',
                'user_id', p_user_id
            )
        );
        
        -- Log the data export
        INSERT INTO data_access_audit (
            user_id, data_subject_id, data_type, data_fields, access_purpose,
            legal_basis, operation_type, access_timestamp, created_at
        ) VALUES (
            NULL, -- System generated export
            p_user_id,
            'PII',
            ARRAY['profile_data', 'consent_records', 'business_entities'],
            'GDPR Article 20 - Data Portability Request',
            'LEGAL_OBLIGATION',
            'EXPORT',
            NOW(),
            NOW()
        );
        
        RETURN export_data;
    END;
    $$ LANGUAGE plpgsql;
    """
    
    op.execute(text(data_export_function_sql))
    
    # Create function for automated request processing
    automated_request_processing_sql = """
    CREATE OR REPLACE FUNCTION process_data_subject_request(p_request_id TEXT)
    RETURNS TEXT AS $$
    DECLARE
        request_record RECORD;
        processing_result TEXT;
        export_data JSONB;
    BEGIN
        -- Get request details
        SELECT * INTO request_record
        FROM data_subject_requests
        WHERE id = p_request_id AND request_status = 'PENDING';
        
        IF NOT FOUND THEN
            RETURN 'Request not found or not in PENDING status';
        END IF;
        
        -- Update request status to IN_PROGRESS
        UPDATE data_subject_requests
        SET 
            request_status = 'IN_PROGRESS',
            automated_fulfillment = TRUE,
            updated_at = NOW()
        WHERE id = p_request_id;
        
        -- Process based on request type
        CASE request_record.request_type
            WHEN 'ACCESS' THEN
                -- Generate data export
                export_data := generate_user_data_export(request_record.user_id);
                
                UPDATE data_subject_requests
                SET 
                    request_status = 'COMPLETED',
                    fulfillment_data = export_data,
                    completed_timestamp = NOW(),
                    processing_notes = 'Automated data export completed',
                    updated_at = NOW()
                WHERE id = p_request_id;
                
                processing_result := 'Data access request completed automatically';
                
            WHEN 'ERASURE' THEN
                -- Execute GDPR erasure
                processing_result := execute_gdpr_erasure(request_record.user_id);
                
                UPDATE data_subject_requests
                SET 
                    request_status = 'COMPLETED',
                    completed_timestamp = NOW(),
                    processing_notes = processing_result,
                    updated_at = NOW()
                WHERE id = p_request_id;
                
            WHEN 'PORTABILITY' THEN
                -- Generate portable data export
                export_data := generate_user_data_export(request_record.user_id);
                
                UPDATE data_subject_requests
                SET 
                    request_status = 'COMPLETED',
                    fulfillment_data = export_data,
                    completed_timestamp = NOW(),
                    processing_notes = 'Automated data portability export completed',
                    updated_at = NOW()
                WHERE id = p_request_id;
                
                processing_result := 'Data portability request completed automatically';
                
            ELSE
                -- Manual processing required
                UPDATE data_subject_requests
                SET 
                    request_status = 'PENDING',
                    processing_notes = 'Manual processing required for this request type',
                    updated_at = NOW()
                WHERE id = p_request_id;
                
                processing_result := 'Request requires manual processing';
        END CASE;
        
        -- Log the processing
        INSERT INTO security_audit_log (
            event_type, severity, user_id, additional_data, event_timestamp, created_at
        ) VALUES (
            'DATA_SUBJECT_REQUEST_PROCESSED',
            'MEDIUM',
            request_record.user_id,
            jsonb_build_object(
                'request_id', p_request_id,
                'request_type', request_record.request_type,
                'processing_result', processing_result,
                'automated', TRUE
            ),
            NOW(),
            NOW()
        );
        
        RETURN processing_result;
    END;
    $$ LANGUAGE plpgsql;
    """
    
    op.execute(text(automated_request_processing_sql))


def initialize_compliance_configuration():
    """
    Initialize encryption keys, retention policies, and compliance configuration.
    
    Sets up the foundational configuration required for audit and compliance operations.
    """
    logger.info("Initializing compliance configuration and encryption keys")
    
    # Generate master encryption key for PII data
    master_key = Fernet.generate_key()
    
    # Insert initial encryption key
    op.execute(
        text("""
        INSERT INTO encryption_keys (
            key_id, key_purpose, key_algorithm, encrypted_key_material,
            key_version, is_active, created_at, activated_at
        ) VALUES (
            gen_random_uuid()::text,
            'PII',
            'FERNET',
            :key_material,
            1,
            TRUE,
            NOW(),
            NOW()
        )
        """),
        {"key_material": master_key.decode()}
    )
    
    # Insert field mapping for encrypted fields
    encrypted_fields = [
        ('users', 'email_encrypted', 'PII', 'EMAIL'),
        ('users', 'phone_number_encrypted', 'PII', 'PHONE'),
        ('users', 'full_name_encrypted', 'PII', 'NAME'),
        ('users', 'date_of_birth_encrypted', 'PII', 'NAME'),
        ('users', 'address_encrypted', 'PII', 'ADDRESS'),
        ('users', 'identification_number_encrypted', 'RESTRICTED', 'SSN')
    ]
    
    for table_name, field_name, classification, pii_category in encrypted_fields:
        op.execute(
            text("""
            INSERT INTO encrypted_field_mapping (
                table_name, field_name, encryption_key_id, data_classification,
                pii_category, encryption_algorithm, requires_consent, created_at, updated_at
            ) VALUES (
                :table_name, :field_name,
                (SELECT key_id FROM encryption_keys WHERE key_purpose = 'PII' AND is_active = TRUE LIMIT 1),
                :classification, :pii_category, 'FERNET', TRUE, NOW(), NOW()
            )
            """),
            {
                "table_name": table_name,
                "field_name": field_name,
                "classification": classification,
                "pii_category": pii_category
            }
        )
    
    # Insert default data retention policies
    retention_policies = [
        ('User Session Data', 'user_sessions', 90, 'SESSION_MANAGEMENT', 30, True),
        ('Audit Log Data', 'audit_log', 2555, 'AUDIT_COMPLIANCE', 90, False), # 7 years
        ('Security Audit Data', 'security_audit_log', 2555, 'SECURITY_COMPLIANCE', 90, False), # 7 years
        ('User PII Data', 'users', 1095, 'DATA_SUBJECT_RIGHTS', 30, False), # 3 years
        ('Data Access Logs', 'data_access_audit', 2555, 'PRIVACY_COMPLIANCE', 90, False) # 7 years
    ]
    
    for policy_name, table_name, retention_days, legal_basis, grace_days, auto_purge in retention_policies:
        op.execute(
            text("""
            INSERT INTO data_retention_policies (
                policy_name, data_category, table_name, retention_period_days,
                grace_period_days, legal_basis, automated_purging, is_active,
                created_at, updated_at
            ) VALUES (
                :policy_name, :table_name, :table_name, :retention_days,
                :grace_days, :legal_basis, :auto_purge, TRUE, NOW(), NOW()
            )
            """),
            {
                "policy_name": policy_name,
                "table_name": table_name,
                "retention_days": retention_days,
                "grace_days": grace_days,
                "legal_basis": legal_basis,
                "auto_purge": auto_purge
            }
        )


def remove_user_data_rights_infrastructure():
    """Remove user data rights fulfillment infrastructure."""
    logger.info("Removing user data rights fulfillment infrastructure")
    
    op.execute(text("DROP FUNCTION IF EXISTS process_data_subject_request(TEXT)"))
    op.execute(text("DROP FUNCTION IF EXISTS generate_user_data_export(INTEGER)"))


def remove_data_retention_procedures():
    """Remove data retention and purging procedures."""
    logger.info("Removing data retention and purging procedures")
    
    op.execute(text("DROP FUNCTION IF EXISTS execute_gdpr_erasure(INTEGER)"))
    op.execute(text("DROP FUNCTION IF EXISTS enforce_data_retention()"))


def remove_postgresql_audit_triggers():
    """Remove PostgreSQL audit triggers and functions."""
    logger.info("Removing PostgreSQL audit triggers and functions")
    
    # Remove triggers from critical tables
    critical_tables = ['users', 'user_sessions', 'business_entities', 'entity_relationships']
    
    for table_name in critical_tables:
        op.execute(text(f"DROP TRIGGER IF EXISTS audit_trigger_{table_name} ON {table_name}"))
    
    # Remove audit functions
    op.execute(text("DROP FUNCTION IF EXISTS check_consent_expiry()"))
    op.execute(text("DROP FUNCTION IF EXISTS log_pii_access(INTEGER, INTEGER, TEXT[], TEXT, TEXT, TEXT, TEXT)"))
    op.execute(text("DROP FUNCTION IF EXISTS audit_table_changes()"))


def remove_encrypted_fields_from_existing_tables():
    """Remove encrypted fields from existing tables."""
    logger.info("Removing encrypted fields from existing tables")
    
    # Remove PII access tracking table
    op.drop_table('user_pii_access_log')
    
    # Remove encrypted fields from users table
    encrypted_fields = [
        'last_pii_access', 'pii_encrypted_at', 'encryption_key_version',
        'identification_number_encrypted', 'address_encrypted', 'date_of_birth_encrypted',
        'full_name_encrypted', 'phone_number_encrypted', 'email_encrypted'
    ]
    
    for field_name in encrypted_fields:
        try:
            op.drop_column('users', field_name)
        except Exception as e:
            logger.warning(f"Could not drop column {field_name}: {e}")


def remove_compliance_tables():
    """Remove GDPR/CCPA compliance tables."""
    logger.info("Removing GDPR/CCPA compliance tables")
    
    op.drop_table('data_retention_policies')
    op.drop_table('data_subject_requests')
    op.drop_table('data_subject_consent')


def remove_encryption_infrastructure():
    """Remove field-level PII encryption infrastructure."""
    logger.info("Removing field-level PII encryption infrastructure")
    
    op.drop_table('encrypted_field_mapping')
    op.drop_table('encryption_keys')


def remove_audit_tables():
    """Remove comprehensive audit tables."""
    logger.info("Removing audit tables")
    
    op.drop_table('data_access_audit')
    op.drop_table('security_audit_log')
    op.drop_table('audit_log')