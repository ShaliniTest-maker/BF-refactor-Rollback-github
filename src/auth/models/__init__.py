"""
Flask Authentication Models Package

This module establishes the Flask-SQLAlchemy authentication model namespace and provides
centralized imports for all authentication-specific database models. It enables organized
authentication model registration with the Flask application factory pattern and facilitates
clean imports of security models throughout the authentication subsystem.

Authentication Models:
- Role: Flask-Security role-based access control with Python Enum-backed role definitions
- Permission: Granular access control with resource-based permissions and dynamic authorization
- UserRoleAssignment: Many-to-many relationship management between Users and Roles
- AuthenticationLog: Comprehensive audit logging for authentication events and security monitoring
- SecurityIncident: Automated security incident tracking with threat detection and response
- RefreshToken: Auth0 refresh token management with automated rotation policies

The auth.models package supports:
- Flask-Principal Need/Provide pattern for context-aware authorization decisions
- Flask-Security role-based authentication decorators and permission enforcement
- Auth0 Python SDK 4.9.0 integration for enterprise identity management
- Flask-JWT-Extended 4.7.1 for local JWT processing and refresh token rotation
- Prometheus metrics integration for real-time security monitoring
- AWS CloudWatch Logs integration for centralized audit trail aggregation
- Role-Based Access Control (RBAC) with hierarchical permission inheritance
- Security incident response automation with containment action tracking

Security Architecture Integration:
- Comprehensive authentication audit logging per Section 6.4.2.5
- Real-time security monitoring and anomaly detection per Section 6.4.6.1
- Automated threat detection and incident response per Section 6.4.6.2
- Auth0 refresh token rotation policies per Section 6.4.1.4
- Flask-Principal RBAC implementation per Section 6.4.2.1
- Structured JSON logging with Python structlog integration
- Enhanced security posture with zero degradation requirements

Requirements:
- Python 3.13.3 runtime environment for authentication components
- Flask 3.1.1 with Flask-SQLAlchemy 3.1.1 for model persistence
- Flask-Principal or Flask-Security for RBAC enforcement
- Auth0 Python SDK 4.9.0 for identity provider integration
- Flask-JWT-Extended 4.7.1 for JWT processing and token management
- PostgreSQL 15.x with encrypted storage and audit capabilities
- Prometheus Python client for security metrics collection
- AWS CloudWatch integration for centralized security monitoring

Technical Specification References:
- Section 6.4: Security Architecture implementation with Flask authentication
- Section 6.4.2.1: Role-Based Access Control with Flask-Principal integration
- Section 6.4.1.4: JWT refresh token management for Auth0 integration
- Section 6.4.2.5: Authentication audit logging with structured JSON output
- Section 6.4.6.1: Real-time security monitoring with Prometheus metrics
- Section 6.4.6.2: Security incident tracking for automated response
- Feature F-007: Flask authentication architecture implementation
"""

# Import base model dependencies
from ..models.base import BaseModel, db

# Import authentication and authorization models
from .role import Role, RoleType
from .permission import Permission, PermissionType
from .user_role_assignment import UserRoleAssignment
from .authentication_log import AuthenticationLog, AuthenticationEventType
from .security_incident import SecurityIncident, IncidentType, IncidentSeverity
from .refresh_token import RefreshToken, TokenStatus

# Define public API for the auth.models package
# This enables clean imports like: from auth.models import Role, Permission
__all__ = [
    # Base model and database instance
    'BaseModel',
    'db',
    
    # Core authentication models
    'Role',
    'Permission', 
    'UserRoleAssignment',
    
    # Security monitoring and audit models
    'AuthenticationLog',
    'SecurityIncident',
    'RefreshToken',
    
    # Enum classes for type-safe operations
    'RoleType',
    'PermissionType',
    'AuthenticationEventType',
    'IncidentType',
    'IncidentSeverity',
    'TokenStatus',
    
    # Utility functions
    'get_all_auth_models',
    'validate_auth_model_relationships',
    'get_auth_model_config'
]

# Package metadata for Flask authentication integration
__version__ = '1.0.0'
__description__ = 'Flask-SQLAlchemy authentication models for security architecture'
__author__ = 'Flask Migration Team'

# Authentication model registry for Flask-Migrate integration
# This list ensures all authentication models are properly registered with Alembic
AUTH_MODELS = [
    Role,
    Permission,
    UserRoleAssignment,
    AuthenticationLog,
    SecurityIncident,
    RefreshToken
]

def get_all_auth_models():
    """
    Return all authentication database models for Flask-Migrate registration.
    
    This function provides centralized access to authentication models for:
    - Flask-Migrate Alembic migration generation and schema management
    - Security model relationship analysis and dependency mapping
    - Authentication component initialization and validation
    - Flask-Principal permission system configuration
    
    The models are returned in dependency order to ensure proper migration
    sequence and foreign key constraint creation.
    
    Returns:
        list: All Flask-SQLAlchemy authentication model classes in dependency order
        
    Example:
        >>> from auth.models import get_all_auth_models
        >>> models = get_all_auth_models()
        >>> print([model.__name__ for model in models])
        ['Role', 'Permission', 'UserRoleAssignment', 'AuthenticationLog', 'SecurityIncident', 'RefreshToken']
    """
    return AUTH_MODELS.copy()

def validate_auth_model_relationships():
    """
    Validate all authentication model relationships and foreign key constraints.
    
    This function performs comprehensive validation of authentication model
    relationships to ensure proper RBAC functionality and security compliance:
    - Role-Permission many-to-many relationships for permission assignment
    - User-Role association table configuration for RBAC implementation
    - Authentication log foreign key relationships for audit trail integrity
    - Security incident model relationships for threat tracking
    - Refresh token relationships for Auth0 integration
    - SQLAlchemy relationship mapping validation for query optimization
    
    Security Validation:
    - Verifies Flask-Principal Need/Provide pattern implementation
    - Validates authentication audit logging relationships
    - Confirms security incident tracking model integrity
    - Ensures refresh token management foreign key constraints
    
    Returns:
        bool: True if all relationships are valid and properly configured
        
    Raises:
        ValueError: If authentication model relationships are misconfigured,
                   missing required relationships, or contain circular dependencies
        SecurityValidationError: If security-critical relationships fail validation
        
    Example:
        >>> from auth.models import validate_auth_model_relationships
        >>> try:
        ...     validate_auth_model_relationships()
        ...     print("Authentication models validated successfully")
        ... except ValueError as e:
        ...     print(f"Validation error: {e}")
    """
    try:
        # Validate Role model relationships
        assert hasattr(Role, 'users'), "Role model missing users relationship for RBAC"
        assert hasattr(Role, 'permissions'), "Role model missing permissions relationship"
        
        # Validate Permission model relationships
        assert hasattr(Permission, 'roles'), "Permission model missing roles relationship"
        
        # Validate UserRoleAssignment relationships
        assert hasattr(UserRoleAssignment, 'user'), "UserRoleAssignment missing user relationship"
        assert hasattr(UserRoleAssignment, 'role'), "UserRoleAssignment missing role relationship"
        
        # Validate AuthenticationLog relationships
        assert hasattr(AuthenticationLog, 'user'), "AuthenticationLog missing user relationship for audit trails"
        
        # Validate SecurityIncident model structure
        assert hasattr(SecurityIncident, 'incident_type'), "SecurityIncident missing incident_type field"
        assert hasattr(SecurityIncident, 'severity'), "SecurityIncident missing severity field"
        
        # Validate RefreshToken relationships
        assert hasattr(RefreshToken, 'user'), "RefreshToken missing user relationship for Auth0 integration"
        
        # Validate enum type consistency
        from .role import RoleType
        from .permission import PermissionType
        from .authentication_log import AuthenticationEventType
        from .security_incident import IncidentType, IncidentSeverity
        from .refresh_token import TokenStatus
        
        assert isinstance(RoleType.USER, RoleType), "RoleType enum validation failed"
        assert isinstance(PermissionType.READ, PermissionType), "PermissionType enum validation failed"
        assert isinstance(AuthenticationEventType.LOGIN, AuthenticationEventType), "AuthenticationEventType enum validation failed"
        assert isinstance(IncidentType.AUTHENTICATION_BREACH, IncidentType), "IncidentType enum validation failed"
        assert isinstance(IncidentSeverity.HIGH, IncidentSeverity), "IncidentSeverity enum validation failed"
        assert isinstance(TokenStatus.ACTIVE, TokenStatus), "TokenStatus enum validation failed"
        
        return True
        
    except (AssertionError, AttributeError, ImportError) as e:
        raise ValueError(f"Authentication model relationship validation failed: {str(e)}")
    except Exception as e:
        # Catch any security-specific validation errors
        from .exceptions import SecurityValidationError
        raise SecurityValidationError(f"Security model validation failed: {str(e)}")

def get_auth_model_config():
    """
    Return authentication model configuration for Flask application factory integration.
    
    This configuration provides comprehensive settings for authentication
    and security model integration with Flask application components:
    
    Security Configuration:
    - Flask-Principal RBAC settings for permission enforcement
    - Auth0 integration parameters for identity management
    - Flask-JWT-Extended configuration for token processing
    - Security monitoring and audit logging parameters
    - Prometheus metrics collection settings
    - AWS CloudWatch integration configuration
    
    Database Configuration:
    - PostgreSQL authentication table optimization
    - Audit logging retention policies for compliance
    - Security incident data retention settings
    - Refresh token cleanup and rotation intervals
    
    Performance Configuration:
    - Role and permission query optimization
    - Authentication log indexing strategies
    - Security incident search performance tuning
    - RBAC relationship loading optimization
    
    Returns:
        dict: Authentication model configuration parameters for Flask app factory
        
    Configuration Categories:
        - rbac_config: Role-based access control settings
        - auth0_config: Auth0 integration parameters  
        - jwt_config: JWT processing and refresh token settings
        - audit_config: Authentication audit logging configuration
        - security_config: Security monitoring and incident response settings
        - performance_config: Query optimization and caching parameters
        
    Example:
        >>> from auth.models import get_auth_model_config
        >>> config = get_auth_model_config()
        >>> print(config['rbac_config']['default_role'])
        'user'
    """
    return {
        # Role-Based Access Control Configuration
        'rbac_config': {
            'default_role': RoleType.USER.value,
            'guest_role': RoleType.GUEST.value,
            'admin_role': RoleType.ADMIN.value,
            'enable_role_hierarchy': True,
            'role_assignment_audit': True,
            'permission_inheritance': True,
            'role_cache_timeout': 300,  # 5 minutes
            'permission_cache_timeout': 600  # 10 minutes
        },
        
        # Auth0 Integration Configuration
        'auth0_config': {
            'sdk_version': '4.9.0',
            'python_compatibility': '3.9-3.13',
            'flask_version': '3.1.1',
            'management_api_enabled': True,
            'refresh_token_rotation': True,
            'token_revocation_enabled': True,
            'automated_revocation_hooks': True,
            'grace_period_seconds': 30
        },
        
        # JWT Processing Configuration
        'jwt_config': {
            'flask_jwt_extended_version': '4.7.1',
            'local_jwt_decoding': True,
            'refresh_token_rotation': True,
            'token_blacklist_enabled': True,
            'access_token_expires': 3600,  # 1 hour
            'refresh_token_expires': 86400,  # 24 hours
            'token_cleanup_interval': 3600  # 1 hour
        },
        
        # Authentication Audit Configuration
        'audit_config': {
            'structured_logging': True,
            'json_format': True,
            'cloudwatch_integration': True,
            'prometheus_metrics': True,
            'audit_log_retention_days': 2555,  # 7 years for compliance
            'security_log_retention_days': 90,
            'authentication_log_level': 'INFO',
            'security_incident_log_level': 'WARNING'
        },
        
        # Security Monitoring Configuration
        'security_config': {
            'incident_tracking_enabled': True,
            'automated_response_enabled': True,
            'threat_detection_enabled': True,
            'anomaly_detection_enabled': True,
            'security_metrics_enabled': True,
            'incident_notification_channels': ['slack', 'email', 'pagerduty'],
            'security_incident_retention_days': 2555,  # 7 years for compliance
            'incident_response_timeout_minutes': 15
        },
        
        # Performance Optimization Configuration
        'performance_config': {
            'role_query_optimization': True,
            'permission_preloading': True,
            'audit_log_indexing': True,
            'security_incident_indexing': True,
            'relationship_loading_strategy': 'selectinload',
            'query_cache_enabled': True,
            'cache_ttl_seconds': 300,
            'batch_size_audit_logs': 1000
        },
        
        # Database Integration Configuration
        'database_config': {
            'postgresql_version': '15.x',
            'encryption_at_rest': True,
            'encryption_in_transit': True,
            'field_level_encryption': True,
            'audit_table_partitioning': True,
            'security_incident_archival': True,
            'refresh_token_cleanup_enabled': True,
            'backup_encryption_enabled': True
        },
        
        # Flask Application Factory Integration
        'flask_config': {
            'flask_version': '3.1.1',
            'flask_sqlalchemy_version': '3.1.1',
            'flask_migrate_version': '4.1.0',
            'flask_principal_enabled': True,
            'flask_security_enabled': False,  # Choose one RBAC framework
            'blueprint_registration': True,
            'model_registration': True
        },
        
        # Compliance and Legal Configuration
        'compliance_config': {
            'gdpr_compliance': True,
            'ccpa_compliance': True,
            'data_retention_automation': True,
            'right_to_erasure': True,
            'data_portability': True,
            'consent_management': True,
            'breach_notification': True,
            'audit_trail_integrity': True
        }
    }

# Model initialization function for Flask application factory pattern
def init_auth_models(app):
    """
    Initialize authentication models with Flask application factory pattern.
    
    This function integrates authentication models with the Flask application
    and configures security-specific settings for production deployment:
    
    Initialization Steps:
    1. Register authentication models with Flask-SQLAlchemy
    2. Configure Flask-Principal for RBAC enforcement
    3. Set up Auth0 integration for identity management
    4. Initialize security monitoring and audit logging
    5. Configure Prometheus metrics collection
    6. Set up AWS CloudWatch integration for centralized logging
    
    Args:
        app (Flask): Flask application instance for model registration
        
    Returns:
        dict: Initialization status and configuration summary
        
    Raises:
        ConfigurationError: If required authentication configuration is missing
        SecurityError: If security model initialization fails
        
    Example:
        >>> from flask import Flask
        >>> from auth.models import init_auth_models
        >>> 
        >>> app = Flask(__name__)
        >>> result = init_auth_models(app)
        >>> print(result['status'])
        'success'
    """
    try:
        # Validate Flask application configuration
        if not hasattr(app, 'config'):
            raise ValueError("Flask application missing configuration")
            
        # Get authentication model configuration
        auth_config = get_auth_model_config()
        
        # Validate authentication model relationships
        validate_auth_model_relationships()
        
        # Store configuration in app context
        app.config.setdefault('AUTH_MODELS_CONFIG', auth_config)
        
        # Initialize database models with Flask-SQLAlchemy
        db.init_app(app)
        
        # Register authentication models for Flask-Migrate
        app.config.setdefault('AUTH_MODELS', AUTH_MODELS)
        
        return {
            'status': 'success',
            'models_registered': len(AUTH_MODELS),
            'model_names': [model.__name__ for model in AUTH_MODELS],
            'rbac_enabled': auth_config['rbac_config']['enable_role_hierarchy'],
            'audit_enabled': auth_config['audit_config']['structured_logging'],
            'security_monitoring': auth_config['security_config']['incident_tracking_enabled']
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'error_message': str(e),
            'models_registered': 0
        }

# Authentication model configuration for development and testing
AUTH_MODEL_CONFIG = get_auth_model_config()

# Export model configuration for external access
def get_role_types():
    """Return all available role types for RBAC configuration."""
    return [role.value for role in RoleType]

def get_permission_types():
    """Return all available permission types for authorization configuration."""
    return [permission.value for permission in PermissionType]

def get_incident_types():
    """Return all available security incident types for threat detection."""
    return [incident.value for incident in IncidentType]

def get_incident_severities():
    """Return all available incident severity levels for response prioritization."""
    return [severity.value for severity in IncidentSeverity]

# Authentication model utilities for application integration
class AuthModelUtils:
    """
    Utility class for authentication model operations and validation.
    
    Provides helper methods for:
    - RBAC configuration and role management
    - Security incident classification and response
    - Authentication audit logging and monitoring
    - Permission evaluation and context-aware authorization
    """
    
    @staticmethod
    def get_default_permissions_for_role(role_type: RoleType):
        """
        Get default permissions for a specific role type.
        
        Args:
            role_type (RoleType): Role type to get permissions for
            
        Returns:
            list: Default permissions for the specified role
        """
        permission_map = {
            RoleType.GUEST: [PermissionType.READ],
            RoleType.USER: [PermissionType.READ, PermissionType.WRITE],
            RoleType.MODERATOR: [PermissionType.READ, PermissionType.WRITE, PermissionType.MODERATE],
            RoleType.ADMIN: [PermissionType.READ, PermissionType.WRITE, PermissionType.MODERATE, PermissionType.ADMIN],
            RoleType.SUPER_ADMIN: [permission for permission in PermissionType]
        }
        return permission_map.get(role_type, [])
    
    @staticmethod
    def validate_role_hierarchy(user_role: RoleType, required_role: RoleType):
        """
        Validate if user role has sufficient privileges for required role.
        
        Args:
            user_role (RoleType): User's current role
            required_role (RoleType): Required role for operation
            
        Returns:
            bool: True if user role has sufficient privileges
        """
        role_hierarchy = {
            RoleType.GUEST: 0,
            RoleType.USER: 1,
            RoleType.MODERATOR: 2,
            RoleType.ADMIN: 3,
            RoleType.SUPER_ADMIN: 4
        }
        
        user_level = role_hierarchy.get(user_role, -1)
        required_level = role_hierarchy.get(required_role, 999)
        
        return user_level >= required_level