# -*- coding: utf-8 -*-
"""
Flask Authentication Utilities Package Initialization

This module establishes the authentication utilities package namespace and provides
centralized imports for all Flask authentication utility functions. It enables organized
utility function discovery and integrates with the Flask authentication architecture
for systematic utility access across auth components.

The utilities package provides comprehensive support for:
- Cryptographic operations and secure token generation
- Input validation and sanitization for security
- Configuration management for Flask authentication
- Response formatting and HTTP status handling
- Time/timezone utilities for authentication workflows
- Migration helpers for Node.js to Flask conversion

Author: DevSecOps Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
"""

import logging
from typing import Dict, Any, Optional, Union, List

# Configure module logger for authentication utilities
logger = logging.getLogger(__name__)

# Package metadata
__version__ = "1.0.0"
__author__ = "DevSecOps Team"
__description__ = "Flask Authentication Utilities Package"

# =============================================================================
# CRYPTOGRAPHIC UTILITIES
# =============================================================================

try:
    from .crypto_helpers import (
        # ItsDangerous integration for secure token generation and signing
        generate_secure_token,
        sign_data_with_timestamp,
        verify_signed_data,
        generate_csrf_token,
        validate_csrf_token,
        
        # AES-GCM encryption utilities for sensitive data protection
        encrypt_sensitive_data,
        decrypt_sensitive_data,
        generate_encryption_key,
        
        # Secure random token generation for session IDs and authentication
        generate_session_id,
        generate_api_token,
        generate_password_reset_token,
        
        # PBKDF2 key derivation for enhanced security
        derive_key_from_password,
        generate_salt,
        
        # Timing-safe comparison utilities for authentication security
        constant_time_compare,
        secure_hash_comparison
    )
    
    logger.debug("Successfully imported cryptographic utilities")
    
except ImportError as e:
    logger.error(f"Failed to import crypto_helpers: {e}")
    # Provide fallback implementations or raise
    raise ImportError(f"Critical cryptographic utilities unavailable: {e}")

# =============================================================================
# VALIDATION UTILITIES
# =============================================================================

try:
    from .validation_helpers import (
        # Input validation and sanitization for authentication security
        validate_email_format,
        validate_username_format,
        validate_password_strength,
        sanitize_user_input,
        
        # SQL injection prevention utilities for Flask-SQLAlchemy integration
        validate_sql_identifier,
        sanitize_database_input,
        check_injection_patterns,
        
        # XSS prevention for authentication form processing
        sanitize_html_input,
        validate_safe_string,
        escape_user_content,
        
        # Authentication request validation with comprehensive error handling
        validate_auth_request,
        validate_token_format,
        validate_session_data,
        
        # Security pattern detection
        detect_malicious_patterns,
        validate_ip_address,
        check_user_agent_security
    )
    
    logger.debug("Successfully imported validation utilities")
    
except ImportError as e:
    logger.error(f"Failed to import validation_helpers: {e}")
    # Log error but continue - validation can have fallbacks
    logger.warning("Some validation utilities may not be available")

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

try:
    from .config_manager import (
        # Flask application factory pattern for authentication configuration
        AuthConfig,
        load_auth_config,
        validate_auth_config,
        
        # Auth0 Python SDK configuration management
        get_auth0_config,
        validate_auth0_settings,
        init_auth0_client,
        
        # JWT token configuration with Flask-JWT-Extended integration
        get_jwt_config,
        configure_jwt_settings,
        validate_jwt_config,
        
        # Flask-Login session configuration management
        get_session_config,
        configure_session_security,
        validate_session_settings,
        
        # Environment-specific configuration for development and production
        load_environment_config,
        get_config_for_environment,
        validate_environment_settings
    )
    
    logger.debug("Successfully imported configuration management utilities")
    
except ImportError as e:
    logger.error(f"Failed to import config_manager: {e}")
    logger.warning("Configuration management utilities unavailable")

# =============================================================================
# RESPONSE FORMATTING UTILITIES
# =============================================================================

try:
    from .response_helpers import (
        # Standardized HTTP response formatting for authentication endpoints
        format_auth_success_response,
        format_auth_error_response,
        format_validation_error_response,
        
        # Consistent error handling with appropriate status codes
        create_error_response,
        create_success_response,
        format_api_response,
        
        # JSON response compatibility with existing client applications
        format_json_response,
        create_paginated_response,
        format_data_response,
        
        # Authentication workflow response standardization
        format_login_response,
        format_logout_response,
        format_token_response,
        
        # CSRF token response integration for web security
        include_csrf_token,
        format_csrf_response,
        add_security_headers
    )
    
    logger.debug("Successfully imported response formatting utilities")
    
except ImportError as e:
    logger.error(f"Failed to import response_helpers: {e}")
    logger.warning("Response formatting utilities may be limited")

# =============================================================================
# TIME AND TIMEZONE UTILITIES
# =============================================================================

try:
    from .time_helpers import (
        # Timezone-aware timestamp generation for authentication logging
        get_utc_timestamp,
        get_local_timestamp,
        format_iso_timestamp,
        
        # JWT token expiration handling and validation
        calculate_token_expiration,
        validate_token_expiry,
        is_token_expired,
        
        # Session timeout calculation and enforcement
        calculate_session_timeout,
        validate_session_expiry,
        extend_session_timeout,
        
        # Authentication audit trail timestamp consistency
        get_audit_timestamp,
        format_audit_time,
        standardize_timestamp,
        
        # Time-based security pattern detection
        detect_rapid_requests,
        validate_request_timing,
        check_suspicious_timing
    )
    
    logger.debug("Successfully imported time and timezone utilities")
    
except ImportError as e:
    logger.error(f"Failed to import time_helpers: {e}")
    logger.warning("Time utilities may be limited")

# =============================================================================
# MIGRATION UTILITIES
# =============================================================================

try:
    from .migration_helpers import (
        # Node.js to Flask authentication data transformation
        transform_user_data,
        convert_session_data,
        migrate_authentication_settings,
        
        # User credential migration with data integrity validation
        migrate_user_credentials,
        validate_migrated_data,
        verify_data_integrity,
        
        # Session management migration from Node.js to Flask patterns
        convert_session_format,
        migrate_session_store,
        validate_session_migration,
        
        # Authentication workflow compatibility verification
        verify_workflow_compatibility,
        validate_endpoint_compatibility,
        check_auth_flow_consistency,
        
        # Backward compatibility maintenance during migration
        ensure_backward_compatibility,
        validate_api_compatibility,
        check_client_compatibility
    )
    
    logger.debug("Successfully imported migration utilities")
    
except ImportError as e:
    logger.error(f"Failed to import migration_helpers: {e}")
    logger.warning("Migration utilities may be unavailable")

# =============================================================================
# PACKAGE-LEVEL CONVENIENCE FUNCTIONS
# =============================================================================

def get_available_utilities() -> Dict[str, List[str]]:
    """
    Get a dictionary of all available utility functions organized by category.
    
    Returns:
        Dict[str, List[str]]: Dictionary mapping utility categories to function lists
    """
    utilities = {
        "crypto": [
            "generate_secure_token", "sign_data_with_timestamp", "verify_signed_data",
            "encrypt_sensitive_data", "decrypt_sensitive_data", "constant_time_compare"
        ],
        "validation": [
            "validate_email_format", "validate_username_format", "validate_password_strength",
            "sanitize_user_input", "validate_auth_request", "detect_malicious_patterns"
        ],
        "config": [
            "load_auth_config", "get_auth0_config", "get_jwt_config",
            "get_session_config", "load_environment_config"
        ],
        "response": [
            "format_auth_success_response", "format_auth_error_response",
            "create_error_response", "format_json_response", "add_security_headers"
        ],
        "time": [
            "get_utc_timestamp", "calculate_token_expiration", "validate_token_expiry",
            "calculate_session_timeout", "get_audit_timestamp"
        ],
        "migration": [
            "transform_user_data", "migrate_user_credentials", "convert_session_format",
            "verify_workflow_compatibility", "ensure_backward_compatibility"
        ]
    }
    
    return utilities

def validate_utility_dependencies() -> bool:
    """
    Validate that all critical utility dependencies are available.
    
    Returns:
        bool: True if all critical dependencies are available, False otherwise
    """
    try:
        # Test critical cryptographic functions
        generate_secure_token(32)
        
        # Test critical validation functions
        validate_email_format("test@example.com")
        
        # Test time utilities
        get_utc_timestamp()
        
        logger.info("All critical utility dependencies validated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Utility dependency validation failed: {e}")
        return False

def init_auth_utils(app: Optional[Any] = None, config: Optional[Dict[str, Any]] = None) -> bool:
    """
    Initialize authentication utilities with Flask application context.
    
    Args:
        app: Flask application instance (optional)
        config: Configuration dictionary (optional)
        
    Returns:
        bool: True if initialization successful, False otherwise
    """
    try:
        if app:
            # Initialize utilities with Flask app context
            logger.info(f"Initializing auth utilities for Flask app: {app.name}")
            
            # Configure logging for auth utilities
            if hasattr(app, 'logger'):
                logger.addHandler(app.logger.handlers[0] if app.logger.handlers else logging.StreamHandler())
        
        if config:
            # Apply configuration settings
            logger.debug("Applying authentication utility configuration")
        
        # Validate dependencies
        if not validate_utility_dependencies():
            logger.warning("Some utility dependencies may not be fully available")
            return False
        
        logger.info("Authentication utilities initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize authentication utilities: {e}")
        return False

# =============================================================================
# PACKAGE EXPORTS
# =============================================================================

# Define what gets imported when someone does "from src.auth.utils import *"
__all__ = [
    # Cryptographic utilities
    "generate_secure_token", "sign_data_with_timestamp", "verify_signed_data",
    "generate_csrf_token", "validate_csrf_token", "encrypt_sensitive_data",
    "decrypt_sensitive_data", "generate_session_id", "constant_time_compare",
    
    # Validation utilities
    "validate_email_format", "validate_username_format", "validate_password_strength",
    "sanitize_user_input", "validate_auth_request", "detect_malicious_patterns",
    
    # Configuration management
    "load_auth_config", "get_auth0_config", "get_jwt_config", "get_session_config",
    
    # Response formatting
    "format_auth_success_response", "format_auth_error_response", "create_error_response",
    "format_json_response", "add_security_headers",
    
    # Time utilities
    "get_utc_timestamp", "calculate_token_expiration", "validate_token_expiry",
    "calculate_session_timeout", "get_audit_timestamp",
    
    # Migration utilities
    "transform_user_data", "migrate_user_credentials", "convert_session_format",
    "verify_workflow_compatibility", "ensure_backward_compatibility",
    
    # Package functions
    "get_available_utilities", "validate_utility_dependencies", "init_auth_utils"
]

# Initialize package-level logging
logger.info(f"Flask Authentication Utilities Package v{__version__} loaded")
logger.debug(f"Available utility categories: {list(get_available_utilities().keys())}")

# Validate critical dependencies on import
if not validate_utility_dependencies():
    logger.warning("Some authentication utilities may not function correctly")

# Export package metadata
__all__.extend(["__version__", "__author__", "__description__"])