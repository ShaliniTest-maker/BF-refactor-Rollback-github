"""
Auth0 Identity Provider Integration Service

This module implements comprehensive Auth0 identity provider integration using
Auth0 Python SDK 4.9.0 for enterprise-grade external authentication management.
Provides user authentication flows, token validation, user profile synchronization,
and Auth0 Management API interactions.

Key Features:
- Auth0 Python SDK 4.9.0 integration with Flask application factory
- JWT token validation with Auth0 public key verification  
- User profile synchronization with Flask-SQLAlchemy models
- Auth0 Management API integration for user lifecycle operations
- Refresh token rotation policy with automated revocation
- Security incident response capabilities
- Comprehensive error handling and logging

Dependencies:
- auth0-python 4.9.0 for Auth0 API integration
- PyJWT for token validation and processing
- Flask-SQLAlchemy for user model synchronization
- Requests with retry logic for reliable API communication
- Integration with security monitoring and token management

Architectural Pattern:
Implements the Service Layer pattern for Auth0 operations, providing clean
abstraction between Flask authentication decorators and Auth0 identity provider
while maintaining Flask application context and session management.
"""

import os
import json
import time
import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Union, Tuple, Any, NamedTuple
from dataclasses import dataclass, asdict
from functools import wraps, lru_cache
from urllib.parse import urlencode, urlparse

import jwt
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask import Flask, current_app, g, request, session, url_for, redirect, jsonify
from werkzeug.security import safe_str_cmp

# Auth0 Python SDK imports
try:
    from auth0.authentication import GetToken, Social, Users
    from auth0.management import Auth0
    from auth0.management.rest import RestClient
    from auth0.exceptions import Auth0Error
except ImportError as e:
    # Handle missing Auth0 SDK during development/testing
    GetToken = None
    Social = None
    Users = None
    Auth0 = None
    RestClient = None
    Auth0Error = Exception
    print(f"Warning: Auth0 SDK not available: {e}")

# Internal imports
try:
    from ..models.user import User
    from ..models.session import UserSession
    from .security_monitor import SecurityMonitor, SecurityEventType, SecuritySeverity
except ImportError:
    # Handle imports during testing or standalone execution
    User = None
    UserSession = None
    SecurityMonitor = None
    SecurityEventType = None
    SecuritySeverity = None


@dataclass
class Auth0Configuration:
    """Auth0 configuration data structure."""
    domain: str
    client_id: str
    client_secret: str
    audience: str
    management_api_audience: Optional[str] = None
    callback_url: Optional[str] = None
    logout_url: Optional[str] = None
    connection: Optional[str] = None
    scope: str = "openid profile email"


@dataclass
class Auth0UserProfile:
    """Auth0 user profile data structure."""
    user_id: str
    email: str
    username: Optional[str] = None
    name: Optional[str] = None
    picture: Optional[str] = None
    email_verified: bool = False
    auth0_sub: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    app_metadata: Optional[Dict[str, Any]] = None
    roles: Optional[List[str]] = None
    permissions: Optional[List[str]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass
class AuthenticationResult:
    """Result of Auth0 authentication operation."""
    success: bool
    user_profile: Optional[Auth0UserProfile] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    expires_in: Optional[int] = None
    token_type: Optional[str] = None
    error_code: Optional[str] = None
    error_description: Optional[str] = None


@dataclass
class TokenValidationResult:
    """Result of token validation operation."""
    valid: bool
    user_profile: Optional[Auth0UserProfile] = None
    token_claims: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    expired: bool = False
    revoked: bool = False


@dataclass
class UserSyncResult:
    """Result of user synchronization operation."""
    success: bool
    user_id: Optional[str] = None
    created: bool = False
    updated: bool = False
    sync_fields: Optional[List[str]] = None
    error_message: Optional[str] = None


class Auth0IntegrationError(Exception):
    """Base exception for Auth0 integration errors."""
    pass


class Auth0AuthenticationError(Auth0IntegrationError):
    """Exception raised when Auth0 authentication fails."""
    pass


class Auth0TokenValidationError(Auth0IntegrationError):
    """Exception raised when Auth0 token validation fails."""
    pass


class Auth0ManagementError(Auth0IntegrationError):
    """Exception raised when Auth0 Management API operations fail."""
    pass


class Auth0UserSyncError(Auth0IntegrationError):
    """Exception raised when user synchronization fails."""
    pass


class Auth0IntegrationService:
    """
    Comprehensive Auth0 identity provider integration service implementing
    enterprise-grade external authentication using Auth0 Python SDK 4.9.0.
    
    This service provides:
    - User authentication flows with Auth0 Universal Login
    - JWT token validation with Auth0 public key verification
    - User profile synchronization with Flask-SQLAlchemy models
    - Auth0 Management API integration for user lifecycle operations
    - Refresh token rotation policy with automated revocation
    - Security incident response capabilities
    """

    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize Auth0 integration service.
        
        Args:
            app: Flask application instance for configuration
        """
        self.app = app
        self.config = None
        self.auth0_domain = None
        self.client_id = None
        self.client_secret = None
        self.audience = None
        
        # Auth0 SDK clients
        self.get_token_client = None
        self.social_client = None
        self.users_client = None
        self.management_client = None
        
        # Token validation
        self.jwks_uri = None
        self.public_keys = {}
        self.algorithms = ['RS256']
        
        # Session and security
        self.security_monitor = None
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.token_cache_ttl = 300  # 5 minutes
        self.user_sync_fields = [
            'email', 'username', 'name', 'picture', 
            'email_verified', 'metadata', 'app_metadata'
        ]
        
        if app:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Initialize Auth0 integration with Flask application factory pattern.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Load configuration
        self._load_configuration(app)
        
        # Initialize Auth0 SDK clients
        self._initialize_auth0_clients()
        
        # Load public keys for token validation
        self._load_auth0_public_keys()
        
        # Initialize security monitoring
        self._initialize_monitoring(app)
        
        # Register error handlers
        self._register_error_handlers(app)
        
        # Cache management client token
        self._management_token_cache = {}
        
        app.logger.info(f"Auth0 Integration Service initialized for domain: {self.auth0_domain}")

    def _load_configuration(self, app: Flask) -> None:
        """Load Auth0 configuration from Flask application config."""
        required_configs = ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET']
        missing_configs = [config for config in required_configs if not app.config.get(config)]
        
        if missing_configs:
            raise Auth0IntegrationError(f"Missing required Auth0 configuration: {missing_configs}")
        
        self.config = Auth0Configuration(
            domain=app.config['AUTH0_DOMAIN'],
            client_id=app.config['AUTH0_CLIENT_ID'],
            client_secret=app.config['AUTH0_CLIENT_SECRET'],
            audience=app.config.get('AUTH0_AUDIENCE', f"https://{app.config['AUTH0_DOMAIN']}/api/v2/"),
            management_api_audience=app.config.get('AUTH0_MANAGEMENT_AUDIENCE'),
            callback_url=app.config.get('AUTH0_CALLBACK_URL'),
            logout_url=app.config.get('AUTH0_LOGOUT_URL'),
            connection=app.config.get('AUTH0_CONNECTION', 'Username-Password-Authentication'),
            scope=app.config.get('AUTH0_SCOPE', 'openid profile email')
        )
        
        # Set instance attributes for easy access
        self.auth0_domain = self.config.domain
        self.client_id = self.config.client_id
        self.client_secret = self.config.client_secret
        self.audience = self.config.audience
        self.jwks_uri = f"https://{self.auth0_domain}/.well-known/jwks.json"

    def _initialize_auth0_clients(self) -> None:
        """Initialize Auth0 SDK clients."""
        if not all([GetToken, Social, Users, Auth0]):
            self.logger.warning("Auth0 SDK not available, some features will be limited")
            return
        
        try:
            # Authentication clients
            self.get_token_client = GetToken(
                domain=self.auth0_domain,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
            
            self.social_client = Social(domain=self.auth0_domain)
            
            self.users_client = Users(domain=self.auth0_domain)
            
            self.logger.info("Auth0 SDK clients initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Auth0 SDK clients: {e}")
            raise Auth0IntegrationError(f"Auth0 SDK initialization failed: {e}")

    def _load_auth0_public_keys(self) -> None:
        """Load Auth0 public keys for JWT token validation."""
        if not self.jwks_uri:
            self.logger.warning("JWKS URI not configured, token validation will be limited")
            return
        
        try:
            # Configure retry strategy for JWKS endpoint
            session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS"]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("https://", adapter)
            
            # Fetch JWKS
            response = session.get(self.jwks_uri, timeout=30)
            response.raise_for_status()
            
            jwks = response.json()
            
            # Extract and store public keys
            for key in jwks.get('keys', []):
                kid = key.get('kid')
                if kid and key.get('kty') == 'RSA':
                    self.public_keys[kid] = key
            
            self.logger.info(f"Loaded {len(self.public_keys)} Auth0 public keys for token validation")
            
        except Exception as e:
            self.logger.error(f"Failed to load Auth0 public keys: {e}")
            # Continue without public keys - will use alternative validation

    def _initialize_monitoring(self, app: Flask) -> None:
        """Initialize security monitoring integration."""
        if SecurityMonitor:
            self.security_monitor = SecurityMonitor(app)
        else:
            self.logger.warning("SecurityMonitor not available, security logging will be limited")

    def _register_error_handlers(self, app: Flask) -> None:
        """Register Auth0-specific error handlers."""
        @app.errorhandler(Auth0IntegrationError)
        def handle_auth0_error(error):
            """Handle Auth0 integration errors."""
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_ERROR,
                    SecuritySeverity.ERROR,
                    "Auth0 integration error",
                    {'error': str(error), 'error_type': type(error).__name__}
                )
            
            self.logger.error(f"Auth0 integration error: {error}")
            return jsonify({'error': 'Authentication service error'}), 500

    def generate_authorization_url(
        self,
        state: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scope: Optional[str] = None,
        connection: Optional[str] = None
    ) -> str:
        """
        Generate Auth0 authorization URL for Universal Login.
        
        Args:
            state: Optional state parameter for CSRF protection
            redirect_uri: Optional callback URL override
            scope: Optional scope override
            connection: Optional connection override
            
        Returns:
            Auth0 authorization URL for user authentication
        """
        try:
            # Use provided values or defaults
            redirect_uri = redirect_uri or self.config.callback_url
            scope = scope or self.config.scope
            connection = connection or self.config.connection
            state = state or str(uuid.uuid4())
            
            # Store state in session for validation
            session['auth0_state'] = state
            
            # Build authorization URL
            auth_params = {
                'response_type': 'code',
                'client_id': self.client_id,
                'redirect_uri': redirect_uri,
                'scope': scope,
                'state': state
            }
            
            if connection:
                auth_params['connection'] = connection
            
            auth_url = f"https://{self.auth0_domain}/authorize?" + urlencode(auth_params)
            
            # Log authorization URL generation
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_AUTHORIZATION_STARTED,
                    SecuritySeverity.INFO,
                    "Auth0 authorization URL generated",
                    {
                        'state': state,
                        'scope': scope,
                        'connection': connection,
                        'redirect_uri': redirect_uri
                    }
                )
            
            return auth_url
            
        except Exception as e:
            self.logger.error(f"Failed to generate authorization URL: {e}")
            raise Auth0IntegrationError(f"Authorization URL generation failed: {e}")

    def handle_callback(
        self,
        code: str,
        state: str,
        redirect_uri: Optional[str] = None
    ) -> AuthenticationResult:
        """
        Handle Auth0 callback and exchange authorization code for tokens.
        
        Args:
            code: Authorization code from Auth0 callback
            state: State parameter for CSRF validation
            redirect_uri: Callback URL used in authorization request
            
        Returns:
            AuthenticationResult with user profile and tokens
        """
        try:
            # Validate state parameter
            session_state = session.get('auth0_state')
            if not session_state or not safe_str_cmp(session_state, state):
                raise Auth0AuthenticationError("Invalid state parameter - possible CSRF attack")
            
            # Clear state from session
            session.pop('auth0_state', None)
            
            # Exchange code for tokens
            redirect_uri = redirect_uri or self.config.callback_url
            
            if not self.get_token_client:
                raise Auth0AuthenticationError("Auth0 GetToken client not initialized")
            
            token_response = self.get_token_client.authorization_code(
                code=code,
                redirect_uri=redirect_uri
            )
            
            if 'error' in token_response:
                error_msg = f"{token_response.get('error')}: {token_response.get('error_description', '')}"
                raise Auth0AuthenticationError(f"Token exchange failed: {error_msg}")
            
            # Extract tokens
            access_token = token_response.get('access_token')
            refresh_token = token_response.get('refresh_token')
            id_token = token_response.get('id_token')
            expires_in = token_response.get('expires_in')
            token_type = token_response.get('token_type', 'Bearer')
            
            # Validate and decode ID token to get user profile
            user_profile = None
            if id_token:
                try:
                    user_profile = self._decode_id_token(id_token)
                except Exception as e:
                    self.logger.warning(f"Failed to decode ID token: {e}")
            
            # If no user profile from ID token, try to get from userinfo endpoint
            if not user_profile and access_token:
                try:
                    user_profile = self._get_user_info(access_token)
                except Exception as e:
                    self.logger.warning(f"Failed to get user info: {e}")
            
            if not user_profile:
                raise Auth0AuthenticationError("Failed to obtain user profile")
            
            # Log successful authentication
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_AUTHENTICATION_SUCCESS,
                    SecuritySeverity.INFO,
                    "Auth0 authentication successful",
                    {
                        'user_id': user_profile.user_id,
                        'email': user_profile.email,
                        'auth0_sub': user_profile.auth0_sub,
                        'has_refresh_token': bool(refresh_token)
                    }
                )
            
            return AuthenticationResult(
                success=True,
                user_profile=user_profile,
                access_token=access_token,
                refresh_token=refresh_token,
                id_token=id_token,
                expires_in=expires_in,
                token_type=token_type
            )
            
        except Auth0AuthenticationError:
            raise
        except Exception as e:
            self.logger.error(f"Auth0 callback handling failed: {e}")
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_AUTHENTICATION_FAILED,
                    SecuritySeverity.ERROR,
                    "Auth0 callback handling failed",
                    {'error': str(e), 'state': state}
                )
            raise Auth0AuthenticationError(f"Callback handling failed: {e}")

    def validate_token(
        self,
        token: str,
        audience: Optional[str] = None,
        issuer: Optional[str] = None
    ) -> TokenValidationResult:
        """
        Validate JWT token using Auth0 public keys.
        
        Args:
            token: JWT token to validate
            audience: Expected audience (defaults to configured audience)
            issuer: Expected issuer (defaults to Auth0 domain)
            
        Returns:
            TokenValidationResult with validation status and claims
        """
        try:
            # Set defaults
            audience = audience or self.audience
            issuer = issuer or f"https://{self.auth0_domain}/"
            
            # Decode header to get key ID
            try:
                unverified_header = jwt.get_unverified_header(token)
            except jwt.InvalidTokenError as e:
                return TokenValidationResult(
                    valid=False,
                    error_message=f"Invalid token header: {e}"
                )
            
            kid = unverified_header.get('kid')
            alg = unverified_header.get('alg')
            
            if not kid:
                return TokenValidationResult(
                    valid=False,
                    error_message="Token missing key ID (kid)"
                )
            
            if alg not in self.algorithms:
                return TokenValidationResult(
                    valid=False,
                    error_message=f"Unsupported algorithm: {alg}"
                )
            
            # Get public key
            if kid not in self.public_keys:
                # Try to refresh public keys
                self._load_auth0_public_keys()
                
                if kid not in self.public_keys:
                    return TokenValidationResult(
                        valid=False,
                        error_message=f"Public key not found for kid: {kid}"
                    )
            
            public_key = self._jwk_to_pem(self.public_keys[kid])
            
            # Validate token
            try:
                token_claims = jwt.decode(
                    token,
                    public_key,
                    algorithms=[alg],
                    audience=audience,
                    issuer=issuer,
                    options={
                        'verify_signature': True,
                        'verify_exp': True,
                        'verify_nbf': True,
                        'verify_iat': True,
                        'verify_aud': True,
                        'verify_iss': True
                    }
                )
                
                # Extract user profile from token claims
                user_profile = self._extract_user_profile_from_claims(token_claims)
                
                # Log successful validation
                if self.security_monitor:
                    self.security_monitor.log_security_event(
                        SecurityEventType.AUTH0_TOKEN_VALIDATED,
                        SecuritySeverity.INFO,
                        "Auth0 token validation successful",
                        {
                            'user_id': user_profile.user_id if user_profile else 'unknown',
                            'aud': token_claims.get('aud'),
                            'iss': token_claims.get('iss'),
                            'exp': token_claims.get('exp')
                        }
                    )
                
                return TokenValidationResult(
                    valid=True,
                    user_profile=user_profile,
                    token_claims=token_claims
                )
                
            except jwt.ExpiredSignatureError:
                return TokenValidationResult(
                    valid=False,
                    expired=True,
                    error_message="Token has expired"
                )
            except jwt.InvalidAudienceError:
                return TokenValidationResult(
                    valid=False,
                    error_message=f"Invalid audience. Expected: {audience}"
                )
            except jwt.InvalidIssuerError:
                return TokenValidationResult(
                    valid=False,
                    error_message=f"Invalid issuer. Expected: {issuer}"
                )
            except jwt.InvalidTokenError as e:
                return TokenValidationResult(
                    valid=False,
                    error_message=f"Token validation failed: {e}"
                )
            
        except Exception as e:
            self.logger.error(f"Token validation error: {e}")
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_TOKEN_VALIDATION_ERROR,
                    SecuritySeverity.ERROR,
                    "Auth0 token validation error",
                    {'error': str(e)}
                )
            
            return TokenValidationResult(
                valid=False,
                error_message=f"Validation error: {e}"
            )

    def refresh_access_token(self, refresh_token: str) -> AuthenticationResult:
        """
        Refresh access token using refresh token with rotation policy.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            AuthenticationResult with new tokens
        """
        try:
            if not self.get_token_client:
                raise Auth0AuthenticationError("Auth0 GetToken client not initialized")
            
            # Use refresh token to get new access token
            token_response = self.get_token_client.refresh_token(refresh_token)
            
            if 'error' in token_response:
                error_msg = f"{token_response.get('error')}: {token_response.get('error_description', '')}"
                raise Auth0AuthenticationError(f"Token refresh failed: {error_msg}")
            
            # Extract new tokens
            access_token = token_response.get('access_token')
            new_refresh_token = token_response.get('refresh_token')  # May be rotated
            id_token = token_response.get('id_token')
            expires_in = token_response.get('expires_in')
            token_type = token_response.get('token_type', 'Bearer')
            
            # Get user profile from new tokens
            user_profile = None
            if id_token:
                try:
                    user_profile = self._decode_id_token(id_token)
                except Exception as e:
                    self.logger.warning(f"Failed to decode refreshed ID token: {e}")
            
            if not user_profile and access_token:
                try:
                    user_profile = self._get_user_info(access_token)
                except Exception as e:
                    self.logger.warning(f"Failed to get user info from refreshed token: {e}")
            
            # Log successful refresh
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_TOKEN_REFRESHED,
                    SecuritySeverity.INFO,
                    "Auth0 token refresh successful",
                    {
                        'user_id': user_profile.user_id if user_profile else 'unknown',
                        'token_rotated': bool(new_refresh_token and new_refresh_token != refresh_token),
                        'has_id_token': bool(id_token)
                    }
                )
            
            return AuthenticationResult(
                success=True,
                user_profile=user_profile,
                access_token=access_token,
                refresh_token=new_refresh_token or refresh_token,  # Use new if rotated
                id_token=id_token,
                expires_in=expires_in,
                token_type=token_type
            )
            
        except Auth0AuthenticationError:
            raise
        except Exception as e:
            self.logger.error(f"Token refresh failed: {e}")
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_TOKEN_REFRESH_FAILED,
                    SecuritySeverity.ERROR,
                    "Auth0 token refresh failed",
                    {'error': str(e)}
                )
            raise Auth0AuthenticationError(f"Token refresh failed: {e}")

    def revoke_refresh_token(
        self,
        refresh_token: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None
    ) -> bool:
        """
        Revoke refresh token for security incident response.
        
        Args:
            refresh_token: Refresh token to revoke
            client_id: Optional client ID override
            client_secret: Optional client secret override
            
        Returns:
            True if revocation was successful
        """
        try:
            client_id = client_id or self.client_id
            client_secret = client_secret or self.client_secret
            
            # Prepare revocation request
            revoke_url = f"https://{self.auth0_domain}/oauth/revoke"
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'token': refresh_token,
                'token_type_hint': 'refresh_token'
            }
            
            # Make revocation request
            response = requests.post(
                revoke_url,
                headers=headers,
                data=data,
                timeout=30
            )
            
            if response.status_code == 200:
                # Log successful revocation
                if self.security_monitor:
                    self.security_monitor.log_security_event(
                        SecurityEventType.AUTH0_TOKEN_REVOKED,
                        SecuritySeverity.INFO,
                        "Auth0 refresh token revoked",
                        {'revocation_successful': True}
                    )
                
                return True
            else:
                self.logger.warning(f"Token revocation failed with status {response.status_code}: {response.text}")
                return False
            
        except Exception as e:
            self.logger.error(f"Token revocation error: {e}")
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_TOKEN_REVOCATION_FAILED,
                    SecuritySeverity.ERROR,
                    "Auth0 token revocation failed",
                    {'error': str(e)}
                )
            return False

    def synchronize_user_profile(
        self,
        auth0_user_profile: Auth0UserProfile,
        create_if_missing: bool = True
    ) -> UserSyncResult:
        """
        Synchronize Auth0 user profile with Flask-SQLAlchemy User model.
        
        Args:
            auth0_user_profile: Auth0 user profile data
            create_if_missing: Whether to create user if not found
            
        Returns:
            UserSyncResult with synchronization details
        """
        try:
            if not User:
                raise Auth0UserSyncError("User model not available")
            
            from flask import current_app
            from ..models import db
            
            # Find existing user by Auth0 sub or email
            existing_user = None
            
            # Try to find by Auth0 sub first
            if auth0_user_profile.auth0_sub:
                existing_user = User.query.filter_by(auth0_sub=auth0_user_profile.auth0_sub).first()
            
            # If not found by sub, try by email
            if not existing_user and auth0_user_profile.email:
                existing_user = User.query.filter_by(email=auth0_user_profile.email).first()
            
            user_created = False
            user_updated = False
            sync_fields = []
            
            if existing_user:
                # Update existing user
                sync_fields = self._sync_user_fields(existing_user, auth0_user_profile)
                if sync_fields:
                    user_updated = True
                    db.session.commit()
                
                user_id = str(existing_user.id)
                
            elif create_if_missing:
                # Create new user
                new_user = User(
                    username=auth0_user_profile.username or auth0_user_profile.email.split('@')[0],
                    email=auth0_user_profile.email,
                    auth0_sub=auth0_user_profile.auth0_sub,
                    email_verified=auth0_user_profile.email_verified,
                    name=auth0_user_profile.name,
                    picture=auth0_user_profile.picture
                )
                
                # Set metadata if available
                if auth0_user_profile.metadata:
                    new_user.user_metadata = auth0_user_profile.metadata
                if auth0_user_profile.app_metadata:
                    new_user.app_metadata = auth0_user_profile.app_metadata
                
                db.session.add(new_user)
                db.session.commit()
                
                user_created = True
                user_id = str(new_user.id)
                sync_fields = self.user_sync_fields
                
            else:
                raise Auth0UserSyncError("User not found and creation not allowed")
            
            # Log successful sync
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_USER_SYNC,
                    SecuritySeverity.INFO,
                    "Auth0 user profile synchronized",
                    {
                        'user_id': user_id,
                        'auth0_sub': auth0_user_profile.auth0_sub,
                        'email': auth0_user_profile.email,
                        'created': user_created,
                        'updated': user_updated,
                        'sync_fields': sync_fields
                    }
                )
            
            return UserSyncResult(
                success=True,
                user_id=user_id,
                created=user_created,
                updated=user_updated,
                sync_fields=sync_fields
            )
            
        except Exception as e:
            self.logger.error(f"User synchronization failed: {e}")
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_USER_SYNC_FAILED,
                    SecuritySeverity.ERROR,
                    "Auth0 user synchronization failed",
                    {
                        'error': str(e),
                        'auth0_sub': auth0_user_profile.auth0_sub,
                        'email': auth0_user_profile.email
                    }
                )
            
            return UserSyncResult(
                success=False,
                error_message=str(e)
            )

    def get_management_client(self) -> Optional[Auth0]:
        """
        Get Auth0 Management API client with cached token.
        
        Returns:
            Auth0 Management API client or None if not available
        """
        try:
            if not Auth0:
                return None
            
            # Check if we have a valid cached token
            current_time = time.time()
            cached_token = self._management_token_cache.get('token')
            token_expires_at = self._management_token_cache.get('expires_at', 0)
            
            if cached_token and current_time < token_expires_at - 60:  # 60 second buffer
                # Use cached token
                return Auth0(domain=self.auth0_domain, token=cached_token)
            
            # Get new management token
            if not self.get_token_client:
                return None
            
            management_audience = self.config.management_api_audience or f"https://{self.auth0_domain}/api/v2/"
            
            token_response = self.get_token_client.client_credentials(
                audience=management_audience
            )
            
            if 'error' in token_response:
                self.logger.error(f"Management token request failed: {token_response}")
                return None
            
            access_token = token_response.get('access_token')
            expires_in = token_response.get('expires_in', 3600)
            
            # Cache the token
            self._management_token_cache = {
                'token': access_token,
                'expires_at': current_time + expires_in
            }
            
            return Auth0(domain=self.auth0_domain, token=access_token)
            
        except Exception as e:
            self.logger.error(f"Failed to get Management API client: {e}")
            return None

    def get_user_by_auth0_id(self, auth0_user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user information from Auth0 Management API.
        
        Args:
            auth0_user_id: Auth0 user ID (sub claim)
            
        Returns:
            User information dictionary or None if not found
        """
        try:
            management_client = self.get_management_client()
            if not management_client:
                return None
            
            user_info = management_client.users.get(auth0_user_id)
            return user_info
            
        except Exception as e:
            self.logger.error(f"Failed to get user from Auth0: {e}")
            return None

    def update_user_metadata(
        self,
        auth0_user_id: str,
        user_metadata: Optional[Dict[str, Any]] = None,
        app_metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Update user metadata in Auth0.
        
        Args:
            auth0_user_id: Auth0 user ID
            user_metadata: User metadata to update
            app_metadata: App metadata to update
            
        Returns:
            True if update was successful
        """
        try:
            management_client = self.get_management_client()
            if not management_client:
                return False
            
            update_data = {}
            if user_metadata is not None:
                update_data['user_metadata'] = user_metadata
            if app_metadata is not None:
                update_data['app_metadata'] = app_metadata
            
            if not update_data:
                return True  # Nothing to update
            
            management_client.users.update(auth0_user_id, update_data)
            
            # Log successful update
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_USER_METADATA_UPDATED,
                    SecuritySeverity.INFO,
                    "Auth0 user metadata updated",
                    {
                        'auth0_user_id': auth0_user_id,
                        'has_user_metadata': bool(user_metadata),
                        'has_app_metadata': bool(app_metadata)
                    }
                )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update user metadata: {e}")
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_USER_METADATA_UPDATE_FAILED,
                    SecuritySeverity.ERROR,
                    "Auth0 user metadata update failed",
                    {'error': str(e), 'auth0_user_id': auth0_user_id}
                )
            return False

    def block_user(self, auth0_user_id: str, reason: str = "Security incident") -> bool:
        """
        Block user in Auth0 for security incident response.
        
        Args:
            auth0_user_id: Auth0 user ID to block
            reason: Reason for blocking
            
        Returns:
            True if user was successfully blocked
        """
        try:
            management_client = self.get_management_client()
            if not management_client:
                return False
            
            management_client.users.update(auth0_user_id, {'blocked': True})
            
            # Log user blocking
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_USER_BLOCKED,
                    SecuritySeverity.WARNING,
                    "Auth0 user blocked for security incident",
                    {
                        'auth0_user_id': auth0_user_id,
                        'reason': reason,
                        'blocked_at': datetime.utcnow().isoformat()
                    }
                )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to block user {auth0_user_id}: {e}")
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.AUTH0_USER_BLOCK_FAILED,
                    SecuritySeverity.ERROR,
                    "Auth0 user blocking failed",
                    {'error': str(e), 'auth0_user_id': auth0_user_id}
                )
            return False

    def generate_logout_url(self, return_to: Optional[str] = None) -> str:
        """
        Generate Auth0 logout URL.
        
        Args:
            return_to: Optional URL to redirect to after logout
            
        Returns:
            Auth0 logout URL
        """
        try:
            logout_params = {
                'client_id': self.client_id
            }
            
            if return_to:
                logout_params['returnTo'] = return_to
            elif self.config.logout_url:
                logout_params['returnTo'] = self.config.logout_url
            
            logout_url = f"https://{self.auth0_domain}/v2/logout?" + urlencode(logout_params)
            
            return logout_url
            
        except Exception as e:
            self.logger.error(f"Failed to generate logout URL: {e}")
            raise Auth0IntegrationError(f"Logout URL generation failed: {e}")

    def _decode_id_token(self, id_token: str) -> Auth0UserProfile:
        """Decode ID token and extract user profile."""
        try:
            # Validate ID token
            validation_result = self.validate_token(id_token)
            
            if not validation_result.valid:
                raise Auth0TokenValidationError(f"ID token validation failed: {validation_result.error_message}")
            
            return validation_result.user_profile
            
        except Exception as e:
            raise Auth0TokenValidationError(f"ID token decoding failed: {e}")

    def _get_user_info(self, access_token: str) -> Auth0UserProfile:
        """Get user information from Auth0 userinfo endpoint."""
        try:
            userinfo_url = f"https://{self.auth0_domain}/userinfo"
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(userinfo_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            user_data = response.json()
            
            return Auth0UserProfile(
                user_id=user_data.get('sub', ''),
                email=user_data.get('email', ''),
                username=user_data.get('preferred_username') or user_data.get('nickname'),
                name=user_data.get('name'),
                picture=user_data.get('picture'),
                email_verified=user_data.get('email_verified', False),
                auth0_sub=user_data.get('sub'),
                metadata=user_data.get('user_metadata'),
                app_metadata=user_data.get('app_metadata'),
                created_at=user_data.get('created_at'),
                updated_at=user_data.get('updated_at')
            )
            
        except Exception as e:
            raise Auth0IntegrationError(f"Failed to get user info: {e}")

    def _extract_user_profile_from_claims(self, token_claims: Dict[str, Any]) -> Auth0UserProfile:
        """Extract user profile from JWT token claims."""
        return Auth0UserProfile(
            user_id=token_claims.get('sub', ''),
            email=token_claims.get('email', ''),
            username=token_claims.get('preferred_username') or token_claims.get('nickname'),
            name=token_claims.get('name'),
            picture=token_claims.get('picture'),
            email_verified=token_claims.get('email_verified', False),
            auth0_sub=token_claims.get('sub'),
            metadata=token_claims.get('user_metadata'),
            app_metadata=token_claims.get('app_metadata'),
            roles=token_claims.get('roles', []),
            permissions=token_claims.get('permissions', [])
        )

    def _sync_user_fields(self, user: User, auth0_profile: Auth0UserProfile) -> List[str]:
        """Synchronize user fields with Auth0 profile data."""
        updated_fields = []
        
        # Email
        if auth0_profile.email and user.email != auth0_profile.email:
            user.email = auth0_profile.email
            updated_fields.append('email')
        
        # Username
        if auth0_profile.username and user.username != auth0_profile.username:
            user.username = auth0_profile.username
            updated_fields.append('username')
        
        # Name
        if auth0_profile.name and getattr(user, 'name', None) != auth0_profile.name:
            user.name = auth0_profile.name
            updated_fields.append('name')
        
        # Picture
        if auth0_profile.picture and getattr(user, 'picture', None) != auth0_profile.picture:
            user.picture = auth0_profile.picture
            updated_fields.append('picture')
        
        # Email verified
        if hasattr(user, 'email_verified') and user.email_verified != auth0_profile.email_verified:
            user.email_verified = auth0_profile.email_verified
            updated_fields.append('email_verified')
        
        # Auth0 sub
        if auth0_profile.auth0_sub and getattr(user, 'auth0_sub', None) != auth0_profile.auth0_sub:
            user.auth0_sub = auth0_profile.auth0_sub
            updated_fields.append('auth0_sub')
        
        # Metadata
        if auth0_profile.metadata and getattr(user, 'user_metadata', None) != auth0_profile.metadata:
            user.user_metadata = auth0_profile.metadata
            updated_fields.append('user_metadata')
        
        if auth0_profile.app_metadata and getattr(user, 'app_metadata', None) != auth0_profile.app_metadata:
            user.app_metadata = auth0_profile.app_metadata
            updated_fields.append('app_metadata')
        
        # Update timestamp
        if updated_fields:
            user.updated_at = datetime.utcnow()
        
        return updated_fields

    def _jwk_to_pem(self, jwk: Dict[str, str]) -> bytes:
        """Convert JSON Web Key to PEM format."""
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives import serialization
            import base64
            
            # Decode RSA components
            def base64_url_decode(data):
                # Add padding if necessary
                padding = 4 - (len(data) % 4)
                if padding != 4:
                    data += '=' * padding
                return base64.urlsafe_b64decode(data)
            
            n = int.from_bytes(base64_url_decode(jwk['n']), byteorder='big')
            e = int.from_bytes(base64_url_decode(jwk['e']), byteorder='big')
            
            # Create RSA public key
            public_numbers = RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key()
            
            # Serialize to PEM format
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return pem
            
        except Exception as e:
            raise Auth0TokenValidationError(f"JWK to PEM conversion failed: {e}")

    @lru_cache(maxsize=128)
    def _get_cached_public_key(self, kid: str) -> Optional[bytes]:
        """Get cached public key for performance optimization."""
        if kid in self.public_keys:
            return self._jwk_to_pem(self.public_keys[kid])
        return None


# Authentication decorator for Auth0 integration
def auth0_required(
    auth0_service: Auth0IntegrationService,
    optional: bool = False,
    scopes: Optional[List[str]] = None
):
    """
    Create Auth0 authentication decorator.
    
    Args:
        auth0_service: Auth0 integration service instance
        optional: Whether authentication is optional
        scopes: Required scopes for the endpoint
        
    Returns:
        Decorator function for Auth0 authentication
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get token from Authorization header
                auth_header = request.headers.get('Authorization')
                if not auth_header:
                    if optional:
                        return f(*args, **kwargs)
                    return jsonify({'error': 'Authorization header required'}), 401
                
                # Extract token
                try:
                    scheme, token = auth_header.split(' ', 1)
                    if scheme.lower() != 'bearer':
                        raise ValueError("Invalid authorization scheme")
                except ValueError:
                    if optional:
                        return f(*args, **kwargs)
                    return jsonify({'error': 'Invalid authorization header format'}), 401
                
                # Validate token
                validation_result = auth0_service.validate_token(token)
                
                if not validation_result.valid:
                    if optional:
                        return f(*args, **kwargs)
                    
                    if validation_result.expired:
                        return jsonify({'error': 'Token expired'}), 401
                    else:
                        return jsonify({'error': 'Invalid token'}), 401
                
                # Check scopes if required
                if scopes:
                    token_scopes = validation_result.token_claims.get('scope', '').split()
                    if not all(scope in token_scopes for scope in scopes):
                        return jsonify({'error': 'Insufficient scope'}), 403
                
                # Store user profile in Flask g for access in route
                g.auth0_user = validation_result.user_profile
                g.auth0_token_claims = validation_result.token_claims
                
                return f(*args, **kwargs)
                
            except Exception as e:
                auth0_service.logger.error(f"Auth0 authentication error: {e}")
                if optional:
                    return f(*args, **kwargs)
                return jsonify({'error': 'Authentication failed'}), 401
        
        return decorated_function
    return decorator


# Module-level instance for Flask application factory integration
auth0_service = Auth0IntegrationService()


def init_auth0_integration(app: Flask) -> Auth0IntegrationService:
    """
    Initialize Auth0 Integration Service with Flask application factory pattern.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured Auth0IntegrationService instance
    """
    auth0_service.init_app(app)
    return auth0_service


# Export public interface
__all__ = [
    'Auth0IntegrationService',
    'Auth0Configuration',
    'Auth0UserProfile',
    'AuthenticationResult',
    'TokenValidationResult',
    'UserSyncResult',
    'Auth0IntegrationError',
    'Auth0AuthenticationError',
    'Auth0TokenValidationError',
    'Auth0ManagementError',
    'Auth0UserSyncError',
    'auth0_required',
    'init_auth0_integration',
    'auth0_service'
]