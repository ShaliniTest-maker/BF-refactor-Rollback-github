"""
JWT Token Management Service

This module implements comprehensive JWT token lifecycle management using Flask-JWT-Extended
and Auth0 integration. Provides token generation, validation, refresh, and revocation
capabilities while maintaining local JWT processing to reduce external dependencies.

Key Features:
- Flask-JWT-Extended integration for local JWT management
- Auth0 refresh token rotation policy implementation
- Token revocation flows with immediate invalidation
- Security incident response token management
- Automated token rotation for enhanced security

Dependencies:
- Flask-JWT-Extended 4.7.1 for comprehensive JWT handling
- Auth0 Python SDK for identity provider integration
- Redis/In-memory store for token blacklist management
- Integration with security monitoring and Auth0 services

Architectural Pattern:
Implements the Service Layer pattern for token management operations,
providing clean abstraction between presentation layer (Flask blueprints)
and token processing logic while maintaining Flask application context.
"""

import os
import json
import time
import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Union, Tuple, Any
from dataclasses import dataclass, asdict
from functools import wraps

import jwt
import redis
from flask import Flask, current_app, g, request
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    decode_token, get_jwt, get_jwt_identity, verify_jwt_in_request,
    jwt_required, get_current_user
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Import application components
try:
    from ..models.user import User
    from ..models.session import UserSession
    from .security_monitor import SecurityMonitor, SecurityEventType, SecuritySeverity
    from .auth0_integration import Auth0IntegrationService
except ImportError:
    # Handle imports during testing or standalone execution
    User = None
    UserSession = None
    SecurityMonitor = None
    SecurityEventType = None
    SecuritySeverity = None
    Auth0IntegrationService = None


@dataclass
class TokenClaims:
    """JWT token claims structure for consistent token generation."""
    user_id: str
    username: str
    email: str
    roles: List[str]
    permissions: List[str]
    session_id: str
    issued_at: int
    expires_at: int
    token_type: str  # 'access' or 'refresh'
    auth0_sub: Optional[str] = None
    custom_claims: Optional[Dict[str, Any]] = None


@dataclass
class TokenPair:
    """Token pair containing access and refresh tokens with metadata."""
    access_token: str
    refresh_token: str
    access_expires_at: int
    refresh_expires_at: int
    token_type: str = "Bearer"
    scope: Optional[str] = None


@dataclass
class TokenRevocationResult:
    """Result of token revocation operation."""
    success: bool
    revoked_count: int
    error_message: Optional[str] = None
    revoked_tokens: Optional[List[str]] = None


class TokenValidationError(Exception):
    """Exception raised when token validation fails."""
    pass


class TokenRevocationError(Exception):
    """Exception raised when token revocation fails."""
    pass


class JWTTokenHandler:
    """
    Comprehensive JWT token management service implementing Flask-JWT-Extended
    integration with Auth0 identity provider for enterprise-grade token lifecycle management.
    
    This service provides:
    - Local JWT processing with reduced external dependencies
    - Auth0 refresh token rotation policy integration
    - Token revocation flows with immediate invalidation
    - Security incident response token management
    - Automated token rotation for enhanced security
    """

    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize JWT token handler with Flask application.
        
        Args:
            app: Flask application instance for configuration
        """
        self.app = app
        self.jwt_manager = None
        self.redis_client = None
        self.auth0_service = None
        self.security_monitor = None
        self.logger = logging.getLogger(__name__)
        
        # Token configuration
        self.access_token_expires = timedelta(hours=1)
        self.refresh_token_expires = timedelta(days=7)
        self.token_blacklist_prefix = "blacklist_token:"
        self.token_family_prefix = "token_family:"
        
        # Auth0 configuration
        self.auth0_domain = None
        self.auth0_algorithms = ['RS256']
        self.auth0_audience = None
        self.auth0_jwks_uri = None
        self.auth0_public_keys = {}
        
        if app:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Initialize JWT token handler with Flask application factory pattern.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Configure Flask-JWT-Extended
        self._configure_jwt_extended(app)
        
        # Initialize Redis for token blacklist
        self._initialize_redis(app)
        
        # Configure Auth0 integration
        self._configure_auth0(app)
        
        # Initialize monitoring and logging
        self._initialize_monitoring(app)
        
        # Register JWT error handlers
        self._register_jwt_handlers()
        
        # Load Auth0 public keys
        self._load_auth0_public_keys()
        
        app.logger.info("JWT Token Handler initialized with Flask-JWT-Extended 4.7.1")

    def _configure_jwt_extended(self, app: Flask) -> None:
        """Configure Flask-JWT-Extended with security settings."""
        # JWT configuration
        app.config.setdefault('JWT_SECRET_KEY', os.environ.get('JWT_SECRET_KEY'))
        app.config.setdefault('JWT_ACCESS_TOKEN_EXPIRES', self.access_token_expires)
        app.config.setdefault('JWT_REFRESH_TOKEN_EXPIRES', self.refresh_token_expires)
        app.config.setdefault('JWT_ALGORITHM', 'HS256')
        app.config.setdefault('JWT_DECODE_ALGORITHMS', ['HS256', 'RS256'])
        
        # Security settings
        app.config.setdefault('JWT_BLACKLIST_ENABLED', True)
        app.config.setdefault('JWT_BLACKLIST_TOKEN_CHECKS', ['access', 'refresh'])
        app.config.setdefault('JWT_ERROR_MESSAGE_KEY', 'message')
        app.config.setdefault('JWT_JSON_KEY', 'access_token')
        app.config.setdefault('JWT_REFRESH_JSON_KEY', 'refresh_token')
        
        # Initialize JWT Manager
        self.jwt_manager = JWTManager(app)

    def _initialize_redis(self, app: Flask) -> None:
        """Initialize Redis client for token blacklist management."""
        try:
            redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
            self.redis_client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_keepalive=True,
                socket_keepalive_options={},
                retry_on_timeout=True,
                health_check_interval=30
            )
            
            # Test Redis connection
            self.redis_client.ping()
            app.logger.info("Redis connection established for token blacklist management")
            
        except (redis.ConnectionError, redis.TimeoutError) as e:
            app.logger.warning(f"Redis connection failed, using in-memory blacklist: {e}")
            # Fallback to in-memory blacklist (not recommended for production)
            self.redis_client = None
            self._blacklist_cache = set()

    def _configure_auth0(self, app: Flask) -> None:
        """Configure Auth0 integration settings."""
        self.auth0_domain = app.config.get('AUTH0_DOMAIN')
        self.auth0_audience = app.config.get('AUTH0_AUDIENCE')
        self.auth0_jwks_uri = f"https://{self.auth0_domain}/.well-known/jwks.json"
        
        if not self.auth0_domain:
            app.logger.warning("AUTH0_DOMAIN not configured, Auth0 features will be limited")

    def _initialize_monitoring(self, app: Flask) -> None:
        """Initialize security monitoring integration."""
        if SecurityMonitor:
            self.security_monitor = SecurityMonitor(app)
        else:
            app.logger.warning("SecurityMonitor not available, security logging will be limited")

    def _register_jwt_handlers(self) -> None:
        """Register JWT error handlers and callbacks."""
        if not self.jwt_manager:
            return

        @self.jwt_manager.token_in_blocklist_loader
        def check_if_token_revoked(jwt_header, jwt_payload):
            """Check if token is in blocklist/blacklist."""
            jti = jwt_payload.get('jti')
            if not jti:
                return False
            
            return self.is_token_revoked(jti)

        @self.jwt_manager.user_identity_loader
        def user_identity_lookup(user):
            """Load user identity for JWT token generation."""
            if hasattr(user, 'id'):
                return str(user.id)
            return str(user)

        @self.jwt_manager.user_lookup_loader
        def user_lookup_callback(_jwt_header, jwt_data):
            """Load user object from JWT token data."""
            identity = jwt_data["sub"]
            if User:
                return User.query.filter_by(id=identity).one_or_none()
            return None

        @self.jwt_manager.expired_token_loader
        def expired_token_callback(jwt_header, jwt_payload):
            """Handle expired token errors."""
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.TOKEN_EXPIRED,
                    SecuritySeverity.INFO,
                    "Expired JWT token accessed",
                    {"jti": jwt_payload.get("jti"), "user_id": jwt_payload.get("sub")}
                )
            
            return {"message": "Token has expired"}, 401

        @self.jwt_manager.invalid_token_loader
        def invalid_token_callback(error):
            """Handle invalid token errors."""
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.INVALID_TOKEN,
                    SecuritySeverity.WARNING,
                    "Invalid JWT token provided",
                    {"error": str(error), "request_path": request.path}
                )
            
            return {"message": "Invalid token"}, 401

        @self.jwt_manager.revoked_token_loader
        def revoked_token_callback(jwt_header, jwt_payload):
            """Handle revoked token access attempts."""
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.REVOKED_TOKEN_ACCESS,
                    SecuritySeverity.WARNING,
                    "Revoked JWT token access attempted",
                    {"jti": jwt_payload.get("jti"), "user_id": jwt_payload.get("sub")}
                )
            
            return {"message": "Token has been revoked"}, 401

    def _load_auth0_public_keys(self) -> None:
        """Load Auth0 public keys for JWT verification."""
        if not self.auth0_jwks_uri:
            return

        try:
            # Configure retry strategy for JWKS endpoint
            session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("https://", adapter)
            
            response = session.get(self.auth0_jwks_uri, timeout=10)
            response.raise_for_status()
            
            jwks = response.json()
            
            # Extract public keys
            for key in jwks.get('keys', []):
                kid = key.get('kid')
                if kid and key.get('kty') == 'RSA':
                    self.auth0_public_keys[kid] = key
            
            self.logger.info(f"Loaded {len(self.auth0_public_keys)} Auth0 public keys")
            
        except Exception as e:
            self.logger.error(f"Failed to load Auth0 public keys: {e}")

    def generate_token_pair(
        self,
        user: Union[User, Dict[str, Any]],
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> TokenPair:
        """
        Generate access and refresh token pair for user authentication.
        
        Args:
            user: User object or dictionary with user information
            additional_claims: Additional claims to include in tokens
            
        Returns:
            TokenPair containing access and refresh tokens with metadata
        """
        try:
            # Extract user information
            if hasattr(user, 'id'):
                user_id = str(user.id)
                username = getattr(user, 'username', '')
                email = getattr(user, 'email', '')
                roles = getattr(user, 'roles', [])
            else:
                user_id = str(user.get('id', ''))
                username = user.get('username', '')
                email = user.get('email', '')
                roles = user.get('roles', [])

            # Generate session ID for token family
            session_id = str(uuid.uuid4())
            current_time = int(time.time())
            
            # Prepare base claims
            base_claims = {
                'user_id': user_id,
                'username': username,
                'email': email,
                'roles': roles,
                'session_id': session_id,
                'iat': current_time,
                'iss': f"https://{self.auth0_domain}" if self.auth0_domain else "flask-app",
                'aud': self.auth0_audience or "flask-app"
            }
            
            # Add additional claims
            if additional_claims:
                base_claims.update(additional_claims)
            
            # Generate access token
            access_expires = self.access_token_expires
            access_claims = base_claims.copy()
            access_claims.update({
                'token_type': 'access',
                'exp': current_time + int(access_expires.total_seconds())
            })
            
            access_token = create_access_token(
                identity=user_id,
                additional_claims=access_claims,
                expires_delta=access_expires
            )
            
            # Generate refresh token
            refresh_expires = self.refresh_token_expires
            refresh_claims = base_claims.copy()
            refresh_claims.update({
                'token_type': 'refresh',
                'exp': current_time + int(refresh_expires.total_seconds())
            })
            
            refresh_token = create_refresh_token(
                identity=user_id,
                additional_claims=refresh_claims,
                expires_delta=refresh_expires
            )
            
            # Store token family information
            self._store_token_family(session_id, {
                'user_id': user_id,
                'created_at': current_time,
                'access_token_jti': self._extract_jti(access_token),
                'refresh_token_jti': self._extract_jti(refresh_token),
                'rotation_count': 0
            })
            
            # Log token generation
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.TOKEN_GENERATED,
                    SecuritySeverity.INFO,
                    "JWT token pair generated",
                    {
                        'user_id': user_id,
                        'session_id': session_id,
                        'access_expires_at': access_claims['exp'],
                        'refresh_expires_at': refresh_claims['exp']
                    }
                )
            
            return TokenPair(
                access_token=access_token,
                refresh_token=refresh_token,
                access_expires_at=access_claims['exp'],
                refresh_expires_at=refresh_claims['exp'],
                token_type="Bearer"
            )
            
        except Exception as e:
            self.logger.error(f"Token generation failed: {e}")
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.TOKEN_GENERATION_FAILED,
                    SecuritySeverity.ERROR,
                    "JWT token generation failed",
                    {'error': str(e), 'user_id': getattr(user, 'id', 'unknown')}
                )
            raise TokenValidationError(f"Token generation failed: {e}")

    def refresh_token_with_rotation(self, refresh_token: str) -> TokenPair:
        """
        Refresh access token implementing Auth0 refresh token rotation policy.
        
        Args:
            refresh_token: Valid refresh token for rotation
            
        Returns:
            New TokenPair with rotated tokens
            
        Raises:
            TokenValidationError: If refresh token is invalid or expired
        """
        try:
            # Decode and validate refresh token
            token_data = decode_token(refresh_token)
            jti = token_data.get('jti')
            user_id = token_data.get('sub')
            session_id = token_data.get('session_id')
            token_type = token_data.get('token_type')
            
            if token_type != 'refresh':
                raise TokenValidationError("Invalid token type for refresh operation")
            
            # Check if token is revoked
            if self.is_token_revoked(jti):
                # Token reuse detected - revoke entire token family
                self._revoke_token_family(session_id)
                
                if self.security_monitor:
                    self.security_monitor.log_security_event(
                        SecurityEventType.TOKEN_REUSE_DETECTED,
                        SecuritySeverity.CRITICAL,
                        "Refresh token reuse detected - revoking token family",
                        {
                            'user_id': user_id,
                            'session_id': session_id,
                            'jti': jti
                        }
                    )
                
                raise TokenValidationError("Token reuse detected - security violation")
            
            # Revoke current refresh token
            self.revoke_token(jti)
            
            # Get user information for new token generation
            user = None
            if User:
                user = User.query.filter_by(id=user_id).first()
            
            if not user:
                # Create minimal user data from token claims
                user = {
                    'id': user_id,
                    'username': token_data.get('username', ''),
                    'email': token_data.get('email', ''),
                    'roles': token_data.get('roles', [])
                }
            
            # Update token family rotation count
            self._update_token_family_rotation(session_id)
            
            # Generate new token pair
            new_token_pair = self.generate_token_pair(
                user,
                additional_claims={
                    'previous_jti': jti,
                    'rotation_timestamp': int(time.time())
                }
            )
            
            # Log successful rotation
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.TOKEN_ROTATED,
                    SecuritySeverity.INFO,
                    "Refresh token rotated successfully",
                    {
                        'user_id': user_id,
                        'session_id': session_id,
                        'previous_jti': jti,
                        'new_access_jti': self._extract_jti(new_token_pair.access_token),
                        'new_refresh_jti': self._extract_jti(new_token_pair.refresh_token)
                    }
                )
            
            return new_token_pair
            
        except jwt.ExpiredSignatureError:
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.EXPIRED_TOKEN_REFRESH,
                    SecuritySeverity.WARNING,
                    "Expired refresh token used for rotation",
                    {'token_jti': jti if 'jti' in locals() else 'unknown'}
                )
            raise TokenValidationError("Refresh token has expired")
            
        except jwt.InvalidTokenError as e:
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.INVALID_TOKEN_REFRESH,
                    SecuritySeverity.WARNING,
                    "Invalid refresh token used for rotation",
                    {'error': str(e)}
                )
            raise TokenValidationError(f"Invalid refresh token: {e}")
        
        except Exception as e:
            self.logger.error(f"Token refresh failed: {e}")
            raise TokenValidationError(f"Token refresh failed: {e}")

    def validate_token(
        self,
        token: str,
        verify_auth0: bool = True,
        verify_local: bool = True
    ) -> Dict[str, Any]:
        """
        Validate JWT token using local verification and optional Auth0 verification.
        
        Args:
            token: JWT token to validate
            verify_auth0: Whether to verify against Auth0 public keys
            verify_local: Whether to verify with local secret
            
        Returns:
            Dictionary containing validated token claims
            
        Raises:
            TokenValidationError: If token validation fails
        """
        validation_errors = []
        
        # Try local verification first (for app-generated tokens)
        if verify_local:
            try:
                return self._validate_local_token(token)
            except Exception as e:
                validation_errors.append(f"Local validation failed: {e}")
        
        # Try Auth0 verification (for Auth0-generated tokens)
        if verify_auth0 and self.auth0_public_keys:
            try:
                return self._validate_auth0_token(token)
            except Exception as e:
                validation_errors.append(f"Auth0 validation failed: {e}")
        
        # If both validations fail, raise error
        error_message = "; ".join(validation_errors)
        if self.security_monitor:
            self.security_monitor.log_security_event(
                SecurityEventType.TOKEN_VALIDATION_FAILED,
                SecuritySeverity.WARNING,
                "JWT token validation failed",
                {'error': error_message, 'request_path': getattr(request, 'path', 'unknown')}
            )
        
        raise TokenValidationError(f"Token validation failed: {error_message}")

    def _validate_local_token(self, token: str) -> Dict[str, Any]:
        """Validate token using local Flask-JWT-Extended configuration."""
        try:
            # Decode token with Flask-JWT-Extended
            token_data = decode_token(token)
            
            # Check if token is revoked
            jti = token_data.get('jti')
            if jti and self.is_token_revoked(jti):
                raise TokenValidationError("Token has been revoked")
            
            return token_data
            
        except Exception as e:
            raise TokenValidationError(f"Local token validation failed: {e}")

    def _validate_auth0_token(self, token: str) -> Dict[str, Any]:
        """Validate token using Auth0 public keys."""
        try:
            # Decode header to get key ID
            header = jwt.get_unverified_header(token)
            kid = header.get('kid')
            
            if not kid or kid not in self.auth0_public_keys:
                raise TokenValidationError("Unknown key ID or key not found")
            
            # Get public key
            key_data = self.auth0_public_keys[kid]
            public_key = self._jwk_to_pem(key_data)
            
            # Verify token with Auth0 public key
            token_data = jwt.decode(
                token,
                public_key,
                algorithms=self.auth0_algorithms,
                audience=self.auth0_audience,
                issuer=f"https://{self.auth0_domain}/"
            )
            
            return token_data
            
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(f"Auth0 token validation failed: {e}")

    def _jwk_to_pem(self, jwk: Dict[str, str]) -> bytes:
        """Convert JWK to PEM format for token verification."""
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives import serialization
            import base64
            
            # Extract RSA components
            n = int.from_bytes(
                base64.urlsafe_b64decode(jwk['n'] + '==='),
                byteorder='big'
            )
            e = int.from_bytes(
                base64.urlsafe_b64decode(jwk['e'] + '==='),
                byteorder='big'
            )
            
            # Create RSA public key
            public_numbers = RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key()
            
            # Convert to PEM format
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return pem
            
        except Exception as e:
            raise TokenValidationError(f"JWK to PEM conversion failed: {e}")

    def revoke_token(self, jti: str, expiration: Optional[int] = None) -> bool:
        """
        Revoke a specific token by adding it to the blacklist.
        
        Args:
            jti: JWT ID of token to revoke
            expiration: Optional expiration time for blacklist entry
            
        Returns:
            True if token was successfully revoked
        """
        try:
            if not jti:
                return False
            
            blacklist_key = f"{self.token_blacklist_prefix}{jti}"
            
            if self.redis_client:
                # Store in Redis with expiration
                if expiration:
                    self.redis_client.setex(blacklist_key, expiration, "revoked")
                else:
                    # Default to refresh token expiration
                    default_expiry = int(self.refresh_token_expires.total_seconds())
                    self.redis_client.setex(blacklist_key, default_expiry, "revoked")
            else:
                # Fallback to in-memory storage
                if hasattr(self, '_blacklist_cache'):
                    self._blacklist_cache.add(jti)
            
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.TOKEN_REVOKED,
                    SecuritySeverity.INFO,
                    "JWT token revoked",
                    {'jti': jti, 'expiration': expiration}
                )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Token revocation failed for JTI {jti}: {e}")
            return False

    def revoke_user_tokens(self, user_id: str) -> TokenRevocationResult:
        """
        Revoke all tokens for a specific user across all sessions.
        
        Args:
            user_id: ID of user whose tokens should be revoked
            
        Returns:
            TokenRevocationResult with operation details
        """
        try:
            revoked_count = 0
            revoked_tokens = []
            
            if self.redis_client:
                # Find all token families for the user
                family_pattern = f"{self.token_family_prefix}*"
                family_keys = self.redis_client.keys(family_pattern)
                
                for family_key in family_keys:
                    family_data = self.redis_client.hgetall(family_key)
                    if family_data.get('user_id') == user_id:
                        # Revoke all tokens in this family
                        session_id = family_key.replace(self.token_family_prefix, '')
                        family_revoked = self._revoke_token_family(session_id)
                        revoked_count += family_revoked
                        revoked_tokens.append(session_id)
            
            # Log user token revocation
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.USER_TOKENS_REVOKED,
                    SecuritySeverity.INFO,
                    "All user tokens revoked",
                    {
                        'user_id': user_id,
                        'revoked_count': revoked_count,
                        'revoked_sessions': revoked_tokens
                    }
                )
            
            return TokenRevocationResult(
                success=True,
                revoked_count=revoked_count,
                revoked_tokens=revoked_tokens
            )
            
        except Exception as e:
            self.logger.error(f"User token revocation failed for user {user_id}: {e}")
            return TokenRevocationResult(
                success=False,
                revoked_count=0,
                error_message=str(e)
            )

    def handle_security_incident_revocation(
        self,
        incident_type: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        immediate: bool = True
    ) -> TokenRevocationResult:
        """
        Handle token revocation for security incidents with immediate invalidation.
        
        Args:
            incident_type: Type of security incident
            user_id: User ID for user-specific revocation
            session_id: Session ID for session-specific revocation
            immediate: Whether to perform immediate revocation
            
        Returns:
            TokenRevocationResult with operation details
        """
        try:
            revoked_count = 0
            revoked_tokens = []
            
            if immediate:
                if session_id:
                    # Revoke specific session tokens
                    family_revoked = self._revoke_token_family(session_id)
                    revoked_count += family_revoked
                    revoked_tokens.append(session_id)
                    
                elif user_id:
                    # Revoke all user tokens
                    result = self.revoke_user_tokens(user_id)
                    revoked_count = result.revoked_count
                    revoked_tokens = result.revoked_tokens or []
                
                else:
                    # Critical incident - consider revoking all tokens
                    self.logger.warning(f"Critical security incident: {incident_type}")
            
            # Log security incident token revocation
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.SECURITY_INCIDENT_TOKEN_REVOCATION,
                    SecuritySeverity.CRITICAL,
                    "Security incident token revocation",
                    {
                        'incident_type': incident_type,
                        'user_id': user_id,
                        'session_id': session_id,
                        'immediate': immediate,
                        'revoked_count': revoked_count,
                        'revoked_tokens': revoked_tokens
                    }
                )
            
            return TokenRevocationResult(
                success=True,
                revoked_count=revoked_count,
                revoked_tokens=revoked_tokens
            )
            
        except Exception as e:
            self.logger.error(f"Security incident token revocation failed: {e}")
            return TokenRevocationResult(
                success=False,
                revoked_count=0,
                error_message=str(e)
            )

    def is_token_revoked(self, jti: str) -> bool:
        """
        Check if a token is revoked by checking the blacklist.
        
        Args:
            jti: JWT ID to check
            
        Returns:
            True if token is revoked, False otherwise
        """
        if not jti:
            return False
        
        try:
            blacklist_key = f"{self.token_blacklist_prefix}{jti}"
            
            if self.redis_client:
                return self.redis_client.exists(blacklist_key) > 0
            else:
                # Fallback to in-memory storage
                return hasattr(self, '_blacklist_cache') and jti in self._blacklist_cache
        
        except Exception as e:
            self.logger.error(f"Token revocation check failed for JTI {jti}: {e}")
            # Fail safe - assume token is revoked if we can't check
            return True

    def _store_token_family(self, session_id: str, family_data: Dict[str, Any]) -> None:
        """Store token family information for rotation tracking."""
        if self.redis_client:
            family_key = f"{self.token_family_prefix}{session_id}"
            self.redis_client.hset(family_key, mapping=family_data)
            # Set expiration to refresh token lifetime
            self.redis_client.expire(family_key, int(self.refresh_token_expires.total_seconds()))

    def _update_token_family_rotation(self, session_id: str) -> None:
        """Update token family rotation count."""
        if self.redis_client:
            family_key = f"{self.token_family_prefix}{session_id}"
            self.redis_client.hincrby(family_key, "rotation_count", 1)
            self.redis_client.hset(family_key, "last_rotation", int(time.time()))

    def _revoke_token_family(self, session_id: str) -> int:
        """Revoke entire token family for security incidents."""
        if not self.redis_client:
            return 0
        
        try:
            family_key = f"{self.token_family_prefix}{session_id}"
            family_data = self.redis_client.hgetall(family_key)
            
            revoked_count = 0
            
            # Revoke access token
            access_jti = family_data.get('access_token_jti')
            if access_jti and self.revoke_token(access_jti):
                revoked_count += 1
            
            # Revoke refresh token
            refresh_jti = family_data.get('refresh_token_jti')
            if refresh_jti and self.revoke_token(refresh_jti):
                revoked_count += 1
            
            # Remove family data
            self.redis_client.delete(family_key)
            
            return revoked_count
            
        except Exception as e:
            self.logger.error(f"Token family revocation failed for session {session_id}: {e}")
            return 0

    def _extract_jti(self, token: str) -> Optional[str]:
        """Extract JTI from token without verification."""
        try:
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            return unverified_payload.get('jti')
        except Exception:
            return None

    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired tokens from blacklist to maintain performance.
        
        Returns:
            Number of expired tokens cleaned up
        """
        if not self.redis_client:
            return 0
        
        try:
            # Redis automatically expires keys, so this is mainly for monitoring
            pattern = f"{self.token_blacklist_prefix}*"
            keys = self.redis_client.keys(pattern)
            
            # Count existing blacklisted tokens for monitoring
            active_blacklist_count = len(keys)
            
            self.logger.info(f"Token blacklist cleanup: {active_blacklist_count} active entries")
            
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    SecurityEventType.TOKEN_CLEANUP,
                    SecuritySeverity.INFO,
                    "Token blacklist cleanup completed",
                    {'active_blacklist_count': active_blacklist_count}
                )
            
            return active_blacklist_count
            
        except Exception as e:
            self.logger.error(f"Token cleanup failed: {e}")
            return 0

    def get_token_info(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get token information without full validation for debugging/monitoring.
        
        Args:
            token: JWT token to analyze
            
        Returns:
            Dictionary with token information or None if token is invalid
        """
        try:
            # Decode without verification for analysis
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            
            return {
                'jti': unverified_payload.get('jti'),
                'sub': unverified_payload.get('sub'),
                'iat': unverified_payload.get('iat'),
                'exp': unverified_payload.get('exp'),
                'token_type': unverified_payload.get('token_type'),
                'session_id': unverified_payload.get('session_id'),
                'is_revoked': self.is_token_revoked(unverified_payload.get('jti')),
                'is_expired': unverified_payload.get('exp', 0) < time.time()
            }
            
        except Exception as e:
            self.logger.debug(f"Token info extraction failed: {e}")
            return None


# Authentication decorator factory
def create_jwt_required_decorator(token_handler: JWTTokenHandler):
    """
    Create a JWT required decorator that integrates with the token handler.
    
    Args:
        token_handler: JWTTokenHandler instance
        
    Returns:
        Decorator function for JWT authentication
    """
    def jwt_required_decorator(optional: bool = False):
        """
        JWT authentication decorator with token handler integration.
        
        Args:
            optional: Whether authentication is optional
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                try:
                    # Use Flask-JWT-Extended verification
                    verify_jwt_in_request(optional=optional)
                    
                    # Additional security logging
                    if hasattr(token_handler, 'security_monitor') and token_handler.security_monitor:
                        jwt_data = get_jwt()
                        user_id = get_jwt_identity()
                        
                        token_handler.security_monitor.log_security_event(
                            SecurityEventType.JWT_ACCESS,
                            SecuritySeverity.INFO,
                            "JWT authenticated access",
                            {
                                'user_id': user_id,
                                'endpoint': request.endpoint,
                                'method': request.method,
                                'jti': jwt_data.get('jti')
                            }
                        )
                    
                    return f(*args, **kwargs)
                    
                except Exception as e:
                    if hasattr(token_handler, 'security_monitor') and token_handler.security_monitor:
                        token_handler.security_monitor.log_security_event(
                            SecurityEventType.JWT_AUTH_FAILED,
                            SecuritySeverity.WARNING,
                            "JWT authentication failed",
                            {
                                'error': str(e),
                                'endpoint': request.endpoint,
                                'method': request.method
                            }
                        )
                    
                    if optional:
                        return f(*args, **kwargs)
                    else:
                        raise
            
            return decorated_function
        return decorator
    
    return jwt_required_decorator


# Module-level instance for Flask application factory integration
jwt_token_handler = JWTTokenHandler()


def init_jwt_token_handler(app: Flask) -> JWTTokenHandler:
    """
    Initialize JWT Token Handler with Flask application factory pattern.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured JWTTokenHandler instance
    """
    jwt_token_handler.init_app(app)
    return jwt_token_handler


# Export public interface
__all__ = [
    'JWTTokenHandler',
    'TokenClaims',
    'TokenPair',
    'TokenRevocationResult',
    'TokenValidationError',
    'TokenRevocationError',
    'create_jwt_required_decorator',
    'init_jwt_token_handler',
    'jwt_token_handler'
]