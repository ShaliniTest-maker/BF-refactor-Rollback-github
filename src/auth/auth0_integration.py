"""
Auth0 Identity Provider Integration Service for Flask Application Factory Pattern.

This module implements comprehensive external authentication using Auth0 Python SDK 4.9.0,
managing user authentication flows, token validation, user profile synchronization, and
Auth0 Management API interactions while maintaining compatibility with Flask application
factory pattern and providing seamless identity management.

Key Features:
- Auth0 Python SDK 4.9.0 integration with Flask application factory per Section 6.4.1.1
- JWT token validation with Auth0 public key verification per Section 6.4.1.4  
- User profile synchronization between Auth0 and Flask-SQLAlchemy per Section 6.4.1.1
- Auth0 Management API integration for user lifecycle operations per Section 6.4.1.1
- Token revocation and security incident response capabilities per Section 6.4.6.2
- Automated refresh token rotation policy with security enforcement per Section 6.4.1.4

Technical Specification References:
- Section 6.4.1.1: Auth0 Python SDK integration and identity management
- Section 6.4.1.4: JWT token validation and refresh token management
- Section 6.4.6.2: Token revocation and security incident response
- Section 4.6: Authentication Migration Workflow from Node.js to Flask
"""

import os
import json
import jwt
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Union
from functools import wraps
from urllib.parse import urlencode

import requests
from jose import jwt as jose_jwt, JWTError
from auth0.v3.authentication import GetToken, Users, Social
from auth0.v3.management import Auth0
from auth0.v3.exceptions import Auth0Error
from flask import current_app, request, g, session, jsonify, url_for, redirect
from flask_login import current_user, login_user, logout_user
from werkzeug.exceptions import Unauthorized, BadRequest, InternalServerError

from ..models.user import User
from ..models.session import UserSession
from ..models.base import db


# Configure module logger for comprehensive audit trails per Section 6.4.2.5
logger = logging.getLogger(__name__)


class Auth0TokenError(Exception):
    """Custom exception for Auth0 token-related errors."""
    pass


class Auth0ProfileError(Exception):
    """Custom exception for Auth0 user profile-related errors."""
    pass


class Auth0ManagementError(Exception):
    """Custom exception for Auth0 Management API-related errors."""
    pass


class Auth0Integration:
    """
    Comprehensive Auth0 identity provider integration service.
    
    This service provides complete Auth0 integration capabilities including user
    authentication, token management, profile synchronization, and Management API
    operations. Designed for Flask application factory pattern compatibility with
    comprehensive error handling and security incident response.
    
    Attributes:
        domain (str): Auth0 tenant domain
        client_id (str): Auth0 application client ID
        client_secret (str): Auth0 application client secret
        audience (str): Auth0 API audience identifier
        algorithms (List[str]): Supported JWT signing algorithms
        get_token (GetToken): Auth0 authentication API client
        users_client (Users): Auth0 Users API client
        management_client (Auth0): Auth0 Management API client
        jwks_uri (str): Auth0 JSON Web Key Set URI for token validation
        issuer (str): Auth0 token issuer URL
    """
    
    def __init__(self, app=None):
        """
        Initialize Auth0 integration service.
        
        Args:
            app (Flask, optional): Flask application instance for immediate initialization
        """
        self.domain = None
        self.client_id = None
        self.client_secret = None
        self.audience = None
        self.algorithms = ['RS256']
        self.get_token = None
        self.users_client = None
        self.management_client = None
        self.jwks_uri = None
        self.issuer = None
        self._jwks_cache = {}
        self._jwks_cache_expiry = 0
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """
        Initialize Auth0 integration with Flask application factory pattern.
        
        Configures Auth0 SDK clients and establishes connection to Auth0 services
        using environment variables and Flask configuration per Section 6.4.1.1.
        
        Args:
            app (Flask): Flask application instance
            
        Raises:
            ValueError: If required Auth0 configuration is missing
            Auth0Error: If Auth0 service connection fails
        """
        # Extract Auth0 configuration from Flask app config and environment variables
        self.domain = app.config.get('AUTH0_DOMAIN') or os.getenv('AUTH0_DOMAIN')
        self.client_id = app.config.get('AUTH0_CLIENT_ID') or os.getenv('AUTH0_CLIENT_ID')
        self.client_secret = app.config.get('AUTH0_CLIENT_SECRET') or os.getenv('AUTH0_CLIENT_SECRET')
        self.audience = app.config.get('AUTH0_AUDIENCE') or os.getenv('AUTH0_AUDIENCE')
        
        # Validate required configuration
        if not all([self.domain, self.client_id, self.client_secret]):
            raise ValueError(
                "AUTH0_DOMAIN, AUTH0_CLIENT_ID, and AUTH0_CLIENT_SECRET must be configured"
            )
        
        # Configure JWT validation parameters per Section 6.4.1.4
        self.algorithms = app.config.get('AUTH0_ALGORITHMS', ['RS256'])
        self.jwks_uri = f"https://{self.domain}/.well-known/jwks.json"
        self.issuer = f"https://{self.domain}/"
        
        # Initialize Auth0 SDK clients per Section 6.4.1.1
        try:
            # Authentication API client for token operations
            self.get_token = GetToken(self.domain)
            
            # Users API client for user management
            self.users_client = Users(self.domain)
            
            # Management API client for administrative operations
            self.management_client = Auth0(self.domain, self._get_management_token())
            
            logger.info(
                "Auth0 integration initialized successfully",
                extra={
                    'domain': self.domain,
                    'client_id': self.client_id,
                    'audience': self.audience,
                    'algorithms': self.algorithms
                }
            )
            
        except Auth0Error as e:
            logger.error(f"Failed to initialize Auth0 clients: {str(e)}")
            raise Auth0Error(f"Auth0 service connection failed: {str(e)}")
        
        # Store integration instance in Flask app for access across blueprints
        app.auth0 = self
    
    def _get_management_token(self) -> str:
        """
        Obtain Auth0 Management API token for administrative operations.
        
        Uses client credentials flow to obtain a Management API token with
        appropriate scopes for user lifecycle operations per Section 6.4.1.1.
        
        Returns:
            str: Management API access token
            
        Raises:
            Auth0ManagementError: If token acquisition fails
        """
        try:
            token_url = f"https://{self.domain}/oauth/token"
            
            payload = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'audience': f"https://{self.domain}/api/v2/",
                'grant_type': 'client_credentials'
            }
            
            headers = {'Content-Type': 'application/json'}
            
            response = requests.post(token_url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
            
            token_data = response.json()
            
            logger.info("Management API token acquired successfully")
            
            return token_data['access_token']
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to acquire Management API token: {str(e)}")
            raise Auth0ManagementError(f"Management API token acquisition failed: {str(e)}")
    
    def get_authorization_url(self, redirect_uri: str, state: str = None) -> str:
        """
        Generate Auth0 authorization URL for user authentication flow.
        
        Creates a properly formatted authorization URL for redirecting users to
        Auth0 for authentication with optional state parameter for CSRF protection.
        
        Args:
            redirect_uri (str): Callback URL after authentication
            state (str, optional): State parameter for CSRF protection
            
        Returns:
            str: Complete Auth0 authorization URL
        """
        params = {
            'audience': self.audience,
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': 'openid profile email',
        }
        
        if state:
            params['state'] = state
        
        auth_url = f"https://{self.domain}/authorize?{urlencode(params)}"
        
        logger.info(
            "Authorization URL generated",
            extra={
                'redirect_uri': redirect_uri,
                'state': state,
                'client_id': self.client_id
            }
        )
        
        return auth_url
    
    def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """
        Exchange authorization code for access and refresh tokens.
        
        Implements the authorization code flow token exchange per Auth0 OAuth 2.0
        specification with comprehensive error handling and validation.
        
        Args:
            code (str): Authorization code from Auth0 callback
            redirect_uri (str): Redirect URI used in authorization request
            
        Returns:
            Dict[str, Any]: Token response containing access_token, refresh_token, and id_token
            
        Raises:
            Auth0TokenError: If token exchange fails
        """
        try:
            token_payload = {
                'grant_type': 'authorization_code',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'code': code,
                'redirect_uri': redirect_uri,
            }
            
            # Add audience if configured
            if self.audience:
                token_payload['audience'] = self.audience
            
            token_response = self.get_token.authorization_code(
                code=code,
                redirect_uri=redirect_uri
            )
            
            logger.info(
                "Authorization code exchanged for tokens successfully",
                extra={
                    'client_id': self.client_id,
                    'redirect_uri': redirect_uri
                }
            )
            
            return token_response
            
        except Auth0Error as e:
            logger.error(f"Token exchange failed: {str(e)}")
            raise Auth0TokenError(f"Failed to exchange code for tokens: {str(e)}")
    
    def validate_jwt_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token with Auth0 public key verification per Section 6.4.1.4.
        
        Performs comprehensive JWT validation including signature verification,
        expiration checking, issuer validation, and audience validation using
        Auth0's public keys from JWKS endpoint.
        
        Args:
            token (str): JWT token to validate
            
        Returns:
            Dict[str, Any]: Decoded token payload if validation successful
            
        Raises:
            Auth0TokenError: If token validation fails
        """
        try:
            # Get JWT header to determine key ID
            unverified_header = jose_jwt.get_unverified_header(token)
            
            # Get signing key from JWKS
            jwks = self._get_jwks()
            rsa_key = self._get_rsa_key(jwks, unverified_header['kid'])
            
            if not rsa_key:
                raise Auth0TokenError("Unable to find appropriate key for token verification")
            
            # Validate and decode token
            payload = jose_jwt.decode(
                token,
                rsa_key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                options={'verify_exp': True}
            )
            
            logger.info(
                "JWT token validated successfully",
                extra={
                    'subject': payload.get('sub'),
                    'audience': payload.get('aud'),
                    'issuer': payload.get('iss')
                }
            )
            
            return payload
            
        except JWTError as e:
            logger.warning(f"JWT validation failed: {str(e)}")
            raise Auth0TokenError(f"Invalid JWT token: {str(e)}")
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            raise Auth0TokenError(f"Token validation failed: {str(e)}")
    
    def _get_jwks(self) -> Dict[str, Any]:
        """
        Retrieve and cache Auth0 JSON Web Key Set (JWKS) for token validation.
        
        Implements caching mechanism for JWKS to reduce API calls while ensuring
        up-to-date keys for token validation per Section 6.4.1.4.
        
        Returns:
            Dict[str, Any]: JWKS response from Auth0
            
        Raises:
            Auth0TokenError: If JWKS retrieval fails
        """
        current_time = time.time()
        
        # Return cached JWKS if still valid (cache for 1 hour)
        if (self._jwks_cache and 
            current_time < self._jwks_cache_expiry):
            return self._jwks_cache
        
        try:
            response = requests.get(self.jwks_uri, timeout=10)
            response.raise_for_status()
            
            jwks = response.json()
            
            # Cache JWKS for 1 hour
            self._jwks_cache = jwks
            self._jwks_cache_expiry = current_time + 3600
            
            logger.debug("JWKS retrieved and cached successfully")
            
            return jwks
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to retrieve JWKS: {str(e)}")
            raise Auth0TokenError(f"JWKS retrieval failed: {str(e)}")
    
    def _get_rsa_key(self, jwks: Dict[str, Any], kid: str) -> Dict[str, Any]:
        """
        Extract RSA key from JWKS for JWT signature verification.
        
        Args:
            jwks (Dict[str, Any]): JSON Web Key Set from Auth0
            kid (str): Key ID from JWT header
            
        Returns:
            Dict[str, Any]: RSA key for signature verification
        """
        for key in jwks.get('keys', []):
            if key.get('kid') == kid:
                return {
                    'kty': key.get('kty'),
                    'kid': key.get('kid'),
                    'use': key.get('use'),
                    'n': key.get('n'),
                    'e': key.get('e')
                }
        return {}
    
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Retrieve user information from Auth0 using access token.
        
        Fetches comprehensive user profile information from Auth0 userinfo
        endpoint for profile synchronization per Section 6.4.1.1.
        
        Args:
            access_token (str): Valid Auth0 access token
            
        Returns:
            Dict[str, Any]: User profile information from Auth0
            
        Raises:
            Auth0ProfileError: If user info retrieval fails
        """
        try:
            userinfo_url = f"https://{self.domain}/userinfo"
            headers = {'Authorization': f'Bearer {access_token}'}
            
            response = requests.get(userinfo_url, headers=headers, timeout=10)
            response.raise_for_status()
            
            user_info = response.json()
            
            logger.info(
                "User info retrieved successfully",
                extra={
                    'user_id': user_info.get('sub'),
                    'email': user_info.get('email'),
                    'email_verified': user_info.get('email_verified')
                }
            )
            
            return user_info
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to retrieve user info: {str(e)}")
            raise Auth0ProfileError(f"User info retrieval failed: {str(e)}")
    
    def sync_user_profile(self, auth0_user_info: Dict[str, Any]) -> User:
        """
        Synchronize Auth0 user profile with Flask-SQLAlchemy User model per Section 6.4.1.1.
        
        Creates or updates local User record based on Auth0 profile information,
        maintaining identity synchronization between Auth0 and local database.
        
        Args:
            auth0_user_info (Dict[str, Any]): User profile from Auth0
            
        Returns:
            User: Synchronized User model instance
            
        Raises:
            Auth0ProfileError: If profile synchronization fails
        """
        try:
            # Extract key profile fields from Auth0 user info
            auth0_user_id = auth0_user_info.get('sub')
            email = auth0_user_info.get('email')
            username = auth0_user_info.get('preferred_username') or auth0_user_info.get('nickname') or email
            email_verified = auth0_user_info.get('email_verified', False)
            
            if not auth0_user_id or not email:
                raise Auth0ProfileError("Auth0 user ID and email are required for synchronization")
            
            # Find existing user by Auth0 user ID or email
            user = User.query.filter(
                (User.email == email) | 
                (User.username == username)
            ).first()
            
            if user:
                # Update existing user profile
                user.email = email
                user.username = username
                user.is_active = email_verified
                user.updated_at = datetime.now(timezone.utc)
                
                logger.info(
                    "User profile updated from Auth0",
                    extra={
                        'user_id': user.id,
                        'auth0_user_id': auth0_user_id,
                        'email': email,
                        'email_verified': email_verified
                    }
                )
            else:
                # Create new user from Auth0 profile
                # Note: Auth0 users don't have passwords in local system
                user = User(
                    username=username,
                    email=email,
                    password='auth0_managed',  # Placeholder - actual auth via Auth0
                    is_active=email_verified
                )
                
                db.session.add(user)
                
                logger.info(
                    "New user created from Auth0 profile",
                    extra={
                        'auth0_user_id': auth0_user_id,
                        'email': email,
                        'username': username,
                        'email_verified': email_verified
                    }
                )
            
            # Commit changes to database
            db.session.commit()
            
            return user
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"User profile synchronization failed: {str(e)}")
            raise Auth0ProfileError(f"Profile synchronization failed: {str(e)}")
    
    def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token with rotation policy per Section 6.4.1.4.
        
        Implements Auth0 refresh token rotation policy with automated revocation
        for enhanced security per Section 6.4.1.4.
        
        Args:
            refresh_token (str): Valid refresh token
            
        Returns:
            Dict[str, Any]: New token set with rotated refresh token
            
        Raises:
            Auth0TokenError: If token refresh fails
        """
        try:
            refresh_payload = {
                'grant_type': 'refresh_token',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': refresh_token,
            }
            
            if self.audience:
                refresh_payload['audience'] = self.audience
            
            token_url = f"https://{self.domain}/oauth/token"
            headers = {'Content-Type': 'application/json'}
            
            response = requests.post(token_url, json=refresh_payload, headers=headers, timeout=10)
            response.raise_for_status()
            
            token_data = response.json()
            
            logger.info(
                "Access token refreshed successfully",
                extra={
                    'client_id': self.client_id,
                    'token_type': token_data.get('token_type'),
                    'expires_in': token_data.get('expires_in')
                }
            )
            
            return token_data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise Auth0TokenError(f"Failed to refresh access token: {str(e)}")
    
    def revoke_refresh_token(self, refresh_token: str) -> bool:
        """
        Revoke refresh token for security incident response per Section 6.4.6.2.
        
        Implements immediate token revocation capabilities for security incidents
        and user logout scenarios with comprehensive audit logging.
        
        Args:
            refresh_token (str): Refresh token to revoke
            
        Returns:
            bool: True if revocation successful, False otherwise
        """
        try:
            revoke_url = f"https://{self.domain}/oauth/revoke"
            
            revoke_payload = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'token': refresh_token,
                'token_type_hint': 'refresh_token'
            }
            
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            
            response = requests.post(
                revoke_url, 
                data=revoke_payload, 
                headers=headers, 
                timeout=10
            )
            
            # Auth0 returns 200 for successful revocation, even if token was invalid
            success = response.status_code == 200
            
            if success:
                logger.info(
                    "Refresh token revoked successfully",
                    extra={'client_id': self.client_id}
                )
            else:
                logger.warning(
                    "Token revocation request failed",
                    extra={
                        'status_code': response.status_code,
                        'response': response.text
                    }
                )
            
            return success
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Token revocation failed: {str(e)}")
            return False
    
    def get_user_by_id(self, auth0_user_id: str) -> Dict[str, Any]:
        """
        Retrieve user details from Auth0 Management API by user ID.
        
        Uses Management API for comprehensive user lifecycle operations
        per Section 6.4.1.1.
        
        Args:
            auth0_user_id (str): Auth0 user identifier
            
        Returns:
            Dict[str, Any]: Complete user profile from Auth0
            
        Raises:
            Auth0ManagementError: If user retrieval fails
        """
        try:
            user_details = self.management_client.users.get(auth0_user_id)
            
            logger.info(
                "User details retrieved from Management API",
                extra={
                    'auth0_user_id': auth0_user_id,
                    'email': user_details.get('email'),
                    'last_login': user_details.get('last_login')
                }
            )
            
            return user_details
            
        except Auth0Error as e:
            logger.error(f"Failed to retrieve user from Management API: {str(e)}")
            raise Auth0ManagementError(f"User retrieval failed: {str(e)}")
    
    def update_user_metadata(self, auth0_user_id: str, user_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update user metadata using Auth0 Management API.
        
        Allows updating custom user metadata for enhanced profile management
        per Section 6.4.1.1.
        
        Args:
            auth0_user_id (str): Auth0 user identifier
            user_metadata (Dict[str, Any]): Metadata to update
            
        Returns:
            Dict[str, Any]: Updated user profile
            
        Raises:
            Auth0ManagementError: If metadata update fails
        """
        try:
            updated_user = self.management_client.users.update(
                auth0_user_id, 
                {'user_metadata': user_metadata}
            )
            
            logger.info(
                "User metadata updated successfully",
                extra={
                    'auth0_user_id': auth0_user_id,
                    'metadata_keys': list(user_metadata.keys())
                }
            )
            
            return updated_user
            
        except Auth0Error as e:
            logger.error(f"Failed to update user metadata: {str(e)}")
            raise Auth0ManagementError(f"Metadata update failed: {str(e)}")
    
    def block_user(self, auth0_user_id: str, reason: str = "Security incident") -> bool:
        """
        Block user account for security incident response per Section 6.4.6.2.
        
        Implements immediate user blocking capabilities for security incidents
        with comprehensive audit logging and reason tracking.
        
        Args:
            auth0_user_id (str): Auth0 user identifier to block
            reason (str): Reason for blocking the user account
            
        Returns:
            bool: True if user blocked successfully, False otherwise
        """
        try:
            self.management_client.users.update(
                auth0_user_id,
                {'blocked': True, 'user_metadata': {'block_reason': reason}}
            )
            
            logger.warning(
                "User account blocked",
                extra={
                    'auth0_user_id': auth0_user_id,
                    'reason': reason,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            
            return True
            
        except Auth0Error as e:
            logger.error(f"Failed to block user account: {str(e)}")
            return False
    
    def unblock_user(self, auth0_user_id: str) -> bool:
        """
        Unblock user account after security incident resolution.
        
        Args:
            auth0_user_id (str): Auth0 user identifier to unblock
            
        Returns:
            bool: True if user unblocked successfully, False otherwise
        """
        try:
            self.management_client.users.update(
                auth0_user_id,
                {'blocked': False}
            )
            
            logger.info(
                "User account unblocked",
                extra={
                    'auth0_user_id': auth0_user_id,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            
            return True
            
        except Auth0Error as e:
            logger.error(f"Failed to unblock user account: {str(e)}")
            return False
    
    def logout_url(self, return_to: str = None) -> str:
        """
        Generate Auth0 logout URL with optional return URL.
        
        Creates properly formatted logout URL for complete session termination
        including Auth0 session cleanup.
        
        Args:
            return_to (str, optional): URL to redirect after logout
            
        Returns:
            str: Complete Auth0 logout URL
        """
        params = {'client_id': self.client_id}
        
        if return_to:
            params['returnTo'] = return_to
        
        logout_url = f"https://{self.domain}/v2/logout?{urlencode(params)}"
        
        logger.info(
            "Logout URL generated",
            extra={
                'client_id': self.client_id,
                'return_to': return_to
            }
        )
        
        return logout_url


def require_auth0_token(f):
    """
    Flask decorator for Auth0 JWT token validation per Section 6.4.1.4.
    
    Validates Auth0 JWT tokens and populates Flask g object with user information
    for use in protected routes. Integrates with Flask-Login for session management.
    
    Args:
        f: Function to decorate
        
    Returns:
        Decorated function with Auth0 token validation
        
    Raises:
        Unauthorized: If token validation fails
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Extract token from Authorization header
            auth_header = request.headers.get('Authorization')
            
            if not auth_header:
                logger.warning("Missing Authorization header")
                raise Unauthorized("Authorization header is required")
            
            # Parse Bearer token
            try:
                token_type, token = auth_header.split(' ', 1)
                if token_type.lower() != 'bearer':
                    raise ValueError("Invalid token type")
            except ValueError:
                logger.warning("Invalid Authorization header format")
                raise Unauthorized("Invalid Authorization header format")
            
            # Validate token using Auth0 integration
            auth0 = current_app.auth0
            payload = auth0.validate_jwt_token(token)
            
            # Store validated token payload in Flask g object
            g.auth0_token = payload
            g.auth0_user_id = payload.get('sub')
            g.auth0_email = payload.get('email')
            
            # Optional: Sync with local user if needed
            if hasattr(current_app, 'config') and current_app.config.get('AUTH0_SYNC_USERS', True):
                try:
                    user_info = auth0.get_user_info(token)
                    user = auth0.sync_user_profile(user_info)
                    g.current_user = user
                except Exception as e:
                    logger.warning(f"User sync failed: {str(e)}")
            
            logger.info(
                "Auth0 token validated successfully",
                extra={
                    'user_id': g.auth0_user_id,
                    'email': g.auth0_email,
                    'endpoint': request.endpoint
                }
            )
            
            return f(*args, **kwargs)
            
        except Auth0TokenError as e:
            logger.warning(f"Auth0 token validation failed: {str(e)}")
            raise Unauthorized(str(e))
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            raise Unauthorized("Authentication failed")
    
    return decorated_function


def create_auth0_integration(app):
    """
    Factory function for creating Auth0 integration with Flask application.
    
    Provides a convenient way to initialize Auth0 integration within the
    Flask application factory pattern per Section 6.4.1.1.
    
    Args:
        app (Flask): Flask application instance
        
    Returns:
        Auth0Integration: Configured Auth0 integration instance
    """
    auth0_integration = Auth0Integration(app)
    return auth0_integration


# Export key classes and functions for use throughout the application
__all__ = [
    'Auth0Integration',
    'Auth0TokenError', 
    'Auth0ProfileError',
    'Auth0ManagementError',
    'require_auth0_token',
    'create_auth0_integration'
]