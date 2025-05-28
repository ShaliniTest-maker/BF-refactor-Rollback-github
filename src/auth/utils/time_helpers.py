"""
Time and date utility functions for authentication operations.

This module provides comprehensive temporal operations for the Flask authentication system,
including timezone-aware timestamp generation, JWT token expiration management, session
timeout handling, and time-based security validation. All functions maintain consistency
with the security architecture requirements and support the migration from Node.js Date
patterns to Python datetime objects with proper timezone handling.

Security Compliance:
- Section 6.4.3.1: Timezone-aware timestamp generation for authentication logging
- Section 6.4.1.4: JWT token expiration handling and validation
- Section 6.4.1.3: Session timeout calculation and enforcement
- Section 6.4.2.5: Authentication audit trail timestamp consistency
- Section 6.4.6.1: Time-based security pattern detection

Author: DevSecOps Team
Version: 1.0.0
Python Version: 3.13.3
Flask Version: 3.1.1
"""

import datetime
import time
from typing import Optional, Union, Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum
import pytz
import structlog
from flask import current_app, g
import hashlib
import hmac
from collections import defaultdict, deque
import threading

# Standard logger for authentication time operations
logger = structlog.get_logger("auth.time_helpers")

# Global timezone constants for consistent operations
UTC_TIMEZONE = pytz.UTC
DEFAULT_TIMEZONE = 'UTC'

# Token expiration constants (in seconds)
JWT_ACCESS_TOKEN_EXPIRY = 3600  # 1 hour
JWT_REFRESH_TOKEN_EXPIRY = 2592000  # 30 days
SESSION_TIMEOUT_DEFAULT = 1800  # 30 minutes
SESSION_TIMEOUT_REMEMBER_ME = 604800  # 7 days

# Security thresholds for time-based pattern detection
MAX_LOGIN_ATTEMPTS_PER_MINUTE = 5
MAX_TOKEN_REFRESH_PER_HOUR = 10
SUSPICIOUS_TIME_PATTERN_THRESHOLD = 3


class TimeValidationResult(Enum):
    """Enumeration for time validation results."""
    VALID = "valid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    INVALID_FORMAT = "invalid_format"
    SUSPICIOUS_PATTERN = "suspicious_pattern"


class TimezoneMode(Enum):
    """Enumeration for timezone handling modes."""
    UTC_ONLY = "utc_only"
    LOCAL_WITH_UTC = "local_with_utc"
    USER_TIMEZONE = "user_timezone"


@dataclass
class TimestampResult:
    """
    Data structure for timestamp generation results.
    
    Attributes:
        timestamp: The generated timestamp
        timezone: The timezone used for generation
        iso_format: ISO 8601 formatted timestamp string
        unix_timestamp: Unix timestamp (seconds since epoch)
        metadata: Additional metadata for audit trails
    """
    timestamp: datetime.datetime
    timezone: str
    iso_format: str
    unix_timestamp: float
    metadata: Dict[str, Any]


@dataclass
class TokenExpirationInfo:
    """
    Data structure for JWT token expiration information.
    
    Attributes:
        expires_at: When the token expires
        issued_at: When the token was issued
        remaining_seconds: Seconds until expiration
        is_expired: Whether the token is currently expired
        refresh_threshold: Time before expiration to trigger refresh
        should_refresh: Whether the token should be refreshed
    """
    expires_at: datetime.datetime
    issued_at: datetime.datetime
    remaining_seconds: int
    is_expired: bool
    refresh_threshold: int
    should_refresh: bool


@dataclass
class SessionTimeoutInfo:
    """
    Data structure for session timeout information.
    
    Attributes:
        session_started: When the session was initiated
        last_activity: Last recorded activity timestamp
        timeout_duration: Session timeout in seconds
        expires_at: When the session will expire
        is_expired: Whether the session has expired
        remaining_seconds: Seconds until session expiration
        remember_me: Whether remember-me is enabled
    """
    session_started: datetime.datetime
    last_activity: datetime.datetime
    timeout_duration: int
    expires_at: datetime.datetime
    is_expired: bool
    remaining_seconds: int
    remember_me: bool


class TimeBasedSecurityMonitor:
    """
    Time-based security pattern detection and monitoring.
    
    This class implements comprehensive monitoring of time-based authentication
    patterns to detect suspicious activities, brute force attempts, and anomalous
    behaviors that could indicate security threats.
    """
    
    def __init__(self):
        """Initialize the security monitor with thread-safe collections."""
        self.login_attempts = defaultdict(deque)
        self.token_refresh_attempts = defaultdict(deque)
        self.session_patterns = defaultdict(list)
        self._lock = threading.Lock()
        
    def record_login_attempt(self, identifier: str, timestamp: Optional[datetime.datetime] = None) -> bool:
        """
        Record a login attempt for security monitoring.
        
        Args:
            identifier: User identifier (IP, username, etc.)
            timestamp: Optional timestamp (defaults to current time)
            
        Returns:
            True if the attempt is within normal patterns, False if suspicious
        """
        if timestamp is None:
            timestamp = get_utc_now()
            
        with self._lock:
            attempts = self.login_attempts[identifier]
            attempts.append(timestamp)
            
            # Clean old attempts (older than 1 minute)
            cutoff_time = timestamp - datetime.timedelta(minutes=1)
            while attempts and attempts[0] < cutoff_time:
                attempts.popleft()
            
            # Check if attempts exceed threshold
            if len(attempts) > MAX_LOGIN_ATTEMPTS_PER_MINUTE:
                logger.warning(
                    "Suspicious login pattern detected",
                    identifier=identifier,
                    attempts_count=len(attempts),
                    time_window="1_minute"
                )
                return False
                
        return True
    
    def record_token_refresh(self, user_id: str, timestamp: Optional[datetime.datetime] = None) -> bool:
        """
        Record a token refresh attempt for security monitoring.
        
        Args:
            user_id: User identifier
            timestamp: Optional timestamp (defaults to current time)
            
        Returns:
            True if the refresh is within normal patterns, False if suspicious
        """
        if timestamp is None:
            timestamp = get_utc_now()
            
        with self._lock:
            refreshes = self.token_refresh_attempts[user_id]
            refreshes.append(timestamp)
            
            # Clean old refreshes (older than 1 hour)
            cutoff_time = timestamp - datetime.timedelta(hours=1)
            while refreshes and refreshes[0] < cutoff_time:
                refreshes.popleft()
            
            # Check if refreshes exceed threshold
            if len(refreshes) > MAX_TOKEN_REFRESH_PER_HOUR:
                logger.warning(
                    "Suspicious token refresh pattern detected",
                    user_id=user_id,
                    refresh_count=len(refreshes),
                    time_window="1_hour"
                )
                return False
                
        return True
    
    def analyze_session_pattern(self, user_id: str, session_duration: int) -> Dict[str, Any]:
        """
        Analyze session duration patterns for anomaly detection.
        
        Args:
            user_id: User identifier
            session_duration: Session duration in seconds
            
        Returns:
            Analysis results with anomaly indicators
        """
        with self._lock:
            patterns = self.session_patterns[user_id]
            patterns.append(session_duration)
            
            # Keep only recent sessions (last 100)
            if len(patterns) > 100:
                patterns.pop(0)
            
            # Analyze for anomalies
            if len(patterns) >= 5:
                avg_duration = sum(patterns) / len(patterns)
                deviation = abs(session_duration - avg_duration) / avg_duration
                
                result = {
                    "session_duration": session_duration,
                    "average_duration": avg_duration,
                    "deviation_ratio": deviation,
                    "is_anomalous": deviation > 2.0,  # 200% deviation threshold
                    "pattern_count": len(patterns)
                }
                
                if result["is_anomalous"]:
                    logger.warning(
                        "Anomalous session duration detected",
                        user_id=user_id,
                        **result
                    )
                
                return result
                
        return {"session_duration": session_duration, "insufficient_data": True}


# Global security monitor instance
security_monitor = TimeBasedSecurityMonitor()


def get_timezone(timezone_name: Optional[str] = None) -> pytz.BaseTzInfo:
    """
    Get a timezone object with validation and fallback.
    
    Args:
        timezone_name: Optional timezone name (e.g., 'US/Eastern')
        
    Returns:
        pytz timezone object
        
    Raises:
        ValueError: If timezone name is invalid
    """
    if timezone_name is None:
        return UTC_TIMEZONE
        
    try:
        return pytz.timezone(timezone_name)
    except pytz.exceptions.UnknownTimeZoneError:
        logger.warning(
            "Unknown timezone specified, falling back to UTC",
            requested_timezone=timezone_name
        )
        return UTC_TIMEZONE


def get_utc_now() -> datetime.datetime:
    """
    Get current UTC timestamp with timezone awareness.
    
    This function provides a consistent way to generate UTC timestamps
    across the authentication system for logging, token generation,
    and audit trail consistency.
    
    Returns:
        Current UTC datetime with timezone information
        
    Example:
        >>> now = get_utc_now()
        >>> print(now.isoformat())
        '2024-01-15T10:30:45.123456+00:00'
    """
    return datetime.datetime.now(UTC_TIMEZONE)


def get_local_now(timezone_name: Optional[str] = None) -> datetime.datetime:
    """
    Get current timestamp in specified timezone with UTC awareness.
    
    Args:
        timezone_name: Target timezone (defaults to UTC)
        
    Returns:
        Current datetime in specified timezone
        
    Example:
        >>> est_now = get_local_now('US/Eastern')
        >>> print(est_now.isoformat())
        '2024-01-15T05:30:45.123456-05:00'
    """
    tz = get_timezone(timezone_name)
    return datetime.datetime.now(tz)


def generate_audit_timestamp(
    timezone_mode: TimezoneMode = TimezoneMode.UTC_ONLY,
    user_timezone: Optional[str] = None,
    include_metadata: bool = True
) -> TimestampResult:
    """
    Generate standardized timestamps for authentication audit trails.
    
    This function ensures timestamp consistency across all authentication
    operations, supporting compliance requirements and security monitoring.
    
    Args:
        timezone_mode: How to handle timezone generation
        user_timezone: User's preferred timezone (if applicable)
        include_metadata: Whether to include additional metadata
        
    Returns:
        TimestampResult with comprehensive timestamp information
        
    Security Compliance:
        - Section 6.4.2.5: Authentication audit trail timestamp consistency
        - Section 6.4.3.1: Timezone-aware timestamp generation
    """
    utc_now = get_utc_now()
    
    if timezone_mode == TimezoneMode.UTC_ONLY:
        primary_timestamp = utc_now
        timezone_used = 'UTC'
    elif timezone_mode == TimezoneMode.USER_TIMEZONE and user_timezone:
        user_tz = get_timezone(user_timezone)
        primary_timestamp = utc_now.astimezone(user_tz)
        timezone_used = user_timezone
    else:
        primary_timestamp = utc_now
        timezone_used = 'UTC'
    
    # Generate metadata for audit compliance
    metadata = {}
    if include_metadata:
        metadata = {
            'generation_method': 'auth_audit_timestamp',
            'timezone_mode': timezone_mode.value,
            'utc_offset': primary_timestamp.strftime('%z'),
            'dst_active': primary_timestamp.dst() is not None,
            'request_id': getattr(g, 'request_id', None),
            'user_id': getattr(g, 'user_id', None),
            'blueprint': getattr(g, 'blueprint_name', None)
        }
    
    return TimestampResult(
        timestamp=primary_timestamp,
        timezone=timezone_used,
        iso_format=primary_timestamp.isoformat(),
        unix_timestamp=primary_timestamp.timestamp(),
        metadata=metadata
    )


def calculate_jwt_expiration(
    issued_at: Optional[datetime.datetime] = None,
    token_type: str = 'access',
    custom_duration: Optional[int] = None
) -> TokenExpirationInfo:
    """
    Calculate JWT token expiration information for Auth0 integration.
    
    This function provides comprehensive token lifetime management for
    Flask-JWT-Extended integration and Auth0 token validation.
    
    Args:
        issued_at: When the token was issued (defaults to now)
        token_type: Type of token ('access' or 'refresh')
        custom_duration: Custom expiration duration in seconds
        
    Returns:
        TokenExpirationInfo with complete expiration details
        
    Security Compliance:
        - Section 6.4.1.4: JWT token expiration handling and validation
    """
    if issued_at is None:
        issued_at = get_utc_now()
    elif issued_at.tzinfo is None:
        issued_at = UTC_TIMEZONE.localize(issued_at)
    
    # Determine expiration duration
    if custom_duration is not None:
        duration = custom_duration
    elif token_type == 'refresh':
        duration = JWT_REFRESH_TOKEN_EXPIRY
    else:  # access token
        duration = JWT_ACCESS_TOKEN_EXPIRY
    
    # Calculate expiration details
    expires_at = issued_at + datetime.timedelta(seconds=duration)
    current_time = get_utc_now()
    remaining_seconds = max(0, int((expires_at - current_time).total_seconds()))
    is_expired = current_time >= expires_at
    
    # Determine refresh threshold (refresh when 25% of lifetime remains)
    refresh_threshold = int(duration * 0.25)
    should_refresh = remaining_seconds <= refresh_threshold and not is_expired
    
    logger.debug(
        "JWT expiration calculated",
        token_type=token_type,
        issued_at=issued_at.isoformat(),
        expires_at=expires_at.isoformat(),
        remaining_seconds=remaining_seconds,
        is_expired=is_expired
    )
    
    return TokenExpirationInfo(
        expires_at=expires_at,
        issued_at=issued_at,
        remaining_seconds=remaining_seconds,
        is_expired=is_expired,
        refresh_threshold=refresh_threshold,
        should_refresh=should_refresh
    )


def validate_jwt_timestamp(
    timestamp: Union[int, float, datetime.datetime],
    tolerance_seconds: int = 300
) -> TimeValidationResult:
    """
    Validate JWT timestamp claims with clock skew tolerance.
    
    This function validates 'iat', 'exp', and 'nbf' claims from JWT tokens
    with appropriate tolerance for clock synchronization issues.
    
    Args:
        timestamp: Timestamp to validate (Unix timestamp or datetime)
        tolerance_seconds: Clock skew tolerance in seconds
        
    Returns:
        TimeValidationResult indicating validation status
        
    Security Compliance:
        - Section 6.4.1.4: JWT token expiration handling and validation
    """
    try:
        # Convert to datetime if necessary
        if isinstance(timestamp, (int, float)):
            token_time = datetime.datetime.fromtimestamp(timestamp, UTC_TIMEZONE)
        elif isinstance(timestamp, datetime.datetime):
            if timestamp.tzinfo is None:
                token_time = UTC_TIMEZONE.localize(timestamp)
            else:
                token_time = timestamp.astimezone(UTC_TIMEZONE)
        else:
            return TimeValidationResult.INVALID_FORMAT
        
        current_time = get_utc_now()
        time_diff = (token_time - current_time).total_seconds()
        
        # Check if token is expired (with tolerance)
        if time_diff < -tolerance_seconds:
            logger.debug(
                "Token timestamp expired",
                token_time=token_time.isoformat(),
                current_time=current_time.isoformat(),
                diff_seconds=time_diff
            )
            return TimeValidationResult.EXPIRED
        
        # Check if token is not yet valid (with tolerance)
        if time_diff > tolerance_seconds:
            logger.debug(
                "Token timestamp not yet valid",
                token_time=token_time.isoformat(),
                current_time=current_time.isoformat(),
                diff_seconds=time_diff
            )
            return TimeValidationResult.NOT_YET_VALID
        
        return TimeValidationResult.VALID
        
    except Exception as e:
        logger.error(
            "JWT timestamp validation error",
            timestamp=str(timestamp),
            error=str(e)
        )
        return TimeValidationResult.INVALID_FORMAT


def calculate_session_timeout(
    session_started: datetime.datetime,
    last_activity: Optional[datetime.datetime] = None,
    timeout_duration: Optional[int] = None,
    remember_me: bool = False
) -> SessionTimeoutInfo:
    """
    Calculate session timeout information for Flask-Login integration.
    
    This function provides comprehensive session lifetime management
    supporting both regular and remember-me sessions with security
    monitoring integration.
    
    Args:
        session_started: When the session was initiated
        last_activity: Last recorded user activity
        timeout_duration: Custom timeout duration in seconds
        remember_me: Whether remember-me functionality is enabled
        
    Returns:
        SessionTimeoutInfo with complete session details
        
    Security Compliance:
        - Section 6.4.1.3: Session timeout calculation and enforcement
    """
    if session_started.tzinfo is None:
        session_started = UTC_TIMEZONE.localize(session_started)
    
    if last_activity is None:
        last_activity = session_started
    elif last_activity.tzinfo is None:
        last_activity = UTC_TIMEZONE.localize(last_activity)
    
    # Determine timeout duration
    if timeout_duration is not None:
        duration = timeout_duration
    elif remember_me:
        duration = SESSION_TIMEOUT_REMEMBER_ME
    else:
        duration = SESSION_TIMEOUT_DEFAULT
    
    # Calculate session expiration based on last activity
    expires_at = last_activity + datetime.timedelta(seconds=duration)
    current_time = get_utc_now()
    remaining_seconds = max(0, int((expires_at - current_time).total_seconds()))
    is_expired = current_time >= expires_at
    
    # Calculate total session duration for security analysis
    total_duration = int((current_time - session_started).total_seconds())
    
    # Record session pattern for security monitoring
    if hasattr(g, 'user_id') and g.user_id:
        security_monitor.analyze_session_pattern(g.user_id, total_duration)
    
    logger.debug(
        "Session timeout calculated",
        session_started=session_started.isoformat(),
        last_activity=last_activity.isoformat(),
        expires_at=expires_at.isoformat(),
        remaining_seconds=remaining_seconds,
        is_expired=is_expired,
        remember_me=remember_me
    )
    
    return SessionTimeoutInfo(
        session_started=session_started,
        last_activity=last_activity,
        timeout_duration=duration,
        expires_at=expires_at,
        is_expired=is_expired,
        remaining_seconds=remaining_seconds,
        remember_me=remember_me
    )


def validate_session_timestamp(
    session_info: SessionTimeoutInfo,
    grace_period_seconds: int = 60
) -> TimeValidationResult:
    """
    Validate session timestamp with grace period for user experience.
    
    Args:
        session_info: Session timeout information
        grace_period_seconds: Grace period for expired sessions
        
    Returns:
        TimeValidationResult indicating session validity
    """
    if session_info.is_expired:
        # Check if within grace period
        grace_cutoff = session_info.expires_at + datetime.timedelta(seconds=grace_period_seconds)
        if get_utc_now() <= grace_cutoff:
            logger.debug(
                "Session expired but within grace period",
                expires_at=session_info.expires_at.isoformat(),
                grace_period_seconds=grace_period_seconds
            )
            return TimeValidationResult.VALID
        else:
            return TimeValidationResult.EXPIRED
    
    return TimeValidationResult.VALID


def detect_time_based_attack_patterns(
    user_identifier: str,
    action_type: str,
    timestamp: Optional[datetime.datetime] = None
) -> Dict[str, Any]:
    """
    Detect time-based security attack patterns for threat analysis.
    
    This function analyzes temporal patterns in authentication activities
    to identify potential security threats, brute force attacks, and
    suspicious behaviors that warrant further investigation.
    
    Args:
        user_identifier: User or IP identifier
        action_type: Type of action ('login', 'token_refresh', 'logout')
        timestamp: Optional timestamp (defaults to current time)
        
    Returns:
        Dictionary with pattern analysis results and threat indicators
        
    Security Compliance:
        - Section 6.4.6.1: Time-based security pattern detection
    """
    if timestamp is None:
        timestamp = get_utc_now()
    
    analysis_result = {
        "identifier": user_identifier,
        "action_type": action_type,
        "timestamp": timestamp.isoformat(),
        "is_suspicious": False,
        "threat_level": "low",
        "patterns_detected": []
    }
    
    try:
        if action_type == 'login':
            is_normal = security_monitor.record_login_attempt(user_identifier, timestamp)
            if not is_normal:
                analysis_result.update({
                    "is_suspicious": True,
                    "threat_level": "high",
                    "patterns_detected": ["rapid_login_attempts"]
                })
        
        elif action_type == 'token_refresh':
            is_normal = security_monitor.record_token_refresh(user_identifier, timestamp)
            if not is_normal:
                analysis_result.update({
                    "is_suspicious": True,
                    "threat_level": "medium",
                    "patterns_detected": ["excessive_token_refresh"]
                })
        
        # Additional pattern analysis can be added here
        # e.g., unusual timing patterns, geographic inconsistencies, etc.
        
        logger.debug(
            "Time-based pattern analysis completed",
            **analysis_result
        )
        
    except Exception as e:
        logger.error(
            "Error in time-based pattern detection",
            user_identifier=user_identifier,
            action_type=action_type,
            error=str(e)
        )
        analysis_result["error"] = str(e)
    
    return analysis_result


def generate_secure_timestamp_hash(
    timestamp: datetime.datetime,
    secret_key: Optional[str] = None,
    additional_data: Optional[str] = None
) -> str:
    """
    Generate a secure hash of timestamp for integrity verification.
    
    This function creates a cryptographic hash of timestamp data that
    can be used to verify timestamp integrity in audit logs and
    security monitoring systems.
    
    Args:
        timestamp: Timestamp to hash
        secret_key: Secret key for HMAC (uses Flask secret if not provided)
        additional_data: Additional data to include in hash
        
    Returns:
        Hex-encoded hash string
        
    Security Compliance:
        - Section 6.4.2.5: Authentication audit trail timestamp consistency
    """
    try:
        if secret_key is None:
            secret_key = current_app.secret_key
        
        # Prepare data for hashing
        timestamp_str = timestamp.isoformat()
        data_to_hash = timestamp_str
        
        if additional_data:
            data_to_hash += f"|{additional_data}"
        
        # Generate HMAC hash
        hash_value = hmac.new(
            secret_key.encode('utf-8'),
            data_to_hash.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        logger.debug(
            "Secure timestamp hash generated",
            timestamp=timestamp_str,
            has_additional_data=additional_data is not None
        )
        
        return hash_value
        
    except Exception as e:
        logger.error(
            "Error generating secure timestamp hash",
            timestamp=timestamp.isoformat() if timestamp else None,
            error=str(e)
        )
        raise


def parse_iso_timestamp(
    iso_string: str,
    default_timezone: Optional[str] = None
) -> datetime.datetime:
    """
    Parse ISO 8601 timestamp string with timezone handling.
    
    This function provides robust parsing of timestamp strings from
    various sources while maintaining timezone awareness and consistency.
    
    Args:
        iso_string: ISO 8601 formatted timestamp string
        default_timezone: Default timezone if none specified in string
        
    Returns:
        Parsed datetime object with timezone information
        
    Raises:
        ValueError: If timestamp string cannot be parsed
    """
    try:
        # Try parsing with built-in fromisoformat (Python 3.7+)
        dt = datetime.datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
        
        # Add timezone if naive
        if dt.tzinfo is None:
            if default_timezone:
                tz = get_timezone(default_timezone)
                dt = tz.localize(dt)
            else:
                dt = UTC_TIMEZONE.localize(dt)
        
        return dt
        
    except ValueError as e:
        logger.error(
            "Failed to parse ISO timestamp",
            iso_string=iso_string,
            error=str(e)
        )
        raise ValueError(f"Invalid timestamp format: {iso_string}")


def get_session_expiry_warning_time(
    session_info: SessionTimeoutInfo,
    warning_minutes: int = 5
) -> Optional[datetime.datetime]:
    """
    Calculate when to show session expiry warning to users.
    
    Args:
        session_info: Session timeout information
        warning_minutes: Minutes before expiration to show warning
        
    Returns:
        Datetime when warning should be shown, or None if session expired
    """
    if session_info.is_expired:
        return None
    
    warning_time = session_info.expires_at - datetime.timedelta(minutes=warning_minutes)
    
    # Only return warning time if it's in the future
    if warning_time > get_utc_now():
        return warning_time
    
    return None


def format_timestamp_for_client(
    timestamp: datetime.datetime,
    client_timezone: Optional[str] = None,
    format_string: str = "%Y-%m-%d %H:%M:%S %Z"
) -> str:
    """
    Format timestamp for client display with timezone conversion.
    
    Args:
        timestamp: Timestamp to format
        client_timezone: Client's preferred timezone
        format_string: Python datetime format string
        
    Returns:
        Formatted timestamp string
    """
    if client_timezone:
        try:
            client_tz = get_timezone(client_timezone)
            display_time = timestamp.astimezone(client_tz)
        except Exception:
            display_time = timestamp.astimezone(UTC_TIMEZONE)
    else:
        display_time = timestamp.astimezone(UTC_TIMEZONE)
    
    return display_time.strftime(format_string)


# Export public interface
__all__ = [
    'get_utc_now',
    'get_local_now',
    'generate_audit_timestamp',
    'calculate_jwt_expiration',
    'validate_jwt_timestamp',
    'calculate_session_timeout',
    'validate_session_timestamp',
    'detect_time_based_attack_patterns',
    'generate_secure_timestamp_hash',
    'parse_iso_timestamp',
    'get_session_expiry_warning_time',
    'format_timestamp_for_client',
    'TimestampResult',
    'TokenExpirationInfo',
    'SessionTimeoutInfo',
    'TimeValidationResult',
    'TimezoneMode',
    'TimeBasedSecurityMonitor'
]