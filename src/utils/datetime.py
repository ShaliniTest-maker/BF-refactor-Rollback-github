"""
Date and time utility functions providing timezone-aware datetime operations,
timestamp formatting, and temporal calculations for the Flask application.

This module offers consistent datetime handling across the Flask application with 
support for UTC normalization, timezone conversion, and datetime serialization 
that supports audit logging and business logic requirements.

Key Features:
- Timezone-aware datetime operations for global deployment (Section 6.4.2.5)
- UTC timestamp standardization for audit trails (Section 5.4.2)
- Datetime formatting for API response consistency (Section 4.3)
- Temporal calculations for business logic operations (Section 2.1)
- Datetime validation and type conversion utilities (Section 5.2.3)

Dependencies:
- Python 3.13.3 datetime and zoneinfo modules
- Flask 3.1.1 for request context integration
- pytz for comprehensive timezone support
"""

import datetime
import re
from typing import Optional, Union, Dict, Any, List, Tuple
from zoneinfo import ZoneInfo
import pytz
from dateutil import parser as dateutil_parser
from dateutil.relativedelta import relativedelta
import calendar
import math

# Flask integration for request context
try:
    from flask import current_app, g, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Logging integration
import logging
logger = logging.getLogger(__name__)


class DateTimeError(Exception):
    """Base exception for datetime utility errors."""
    pass


class InvalidTimezoneError(DateTimeError):
    """Raised when an invalid timezone is provided."""
    pass


class InvalidDateFormatError(DateTimeError):
    """Raised when a date string cannot be parsed."""
    pass


class DateTimeValidator:
    """
    Comprehensive datetime validation and parsing utilities.
    
    Provides validation for various datetime formats, timezone validation,
    and secure datetime parsing for API inputs.
    """
    
    # Common datetime format patterns for API validation
    ISO_8601_PATTERNS = [
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z?$',
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?[+-]\d{2}:\d{2}$',
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?[+-]\d{4}$',
    ]
    
    DATE_PATTERNS = [
        r'^\d{4}-\d{2}-\d{2}$',  # YYYY-MM-DD
        r'^\d{2}/\d{2}/\d{4}$',  # MM/DD/YYYY
        r'^\d{2}-\d{2}-\d{4}$',  # MM-DD-YYYY
    ]
    
    TIME_PATTERNS = [
        r'^\d{2}:\d{2}:\d{2}(\.\d{1,6})?$',  # HH:MM:SS.microseconds
        r'^\d{2}:\d{2}$',  # HH:MM
    ]
    
    @classmethod
    def validate_iso8601(cls, datetime_string: str) -> bool:
        """
        Validate if a string matches ISO 8601 datetime format.
        
        Args:
            datetime_string: String to validate
            
        Returns:
            True if valid ISO 8601 format, False otherwise
        """
        if not isinstance(datetime_string, str):
            return False
            
        return any(re.match(pattern, datetime_string) 
                  for pattern in cls.ISO_8601_PATTERNS)
    
    @classmethod
    def validate_date_format(cls, date_string: str) -> bool:
        """
        Validate if a string matches common date formats.
        
        Args:
            date_string: String to validate
            
        Returns:
            True if valid date format, False otherwise
        """
        if not isinstance(date_string, str):
            return False
            
        return any(re.match(pattern, date_string) 
                  for pattern in cls.DATE_PATTERNS)
    
    @classmethod
    def validate_time_format(cls, time_string: str) -> bool:
        """
        Validate if a string matches common time formats.
        
        Args:
            time_string: String to validate
            
        Returns:
            True if valid time format, False otherwise
        """
        if not isinstance(time_string, str):
            return False
            
        return any(re.match(pattern, time_string) 
                  for pattern in cls.TIME_PATTERNS)
    
    @classmethod
    def validate_timezone(cls, timezone_string: str) -> bool:
        """
        Validate if a timezone string is valid.
        
        Args:
            timezone_string: Timezone identifier to validate
            
        Returns:
            True if valid timezone, False otherwise
        """
        try:
            if timezone_string in pytz.all_timezones:
                return True
            # Also check zoneinfo compatibility (Python 3.9+)
            ZoneInfo(timezone_string)
            return True
        except (pytz.UnknownTimeZoneError, Exception):
            return False


class DateTimeFormatter:
    """
    Datetime formatting utilities for API responses and audit logging.
    
    Provides consistent formatting patterns across the Flask application
    for API responses, audit trails, and user interface display.
    """
    
    # Standard format patterns for different use cases
    API_RESPONSE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
    AUDIT_LOG_FORMAT = '%Y-%m-%dT%H:%M:%S.%f+00:00'
    USER_DISPLAY_FORMAT = '%Y-%m-%d %H:%M:%S'
    DATE_ONLY_FORMAT = '%Y-%m-%d'
    TIME_ONLY_FORMAT = '%H:%M:%S'
    COMPACT_FORMAT = '%Y%m%d_%H%M%S'
    
    @classmethod
    def to_api_response(cls, dt: datetime.datetime) -> str:
        """
        Format datetime for API responses (ISO 8601 UTC).
        
        Ensures consistent datetime formatting across all API endpoints
        for client application compatibility.
        
        Args:
            dt: Datetime object to format
            
        Returns:
            ISO 8601 formatted string in UTC
            
        Raises:
            DateTimeError: If datetime cannot be formatted
        """
        try:
            if dt is None:
                return None
            
            # Ensure UTC timezone
            utc_dt = DateTimeConverter.to_utc(dt)
            return utc_dt.strftime(cls.API_RESPONSE_FORMAT)
        except Exception as e:
            logger.error(f"Failed to format datetime for API response: {e}")
            raise DateTimeError(f"Unable to format datetime: {e}")
    
    @classmethod
    def to_audit_log(cls, dt: datetime.datetime) -> str:
        """
        Format datetime for audit logging with timezone information.
        
        Used for security audit trails and compliance logging
        as specified in Section 6.4.2.5.
        
        Args:
            dt: Datetime object to format
            
        Returns:
            Formatted string for audit logs
            
        Raises:
            DateTimeError: If datetime cannot be formatted
        """
        try:
            if dt is None:
                return None
                
            # Ensure UTC for audit consistency
            utc_dt = DateTimeConverter.to_utc(dt)
            return utc_dt.strftime(cls.AUDIT_LOG_FORMAT)
        except Exception as e:
            logger.error(f"Failed to format datetime for audit log: {e}")
            raise DateTimeError(f"Unable to format datetime for audit: {e}")
    
    @classmethod
    def to_user_display(cls, dt: datetime.datetime, 
                       timezone: str = 'UTC') -> str:
        """
        Format datetime for user interface display in specified timezone.
        
        Args:
            dt: Datetime object to format
            timezone: Target timezone for display (default: UTC)
            
        Returns:
            User-friendly formatted string
            
        Raises:
            DateTimeError: If datetime cannot be formatted
            InvalidTimezoneError: If timezone is invalid
        """
        try:
            if dt is None:
                return None
                
            # Convert to target timezone
            target_dt = DateTimeConverter.to_timezone(dt, timezone)
            formatted = target_dt.strftime(cls.USER_DISPLAY_FORMAT)
            
            # Include timezone info if not UTC
            if timezone != 'UTC':
                formatted += f" {timezone}"
                
            return formatted
        except InvalidTimezoneError:
            raise
        except Exception as e:
            logger.error(f"Failed to format datetime for user display: {e}")
            raise DateTimeError(f"Unable to format datetime: {e}")
    
    @classmethod
    def to_compact(cls, dt: datetime.datetime) -> str:
        """
        Format datetime for compact representation (filenames, IDs).
        
        Args:
            dt: Datetime object to format
            
        Returns:
            Compact formatted string (YYYYMMDD_HHMMSS)
        """
        try:
            if dt is None:
                return None
                
            utc_dt = DateTimeConverter.to_utc(dt)
            return utc_dt.strftime(cls.COMPACT_FORMAT)
        except Exception as e:
            logger.error(f"Failed to format datetime compactly: {e}")
            raise DateTimeError(f"Unable to format datetime: {e}")


class DateTimeConverter:
    """
    Timezone-aware datetime conversion utilities.
    
    Provides conversion between timezones, UTC normalization,
    and parsing of various datetime formats.
    """
    
    @classmethod
    def to_utc(cls, dt: datetime.datetime) -> datetime.datetime:
        """
        Convert datetime to UTC timezone.
        
        Essential for audit logging and consistent timestamp storage
        as required by Section 5.4.2.
        
        Args:
            dt: Datetime object to convert
            
        Returns:
            Datetime object in UTC timezone
            
        Raises:
            DateTimeError: If conversion fails
        """
        try:
            if dt is None:
                return None
                
            if dt.tzinfo is None:
                # Assume naive datetime is UTC
                logger.warning("Converting naive datetime to UTC - assuming UTC")
                return dt.replace(tzinfo=datetime.timezone.utc)
            
            return dt.astimezone(datetime.timezone.utc)
        except Exception as e:
            logger.error(f"Failed to convert datetime to UTC: {e}")
            raise DateTimeError(f"UTC conversion failed: {e}")
    
    @classmethod
    def to_timezone(cls, dt: datetime.datetime, 
                   timezone: str) -> datetime.datetime:
        """
        Convert datetime to specified timezone.
        
        Args:
            dt: Datetime object to convert
            timezone: Target timezone identifier
            
        Returns:
            Datetime object in target timezone
            
        Raises:
            InvalidTimezoneError: If timezone is invalid
            DateTimeError: If conversion fails
        """
        try:
            if dt is None:
                return None
                
            # Validate timezone
            if not DateTimeValidator.validate_timezone(timezone):
                raise InvalidTimezoneError(f"Invalid timezone: {timezone}")
            
            # Ensure datetime has timezone info
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            
            # Convert using zoneinfo (preferred for Python 3.9+)
            try:
                target_tz = ZoneInfo(timezone)
                return dt.astimezone(target_tz)
            except Exception:
                # Fallback to pytz
                target_tz = pytz.timezone(timezone)
                return dt.astimezone(target_tz)
                
        except InvalidTimezoneError:
            raise
        except Exception as e:
            logger.error(f"Failed to convert datetime to timezone {timezone}: {e}")
            raise DateTimeError(f"Timezone conversion failed: {e}")
    
    @classmethod
    def parse_datetime(cls, datetime_string: str, 
                      default_timezone: str = 'UTC') -> datetime.datetime:
        """
        Parse datetime string with automatic format detection.
        
        Supports various datetime formats including ISO 8601, RFC 3339,
        and common human-readable formats.
        
        Args:
            datetime_string: String to parse
            default_timezone: Default timezone if none specified
            
        Returns:
            Parsed datetime object with timezone information
            
        Raises:
            InvalidDateFormatError: If string cannot be parsed
            InvalidTimezoneError: If default timezone is invalid
        """
        try:
            if not datetime_string:
                return None
                
            # Validate default timezone
            if not DateTimeValidator.validate_timezone(default_timezone):
                raise InvalidTimezoneError(f"Invalid default timezone: {default_timezone}")
            
            # Use dateutil parser for flexible parsing
            parsed_dt = dateutil_parser.parse(datetime_string)
            
            # If no timezone info, apply default timezone
            if parsed_dt.tzinfo is None:
                default_tz = ZoneInfo(default_timezone)
                parsed_dt = parsed_dt.replace(tzinfo=default_tz)
            
            return parsed_dt
            
        except (ValueError, dateutil_parser.ParserError) as e:
            logger.error(f"Failed to parse datetime string '{datetime_string}': {e}")
            raise InvalidDateFormatError(f"Unable to parse datetime: {e}")
        except InvalidTimezoneError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error parsing datetime: {e}")
            raise DateTimeError(f"Datetime parsing failed: {e}")
    
    @classmethod
    def from_timestamp(cls, timestamp: Union[int, float], 
                      timezone: str = 'UTC') -> datetime.datetime:
        """
        Convert Unix timestamp to datetime object.
        
        Args:
            timestamp: Unix timestamp (seconds since epoch)
            timezone: Target timezone for the datetime object
            
        Returns:
            Datetime object in specified timezone
            
        Raises:
            DateTimeError: If conversion fails
            InvalidTimezoneError: If timezone is invalid
        """
        try:
            if timestamp is None:
                return None
                
            # Validate timezone
            if not DateTimeValidator.validate_timezone(timezone):
                raise InvalidTimezoneError(f"Invalid timezone: {timezone}")
            
            # Create UTC datetime from timestamp
            utc_dt = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
            
            # Convert to target timezone if not UTC
            if timezone != 'UTC':
                return cls.to_timezone(utc_dt, timezone)
            
            return utc_dt
            
        except InvalidTimezoneError:
            raise
        except Exception as e:
            logger.error(f"Failed to convert timestamp {timestamp}: {e}")
            raise DateTimeError(f"Timestamp conversion failed: {e}")
    
    @classmethod
    def to_timestamp(cls, dt: datetime.datetime) -> float:
        """
        Convert datetime object to Unix timestamp.
        
        Args:
            dt: Datetime object to convert
            
        Returns:
            Unix timestamp (seconds since epoch)
            
        Raises:
            DateTimeError: If conversion fails
        """
        try:
            if dt is None:
                return None
                
            # Ensure timezone-aware datetime
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
                
            return dt.timestamp()
            
        except Exception as e:
            logger.error(f"Failed to convert datetime to timestamp: {e}")
            raise DateTimeError(f"Timestamp conversion failed: {e}")


class TemporalCalculator:
    """
    Temporal calculations and business logic utilities.
    
    Provides date arithmetic, business day calculations, age calculations,
    and other temporal operations required for business logic.
    """
    
    @classmethod
    def add_business_days(cls, start_date: datetime.date, 
                         business_days: int) -> datetime.date:
        """
        Add business days to a date (excluding weekends).
        
        Args:
            start_date: Starting date
            business_days: Number of business days to add
            
        Returns:
            Date after adding business days
        """
        try:
            current_date = start_date
            days_added = 0
            
            while days_added < business_days:
                current_date += datetime.timedelta(days=1)
                # Monday = 0, Sunday = 6
                if current_date.weekday() < 5:  # Monday to Friday
                    days_added += 1
                    
            return current_date
            
        except Exception as e:
            logger.error(f"Failed to add business days: {e}")
            raise DateTimeError(f"Business day calculation failed: {e}")
    
    @classmethod
    def calculate_age(cls, birth_date: datetime.date, 
                     reference_date: Optional[datetime.date] = None) -> int:
        """
        Calculate age in years from birth date.
        
        Args:
            birth_date: Date of birth
            reference_date: Reference date for calculation (default: today)
            
        Returns:
            Age in years
        """
        try:
            if reference_date is None:
                reference_date = datetime.date.today()
                
            age = reference_date.year - birth_date.year
            
            # Adjust if birthday hasn't occurred this year
            if (reference_date.month, reference_date.day) < (birth_date.month, birth_date.day):
                age -= 1
                
            return age
            
        except Exception as e:
            logger.error(f"Failed to calculate age: {e}")
            raise DateTimeError(f"Age calculation failed: {e}")
    
    @classmethod
    def get_date_range(cls, start_date: datetime.date, 
                      end_date: datetime.date) -> List[datetime.date]:
        """
        Generate list of dates between start and end dates (inclusive).
        
        Args:
            start_date: Starting date
            end_date: Ending date
            
        Returns:
            List of dates in the range
        """
        try:
            date_list = []
            current_date = start_date
            
            while current_date <= end_date:
                date_list.append(current_date)
                current_date += datetime.timedelta(days=1)
                
            return date_list
            
        except Exception as e:
            logger.error(f"Failed to generate date range: {e}")
            raise DateTimeError(f"Date range generation failed: {e}")
    
    @classmethod
    def get_month_boundaries(cls, dt: datetime.datetime) -> Tuple[datetime.datetime, datetime.datetime]:
        """
        Get start and end of month for given datetime.
        
        Args:
            dt: Reference datetime
            
        Returns:
            Tuple of (month_start, month_end) datetimes
        """
        try:
            # First day of month
            month_start = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # Last day of month
            last_day = calendar.monthrange(dt.year, dt.month)[1]
            month_end = dt.replace(day=last_day, hour=23, minute=59, second=59, microsecond=999999)
            
            return month_start, month_end
            
        except Exception as e:
            logger.error(f"Failed to get month boundaries: {e}")
            raise DateTimeError(f"Month boundary calculation failed: {e}")
    
    @classmethod
    def add_relative_time(cls, dt: datetime.datetime, 
                         **kwargs) -> datetime.datetime:
        """
        Add relative time periods to datetime using dateutil.relativedelta.
        
        Args:
            dt: Base datetime
            **kwargs: Keyword arguments for relativedelta (years, months, days, etc.)
            
        Returns:
            Datetime with relative time added
        """
        try:
            return dt + relativedelta(**kwargs)
            
        except Exception as e:
            logger.error(f"Failed to add relative time: {e}")
            raise DateTimeError(f"Relative time calculation failed: {e}")
    
    @classmethod
    def time_until_expiration(cls, expiration_dt: datetime.datetime) -> Dict[str, int]:
        """
        Calculate time remaining until expiration datetime.
        
        Args:
            expiration_dt: Expiration datetime
            
        Returns:
            Dictionary with days, hours, minutes, seconds until expiration
        """
        try:
            now = DateTimeConverter.to_utc(datetime.datetime.now())
            expiration_utc = DateTimeConverter.to_utc(expiration_dt)
            
            if expiration_utc <= now:
                return {'days': 0, 'hours': 0, 'minutes': 0, 'seconds': 0, 'expired': True}
            
            delta = expiration_utc - now
            
            days = delta.days
            seconds = delta.seconds
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            remaining_seconds = seconds % 60
            
            return {
                'days': days,
                'hours': hours,
                'minutes': minutes,
                'seconds': remaining_seconds,
                'expired': False
            }
            
        except Exception as e:
            logger.error(f"Failed to calculate time until expiration: {e}")
            raise DateTimeError(f"Expiration calculation failed: {e}")


class TimestampGenerator:
    """
    UTC timestamp generation utilities for audit logging and system tracking.
    
    Provides consistent timestamp generation for audit trails, logging,
    and system event tracking as required by Section 5.4.2.
    """
    
    @classmethod
    def now_utc(cls) -> datetime.datetime:
        """
        Generate current UTC timestamp.
        
        Returns:
            Current datetime in UTC timezone
        """
        return datetime.datetime.now(datetime.timezone.utc)
    
    @classmethod
    def now_iso(cls) -> str:
        """
        Generate current UTC timestamp in ISO 8601 format.
        
        Returns:
            Current timestamp as ISO 8601 string
        """
        return DateTimeFormatter.to_api_response(cls.now_utc())
    
    @classmethod
    def audit_timestamp(cls) -> str:
        """
        Generate audit log timestamp in standardized format.
        
        Returns:
            Current timestamp formatted for audit logs
        """
        return DateTimeFormatter.to_audit_log(cls.now_utc())
    
    @classmethod
    def request_timestamp(cls) -> datetime.datetime:
        """
        Generate timestamp for current Flask request context.
        
        Integrates with Flask request context for consistent
        request-scoped timestamps.
        
        Returns:
            UTC timestamp for current request
        """
        if FLASK_AVAILABLE and g:
            # Store request timestamp in Flask g context
            if not hasattr(g, 'request_timestamp'):
                g.request_timestamp = cls.now_utc()
            return g.request_timestamp
        
        return cls.now_utc()
    
    @classmethod
    def correlation_id_timestamp(cls) -> str:
        """
        Generate timestamp-based correlation ID for request tracking.
        
        Returns:
            Compact timestamp for correlation IDs
        """
        return DateTimeFormatter.to_compact(cls.now_utc())


# Convenience functions for common operations
def now_utc() -> datetime.datetime:
    """Get current UTC datetime."""
    return TimestampGenerator.now_utc()


def now_iso() -> str:
    """Get current UTC datetime as ISO 8601 string."""
    return TimestampGenerator.now_iso()


def parse_datetime(datetime_string: str, default_timezone: str = 'UTC') -> datetime.datetime:
    """Parse datetime string with automatic format detection."""
    return DateTimeConverter.parse_datetime(datetime_string, default_timezone)


def format_for_api(dt: datetime.datetime) -> str:
    """Format datetime for API response."""
    return DateTimeFormatter.to_api_response(dt)


def format_for_audit(dt: datetime.datetime) -> str:
    """Format datetime for audit logging."""
    return DateTimeFormatter.to_audit_log(dt)


def to_utc(dt: datetime.datetime) -> datetime.datetime:
    """Convert datetime to UTC."""
    return DateTimeConverter.to_utc(dt)


def to_timezone(dt: datetime.datetime, timezone: str) -> datetime.datetime:
    """Convert datetime to specified timezone."""
    return DateTimeConverter.to_timezone(dt, timezone)


def validate_iso8601(datetime_string: str) -> bool:
    """Validate ISO 8601 datetime format."""
    return DateTimeValidator.validate_iso8601(datetime_string)


def add_business_days(start_date: datetime.date, business_days: int) -> datetime.date:
    """Add business days to a date."""
    return TemporalCalculator.add_business_days(start_date, business_days)


def calculate_age(birth_date: datetime.date, reference_date: Optional[datetime.date] = None) -> int:
    """Calculate age in years."""
    return TemporalCalculator.calculate_age(birth_date, reference_date)


# Flask integration helper
def get_request_timezone() -> str:
    """
    Get timezone from Flask request context.
    
    Checks request headers and user preferences for timezone information.
    Falls back to UTC if no timezone information is available.
    
    Returns:
        Timezone identifier string
    """
    if not FLASK_AVAILABLE:
        return 'UTC'
    
    try:
        # Check Accept-Timezone header
        if request and hasattr(request, 'headers'):
            timezone_header = request.headers.get('Accept-Timezone')
            if timezone_header and DateTimeValidator.validate_timezone(timezone_header):
                return timezone_header
        
        # Check user preferences in Flask g context
        if g and hasattr(g, 'user_timezone'):
            if DateTimeValidator.validate_timezone(g.user_timezone):
                return g.user_timezone
        
        # Default to UTC
        return 'UTC'
        
    except Exception as e:
        logger.warning(f"Failed to get request timezone: {e}")
        return 'UTC'


# Security utilities for datetime validation in API inputs
def sanitize_datetime_input(user_input: str) -> Optional[datetime.datetime]:
    """
    Safely parse and validate datetime input from API requests.
    
    Performs security validation and safe parsing of datetime
    strings from untrusted sources.
    
    Args:
        user_input: User-provided datetime string
        
    Returns:
        Parsed and validated datetime object or None if invalid
    """
    try:
        # Basic input validation
        if not user_input or not isinstance(user_input, str):
            return None
        
        # Limit input length to prevent DoS
        if len(user_input) > 100:
            logger.warning(f"Datetime input too long: {len(user_input)} characters")
            return None
        
        # Validate format before parsing
        if not DateTimeValidator.validate_iso8601(user_input):
            logger.warning(f"Invalid datetime format: {user_input}")
            return None
        
        # Parse with security constraints
        parsed_dt = DateTimeConverter.parse_datetime(user_input)
        
        # Validate reasonable date range (1900-2200)
        if parsed_dt.year < 1900 or parsed_dt.year > 2200:
            logger.warning(f"Datetime year out of range: {parsed_dt.year}")
            return None
        
        return parsed_dt
        
    except Exception as e:
        logger.warning(f"Failed to sanitize datetime input '{user_input}': {e}")
        return None