"""
Structured Logging Utilities for Flask Application

This module provides comprehensive logging capabilities implementing structured JSON logging,
audit trail generation, security event monitoring, and AWS CloudWatch integration for the
Flask 3.1.1 application migrated from Node.js. The module integrates with OpenTelemetry
for distributed tracing, supports correlation ID generation, and provides enterprise-grade
logging patterns for compliance, security monitoring, and operational observability.

Key Features:
- Structured JSON logging with Python structlog library
- Audit trail generation for regulatory compliance
- Security event logging for threat detection
- AWS CloudWatch Logs integration with FluentD support
- Request correlation and distributed tracing
- Flask application factory pattern integration
- Performance monitoring and anomaly detection
- Container orchestration logging support

Requirements:
- Python 3.13.3 runtime compatibility
- Flask 3.1.1 application factory integration
- structlog library for structured logging
- AWS CloudWatch Logs integration
- OpenTelemetry distributed tracing support
- Prometheus metrics integration
"""

import structlog
import logging
import logging.config
import json
import uuid
import time
import traceback
import sys
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union, List
from enum import Enum
from dataclasses import dataclass, asdict
from functools import wraps
from contextlib import contextmanager
import threading
from collections import defaultdict, deque

# Flask imports
from flask import Flask, request, g, current_app, has_request_context
from werkzeug.local import LocalProxy

# AWS and monitoring imports
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

# OpenTelemetry imports for distributed tracing
try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
    from opentelemetry.instrumentation.logging import LoggingInstrumentor
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False

# Prometheus metrics for logging performance
try:
    from prometheus_client import Counter, Histogram, Gauge
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


class LogLevel(Enum):
    """Standard log levels with numeric values for filtering and routing."""
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class LogCategory(Enum):
    """Log categories for enhanced routing and filtering in enterprise environments."""
    APPLICATION = "application"
    SECURITY = "security"
    AUDIT = "audit"
    PERFORMANCE = "performance"
    ERROR = "error"
    BUSINESS = "business"
    INFRASTRUCTURE = "infrastructure"


class SecurityEventType(Enum):
    """Security event types for threat detection and incident response."""
    AUTHENTICATION_SUCCESS = "auth_success"
    AUTHENTICATION_FAILURE = "auth_failure"
    AUTHORIZATION_FAILURE = "authz_failure"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    DATA_ACCESS = "data_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    SESSION_ANOMALY = "session_anomaly"


@dataclass
class LogContext:
    """
    Structured log context containing request and application metadata.
    
    This class encapsulates all contextual information that should be included
    with log entries for enhanced observability and debugging capabilities.
    """
    request_id: str
    correlation_id: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    blueprint: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: str = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class AuditLogEntry:
    """
    Audit log entry structure for compliance and regulatory requirements.
    
    This structure ensures comprehensive audit trail generation with all
    required fields for security monitoring and compliance validation.
    """
    event_type: str
    user_id: Optional[str]
    resource: Optional[str]
    action: str
    outcome: str  # success, failure, error
    timestamp: str
    context: LogContext
    details: Optional[Dict[str, Any]] = None
    risk_score: Optional[int] = None  # 0-100 security risk assessment
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class SecurityEvent:
    """
    Security event structure for threat detection and incident response.
    
    This structure captures detailed security-related events for analysis
    by security monitoring systems and incident response procedures.
    """
    event_type: SecurityEventType
    severity: str  # low, medium, high, critical
    description: str
    user_id: Optional[str]
    source_ip: Optional[str]
    context: LogContext
    indicators: List[str] = None  # IoCs or suspicious patterns
    threat_score: Optional[int] = None  # 0-100 threat assessment
    remediation_actions: List[str] = None
    
    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []
        if self.remediation_actions is None:
            self.remediation_actions = []


class LoggerMetrics:
    """
    Prometheus metrics for logging system performance monitoring.
    
    Tracks logging volume, performance, and error rates to ensure
    logging infrastructure operates within performance requirements.
    """
    
    def __init__(self):
        if PROMETHEUS_AVAILABLE:
            self.log_entries_total = Counter(
                'flask_log_entries_total',
                'Total number of log entries by level and category',
                ['level', 'category', 'blueprint']
            )
            
            self.log_processing_duration = Histogram(
                'flask_log_processing_seconds',
                'Time spent processing log entries',
                ['level', 'category']
            )
            
            self.audit_events_total = Counter(
                'flask_audit_events_total',
                'Total number of audit events by type and outcome',
                ['event_type', 'outcome', 'user_id']
            )
            
            self.security_events_total = Counter(
                'flask_security_events_total',
                'Total number of security events by type and severity',
                ['event_type', 'severity', 'threat_score_range']
            )
            
            self.cloudwatch_log_errors = Counter(
                'flask_cloudwatch_log_errors_total',
                'Total number of CloudWatch logging errors',
                ['error_type']
            )
            
            self.correlation_id_usage = Gauge(
                'flask_active_correlation_ids',
                'Number of active correlation IDs being tracked'
            )
        else:
            # Placeholder metrics when Prometheus is not available
            self.log_entries_total = None
            self.log_processing_duration = None
            self.audit_events_total = None
            self.security_events_total = None
            self.cloudwatch_log_errors = None
            self.correlation_id_usage = None
    
    def record_log_entry(self, level: str, category: str, blueprint: str = "unknown"):
        """Record a log entry metric."""
        if self.log_entries_total:
            self.log_entries_total.labels(
                level=level,
                category=category,
                blueprint=blueprint
            ).inc()
    
    def record_processing_time(self, duration: float, level: str, category: str):
        """Record log processing duration."""
        if self.log_processing_duration:
            self.log_processing_duration.labels(
                level=level,
                category=category
            ).observe(duration)
    
    def record_audit_event(self, event_type: str, outcome: str, user_id: str = "anonymous"):
        """Record an audit event metric."""
        if self.audit_events_total:
            self.audit_events_total.labels(
                event_type=event_type,
                outcome=outcome,
                user_id=user_id
            ).inc()
    
    def record_security_event(self, event_type: str, severity: str, threat_score: int = 0):
        """Record a security event metric."""
        if self.security_events_total:
            # Categorize threat scores into ranges for metrics
            if threat_score >= 80:
                score_range = "critical"
            elif threat_score >= 60:
                score_range = "high"
            elif threat_score >= 40:
                score_range = "medium"
            else:
                score_range = "low"
            
            self.security_events_total.labels(
                event_type=event_type,
                severity=severity,
                threat_score_range=score_range
            ).inc()
    
    def record_cloudwatch_error(self, error_type: str):
        """Record a CloudWatch logging error."""
        if self.cloudwatch_log_errors:
            self.cloudwatch_log_errors.labels(error_type=error_type).inc()
    
    def update_correlation_ids(self, count: int):
        """Update the count of active correlation IDs."""
        if self.correlation_id_usage:
            self.correlation_id_usage.set(count)


class CloudWatchLogger:
    """
    AWS CloudWatch Logs integration for centralized log aggregation.
    
    Provides direct integration with AWS CloudWatch Logs service for
    enterprise-grade log aggregation, retention, and monitoring capabilities.
    Supports both direct CloudWatch API calls and FluentD/FireLens routing.
    """
    
    def __init__(self, log_group: str, log_stream: str = None, region: str = 'us-east-1'):
        self.log_group = log_group
        self.log_stream = log_stream or f"flask-app-{os.getenv('HOSTNAME', 'unknown')}"
        self.region = region
        self.client = None
        self.sequence_token = None
        self.enabled = AWS_AVAILABLE and bool(os.getenv('AWS_CLOUDWATCH_ENABLED', 'false').lower() == 'true')
        
        if self.enabled:
            try:
                self.client = boto3.client('logs', region_name=region)
                self._create_log_group_if_not_exists()
                self._create_log_stream_if_not_exists()
            except (NoCredentialsError, ClientError) as e:
                self.enabled = False
                print(f"CloudWatch logging disabled due to AWS error: {e}")
    
    def _create_log_group_if_not_exists(self):
        """Create CloudWatch log group if it doesn't exist."""
        try:
            self.client.create_log_group(logGroupName=self.log_group)
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                raise
    
    def _create_log_stream_if_not_exists(self):
        """Create CloudWatch log stream if it doesn't exist."""
        try:
            self.client.create_log_stream(
                logGroupName=self.log_group,
                logStreamName=self.log_stream
            )
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                raise
    
    def send_log_batch(self, log_events: List[Dict[str, Any]]):
        """
        Send a batch of log events to CloudWatch Logs.
        
        Args:
            log_events: List of log event dictionaries containing timestamp and message
        """
        if not self.enabled or not log_events:
            return
        
        try:
            # Sort events by timestamp (required by CloudWatch)
            sorted_events = sorted(log_events, key=lambda x: x['timestamp'])
            
            put_log_events_args = {
                'logGroupName': self.log_group,
                'logStreamName': self.log_stream,
                'logEvents': sorted_events
            }
            
            if self.sequence_token:
                put_log_events_args['sequenceToken'] = self.sequence_token
            
            response = self.client.put_log_events(**put_log_events_args)
            self.sequence_token = response.get('nextSequenceToken')
            
        except ClientError as e:
            print(f"CloudWatch logging error: {e}")
            # Don't raise to avoid affecting application flow
    
    def send_single_log(self, message: str, timestamp: int = None):
        """Send a single log message to CloudWatch."""
        if timestamp is None:
            timestamp = int(time.time() * 1000)  # CloudWatch expects milliseconds
        
        log_event = {
            'timestamp': timestamp,
            'message': message
        }
        
        self.send_log_batch([log_event])


class DistributedTracingIntegration:
    """
    OpenTelemetry distributed tracing integration for correlation tracking.
    
    Provides seamless integration with OpenTelemetry for distributed request
    tracing, correlation ID propagation, and enhanced observability across
    the Flask application and external service interactions.
    """
    
    def __init__(self):
        self.enabled = OTEL_AVAILABLE
        self.tracer = None
        
        if self.enabled:
            try:
                self.tracer = trace.get_tracer(__name__)
                # Initialize logging instrumentation
                LoggingInstrumentor().instrument()
            except Exception as e:
                self.enabled = False
                print(f"OpenTelemetry tracing disabled: {e}")
    
    def get_current_trace_context(self) -> Dict[str, str]:
        """Get current trace and span IDs for correlation."""
        if not self.enabled:
            return {}
        
        try:
            span = trace.get_current_span()
            if span and span.get_span_context().is_valid:
                span_context = span.get_span_context()
                return {
                    'trace_id': format(span_context.trace_id, '032x'),
                    'span_id': format(span_context.span_id, '016x')
                }
        except Exception:
            pass
        
        return {}
    
    def create_log_span(self, operation_name: str, log_level: str, category: str):
        """Create a span for logging operations."""
        if not self.enabled or not self.tracer:
            return None
        
        try:
            return self.tracer.start_span(
                f"log.{operation_name}",
                attributes={
                    "log.level": log_level,
                    "log.category": category,
                    "component": "logging"
                }
            )
        except Exception:
            return None
    
    def add_log_to_span(self, span, log_data: Dict[str, Any]):
        """Add log data as span attributes."""
        if not span:
            return
        
        try:
            # Add relevant log data as span attributes
            span.set_attribute("log.message", str(log_data.get('message', '')))
            span.set_attribute("log.timestamp", log_data.get('timestamp', ''))
            
            if 'user_id' in log_data:
                span.set_attribute("user.id", str(log_data['user_id']))
            
            if 'request_id' in log_data:
                span.set_attribute("request.id", str(log_data['request_id']))
                
        except Exception:
            pass


class StructuredLogger:
    """
    Main structured logging implementation using structlog and Flask integration.
    
    This class provides the core logging functionality with structured JSON output,
    Flask application factory integration, request context management, and
    comprehensive logging patterns for enterprise applications.
    """
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self.metrics = LoggerMetrics()
        self.cloudwatch = None
        self.tracing = DistributedTracingIntegration()
        self.correlation_tracker = defaultdict(set)
        self.correlation_lock = threading.Lock()
        
        # Initialize structlog configuration
        self._configure_structlog()
        
        # Get the structured logger instance
        self.logger = structlog.get_logger("flask_app")
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize logging with Flask application factory pattern."""
        self.app = app
        
        # Initialize CloudWatch integration if configured
        log_group = app.config.get('CLOUDWATCH_LOG_GROUP', '/aws/flask/application')
        log_stream = app.config.get('CLOUDWATCH_LOG_STREAM')
        aws_region = app.config.get('AWS_REGION', 'us-east-1')
        
        if app.config.get('CLOUDWATCH_LOGGING_ENABLED', False):
            self.cloudwatch = CloudWatchLogger(log_group, log_stream, aws_region)
        
        # Register request handlers for context management
        app.before_request(self._setup_request_context)
        app.teardown_request(self._cleanup_request_context)
        
        # Register error handlers for automatic error logging
        app.errorhandler(Exception)(self._handle_exception)
        
        # Store logger instance in app for easy access
        app.logger_instance = self
        
        # Initialize standard Python logging integration
        self._setup_python_logging_integration(app)
    
    def _configure_structlog(self):
        """Configure structlog for structured JSON logging."""
        shared_processors = [
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            self._add_flask_context,
            self._add_tracing_context,
        ]
        
        if os.getenv('FLASK_ENV') == 'development':
            # Pretty console output for development
            processors = shared_processors + [
                structlog.dev.ConsoleRenderer(colors=True)
            ]
        else:
            # JSON output for production
            processors = shared_processors + [
                structlog.processors.JSONRenderer()
            ]
        
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
            logger_factory=structlog.WriteLoggerFactory(),
            cache_logger_on_first_use=True,
        )
    
    def _add_flask_context(self, logger, name, event_dict):
        """Add Flask request context to log entries."""
        if has_request_context():
            try:
                # Add request-specific context
                event_dict.update({
                    'request_id': getattr(g, 'request_id', None),
                    'correlation_id': getattr(g, 'correlation_id', None),
                    'user_id': getattr(g, 'user_id', None),
                    'session_id': getattr(g, 'session_id', None),
                    'blueprint': request.blueprint,
                    'endpoint': request.endpoint,
                    'method': request.method,
                    'url': request.url,
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                })
            except Exception:
                # Don't fail logging if context extraction fails
                pass
        
        return event_dict
    
    def _add_tracing_context(self, logger, name, event_dict):
        """Add OpenTelemetry tracing context to log entries."""
        trace_context = self.tracing.get_current_trace_context()
        if trace_context:
            event_dict.update(trace_context)
        
        return event_dict
    
    def _setup_request_context(self):
        """Set up logging context for each Flask request."""
        # Generate unique request ID
        g.request_id = str(uuid.uuid4())
        
        # Generate or extract correlation ID
        correlation_id = request.headers.get('X-Correlation-ID') or str(uuid.uuid4())
        g.correlation_id = correlation_id
        
        # Extract user context if available
        g.user_id = getattr(g, 'current_user_id', None)
        g.session_id = getattr(g, 'session_id', None)
        
        # Track correlation ID
        with self.correlation_lock:
            self.correlation_tracker[correlation_id].add(g.request_id)
            self.metrics.update_correlation_ids(len(self.correlation_tracker))
        
        # Set structlog context variables
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=g.request_id,
            correlation_id=g.correlation_id,
            user_id=g.user_id,
            session_id=g.session_id,
        )
    
    def _cleanup_request_context(self, exception=None):
        """Clean up logging context after request completion."""
        try:
            # Clean up correlation tracking
            correlation_id = getattr(g, 'correlation_id', None)
            request_id = getattr(g, 'request_id', None)
            
            if correlation_id and request_id:
                with self.correlation_lock:
                    self.correlation_tracker[correlation_id].discard(request_id)
                    if not self.correlation_tracker[correlation_id]:
                        del self.correlation_tracker[correlation_id]
                    self.metrics.update_correlation_ids(len(self.correlation_tracker))
        except Exception:
            pass
    
    def _handle_exception(self, error):
        """Automatic exception logging for unhandled errors."""
        self.error(
            "Unhandled exception occurred",
            category=LogCategory.ERROR,
            error_type=type(error).__name__,
            error_message=str(error),
            traceback=traceback.format_exc(),
            exc_info=True
        )
        
        # Re-raise the exception for normal Flask error handling
        raise error
    
    def _setup_python_logging_integration(self, app: Flask):
        """Set up integration with Python's standard logging module."""
        # Configure the standard Python logger to use our structured format
        root_logger = logging.getLogger()
        
        # Remove existing handlers to avoid duplication
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Create a handler that outputs to stdout for container environments
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        
        # Use structlog formatting for standard Python logs
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.INFO)
        
        # Redirect Flask's default logger to our structured logger
        app.logger.handlers.clear()
        app.logger.propagate = True
    
    def _create_log_context(self) -> LogContext:
        """Create a LogContext object from current Flask request context."""
        trace_context = self.tracing.get_current_trace_context()
        
        return LogContext(
            request_id=getattr(g, 'request_id', str(uuid.uuid4())),
            correlation_id=getattr(g, 'correlation_id', str(uuid.uuid4())),
            user_id=getattr(g, 'user_id', None),
            session_id=getattr(g, 'session_id', None),
            blueprint=getattr(request, 'blueprint', None) if has_request_context() else None,
            endpoint=getattr(request, 'endpoint', None) if has_request_context() else None,
            method=getattr(request, 'method', None) if has_request_context() else None,
            ip_address=getattr(request, 'remote_addr', None) if has_request_context() else None,
            user_agent=request.headers.get('User-Agent') if has_request_context() else None,
            trace_id=trace_context.get('trace_id'),
            span_id=trace_context.get('span_id'),
        )
    
    def _log_with_metrics(self, level: str, category: LogCategory, **kwargs):
        """Internal logging method with metrics collection."""
        start_time = time.time()
        
        try:
            # Extract blueprint for metrics
            blueprint = kwargs.get('blueprint', 
                                 getattr(request, 'blueprint', 'unknown') if has_request_context() else 'unknown')
            
            # Create trace span for logging operation
            span = self.tracing.create_log_span("structured_log", level, category.value)
            
            try:
                # Add category and timestamp to log entry
                kwargs.update({
                    'category': category.value,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'application': 'flask_app',
                    'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                })
                
                # Log based on level
                log_method = getattr(self.logger, level.lower())
                message = kwargs.pop('message', '')
                log_method(message, **kwargs)
                
                # Add log data to trace span
                if span:
                    self.tracing.add_log_to_span(span, {'message': message, **kwargs})
                
                # Send to CloudWatch if enabled
                if self.cloudwatch:
                    log_entry = {
                        'timestamp': int(time.time() * 1000),
                        'message': json.dumps({'message': message, **kwargs})
                    }
                    self.cloudwatch.send_single_log(log_entry['message'], log_entry['timestamp'])
                
                # Record metrics
                self.metrics.record_log_entry(level, category.value, blueprint)
                
            finally:
                if span:
                    span.set_status(Status(StatusCode.OK))
                    span.end()
            
        except Exception as e:
            # Don't let logging errors affect application flow
            print(f"Logging error: {e}")
            if self.metrics:
                self.metrics.record_cloudwatch_error("logging_error")
        
        finally:
            # Record processing time
            duration = time.time() - start_time
            self.metrics.record_processing_time(duration, level, category.value)
    
    def debug(self, message: str, category: LogCategory = LogCategory.APPLICATION, **kwargs):
        """Log debug message with structured context."""
        kwargs['message'] = message
        self._log_with_metrics('debug', category, **kwargs)
    
    def info(self, message: str, category: LogCategory = LogCategory.APPLICATION, **kwargs):
        """Log info message with structured context."""
        kwargs['message'] = message
        self._log_with_metrics('info', category, **kwargs)
    
    def warning(self, message: str, category: LogCategory = LogCategory.APPLICATION, **kwargs):
        """Log warning message with structured context."""
        kwargs['message'] = message
        self._log_with_metrics('warning', category, **kwargs)
    
    def error(self, message: str, category: LogCategory = LogCategory.ERROR, **kwargs):
        """Log error message with structured context."""
        kwargs['message'] = message
        self._log_with_metrics('error', category, **kwargs)
    
    def critical(self, message: str, category: LogCategory = LogCategory.ERROR, **kwargs):
        """Log critical message with structured context."""
        kwargs['message'] = message
        self._log_with_metrics('critical', category, **kwargs)
    
    def audit(self, event_type: str, action: str, resource: str = None, 
              outcome: str = "success", user_id: str = None, details: Dict[str, Any] = None,
              risk_score: int = None):
        """
        Log audit event for compliance and regulatory requirements.
        
        Args:
            event_type: Type of audit event (e.g., 'user_login', 'data_access')
            action: Action performed (e.g., 'create', 'read', 'update', 'delete')
            resource: Resource affected by the action
            outcome: Outcome of the action ('success', 'failure', 'error')
            user_id: User performing the action
            details: Additional audit details
            risk_score: Risk assessment score (0-100)
        """
        context = self._create_log_context()
        
        audit_entry = AuditLogEntry(
            event_type=event_type,
            user_id=user_id or context.user_id,
            resource=resource,
            action=action,
            outcome=outcome,
            timestamp=datetime.now(timezone.utc).isoformat(),
            context=context,
            details=details,
            risk_score=risk_score
        )
        
        # Log the audit entry
        self.info(
            f"Audit event: {event_type}",
            category=LogCategory.AUDIT,
            audit_event=asdict(audit_entry),
            event_type=event_type,
            action=action,
            resource=resource,
            outcome=outcome,
            risk_score=risk_score
        )
        
        # Record audit metrics
        self.metrics.record_audit_event(event_type, outcome, user_id or "anonymous")
    
    def security_event(self, event_type: SecurityEventType, severity: str, description: str,
                      user_id: str = None, source_ip: str = None, indicators: List[str] = None,
                      threat_score: int = None, remediation_actions: List[str] = None):
        """
        Log security event for threat detection and incident response.
        
        Args:
            event_type: Type of security event
            severity: Severity level ('low', 'medium', 'high', 'critical')
            description: Human-readable event description
            user_id: User associated with the event
            source_ip: Source IP address of the event
            indicators: List of indicators of compromise
            threat_score: Threat assessment score (0-100)
            remediation_actions: List of recommended remediation actions
        """
        context = self._create_log_context()
        
        security_event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            description=description,
            user_id=user_id or context.user_id,
            source_ip=source_ip or context.ip_address,
            context=context,
            indicators=indicators or [],
            threat_score=threat_score,
            remediation_actions=remediation_actions or []
        )
        
        # Determine log level based on severity
        if severity == 'critical':
            log_level = 'critical'
        elif severity == 'high':
            log_level = 'error'
        elif severity == 'medium':
            log_level = 'warning'
        else:
            log_level = 'info'
        
        # Log the security event
        getattr(self, log_level)(
            f"Security event: {description}",
            category=LogCategory.SECURITY,
            security_event=asdict(security_event),
            event_type=event_type.value,
            severity=severity,
            threat_score=threat_score,
            indicators=indicators,
            remediation_actions=remediation_actions
        )
        
        # Record security metrics
        self.metrics.record_security_event(event_type.value, severity, threat_score or 0)
    
    def performance_log(self, operation: str, duration: float, status: str = "success",
                       details: Dict[str, Any] = None, threshold_ms: float = None):
        """
        Log performance metrics for monitoring and optimization.
        
        Args:
            operation: Name of the operation being measured
            duration: Duration in seconds
            status: Operation status ('success', 'failure', 'timeout')
            details: Additional performance details
            threshold_ms: Performance threshold in milliseconds for alerting
        """
        duration_ms = duration * 1000
        
        performance_data = {
            'operation': operation,
            'duration_ms': duration_ms,
            'duration_seconds': duration,
            'status': status,
            'details': details or {},
        }
        
        # Check if performance threshold is exceeded
        if threshold_ms and duration_ms > threshold_ms:
            performance_data['threshold_exceeded'] = True
            performance_data['threshold_ms'] = threshold_ms
            log_level = 'warning'
            message = f"Performance threshold exceeded for {operation}: {duration_ms:.2f}ms (threshold: {threshold_ms}ms)"
        else:
            performance_data['threshold_exceeded'] = False
            log_level = 'info'
            message = f"Performance metric for {operation}: {duration_ms:.2f}ms"
        
        # Log performance data
        getattr(self, log_level)(
            message,
            category=LogCategory.PERFORMANCE,
            performance=performance_data
        )
    
    def business_event(self, event_name: str, entity_type: str = None, entity_id: str = None,
                      metrics: Dict[str, Union[int, float]] = None, metadata: Dict[str, Any] = None):
        """
        Log business events for analytics and monitoring.
        
        Args:
            event_name: Name of the business event
            entity_type: Type of business entity involved
            entity_id: ID of the business entity
            metrics: Numeric metrics associated with the event
            metadata: Additional event metadata
        """
        business_data = {
            'event_name': event_name,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'metrics': metrics or {},
            'metadata': metadata or {},
        }
        
        self.info(
            f"Business event: {event_name}",
            category=LogCategory.BUSINESS,
            business_event=business_data
        )


# Decorators for automatic logging

def log_function_call(category: LogCategory = LogCategory.APPLICATION, 
                     log_args: bool = False, log_result: bool = False,
                     performance_threshold_ms: float = None):
    """
    Decorator to automatically log function calls with performance metrics.
    
    Args:
        category: Log category for the function call
        log_args: Whether to log function arguments
        log_result: Whether to log function return value
        performance_threshold_ms: Performance threshold for warning logs
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = current_app.logger_instance if current_app else StructuredLogger()
            
            start_time = time.time()
            function_name = f"{func.__module__}.{func.__name__}"
            
            # Log function entry
            log_data = {
                'function': function_name,
                'action': 'function_entry'
            }
            
            if log_args:
                log_data['args'] = str(args)
                log_data['kwargs'] = str(kwargs)
            
            logger.debug(f"Entering function {function_name}", category=category, **log_data)
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Calculate execution time
                duration = time.time() - start_time
                
                # Log function exit with performance data
                exit_data = {
                    'function': function_name,
                    'action': 'function_exit',
                    'duration_seconds': duration,
                    'status': 'success'
                }
                
                if log_result:
                    exit_data['result'] = str(result)
                
                # Log performance metric
                logger.performance_log(
                    operation=function_name,
                    duration=duration,
                    status='success',
                    threshold_ms=performance_threshold_ms
                )
                
                logger.debug(f"Exiting function {function_name}", category=category, **exit_data)
                
                return result
                
            except Exception as e:
                # Calculate execution time for failed function
                duration = time.time() - start_time
                
                # Log function error
                error_data = {
                    'function': function_name,
                    'action': 'function_error',
                    'duration_seconds': duration,
                    'status': 'error',
                    'error_type': type(e).__name__,
                    'error_message': str(e)
                }
                
                logger.error(f"Error in function {function_name}", category=category, **error_data)
                
                # Log performance metric for failed operation
                logger.performance_log(
                    operation=function_name,
                    duration=duration,
                    status='error'
                )
                
                raise
        
        return wrapper
    return decorator


def log_audit_event(event_type: str, action: str, resource: str = None):
    """
    Decorator to automatically log audit events for functions.
    
    Args:
        event_type: Type of audit event
        action: Action being performed
        resource: Resource being acted upon
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = current_app.logger_instance if current_app else StructuredLogger()
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Log successful audit event
                logger.audit(
                    event_type=event_type,
                    action=action,
                    resource=resource,
                    outcome='success',
                    details={'function': f"{func.__module__}.{func.__name__}"}
                )
                
                return result
                
            except Exception as e:
                # Log failed audit event
                logger.audit(
                    event_type=event_type,
                    action=action,
                    resource=resource,
                    outcome='failure',
                    details={
                        'function': f"{func.__module__}.{func.__name__}",
                        'error': str(e)
                    }
                )
                
                raise
        
        return wrapper
    return decorator


@contextmanager
def log_operation(operation_name: str, category: LogCategory = LogCategory.APPLICATION,
                 performance_threshold_ms: float = None):
    """
    Context manager for logging operations with automatic performance tracking.
    
    Args:
        operation_name: Name of the operation being logged
        category: Log category for the operation
        performance_threshold_ms: Performance threshold for warning logs
    """
    logger = current_app.logger_instance if current_app else StructuredLogger()
    
    start_time = time.time()
    
    logger.debug(f"Starting operation: {operation_name}", category=category, 
                operation=operation_name, action='start')
    
    try:
        yield logger
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Log successful completion
        logger.debug(f"Completed operation: {operation_name}", category=category,
                    operation=operation_name, action='complete', duration_seconds=duration)
        
        # Log performance metric
        logger.performance_log(
            operation=operation_name,
            duration=duration,
            status='success',
            threshold_ms=performance_threshold_ms
        )
        
    except Exception as e:
        # Calculate duration for failed operation
        duration = time.time() - start_time
        
        # Log failed operation
        logger.error(f"Failed operation: {operation_name}", category=category,
                    operation=operation_name, action='error', duration_seconds=duration,
                    error_type=type(e).__name__, error_message=str(e))
        
        # Log performance metric for failed operation
        logger.performance_log(
            operation=operation_name,
            duration=duration,
            status='error'
        )
        
        raise


# Global logger instance for convenience
def get_logger() -> StructuredLogger:
    """Get the application logger instance."""
    if current_app and hasattr(current_app, 'logger_instance'):
        return current_app.logger_instance
    else:
        # Return a basic logger if Flask app context is not available
        return StructuredLogger()


# Convenience functions for common logging patterns

def log_user_action(action: str, resource: str = None, outcome: str = "success", 
                   details: Dict[str, Any] = None):
    """Convenience function for logging user actions."""
    logger = get_logger()
    logger.audit(
        event_type='user_action',
        action=action,
        resource=resource,
        outcome=outcome,
        details=details
    )


def log_api_request(endpoint: str, method: str, status_code: int, duration: float,
                   user_id: str = None, details: Dict[str, Any] = None):
    """Convenience function for logging API requests."""
    logger = get_logger()
    
    # Log API request as audit event
    logger.audit(
        event_type='api_request',
        action=f"{method} {endpoint}",
        resource=endpoint,
        outcome='success' if 200 <= status_code < 400 else 'failure',
        user_id=user_id,
        details={
            'status_code': status_code,
            'duration_seconds': duration,
            **(details or {})
        }
    )
    
    # Also log as performance metric
    logger.performance_log(
        operation=f"{method} {endpoint}",
        duration=duration,
        status='success' if 200 <= status_code < 400 else 'failure',
        details={'status_code': status_code}
    )


def log_database_operation(operation: str, table: str, duration: float, 
                         records_affected: int = None, user_id: str = None):
    """Convenience function for logging database operations."""
    logger = get_logger()
    
    # Log as audit event
    logger.audit(
        event_type='database_operation',
        action=operation,
        resource=table,
        outcome='success',
        user_id=user_id,
        details={
            'records_affected': records_affected,
            'duration_seconds': duration
        }
    )
    
    # Log as performance metric
    logger.performance_log(
        operation=f"db_{operation}_{table}",
        duration=duration,
        status='success',
        details={
            'table': table,
            'records_affected': records_affected
        }
    )


def log_security_incident(incident_type: SecurityEventType, description: str,
                         severity: str = "medium", threat_score: int = None,
                         indicators: List[str] = None):
    """Convenience function for logging security incidents."""
    logger = get_logger()
    logger.security_event(
        event_type=incident_type,
        severity=severity,
        description=description,
        threat_score=threat_score,
        indicators=indicators or []
    )


# Flask application factory integration function
def init_logging(app: Flask) -> StructuredLogger:
    """
    Initialize structured logging for Flask application factory pattern.
    
    This function should be called from the Flask application factory
    to set up comprehensive logging capabilities.
    
    Args:
        app: Flask application instance
        
    Returns:
        StructuredLogger: Configured logger instance
    """
    logger = StructuredLogger(app)
    
    # Log successful initialization
    logger.info(
        "Structured logging initialized successfully",
        category=LogCategory.INFRASTRUCTURE,
        flask_version=getattr(Flask, '__version__', 'unknown'),
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        structlog_available=True,
        cloudwatch_enabled=bool(logger.cloudwatch),
        opentelemetry_enabled=logger.tracing.enabled,
        prometheus_metrics_enabled=PROMETHEUS_AVAILABLE
    )
    
    return logger