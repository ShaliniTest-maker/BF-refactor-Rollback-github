"""
Security Monitoring and Logging Service

This module implements comprehensive authentication security event tracking using Python 
structlog and Prometheus metrics. Provides real-time security monitoring, anomaly detection, 
and incident response capabilities while integrating with AWS CloudWatch for centralized 
log aggregation and alerting.

Key Features:
- Structured JSON security logging with Python structlog (Section 6.4.2.5)
- Prometheus metrics integration for authentication event tracking (Section 6.4.6.1)
- Real-time anomaly detection for authentication patterns (Section 6.4.6.1)  
- AWS CloudWatch integration for security log aggregation (Section 6.4.2.5)
- Automated security incident detection and response (Section 6.4.6.2)
- Flask application factory integration with Service Layer pattern
- Thread-safe real-time monitoring with ML-based anomaly detection
"""

import logging
import time
import threading
import uuid
import json
import hashlib
import os
import traceback
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import queue

# Third-party imports
import structlog
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from flask import Flask, request, g, Response, current_app

# Configure structlog for comprehensive JSON security logging
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    logger_factory=structlog.WriteLoggerFactory(),
    cache_logger_on_first_use=True,
)


class SecurityEventType(Enum):
    """Security event classification for comprehensive monitoring"""
    AUTHENTICATION_SUCCESS = "auth_success"
    AUTHENTICATION_FAILURE = "auth_failure"
    AUTHORIZATION_VIOLATION = "authz_violation"
    SUSPICIOUS_LOGIN_PATTERN = "suspicious_login"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS_VIOLATION = "data_access_violation"
    SESSION_ANOMALY = "session_anomaly"
    BRUTE_FORCE_ATTEMPT = "brute_force"
    TOKEN_ABUSE = "token_abuse"
    SQL_INJECTION_ATTEMPT = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    CSRF_VIOLATION = "csrf_violation"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SECURITY_CONFIGURATION_CHANGE = "security_config_change"
    CRITICAL_ERROR = "critical_error"


class SecuritySeverity(Enum):
    """Security event severity levels for alert routing"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityEvent:
    """Comprehensive security event data structure"""
    event_id: str
    event_type: SecurityEventType
    severity: SecuritySeverity
    timestamp: datetime
    user_id: Optional[str]
    session_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    endpoint: Optional[str]
    blueprint: Optional[str]
    request_method: Optional[str]
    status_code: Optional[int]
    response_time: Optional[float]
    details: Dict[str, Any]
    correlation_id: Optional[str] = None
    threat_score: float = 0.0
    is_anomaly: bool = False


class PrometheusSecurityMetrics:
    """Prometheus metrics collection for security monitoring per Section 6.4.6.1"""
    
    def __init__(self):
        self.registry = CollectorRegistry()
        
        # Authentication metrics
        self.auth_attempts_total = Counter(
            'flask_auth_attempts_total',
            'Total authentication attempts by status and method',
            ['status', 'method', 'blueprint', 'endpoint'],
            registry=self.registry
        )
        
        self.auth_response_time = Histogram(
            'flask_auth_response_time_seconds',
            'Authentication response time in seconds',
            ['method', 'status'],
            registry=self.registry
        )
        
        # Security event metrics
        self.security_events_total = Counter(
            'flask_security_events_total',
            'Total security events by type and severity',
            ['event_type', 'severity', 'blueprint'],
            registry=self.registry
        )
        
        self.security_anomalies_total = Counter(
            'flask_security_anomalies_total',
            'Total security anomalies detected',
            ['anomaly_type', 'severity'],
            registry=self.registry
        )
        
        # Session monitoring metrics
        self.active_sessions_gauge = Gauge(
            'flask_active_sessions',
            'Number of active user sessions',
            registry=self.registry
        )
        
        self.suspicious_sessions_total = Counter(
            'flask_suspicious_sessions_total',
            'Total suspicious session activities',
            ['activity_type', 'severity'],
            registry=self.registry
        )
        
        # Failed login tracking
        self.failed_logins_total = Counter(
            'flask_failed_logins_total',
            'Total failed login attempts by source',
            ['source_ip', 'user_id', 'failure_reason'],
            registry=self.registry
        )
        
        # Rate limiting metrics
        self.rate_limit_violations_total = Counter(
            'flask_rate_limit_violations_total',
            'Total rate limit violations',
            ['endpoint', 'ip_address', 'violation_type'],
            registry=self.registry
        )
        
        # Threat detection metrics
        self.threat_score_histogram = Histogram(
            'flask_threat_score',
            'Distribution of calculated threat scores',
            ['event_type'],
            registry=self.registry
        )
    
    def record_auth_attempt(self, success: bool, method: str = 'password', 
                           blueprint: str = 'auth', endpoint: str = 'login',
                           response_time: float = 0.0):
        """Record authentication attempt with comprehensive metrics"""
        status = 'success' if success else 'failure'
        self.auth_attempts_total.labels(
            status=status, method=method, blueprint=blueprint, endpoint=endpoint
        ).inc()
        
        if response_time > 0:
            self.auth_response_time.labels(method=method, status=status).observe(response_time)
    
    def record_security_event(self, event_type: SecurityEventType, severity: SecuritySeverity,
                             blueprint: str = 'unknown', threat_score: float = 0.0):
        """Record security event with threat scoring"""
        self.security_events_total.labels(
            event_type=event_type.value, severity=severity.value, blueprint=blueprint
        ).inc()
        
        if threat_score > 0:
            self.threat_score_histogram.labels(event_type=event_type.value).observe(threat_score)
    
    def record_anomaly(self, anomaly_type: str, severity: SecuritySeverity):
        """Record detected security anomaly"""
        self.security_anomalies_total.labels(
            anomaly_type=anomaly_type, severity=severity.value
        ).inc()
    
    def update_active_sessions(self, count: int):
        """Update active session count"""
        self.active_sessions_gauge.set(count)
    
    def get_metrics(self) -> str:
        """Export Prometheus metrics in exposition format"""
        return generate_latest(self.registry)


class AnomalyDetector:
    """ML-based anomaly detection for authentication patterns per Section 6.4.6.1"""
    
    def __init__(self, window_size: int = 100, contamination: float = 0.1):
        self.window_size = window_size
        self.contamination = contamination
        self.logger = structlog.get_logger("anomaly_detector")
        
        # Feature tracking for ML models
        self.auth_patterns = deque(maxlen=window_size)
        self.request_patterns = deque(maxlen=window_size)
        self.user_behavior = defaultdict(lambda: deque(maxlen=50))
        
        # ML models for anomaly detection
        self.auth_classifier = IsolationForest(contamination=contamination, random_state=42)
        self.behavior_classifier = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        
        # Pattern thresholds
        self.failed_login_threshold = 5  # failures per 5 minutes
        self.rapid_request_threshold = 30  # requests per minute
        self.session_anomaly_threshold = 0.8  # anomaly score threshold
        
        self._lock = threading.Lock()
    
    def analyze_authentication_pattern(self, user_id: str, ip_address: str, 
                                     user_agent: str, success: bool, 
                                     timestamp: datetime) -> Tuple[bool, float]:
        """Analyze authentication pattern for anomalies"""
        with self._lock:
            # Extract features for ML analysis
            hour_of_day = timestamp.hour
            day_of_week = timestamp.weekday()
            user_agent_hash = hash(user_agent) % 1000  # Normalized user agent
            ip_hash = hash(ip_address) % 1000  # Normalized IP
            
            pattern_features = [
                hour_of_day,
                day_of_week,
                user_agent_hash,
                ip_hash,
                1 if success else 0,
                len(self.user_behavior.get(user_id, []))
            ]
            
            self.auth_patterns.append(pattern_features)
            
            # Track user-specific behavior
            if user_id:
                self.user_behavior[user_id].append({
                    'timestamp': timestamp,
                    'ip_address': ip_address,
                    'user_agent': user_agent,
                    'success': success
                })
            
            # Detect anomalies if we have enough data
            if len(self.auth_patterns) >= 20:
                try:
                    patterns_array = np.array(list(self.auth_patterns))
                    normalized_patterns = self.scaler.fit_transform(patterns_array)
                    anomaly_scores = self.auth_classifier.fit_predict(normalized_patterns)
                    
                    # Check if latest pattern is anomalous
                    latest_score = anomaly_scores[-1]
                    is_anomaly = latest_score == -1
                    
                    # Calculate threat score based on multiple factors
                    threat_score = self._calculate_threat_score(
                        user_id, ip_address, success, timestamp
                    )
                    
                    if is_anomaly or threat_score > 0.7:
                        self.logger.warning(
                            "Authentication anomaly detected",
                            user_id=user_id,
                            ip_address=ip_address,
                            threat_score=threat_score,
                            is_ml_anomaly=is_anomaly
                        )
                        return True, threat_score
                    
                except Exception as e:
                    self.logger.error("ML anomaly detection failed", error=str(e))
            
            return False, 0.0
    
    def _calculate_threat_score(self, user_id: str, ip_address: str, 
                               success: bool, timestamp: datetime) -> float:
        """Calculate comprehensive threat score for security event"""
        threat_score = 0.0
        
        # Failed login penalty
        if not success:
            threat_score += 0.3
        
        # Check for rapid failed logins
        if user_id:
            recent_failures = [
                event for event in self.user_behavior[user_id]
                if not event['success'] and 
                (timestamp - event['timestamp']).total_seconds() < 300  # 5 minutes
            ]
            if len(recent_failures) >= self.failed_login_threshold:
                threat_score += 0.5
        
        # Time-based anomalies (unusual hours)
        hour = timestamp.hour
        if hour < 6 or hour > 22:  # Outside normal business hours
            threat_score += 0.2
        
        # Geographic anomalies (basic IP-based heuristic)
        # In production, this would integrate with IP geolocation services
        if self._is_suspicious_ip(ip_address):
            threat_score += 0.4
        
        return min(threat_score, 1.0)  # Cap at 1.0
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Basic suspicious IP detection (placeholder for production geolocation)"""
        # In production, this would check against threat intelligence feeds
        # For now, simple heuristics
        suspicious_patterns = ['192.168.', '10.', '172.16.']
        return not any(ip_address.startswith(pattern) for pattern in suspicious_patterns)
    
    def detect_session_anomalies(self, user_id: str, session_data: Dict[str, Any]) -> bool:
        """Detect session-based anomalies"""
        if not user_id or user_id not in self.user_behavior:
            return False
        
        user_sessions = self.user_behavior[user_id]
        if len(user_sessions) < 3:
            return False
        
        # Check for session characteristics anomalies
        current_session = session_data
        recent_sessions = list(user_sessions)[-5:]  # Last 5 sessions
        
        # Detect unusual session duration patterns
        current_duration = current_session.get('duration', 0)
        avg_duration = np.mean([s.get('duration', 0) for s in recent_sessions])
        
        if avg_duration > 0 and abs(current_duration - avg_duration) / avg_duration > 2.0:
            return True
        
        # Detect unusual access patterns
        current_endpoints = set(current_session.get('endpoints', []))
        typical_endpoints = set()
        for session in recent_sessions:
            typical_endpoints.update(session.get('endpoints', []))
        
        if current_endpoints and typical_endpoints:
            overlap = len(current_endpoints.intersection(typical_endpoints))
            if overlap / len(current_endpoints) < 0.3:  # Less than 30% overlap
                return True
        
        return False


class AWSCloudWatchIntegration:
    """AWS CloudWatch integration for security log aggregation per Section 6.4.2.5"""
    
    def __init__(self, region_name: str = 'us-east-1'):
        self.region_name = region_name
        self.logger = structlog.get_logger("cloudwatch_integration")
        
        try:
            self.cloudwatch_logs = boto3.client('cloudwatch_logs', region_name=region_name)
            self.cloudwatch = boto3.client('cloudwatch', region_name=region_name)
            self.sns = boto3.client('sns', region_name=region_name)
        except Exception as e:
            self.logger.error("Failed to initialize AWS clients", error=str(e))
            self.cloudwatch_logs = None
            self.cloudwatch = None
            self.sns = None
        
        self.log_group_name = '/aws/flask/security-monitoring'
        self.log_stream_name = f'security-events-{datetime.utcnow().strftime("%Y%m%d")}'
        self.sns_topic_arn = os.getenv('SECURITY_ALERTS_SNS_TOPIC')
        
        self._ensure_log_group_exists()
    
    def _ensure_log_group_exists(self):
        """Ensure CloudWatch log group exists for security events"""
        if not self.cloudwatch_logs:
            return
        
        try:
            self.cloudwatch_logs.describe_log_groups(
                logGroupNamePrefix=self.log_group_name
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                try:
                    self.cloudwatch_logs.create_log_group(
                        logGroupName=self.log_group_name,
                        tags={
                            'Application': 'flask-security-monitor',
                            'Environment': os.getenv('FLASK_ENV', 'production'),
                            'Purpose': 'security-monitoring'
                        }
                    )
                    self.logger.info("Created CloudWatch log group", log_group=self.log_group_name)
                except Exception as create_error:
                    self.logger.error("Failed to create log group", error=str(create_error))
    
    def send_security_event(self, event: SecurityEvent):
        """Send security event to CloudWatch Logs"""
        if not self.cloudwatch_logs:
            return
        
        try:
            log_entry = {
                'timestamp': int(event.timestamp.timestamp() * 1000),
                'message': json.dumps({
                    'event_id': event.event_id,
                    'event_type': event.event_type.value,
                    'severity': event.severity.value,
                    'user_id': event.user_id,
                    'session_id': event.session_id,
                    'ip_address': event.ip_address,
                    'user_agent': event.user_agent,
                    'endpoint': event.endpoint,
                    'blueprint': event.blueprint,
                    'request_method': event.request_method,
                    'status_code': event.status_code,
                    'response_time': event.response_time,
                    'threat_score': event.threat_score,
                    'is_anomaly': event.is_anomaly,
                    'correlation_id': event.correlation_id,
                    'details': event.details,
                    'timestamp_iso': event.timestamp.isoformat()
                })
            }
            
            self.cloudwatch_logs.put_log_events(
                logGroupName=self.log_group_name,
                logStreamName=self.log_stream_name,
                logEvents=[log_entry]
            )
            
        except Exception as e:
            self.logger.error("Failed to send event to CloudWatch", 
                            event_id=event.event_id, error=str(e))
    
    def send_critical_alert(self, event: SecurityEvent):
        """Send critical security alert via SNS"""
        if not self.sns or not self.sns_topic_arn:
            return
        
        if event.severity not in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH]:
            return
        
        try:
            alert_message = {
                'alert_type': 'security_incident',
                'event_id': event.event_id,
                'event_type': event.event_type.value,
                'severity': event.severity.value,
                'timestamp': event.timestamp.isoformat(),
                'user_id': event.user_id,
                'ip_address': event.ip_address,
                'endpoint': event.endpoint,
                'threat_score': event.threat_score,
                'details': event.details
            }
            
            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Message=json.dumps(alert_message),
                Subject=f"Critical Security Alert: {event.event_type.value}",
                MessageAttributes={
                    'severity': {
                        'DataType': 'String',
                        'StringValue': event.severity.value
                    },
                    'event_type': {
                        'DataType': 'String',
                        'StringValue': event.event_type.value
                    }
                }
            )
            
            self.logger.info("Critical security alert sent", 
                           event_id=event.event_id, severity=event.severity.value)
            
        except Exception as e:
            self.logger.error("Failed to send critical alert", 
                            event_id=event.event_id, error=str(e))


class SecurityMonitor:
    """
    Comprehensive security monitoring and logging service
    
    This is the main class that coordinates all security monitoring activities
    including structured logging, metrics collection, anomaly detection, and
    incident response per Sections 6.4.2.5, 6.4.6.1, and 6.4.6.2.
    """
    
    def __init__(self, app: Optional[Flask] = None):
        self.app = app
        self.logger = structlog.get_logger("security_monitor")
        
        # Core components
        self.metrics = PrometheusSecurityMetrics()
        self.anomaly_detector = AnomalyDetector()
        self.cloudwatch = AWSCloudWatchIntegration()
        
        # Event tracking
        self.recent_events = deque(maxlen=1000)
        self.active_sessions = {}
        self.failed_attempts = defaultdict(lambda: deque(maxlen=50))
        
        # Threading for real-time processing
        self.event_queue = queue.Queue()
        self.processing_thread = None
        self.is_running = False
        self._lock = threading.Lock()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize security monitor with Flask application factory pattern"""
        self.app = app
        app.security_monitor = self
        
        # Register Flask request hooks
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        app.teardown_appcontext(self._teardown_request)
        
        # Register metrics endpoint
        app.add_url_rule('/metrics', 'security_metrics', self._metrics_endpoint)
        
        # Start background processing
        self.start_monitoring()
        
        self.logger.info("Security monitor initialized with Flask application factory")
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        if self.is_running:
            return
        
        self.is_running = True
        self.processing_thread = threading.Thread(target=self._process_events, daemon=True)
        self.processing_thread.start()
        self.logger.info("Security monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.is_running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        self.logger.info("Security monitoring stopped")
    
    def _before_request(self):
        """Flask before request hook for security context setup"""
        g.security_start_time = time.time()
        g.security_request_id = str(uuid.uuid4())
        g.security_context = {
            'request_id': g.security_request_id,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'endpoint': request.endpoint,
            'blueprint': request.blueprint,
            'method': request.method,
            'url': request.url
        }
        
        # Set up structured logging context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=g.security_request_id,
            ip_address=request.remote_addr,
            endpoint=request.endpoint,
            blueprint=request.blueprint
        )
    
    def _after_request(self, response):
        """Flask after request hook for security event collection"""
        if hasattr(g, 'security_start_time'):
            response_time = time.time() - g.security_start_time
            
            # Check for security-relevant response codes
            if response.status_code in [401, 403, 429]:
                event_type = self._determine_event_type(response.status_code)
                severity = SecuritySeverity.MEDIUM if response.status_code == 429 else SecuritySeverity.HIGH
                
                self.record_security_event(
                    event_type=event_type,
                    severity=severity,
                    details={
                        'status_code': response.status_code,
                        'response_time': response_time,
                        'request_size': request.content_length or 0
                    }
                )
        
        return response
    
    def _teardown_request(self, exception):
        """Flask teardown request hook for exception handling"""
        if exception:
            self.record_security_event(
                event_type=SecurityEventType.CRITICAL_ERROR,
                severity=SecuritySeverity.HIGH,
                details={
                    'exception_type': type(exception).__name__,
                    'exception_message': str(exception),
                    'traceback': traceback.format_exc()
                }
            )
    
    def _metrics_endpoint(self):
        """Prometheus metrics endpoint"""
        return Response(
            self.metrics.get_metrics(),
            mimetype=CONTENT_TYPE_LATEST
        )
    
    def _determine_event_type(self, status_code: int) -> SecurityEventType:
        """Determine security event type based on status code"""
        mapping = {
            401: SecurityEventType.AUTHENTICATION_FAILURE,
            403: SecurityEventType.AUTHORIZATION_VIOLATION,
            429: SecurityEventType.RATE_LIMIT_EXCEEDED
        }
        return mapping.get(status_code, SecurityEventType.CRITICAL_ERROR)
    
    def record_authentication_attempt(self, user_id: str, success: bool, 
                                    method: str = 'password', 
                                    details: Optional[Dict[str, Any]] = None):
        """Record authentication attempt with comprehensive tracking"""
        timestamp = datetime.utcnow()
        ip_address = getattr(g, 'security_context', {}).get('ip_address')
        user_agent = getattr(g, 'security_context', {}).get('user_agent')
        
        # Anomaly detection
        is_anomaly, threat_score = self.anomaly_detector.analyze_authentication_pattern(
            user_id, ip_address or '', user_agent or '', success, timestamp
        )
        
        # Determine event severity
        if not success:
            severity = SecuritySeverity.HIGH if is_anomaly else SecuritySeverity.MEDIUM
            event_type = SecurityEventType.AUTHENTICATION_FAILURE
        else:
            severity = SecuritySeverity.LOW if not is_anomaly else SecuritySeverity.MEDIUM
            event_type = SecurityEventType.AUTHENTICATION_SUCCESS
        
        # Create security event
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            severity=severity,
            timestamp=timestamp,
            user_id=user_id,
            session_id=getattr(g, 'session_id', None),
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=getattr(g, 'security_context', {}).get('endpoint'),
            blueprint=getattr(g, 'security_context', {}).get('blueprint'),
            request_method=getattr(g, 'security_context', {}).get('method'),
            details=details or {},
            correlation_id=getattr(g, 'security_request_id', None),
            threat_score=threat_score,
            is_anomaly=is_anomaly
        )
        
        # Queue event for processing
        self.event_queue.put(event)
        
        # Update metrics
        self.metrics.record_auth_attempt(
            success=success,
            method=method,
            blueprint=event.blueprint or 'auth',
            endpoint=event.endpoint or 'login'
        )
        
        if not success:
            self.metrics.failed_logins_total.labels(
                source_ip=ip_address or 'unknown',
                user_id=user_id,
                failure_reason=details.get('reason', 'unknown') if details else 'unknown'
            ).inc()
        
        # Log authentication attempt
        self.logger.info(
            "Authentication attempt recorded",
            user_id=user_id,
            success=success,
            method=method,
            threat_score=threat_score,
            is_anomaly=is_anomaly
        )
    
    def record_security_event(self, event_type: SecurityEventType, 
                             severity: SecuritySeverity,
                             user_id: Optional[str] = None,
                             details: Optional[Dict[str, Any]] = None):
        """Record general security event"""
        timestamp = datetime.utcnow()
        context = getattr(g, 'security_context', {})
        
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            severity=severity,
            timestamp=timestamp,
            user_id=user_id or getattr(g, 'user_id', None),
            session_id=getattr(g, 'session_id', None),
            ip_address=context.get('ip_address'),
            user_agent=context.get('user_agent'),
            endpoint=context.get('endpoint'),
            blueprint=context.get('blueprint'),
            request_method=context.get('method'),
            details=details or {},
            correlation_id=getattr(g, 'security_request_id', None)
        )
        
        # Queue event for processing
        self.event_queue.put(event)
        
        # Update metrics
        self.metrics.record_security_event(
            event_type=event_type,
            severity=severity,
            blueprint=event.blueprint or 'unknown'
        )
        
        # Log security event
        self.logger.warning(
            "Security event recorded",
            event_type=event_type.value,
            severity=severity.value,
            user_id=user_id,
            details=details
        )
    
    def track_session_activity(self, user_id: str, session_id: str, 
                              activity_data: Dict[str, Any]):
        """Track user session activity for anomaly detection"""
        timestamp = datetime.utcnow()
        
        # Update active sessions
        with self._lock:
            self.active_sessions[session_id] = {
                'user_id': user_id,
                'last_activity': timestamp,
                'activity_data': activity_data
            }
            
            # Update metrics
            self.metrics.update_active_sessions(len(self.active_sessions))
        
        # Check for session anomalies
        if self.anomaly_detector.detect_session_anomalies(user_id, activity_data):
            self.record_security_event(
                event_type=SecurityEventType.SESSION_ANOMALY,
                severity=SecuritySeverity.MEDIUM,
                user_id=user_id,
                details={'session_id': session_id, 'activity': activity_data}
            )
    
    def cleanup_expired_sessions(self, max_age_hours: int = 24):
        """Clean up expired session tracking data"""
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        with self._lock:
            expired_sessions = [
                session_id for session_id, data in self.active_sessions.items()
                if data['last_activity'] < cutoff_time
            ]
            
            for session_id in expired_sessions:
                del self.active_sessions[session_id]
            
            # Update metrics
            self.metrics.update_active_sessions(len(self.active_sessions))
        
        if expired_sessions:
            self.logger.info("Cleaned up expired sessions", count=len(expired_sessions))
    
    def _process_events(self):
        """Background thread for processing security events"""
        self.logger.info("Security event processing thread started")
        
        while self.is_running:
            try:
                # Process events with timeout
                event = self.event_queue.get(timeout=1.0)
                
                # Store in recent events
                with self._lock:
                    self.recent_events.append(event)
                
                # Send to CloudWatch
                self.cloudwatch.send_security_event(event)
                
                # Send critical alerts
                if event.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH]:
                    self.cloudwatch.send_critical_alert(event)
                
                # Update anomaly metrics
                if event.is_anomaly:
                    self.metrics.record_anomaly(
                        anomaly_type=event.event_type.value,
                        severity=event.severity
                    )
                
                self.event_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error("Error processing security event", error=str(e))
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security monitoring status"""
        with self._lock:
            recent_event_count = len(self.recent_events)
            active_session_count = len(self.active_sessions)
            
            # Calculate threat level based on recent events
            threat_level = self._calculate_threat_level()
        
        return {
            'status': 'active',
            'recent_events': recent_event_count,
            'active_sessions': active_session_count,
            'threat_level': threat_level,
            'monitoring_since': getattr(self, 'start_time', datetime.utcnow()).isoformat(),
            'queue_size': self.event_queue.qsize(),
            'anomaly_detector_ready': len(self.anomaly_detector.auth_patterns) >= 20
        }
    
    def _calculate_threat_level(self) -> str:
        """Calculate overall system threat level"""
        if not self.recent_events:
            return 'low'
        
        # Analyze recent events (last hour)
        hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_events = [e for e in self.recent_events if e.timestamp > hour_ago]
        
        if not recent_events:
            return 'low'
        
        # Count high-severity events
        critical_count = sum(1 for e in recent_events if e.severity == SecuritySeverity.CRITICAL)
        high_count = sum(1 for e in recent_events if e.severity == SecuritySeverity.HIGH)
        anomaly_count = sum(1 for e in recent_events if e.is_anomaly)
        
        if critical_count > 0 or high_count > 5:
            return 'critical'
        elif high_count > 2 or anomaly_count > 3:
            return 'high'
        elif high_count > 0 or anomaly_count > 1:
            return 'medium'
        else:
            return 'low'


def create_security_monitor(app: Flask) -> SecurityMonitor:
    """
    Factory function to create and configure security monitor
    
    This function integrates with the Flask application factory pattern
    to provide comprehensive security monitoring capabilities.
    """
    monitor = SecurityMonitor(app)
    return monitor


# Flask CLI commands for security monitoring
def register_security_cli_commands(app: Flask):
    """Register Flask CLI commands for security monitoring operations"""
    
    @app.cli.command()
    def security_status():
        """Display current security monitoring status"""
        if hasattr(app, 'security_monitor'):
            status = app.security_monitor.get_security_status()
            print(f"Security Monitor Status: {json.dumps(status, indent=2)}")
        else:
            print("Security monitor not initialized")
    
    @app.cli.command()
    def cleanup_sessions():
        """Clean up expired security monitoring sessions"""
        if hasattr(app, 'security_monitor'):
            app.security_monitor.cleanup_expired_sessions()
            print("Expired sessions cleaned up")
        else:
            print("Security monitor not initialized")