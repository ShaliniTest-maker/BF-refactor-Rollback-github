"""
Security Policy Enforcement Service

This module implements comprehensive security policy enforcement, access control policies,
and threat detection capabilities for the Flask application. It provides role-based access
control (RBAC), security violation detection, automated security responses, and continuous
security monitoring as specified in Section 6.4 of the technical specification.

The service coordinates security policy enforcement across authentication workflows,
monitors security violations, and implements automated security responses to maintain
consistent security posture and policy compliance throughout the authentication system.

Features:
- Role-based access control policy enforcement (Section 6.4.2.1)
- Security violation detection and incident response coordination (Section 6.4.6.2)
- Authentication security monitoring and threat detection (Section 6.4.6.1)
- Security policy enforcement across authentication workflows (Section 6.4.2)
- Automated security response and containment procedures (Section 6.4.6.2)

Architecture:
- Service Layer pattern implementation for centralized security logic
- Flask 3.1.1 integration with application factory pattern
- Auth0 Python SDK 4.9.0 integration for identity management
- Flask-SQLAlchemy 3.1.1 integration for security data persistence
- Prometheus metrics collection for security monitoring
- AWS CloudWatch integration for centralized logging

Author: Flask Migration Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
"""

import time
import uuid
import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Callable
from enum import Enum
from dataclasses import dataclass, asdict
from functools import wraps, lru_cache
import ipaddress
import hashlib
import structlog
from flask import Flask, current_app, g, request, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import Forbidden, Unauthorized, TooManyRequests
import redis
from prometheus_client import Counter, Histogram, Gauge, Summary
import boto3
from botocore.exceptions import ClientError, BotoCoreError


# Security Policy Enums and Data Classes
class SecurityPolicyType(Enum):
    """Security policy type enumeration"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    RATE_LIMITING = "rate_limiting"
    PASSWORD_POLICY = "password_policy"
    SESSION_POLICY = "session_policy"
    AUDIT_POLICY = "audit_policy"


class SecurityViolationType(Enum):
    """Security violation type enumeration"""
    BRUTE_FORCE_ATTACK = "brute_force_attack"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_LOGIN = "suspicious_login"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_SESSION = "invalid_session"
    CSRF_VIOLATION = "csrf_violation"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    DATA_EXFILTRATION = "data_exfiltration"


class SecurityLevel(Enum):
    """Security level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResponseAction(Enum):
    """Automated response action enumeration"""
    LOG_ONLY = "log_only"
    RATE_LIMIT = "rate_limit"
    TEMPORARY_BLOCK = "temporary_block"
    PERMANENT_BLOCK = "permanent_block"
    SESSION_REVOCATION = "session_revocation"
    ACCOUNT_LOCKOUT = "account_lockout"
    ALERT_SECURITY_TEAM = "alert_security_team"
    EMERGENCY_SHUTDOWN = "emergency_shutdown"


@dataclass
class SecurityPolicy:
    """Security policy data structure"""
    id: str
    name: str
    policy_type: SecurityPolicyType
    description: str
    enabled: bool
    rules: Dict[str, Any]
    violation_threshold: int
    response_actions: List[ResponseAction]
    created_at: datetime
    updated_at: datetime


@dataclass
class SecurityViolation:
    """Security violation data structure"""
    id: str
    violation_type: SecurityViolationType
    severity: SecurityLevel
    source_ip: str
    user_id: Optional[str]
    session_id: Optional[str]
    endpoint: Optional[str]
    description: str
    evidence: Dict[str, Any]
    timestamp: datetime
    resolved: bool = False
    response_actions_taken: List[ResponseAction] = None

    def __post_init__(self):
        if self.response_actions_taken is None:
            self.response_actions_taken = []


@dataclass
class SecurityMetrics:
    """Security metrics data structure"""
    total_violations: int
    violations_by_type: Dict[SecurityViolationType, int]
    blocked_ips: Set[str]
    active_threats: int
    policy_violations: int
    automated_responses: int
    false_positives: int
    response_time_avg: float


class RateLimitBucket:
    """Rate limiting bucket implementation using token bucket algorithm"""
    
    def __init__(self, capacity: int, refill_rate: float, refill_period: int = 60):
        """
        Initialize rate limit bucket
        
        Args:
            capacity: Maximum number of tokens in bucket
            refill_rate: Rate at which tokens are added per refill_period
            refill_period: Period in seconds for token refill
        """
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.refill_period = refill_period
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens from bucket
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            bool: True if tokens were consumed, False if insufficient tokens
        """
        with self.lock:
            now = time.time()
            time_passed = now - self.last_refill
            
            # Refill tokens based on time passed
            if time_passed > 0:
                tokens_to_add = (time_passed / self.refill_period) * self.refill_rate
                self.tokens = min(self.capacity, self.tokens + tokens_to_add)
                self.last_refill = now
            
            # Check if enough tokens available
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def get_tokens(self) -> float:
        """Get current token count"""
        with self.lock:
            return self.tokens


class SecurityPolicyService:
    """
    Comprehensive Security Policy Enforcement Service
    
    This service implements enterprise-grade security policy enforcement,
    access control, threat detection, and automated response capabilities
    for the Flask application authentication system.
    
    Capabilities:
    - Role-based access control (RBAC) enforcement
    - Real-time threat detection and monitoring
    - Automated security incident response
    - Rate limiting and brute force protection
    - Security policy validation and enforcement
    - Comprehensive security metrics collection
    - Integration with external security services
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize Security Policy Service
        
        Args:
            app: Flask application instance
        """
        self.app = app
        self.logger = structlog.get_logger("security_policy_service")
        
        # Security state management
        self.policies: Dict[str, SecurityPolicy] = {}
        self.violations: Dict[str, SecurityViolation] = {}
        self.rate_limiters: Dict[str, RateLimitBucket] = {}
        self.blocked_ips: Set[str] = set()
        self.trusted_ips: Set[str] = set()
        self.security_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Threading and synchronization
        self.lock = threading.RLock()
        self.monitoring_thread: Optional[threading.Thread] = None
        self.monitoring_active = False
        
        # External service clients
        self.redis_client: Optional[redis.Redis] = None
        self.aws_sns_client: Optional[boto3.client] = None
        self.aws_cloudwatch_client: Optional[boto3.client] = None
        
        # Configuration
        self.config = {
            'rate_limit_capacity': 100,
            'rate_limit_refill_rate': 10.0,
            'brute_force_threshold': 5,
            'lockout_duration': 900,  # 15 minutes
            'violation_retention_days': 30,
            'monitoring_interval': 10,  # seconds
            'alert_threshold': 10,
            'enable_auto_response': True,
            'enable_ip_blocking': True,
            'enable_session_tracking': True,
            'enable_metrics_collection': True
        }
        
        # Prometheus metrics
        self._init_metrics()
        
        if app:
            self.init_app(app)
    
    def _init_metrics(self):
        """Initialize Prometheus metrics for security monitoring"""
        self.metrics = {
            'security_violations_total': Counter(
                'security_violations_total',
                'Total number of security violations detected',
                ['violation_type', 'severity', 'source']
            ),
            'security_policies_enforced_total': Counter(
                'security_policies_enforced_total',
                'Total number of security policies enforced',
                ['policy_type', 'action', 'result']
            ),
            'rate_limit_requests_total': Counter(
                'rate_limit_requests_total',
                'Total number of rate limited requests',
                ['endpoint', 'user_id', 'result']
            ),
            'blocked_ips_total': Gauge(
                'blocked_ips_total',
                'Current number of blocked IP addresses'
            ),
            'active_threats_total': Gauge(
                'active_threats_total',
                'Current number of active security threats'
            ),
            'security_response_time_seconds': Histogram(
                'security_response_time_seconds',
                'Security policy enforcement response time',
                ['policy_type', 'action']
            ),
            'authentication_attempts_total': Counter(
                'authentication_attempts_total',
                'Total authentication attempts',
                ['result', 'source', 'user_id']
            ),
            'authorization_checks_total': Counter(
                'authorization_checks_total',
                'Total authorization checks performed',
                ['resource', 'permission', 'result']
            )
        }
    
    def init_app(self, app: Flask):
        """
        Initialize service with Flask application
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Update configuration from Flask app config
        self.config.update(app.config.get('SECURITY_POLICY_CONFIG', {}))
        
        # Initialize external service clients
        self._init_external_clients()
        
        # Load default security policies
        self._load_default_policies()
        
        # Initialize IP whitelist/blacklist
        self._init_ip_lists()
        
        # Start security monitoring
        self.start_monitoring()
        
        # Register Flask hooks
        self._register_flask_hooks()
        
        # Store service instance in app
        app.security_policy_service = self
        
        self.logger.info(
            "Security Policy Service initialized",
            config=self.config,
            policies_loaded=len(self.policies)
        )
    
    def _init_external_clients(self):
        """Initialize external service clients"""
        try:
            # Redis client for distributed rate limiting and session storage
            redis_url = self.app.config.get('REDIS_URL', 'redis://localhost:6379/0')
            self.redis_client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            
            # Test Redis connection
            self.redis_client.ping()
            self.logger.info("Redis client initialized successfully")
            
        except Exception as e:
            self.logger.warning("Redis client initialization failed", error=str(e))
            self.redis_client = None
        
        try:
            # AWS SNS client for security alerts
            aws_region = self.app.config.get('AWS_REGION', 'us-east-1')
            self.aws_sns_client = boto3.client('sns', region_name=aws_region)
            self.aws_cloudwatch_client = boto3.client('cloudwatch', region_name=aws_region)
            
            self.logger.info("AWS clients initialized successfully")
            
        except Exception as e:
            self.logger.warning("AWS clients initialization failed", error=str(e))
    
    def _load_default_policies(self):
        """Load default security policies"""
        default_policies = [
            SecurityPolicy(
                id="auth_rate_limit",
                name="Authentication Rate Limiting",
                policy_type=SecurityPolicyType.RATE_LIMITING,
                description="Rate limiting for authentication attempts",
                enabled=True,
                rules={
                    'max_attempts': 5,
                    'window_minutes': 15,
                    'lockout_minutes': 30
                },
                violation_threshold=3,
                response_actions=[ResponseAction.RATE_LIMIT, ResponseAction.TEMPORARY_BLOCK],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            ),
            SecurityPolicy(
                id="brute_force_protection",
                name="Brute Force Attack Protection",
                policy_type=SecurityPolicyType.AUTHENTICATION,
                description="Protection against brute force attacks",
                enabled=True,
                rules={
                    'failed_attempts_threshold': 5,
                    'detection_window_minutes': 10,
                    'lockout_duration_minutes': 60
                },
                violation_threshold=1,
                response_actions=[ResponseAction.ACCOUNT_LOCKOUT, ResponseAction.ALERT_SECURITY_TEAM],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            ),
            SecurityPolicy(
                id="suspicious_ip_monitoring",
                name="Suspicious IP Address Monitoring",
                policy_type=SecurityPolicyType.AUTHORIZATION,
                description="Monitoring for suspicious IP addresses",
                enabled=True,
                rules={
                    'geographic_anomaly_detection': True,
                    'known_malicious_ip_check': True,
                    'rapid_request_detection': True
                },
                violation_threshold=2,
                response_actions=[ResponseAction.LOG_ONLY, ResponseAction.RATE_LIMIT],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            ),
            SecurityPolicy(
                id="privilege_escalation_detection",
                name="Privilege Escalation Detection",
                policy_type=SecurityPolicyType.AUTHORIZATION,
                description="Detection of privilege escalation attempts",
                enabled=True,
                rules={
                    'role_change_monitoring': True,
                    'admin_endpoint_access_monitoring': True,
                    'permission_boundary_violations': True
                },
                violation_threshold=1,
                response_actions=[ResponseAction.ALERT_SECURITY_TEAM, ResponseAction.SESSION_REVOCATION],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            ),
            SecurityPolicy(
                id="session_security",
                name="Session Security Policy",
                policy_type=SecurityPolicyType.SESSION_POLICY,
                description="Session security and management policies",
                enabled=True,
                rules={
                    'session_timeout_minutes': 60,
                    'concurrent_session_limit': 3,
                    'session_hijacking_detection': True,
                    'secure_cookie_enforcement': True
                },
                violation_threshold=2,
                response_actions=[ResponseAction.SESSION_REVOCATION, ResponseAction.LOG_ONLY],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
        ]
        
        for policy in default_policies:
            self.policies[policy.id] = policy
            
        self.logger.info(f"Loaded {len(default_policies)} default security policies")
    
    def _init_ip_lists(self):
        """Initialize IP whitelist and blacklist"""
        # Load trusted IPs from configuration
        trusted_ips = self.app.config.get('TRUSTED_IPS', [])
        for ip in trusted_ips:
            try:
                ipaddress.ip_address(ip)
                self.trusted_ips.add(ip)
            except ValueError:
                self.logger.warning(f"Invalid trusted IP address: {ip}")
        
        # Load blocked IPs from persistent storage
        if self.redis_client:
            try:
                blocked_ips = self.redis_client.smembers('security:blocked_ips')
                self.blocked_ips.update(blocked_ips)
                self.logger.info(f"Loaded {len(blocked_ips)} blocked IPs from Redis")
            except Exception as e:
                self.logger.warning("Failed to load blocked IPs from Redis", error=str(e))
    
    def _register_flask_hooks(self):
        """Register Flask request hooks for security monitoring"""
        
        @self.app.before_request
        def before_request_security_check():
            """Security check before each request"""
            self._track_request_metrics()
            self._check_ip_blocking()
            self._check_rate_limiting()
            self._validate_session_security()
        
        @self.app.after_request
        def after_request_security_log(response):
            """Security logging after each request"""
            self._log_request_security(response)
            return response
        
        @self.app.teardown_request
        def teardown_request_security(exception):
            """Security cleanup after request"""
            if exception:
                self._handle_request_exception(exception)
    
    def start_monitoring(self):
        """Start security monitoring thread"""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._security_monitoring_loop,
            daemon=True,
            name="SecurityPolicyMonitoring"
        )
        self.monitoring_thread.start()
        
        self.logger.info("Security monitoring started")
    
    def stop_monitoring(self):
        """Stop security monitoring thread"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=30)
        
        self.logger.info("Security monitoring stopped")
    
    def _security_monitoring_loop(self):
        """Main security monitoring loop"""
        while self.monitoring_active:
            try:
                self._analyze_security_patterns()
                self._cleanup_expired_violations()
                self._update_threat_intelligence()
                self._sync_blocked_ips()
                self._collect_security_metrics()
                
                time.sleep(self.config['monitoring_interval'])
                
            except Exception as e:
                self.logger.error("Error in security monitoring loop", error=str(e))
                time.sleep(self.config['monitoring_interval'])
    
    def enforce_policy(self, policy_type: SecurityPolicyType, context: Dict[str, Any]) -> bool:
        """
        Enforce security policy for given context
        
        Args:
            policy_type: Type of security policy to enforce
            context: Request context information
            
        Returns:
            bool: True if policy allows access, False otherwise
        """
        start_time = time.time()
        
        try:
            # Find applicable policies
            applicable_policies = [
                policy for policy in self.policies.values()
                if policy.policy_type == policy_type and policy.enabled
            ]
            
            if not applicable_policies:
                self.logger.debug(f"No policies found for type: {policy_type}")
                return True
            
            # Evaluate each policy
            for policy in applicable_policies:
                if not self._evaluate_policy(policy, context):
                    self._record_policy_violation(policy, context)
                    
                    # Record metrics
                    self.metrics['security_policies_enforced_total'].labels(
                        policy_type=policy_type.value,
                        action='deny',
                        result='blocked'
                    ).inc()
                    
                    return False
            
            # All policies passed
            self.metrics['security_policies_enforced_total'].labels(
                policy_type=policy_type.value,
                action='allow',
                result='passed'
            ).inc()
            
            return True
            
        finally:
            # Record response time
            response_time = time.time() - start_time
            self.metrics['security_response_time_seconds'].labels(
                policy_type=policy_type.value,
                action='enforce'
            ).observe(response_time)
    
    def _evaluate_policy(self, policy: SecurityPolicy, context: Dict[str, Any]) -> bool:
        """
        Evaluate individual security policy
        
        Args:
            policy: Security policy to evaluate
            context: Request context information
            
        Returns:
            bool: True if policy allows access, False otherwise
        """
        try:
            if policy.policy_type == SecurityPolicyType.RATE_LIMITING:
                return self._evaluate_rate_limiting_policy(policy, context)
            elif policy.policy_type == SecurityPolicyType.AUTHENTICATION:
                return self._evaluate_authentication_policy(policy, context)
            elif policy.policy_type == SecurityPolicyType.AUTHORIZATION:
                return self._evaluate_authorization_policy(policy, context)
            elif policy.policy_type == SecurityPolicyType.SESSION_POLICY:
                return self._evaluate_session_policy(policy, context)
            else:
                self.logger.warning(f"Unknown policy type: {policy.policy_type}")
                return True
                
        except Exception as e:
            self.logger.error(
                "Error evaluating policy",
                policy_id=policy.id,
                error=str(e)
            )
            # Fail closed - deny access on policy evaluation error
            return False
    
    def _evaluate_rate_limiting_policy(self, policy: SecurityPolicy, context: Dict[str, Any]) -> bool:
        """Evaluate rate limiting policy"""
        source_ip = context.get('source_ip', 'unknown')
        user_id = context.get('user_id')
        endpoint = context.get('endpoint', 'unknown')
        
        # Create rate limiting key
        if user_id:
            rate_limit_key = f"user:{user_id}:{endpoint}"
        else:
            rate_limit_key = f"ip:{source_ip}:{endpoint}"
        
        # Get or create rate limiter
        if rate_limit_key not in self.rate_limiters:
            self.rate_limiters[rate_limit_key] = RateLimitBucket(
                capacity=policy.rules.get('max_attempts', self.config['rate_limit_capacity']),
                refill_rate=self.config['rate_limit_refill_rate']
            )
        
        rate_limiter = self.rate_limiters[rate_limit_key]
        
        # Check rate limit
        if not rate_limiter.consume():
            self.metrics['rate_limit_requests_total'].labels(
                endpoint=endpoint,
                user_id=user_id or 'anonymous',
                result='blocked'
            ).inc()
            
            # Record violation
            self._record_security_violation(
                SecurityViolationType.RATE_LIMIT_EXCEEDED,
                SecurityLevel.MEDIUM,
                context,
                f"Rate limit exceeded for {rate_limit_key}"
            )
            
            return False
        
        self.metrics['rate_limit_requests_total'].labels(
            endpoint=endpoint,
            user_id=user_id or 'anonymous',
            result='allowed'
        ).inc()
        
        return True
    
    def _evaluate_authentication_policy(self, policy: SecurityPolicy, context: Dict[str, Any]) -> bool:
        """Evaluate authentication policy"""
        if policy.id == "brute_force_protection":
            return self._check_brute_force_protection(context)
        
        return True
    
    def _evaluate_authorization_policy(self, policy: SecurityPolicy, context: Dict[str, Any]) -> bool:
        """Evaluate authorization policy"""
        if policy.id == "suspicious_ip_monitoring":
            return self._check_suspicious_ip(context)
        elif policy.id == "privilege_escalation_detection":
            return self._check_privilege_escalation(context)
        
        return True
    
    def _evaluate_session_policy(self, policy: SecurityPolicy, context: Dict[str, Any]) -> bool:
        """Evaluate session policy"""
        if policy.id == "session_security":
            return self._check_session_security(context)
        
        return True
    
    def _check_brute_force_protection(self, context: Dict[str, Any]) -> bool:
        """Check for brute force attack patterns"""
        source_ip = context.get('source_ip', 'unknown')
        user_id = context.get('user_id')
        
        # Check failed authentication attempts
        key = f"auth_failures:{source_ip}"
        if user_id:
            key += f":{user_id}"
        
        if self.redis_client:
            try:
                failures = self.redis_client.get(key)
                if failures and int(failures) >= self.config['brute_force_threshold']:
                    self._record_security_violation(
                        SecurityViolationType.BRUTE_FORCE_ATTACK,
                        SecurityLevel.HIGH,
                        context,
                        f"Brute force attack detected from {source_ip}"
                    )
                    return False
            except Exception as e:
                self.logger.warning("Redis operation failed", error=str(e))
        
        return True
    
    def _check_suspicious_ip(self, context: Dict[str, Any]) -> bool:
        """Check for suspicious IP addresses"""
        source_ip = context.get('source_ip', 'unknown')
        
        # Check if IP is in blocked list
        if source_ip in self.blocked_ips:
            self._record_security_violation(
                SecurityViolationType.UNAUTHORIZED_ACCESS,
                SecurityLevel.HIGH,
                context,
                f"Access attempt from blocked IP: {source_ip}"
            )
            return False
        
        # Additional suspicious IP checks would go here
        # (GeoIP anomalies, known malicious IPs, etc.)
        
        return True
    
    def _check_privilege_escalation(self, context: Dict[str, Any]) -> bool:
        """Check for privilege escalation attempts"""
        user_id = context.get('user_id')
        endpoint = context.get('endpoint', '')
        
        # Check for admin endpoint access by non-admin users
        if 'admin' in endpoint.lower() and user_id:
            # This would typically check user roles from the database
            # For now, we'll implement a basic check
            if not self._user_has_admin_role(user_id):
                self._record_security_violation(
                    SecurityViolationType.PRIVILEGE_ESCALATION,
                    SecurityLevel.HIGH,
                    context,
                    f"Non-admin user {user_id} attempted to access admin endpoint: {endpoint}"
                )
                return False
        
        return True
    
    def _check_session_security(self, context: Dict[str, Any]) -> bool:
        """Check session security policies"""
        session_id = context.get('session_id')
        
        if not session_id:
            return True
        
        # Check session validity and security
        if session_id in self.security_sessions:
            session_info = self.security_sessions[session_id]
            
            # Check session timeout
            if datetime.utcnow() > session_info.get('expires_at', datetime.utcnow()):
                self._record_security_violation(
                    SecurityViolationType.INVALID_SESSION,
                    SecurityLevel.MEDIUM,
                    context,
                    f"Expired session access attempt: {session_id}"
                )
                return False
        
        return True
    
    def _user_has_admin_role(self, user_id: str) -> bool:
        """
        Check if user has admin role
        
        This is a placeholder implementation. In a real application,
        this would query the user's roles from the database.
        """
        # This would typically query the database for user roles
        # For demonstration purposes, we'll return False
        return False
    
    def _record_policy_violation(self, policy: SecurityPolicy, context: Dict[str, Any]):
        """Record security policy violation"""
        violation_id = str(uuid.uuid4())
        
        violation = SecurityViolation(
            id=violation_id,
            violation_type=SecurityViolationType.UNAUTHORIZED_ACCESS,
            severity=SecurityLevel.MEDIUM,
            source_ip=context.get('source_ip', 'unknown'),
            user_id=context.get('user_id'),
            session_id=context.get('session_id'),
            endpoint=context.get('endpoint'),
            description=f"Policy violation: {policy.name}",
            evidence={'policy_id': policy.id, 'context': context},
            timestamp=datetime.utcnow()
        )
        
        self.violations[violation_id] = violation
        
        # Execute response actions
        self._execute_response_actions(policy.response_actions, violation)
        
        self.logger.warning(
            "Security policy violation recorded",
            violation_id=violation_id,
            policy_id=policy.id,
            user_id=context.get('user_id'),
            source_ip=context.get('source_ip')
        )
    
    def _record_security_violation(
        self,
        violation_type: SecurityViolationType,
        severity: SecurityLevel,
        context: Dict[str, Any],
        description: str
    ):
        """Record security violation"""
        violation_id = str(uuid.uuid4())
        
        violation = SecurityViolation(
            id=violation_id,
            violation_type=violation_type,
            severity=severity,
            source_ip=context.get('source_ip', 'unknown'),
            user_id=context.get('user_id'),
            session_id=context.get('session_id'),
            endpoint=context.get('endpoint'),
            description=description,
            evidence=context,
            timestamp=datetime.utcnow()
        )
        
        self.violations[violation_id] = violation
        
        # Record metrics
        self.metrics['security_violations_total'].labels(
            violation_type=violation_type.value,
            severity=severity.value,
            source='policy_service'
        ).inc()
        
        # Determine response actions based on severity
        response_actions = self._determine_response_actions(violation_type, severity)
        self._execute_response_actions(response_actions, violation)
        
        self.logger.error(
            "Security violation detected",
            violation_id=violation_id,
            violation_type=violation_type.value,
            severity=severity.value,
            description=description,
            user_id=context.get('user_id'),
            source_ip=context.get('source_ip')
        )
    
    def _determine_response_actions(
        self,
        violation_type: SecurityViolationType,
        severity: SecurityLevel
    ) -> List[ResponseAction]:
        """Determine appropriate response actions for violation"""
        actions = [ResponseAction.LOG_ONLY]
        
        if severity == SecurityLevel.CRITICAL:
            actions.extend([
                ResponseAction.PERMANENT_BLOCK,
                ResponseAction.SESSION_REVOCATION,
                ResponseAction.ALERT_SECURITY_TEAM
            ])
        elif severity == SecurityLevel.HIGH:
            actions.extend([
                ResponseAction.TEMPORARY_BLOCK,
                ResponseAction.SESSION_REVOCATION,
                ResponseAction.ALERT_SECURITY_TEAM
            ])
        elif severity == SecurityLevel.MEDIUM:
            actions.extend([
                ResponseAction.RATE_LIMIT,
                ResponseAction.SESSION_REVOCATION
            ])
        
        # Violation-specific actions
        if violation_type == SecurityViolationType.BRUTE_FORCE_ATTACK:
            actions.append(ResponseAction.ACCOUNT_LOCKOUT)
        elif violation_type == SecurityViolationType.PRIVILEGE_ESCALATION:
            actions.extend([ResponseAction.SESSION_REVOCATION, ResponseAction.ALERT_SECURITY_TEAM])
        
        return list(set(actions))  # Remove duplicates
    
    def _execute_response_actions(self, actions: List[ResponseAction], violation: SecurityViolation):
        """Execute automated response actions"""
        if not self.config.get('enable_auto_response', True):
            return
        
        for action in actions:
            try:
                if action == ResponseAction.LOG_ONLY:
                    continue  # Already logged
                elif action == ResponseAction.RATE_LIMIT:
                    self._apply_rate_limiting(violation)
                elif action == ResponseAction.TEMPORARY_BLOCK:
                    self._block_ip_temporarily(violation.source_ip)
                elif action == ResponseAction.PERMANENT_BLOCK:
                    self._block_ip_permanently(violation.source_ip)
                elif action == ResponseAction.SESSION_REVOCATION:
                    self._revoke_session(violation.session_id)
                elif action == ResponseAction.ACCOUNT_LOCKOUT:
                    self._lockout_account(violation.user_id)
                elif action == ResponseAction.ALERT_SECURITY_TEAM:
                    self._alert_security_team(violation)
                elif action == ResponseAction.EMERGENCY_SHUTDOWN:
                    self._trigger_emergency_shutdown(violation)
                
                violation.response_actions_taken.append(action)
                
                self.logger.info(
                    "Response action executed",
                    action=action.value,
                    violation_id=violation.id
                )
                
            except Exception as e:
                self.logger.error(
                    "Failed to execute response action",
                    action=action.value,
                    violation_id=violation.id,
                    error=str(e)
                )
    
    def _apply_rate_limiting(self, violation: SecurityViolation):
        """Apply rate limiting to source"""
        # Implementation would update rate limiting rules
        pass
    
    def _block_ip_temporarily(self, ip_address: str, duration_minutes: int = None):
        """Block IP address temporarily"""
        if not self.config.get('enable_ip_blocking', True):
            return
        
        duration = duration_minutes or self.config.get('lockout_duration', 900) // 60
        
        self.blocked_ips.add(ip_address)
        
        if self.redis_client:
            try:
                # Store in Redis with expiration
                self.redis_client.setex(
                    f"security:temp_block:{ip_address}",
                    duration * 60,
                    "1"
                )
                self.redis_client.sadd('security:blocked_ips', ip_address)
            except Exception as e:
                self.logger.warning("Failed to store IP block in Redis", error=str(e))
        
        self.logger.warning(f"IP {ip_address} temporarily blocked for {duration} minutes")
    
    def _block_ip_permanently(self, ip_address: str):
        """Block IP address permanently"""
        if not self.config.get('enable_ip_blocking', True):
            return
        
        self.blocked_ips.add(ip_address)
        
        if self.redis_client:
            try:
                self.redis_client.sadd('security:blocked_ips', ip_address)
                self.redis_client.set(f"security:perm_block:{ip_address}", "1")
            except Exception as e:
                self.logger.warning("Failed to store permanent IP block in Redis", error=str(e))
        
        self.logger.error(f"IP {ip_address} permanently blocked")
    
    def _revoke_session(self, session_id: Optional[str]):
        """Revoke user session"""
        if not session_id:
            return
        
        # Remove from security sessions
        if session_id in self.security_sessions:
            del self.security_sessions[session_id]
        
        # Mark session as revoked in Redis
        if self.redis_client:
            try:
                self.redis_client.sadd('security:revoked_sessions', session_id)
            except Exception as e:
                self.logger.warning("Failed to store session revocation in Redis", error=str(e))
        
        self.logger.warning(f"Session {session_id} revoked")
    
    def _lockout_account(self, user_id: Optional[str]):
        """Lock out user account"""
        if not user_id:
            return
        
        # Implementation would disable user account
        # This is a placeholder for account lockout logic
        
        if self.redis_client:
            try:
                lockout_duration = self.config.get('lockout_duration', 900)
                self.redis_client.setex(
                    f"security:account_lockout:{user_id}",
                    lockout_duration,
                    "1"
                )
            except Exception as e:
                self.logger.warning("Failed to store account lockout in Redis", error=str(e))
        
        self.logger.error(f"Account {user_id} locked out")
    
    def _alert_security_team(self, violation: SecurityViolation):
        """Send alert to security team"""
        alert_data = {
            'violation_id': violation.id,
            'type': violation.violation_type.value,
            'severity': violation.severity.value,
            'source_ip': violation.source_ip,
            'user_id': violation.user_id,
            'timestamp': violation.timestamp.isoformat(),
            'description': violation.description
        }
        
        # Send SNS notification
        if self.aws_sns_client:
            try:
                topic_arn = self.app.config.get('SECURITY_ALERT_SNS_TOPIC')
                if topic_arn:
                    self.aws_sns_client.publish(
                        TopicArn=topic_arn,
                        Subject=f"Security Alert: {violation.violation_type.value}",
                        Message=json.dumps(alert_data, indent=2)
                    )
            except Exception as e:
                self.logger.error("Failed to send SNS alert", error=str(e))
        
        # Log structured alert
        self.logger.critical("SECURITY ALERT", **alert_data)
    
    def _trigger_emergency_shutdown(self, violation: SecurityViolation):
        """Trigger emergency shutdown procedures"""
        self.logger.critical(
            "EMERGENCY SHUTDOWN TRIGGERED",
            violation_id=violation.id,
            violation_type=violation.violation_type.value,
            severity=violation.severity.value
        )
        
        # This would implement emergency shutdown procedures
        # For safety, this is left as a placeholder
    
    def _track_request_metrics(self):
        """Track request metrics for security monitoring"""
        if not hasattr(g, 'request_start_time'):
            g.request_start_time = time.time()
        
        # Track authentication attempts
        if request.endpoint and 'auth' in request.endpoint:
            self.metrics['authentication_attempts_total'].labels(
                result='attempted',
                source=request.remote_addr or 'unknown',
                user_id=getattr(g, 'user_id', 'anonymous')
            ).inc()
    
    def _check_ip_blocking(self):
        """Check if request IP is blocked"""
        if not request.remote_addr:
            return
        
        if request.remote_addr in self.blocked_ips:
            self.logger.warning(
                "Blocked IP access attempt",
                ip_address=request.remote_addr,
                endpoint=request.endpoint
            )
            abort(403, "Access denied")
    
    def _check_rate_limiting(self):
        """Check rate limiting for current request"""
        context = {
            'source_ip': request.remote_addr,
            'user_id': getattr(g, 'user_id', None),
            'endpoint': request.endpoint,
            'method': request.method
        }
        
        if not self.enforce_policy(SecurityPolicyType.RATE_LIMITING, context):
            abort(429, "Too many requests")
    
    def _validate_session_security(self):
        """Validate session security policies"""
        if not self.config.get('enable_session_tracking', True):
            return
        
        session_id = session.get('session_id')
        if session_id:
            context = {
                'source_ip': request.remote_addr,
                'user_id': getattr(g, 'user_id', None),
                'session_id': session_id,
                'endpoint': request.endpoint
            }
            
            if not self.enforce_policy(SecurityPolicyType.SESSION_POLICY, context):
                session.clear()
                abort(401, "Session invalid")
    
    def _log_request_security(self, response):
        """Log security information for request"""
        # Calculate request duration
        request_duration = time.time() - getattr(g, 'request_start_time', time.time())
        
        # Log security-relevant requests
        security_log_data = {
            'method': request.method,
            'endpoint': request.endpoint,
            'status_code': response.status_code,
            'duration_ms': round(request_duration * 1000, 2),
            'user_id': getattr(g, 'user_id', None),
            'session_id': session.get('session_id'),
            'source_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Log based on status code
        if response.status_code >= 400:
            self.logger.warning("Security-relevant request", **security_log_data)
        else:
            self.logger.debug("Request completed", **security_log_data)
    
    def _handle_request_exception(self, exception):
        """Handle request exceptions for security monitoring"""
        if isinstance(exception, (Forbidden, Unauthorized)):
            context = {
                'source_ip': request.remote_addr,
                'user_id': getattr(g, 'user_id', None),
                'session_id': session.get('session_id'),
                'endpoint': request.endpoint,
                'exception_type': type(exception).__name__
            }
            
            self._record_security_violation(
                SecurityViolationType.UNAUTHORIZED_ACCESS,
                SecurityLevel.MEDIUM,
                context,
                f"Access denied: {str(exception)}"
            )
    
    def _analyze_security_patterns(self):
        """Analyze security patterns and anomalies"""
        # Analyze violation patterns
        recent_violations = [
            v for v in self.violations.values()
            if v.timestamp > datetime.utcnow() - timedelta(hours=1)
        ]
        
        # Check for attack patterns
        ip_violations = defaultdict(list)
        for violation in recent_violations:
            ip_violations[violation.source_ip].append(violation)
        
        # Detect coordinated attacks
        for ip, violations in ip_violations.items():
            if len(violations) > 10:  # Threshold for coordinated attack
                self._record_security_violation(
                    SecurityViolationType.BRUTE_FORCE_ATTACK,
                    SecurityLevel.HIGH,
                    {'source_ip': ip},
                    f"Coordinated attack detected from {ip} with {len(violations)} violations"
                )
    
    def _cleanup_expired_violations(self):
        """Clean up expired security violations"""
        cutoff_date = datetime.utcnow() - timedelta(days=self.config['violation_retention_days'])
        
        expired_violations = [
            v_id for v_id, v in self.violations.items()
            if v.timestamp < cutoff_date
        ]
        
        for v_id in expired_violations:
            del self.violations[v_id]
        
        if expired_violations:
            self.logger.info(f"Cleaned up {len(expired_violations)} expired violations")
    
    def _update_threat_intelligence(self):
        """Update threat intelligence data"""
        # This would integrate with external threat intelligence feeds
        # For now, it's a placeholder
        pass
    
    def _sync_blocked_ips(self):
        """Synchronize blocked IPs with Redis"""
        if not self.redis_client:
            return
        
        try:
            # Check for expired temporary blocks
            for ip in list(self.blocked_ips):
                temp_block_key = f"security:temp_block:{ip}"
                if not self.redis_client.exists(temp_block_key):
                    perm_block_key = f"security:perm_block:{ip}"
                    if not self.redis_client.exists(perm_block_key):
                        self.blocked_ips.remove(ip)
                        self.redis_client.srem('security:blocked_ips', ip)
            
            # Update metrics
            self.metrics['blocked_ips_total'].set(len(self.blocked_ips))
            
        except Exception as e:
            self.logger.warning("Failed to sync blocked IPs", error=str(e))
    
    def _collect_security_metrics(self):
        """Collect and update security metrics"""
        if not self.config.get('enable_metrics_collection', True):
            return
        
        # Count active threats
        recent_violations = [
            v for v in self.violations.values()
            if v.timestamp > datetime.utcnow() - timedelta(hours=1) and not v.resolved
        ]
        
        self.metrics['active_threats_total'].set(len(recent_violations))
        
        # Send metrics to CloudWatch
        if self.aws_cloudwatch_client:
            try:
                self.aws_cloudwatch_client.put_metric_data(
                    Namespace='SecurityPolicy',
                    MetricData=[
                        {
                            'MetricName': 'ActiveThreats',
                            'Value': len(recent_violations),
                            'Unit': 'Count',
                            'Timestamp': datetime.utcnow()
                        },
                        {
                            'MetricName': 'BlockedIPs',
                            'Value': len(self.blocked_ips),
                            'Unit': 'Count',
                            'Timestamp': datetime.utcnow()
                        }
                    ]
                )
            except Exception as e:
                self.logger.warning("Failed to send metrics to CloudWatch", error=str(e))
    
    # Public API Methods
    
    def validate_access(self, user_id: str, resource: str, permission: str) -> bool:
        """
        Validate user access to resource with specific permission
        
        Args:
            user_id: User identifier
            resource: Resource being accessed
            permission: Required permission
            
        Returns:
            bool: True if access is allowed, False otherwise
        """
        context = {
            'user_id': user_id,
            'resource': resource,
            'permission': permission,
            'source_ip': request.remote_addr if request else 'system',
            'endpoint': request.endpoint if request else 'system'
        }
        
        # Record authorization check metric
        result = self.enforce_policy(SecurityPolicyType.AUTHORIZATION, context)
        
        self.metrics['authorization_checks_total'].labels(
            resource=resource,
            permission=permission,
            result='allowed' if result else 'denied'
        ).inc()
        
        return result
    
    def record_authentication_attempt(
        self,
        user_id: Optional[str],
        success: bool,
        source_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Record authentication attempt for monitoring
        
        Args:
            user_id: User identifier (if known)
            success: Whether authentication was successful
            source_ip: Source IP address
            details: Additional authentication details
        """
        source_ip = source_ip or (request.remote_addr if request else 'unknown')
        
        # Record metrics
        self.metrics['authentication_attempts_total'].labels(
            result='success' if success else 'failure',
            source=source_ip,
            user_id=user_id or 'anonymous'
        ).inc()
        
        # Track failed attempts for brute force detection
        if not success:
            key = f"auth_failures:{source_ip}"
            if user_id:
                key += f":{user_id}"
            
            if self.redis_client:
                try:
                    # Increment failure count with expiration
                    pipe = self.redis_client.pipeline()
                    pipe.incr(key)
                    pipe.expire(key, 900)  # 15 minutes
                    pipe.execute()
                except Exception as e:
                    self.logger.warning("Failed to record auth failure in Redis", error=str(e))
        else:
            # Clear failure count on successful authentication
            if self.redis_client and user_id:
                try:
                    key = f"auth_failures:{source_ip}:{user_id}"
                    self.redis_client.delete(key)
                except Exception as e:
                    self.logger.warning("Failed to clear auth failures in Redis", error=str(e))
    
    def get_security_metrics(self) -> SecurityMetrics:
        """
        Get current security metrics
        
        Returns:
            SecurityMetrics: Current security metrics summary
        """
        violations_by_type = defaultdict(int)
        for violation in self.violations.values():
            violations_by_type[violation.violation_type] += 1
        
        active_threats = len([
            v for v in self.violations.values()
            if v.timestamp > datetime.utcnow() - timedelta(hours=1) and not v.resolved
        ])
        
        return SecurityMetrics(
            total_violations=len(self.violations),
            violations_by_type=dict(violations_by_type),
            blocked_ips=self.blocked_ips.copy(),
            active_threats=active_threats,
            policy_violations=len([v for v in self.violations.values() if not v.resolved]),
            automated_responses=sum(len(v.response_actions_taken) for v in self.violations.values()),
            false_positives=0,  # Would be calculated based on resolved violations
            response_time_avg=0.0  # Would be calculated from metrics
        )
    
    def add_security_policy(self, policy: SecurityPolicy):
        """
        Add new security policy
        
        Args:
            policy: Security policy to add
        """
        self.policies[policy.id] = policy
        
        self.logger.info(
            "Security policy added",
            policy_id=policy.id,
            policy_name=policy.name,
            policy_type=policy.policy_type.value
        )
    
    def remove_security_policy(self, policy_id: str):
        """
        Remove security policy
        
        Args:
            policy_id: ID of policy to remove
        """
        if policy_id in self.policies:
            policy = self.policies.pop(policy_id)
            self.logger.info(
                "Security policy removed",
                policy_id=policy_id,
                policy_name=policy.name
            )
        else:
            self.logger.warning(f"Attempted to remove non-existent policy: {policy_id}")
    
    def unblock_ip(self, ip_address: str):
        """
        Unblock IP address
        
        Args:
            ip_address: IP address to unblock
        """
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            
            if self.redis_client:
                try:
                    self.redis_client.srem('security:blocked_ips', ip_address)
                    self.redis_client.delete(f"security:temp_block:{ip_address}")
                    self.redis_client.delete(f"security:perm_block:{ip_address}")
                except Exception as e:
                    self.logger.warning("Failed to remove IP from Redis", error=str(e))
            
            self.logger.info(f"IP {ip_address} unblocked")
        else:
            self.logger.warning(f"Attempted to unblock non-blocked IP: {ip_address}")
    
    def resolve_violation(self, violation_id: str, resolution_notes: str = ""):
        """
        Mark security violation as resolved
        
        Args:
            violation_id: ID of violation to resolve
            resolution_notes: Notes about resolution
        """
        if violation_id in self.violations:
            violation = self.violations[violation_id]
            violation.resolved = True
            
            self.logger.info(
                "Security violation resolved",
                violation_id=violation_id,
                violation_type=violation.violation_type.value,
                resolution_notes=resolution_notes
            )
        else:
            self.logger.warning(f"Attempted to resolve non-existent violation: {violation_id}")


# Decorator factory for easy security policy enforcement
def require_security_policy(policy_type: SecurityPolicyType):
    """
    Decorator to enforce security policy on Flask routes
    
    Args:
        policy_type: Type of security policy to enforce
        
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if hasattr(current_app, 'security_policy_service'):
                context = {
                    'source_ip': request.remote_addr,
                    'user_id': getattr(g, 'user_id', None),
                    'session_id': session.get('session_id'),
                    'endpoint': request.endpoint,
                    'method': request.method
                }
                
                service = current_app.security_policy_service
                if not service.enforce_policy(policy_type, context):
                    abort(403, "Security policy violation")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Helper functions for common security checks
def require_authentication_policy(f):
    """Decorator to enforce authentication policies"""
    return require_security_policy(SecurityPolicyType.AUTHENTICATION)(f)


def require_authorization_policy(f):
    """Decorator to enforce authorization policies"""
    return require_security_policy(SecurityPolicyType.AUTHORIZATION)(f)


def require_rate_limiting(f):
    """Decorator to enforce rate limiting policies"""
    return require_security_policy(SecurityPolicyType.RATE_LIMITING)(f)


# Export key classes and functions
__all__ = [
    'SecurityPolicyService',
    'SecurityPolicy',
    'SecurityViolation',
    'SecurityMetrics',
    'SecurityPolicyType',
    'SecurityViolationType',
    'SecurityLevel',
    'ResponseAction',
    'require_security_policy',
    'require_authentication_policy',
    'require_authorization_policy',
    'require_rate_limiting'
]