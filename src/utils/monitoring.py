"""
Application monitoring and health check utilities for Flask 3.1.1 application.

This module provides comprehensive monitoring capabilities including:
- Prometheus metrics integration for Flask applications
- Health check endpoints for container orchestration (Section 8.3)
- Performance monitoring and SLA compliance tracking (Section 5.4.5)
- Anomaly detection for security and operational monitoring (Section 6.4.6.1)
- Custom metrics collection for business logic monitoring (Section 5.4.1)
- AWS CloudWatch integration for enterprise observability

The module integrates with the Flask application factory pattern and supports
Python 3.13.3 runtime requirements with comprehensive monitoring capabilities.
"""

import time
import threading
import psutil
import os
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any, Union
from functools import wraps
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum

# Flask framework imports
from flask import Flask, request, g, current_app, jsonify, Response
from werkzeug.exceptions import InternalServerError

# Prometheus client library for metrics collection
from prometheus_client import (
    Counter, Histogram, Gauge, Summary, Info, Enum as PrometheusEnum,
    generate_latest, CollectorRegistry, CONTENT_TYPE_LATEST,
    multiprocess, CollectorRegistry as DefaultRegistry
)

# AWS CloudWatch integration
try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

# Machine learning for anomaly detection
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Internal imports
from src.utils.logging import get_logger
from src.utils.config import get_config


class HealthStatus(Enum):
    """Health check status enumeration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class MetricType(Enum):
    """Metric type enumeration for categorization."""
    COUNTER = "counter"
    HISTOGRAM = "histogram"
    GAUGE = "gauge"
    SUMMARY = "summary"


@dataclass
class HealthCheckResult:
    """Health check result data structure."""
    name: str
    status: HealthStatus
    message: str
    timestamp: datetime
    duration_ms: float
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricDefinition:
    """Metric definition for consistent metric creation."""
    name: str
    description: str
    metric_type: MetricType
    labels: List[str] = field(default_factory=list)
    buckets: Optional[List[float]] = None


class PrometheusMetricsManager:
    """
    Prometheus metrics manager for Flask application monitoring.
    
    Implements comprehensive metrics collection per Section 5.4.1 with support for:
    - HTTP request metrics
    - Authentication and authorization metrics
    - Security event metrics
    - Performance metrics
    - Business logic metrics
    """
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        """Initialize Prometheus metrics manager."""
        self.logger = get_logger(__name__)
        self.registry = registry or CollectorRegistry()
        self._metrics: Dict[str, Any] = {}
        self._setup_core_metrics()
    
    def _setup_core_metrics(self):
        """Setup core application metrics."""
        
        # HTTP Request Metrics
        self._metrics['http_requests_total'] = Counter(
            'flask_http_requests_total',
            'Total HTTP requests by method, endpoint, and status',
            ['method', 'endpoint', 'blueprint', 'status_code'],
            registry=self.registry
        )
        
        self._metrics['http_request_duration_seconds'] = Histogram(
            'flask_http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint', 'blueprint'],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
            registry=self.registry
        )
        
        self._metrics['http_request_size_bytes'] = Histogram(
            'flask_http_request_size_bytes',
            'HTTP request size in bytes',
            ['method', 'endpoint', 'blueprint'],
            registry=self.registry
        )
        
        self._metrics['http_response_size_bytes'] = Histogram(
            'flask_http_response_size_bytes',
            'HTTP response size in bytes',
            ['method', 'endpoint', 'blueprint'],
            registry=self.registry
        )
        
        # Authentication Metrics
        self._metrics['auth_attempts_total'] = Counter(
            'flask_auth_attempts_total',
            'Total authentication attempts by status and method',
            ['status', 'method', 'user_type'],
            registry=self.registry
        )
        
        self._metrics['auth_duration_seconds'] = Histogram(
            'flask_auth_duration_seconds',
            'Authentication duration in seconds',
            ['method', 'provider'],
            registry=self.registry
        )
        
        # Security Metrics
        self._metrics['security_events_total'] = Counter(
            'flask_security_events_total',
            'Total security events by type and severity',
            ['event_type', 'severity', 'source'],
            registry=self.registry
        )
        
        self._metrics['rate_limit_exceeded_total'] = Counter(
            'flask_rate_limit_exceeded_total',
            'Total rate limit violations',
            ['endpoint', 'client_type'],
            registry=self.registry
        )
        
        # Performance Metrics
        self._metrics['active_connections'] = Gauge(
            'flask_active_connections',
            'Number of active connections',
            registry=self.registry
        )
        
        self._metrics['database_operations_total'] = Counter(
            'flask_database_operations_total',
            'Total database operations by type and status',
            ['operation', 'table', 'status'],
            registry=self.registry
        )
        
        self._metrics['database_query_duration_seconds'] = Histogram(
            'flask_database_query_duration_seconds',
            'Database query duration in seconds',
            ['operation', 'table'],
            registry=self.registry
        )
        
        # Application Health Metrics
        self._metrics['application_info'] = Info(
            'flask_application_info',
            'Application information',
            registry=self.registry
        )
        
        self._metrics['python_runtime_errors_total'] = Counter(
            'flask_python_runtime_errors_total',
            'Total Python runtime errors by type',
            ['error_type', 'blueprint', 'function'],
            registry=self.registry
        )
        
        # Business Logic Metrics
        self._metrics['business_operations_total'] = Counter(
            'flask_business_operations_total',
            'Total business operations by type and status',
            ['operation_type', 'service', 'status'],
            registry=self.registry
        )
        
        self._metrics['cache_operations_total'] = Counter(
            'flask_cache_operations_total',
            'Total cache operations by type and result',
            ['operation', 'cache_type', 'result'],
            registry=self.registry
        )
        
        # Set application info
        self._metrics['application_info'].info({
            'version': os.getenv('APP_VERSION', '1.0.0'),
            'python_version': '3.13.3',
            'flask_version': '3.1.1',
            'environment': os.getenv('FLASK_ENV', 'production')
        })
    
    def track_http_request(self, method: str, endpoint: str, blueprint: str, 
                          status_code: int, duration: float, 
                          request_size: int = 0, response_size: int = 0):
        """Track HTTP request metrics."""
        self._metrics['http_requests_total'].labels(
            method=method,
            endpoint=endpoint,
            blueprint=blueprint,
            status_code=status_code
        ).inc()
        
        self._metrics['http_request_duration_seconds'].labels(
            method=method,
            endpoint=endpoint,
            blueprint=blueprint
        ).observe(duration)
        
        if request_size > 0:
            self._metrics['http_request_size_bytes'].labels(
                method=method,
                endpoint=endpoint,
                blueprint=blueprint
            ).observe(request_size)
        
        if response_size > 0:
            self._metrics['http_response_size_bytes'].labels(
                method=method,
                endpoint=endpoint,
                blueprint=blueprint
            ).observe(response_size)
    
    def track_authentication(self, success: bool, method: str = 'password', 
                           user_type: str = 'user', duration: float = 0, 
                           provider: str = 'local'):
        """Track authentication metrics."""
        status = 'success' if success else 'failure'
        
        self._metrics['auth_attempts_total'].labels(
            status=status,
            method=method,
            user_type=user_type
        ).inc()
        
        if duration > 0:
            self._metrics['auth_duration_seconds'].labels(
                method=method,
                provider=provider
            ).observe(duration)
    
    def track_security_event(self, event_type: str, severity: str = 'info', 
                           source: str = 'application'):
        """Track security events."""
        self._metrics['security_events_total'].labels(
            event_type=event_type,
            severity=severity,
            source=source
        ).inc()
    
    def track_database_operation(self, operation: str, table: str, 
                               success: bool, duration: float = 0):
        """Track database operation metrics."""
        status = 'success' if success else 'failure'
        
        self._metrics['database_operations_total'].labels(
            operation=operation,
            table=table,
            status=status
        ).inc()
        
        if duration > 0:
            self._metrics['database_query_duration_seconds'].labels(
                operation=operation,
                table=table
            ).observe(duration)
    
    def track_business_operation(self, operation_type: str, service: str, 
                               success: bool):
        """Track business logic operation metrics."""
        status = 'success' if success else 'failure'
        
        self._metrics['business_operations_total'].labels(
            operation_type=operation_type,
            service=service,
            status=status
        ).inc()
    
    def track_python_error(self, error_type: str, blueprint: str = 'unknown', 
                          function: str = 'unknown'):
        """Track Python runtime errors."""
        self._metrics['python_runtime_errors_total'].labels(
            error_type=error_type,
            blueprint=blueprint,
            function=function
        ).inc()
    
    def update_active_connections(self, count: int):
        """Update active connections gauge."""
        self._metrics['active_connections'].set(count)
    
    def get_metrics(self) -> str:
        """Generate metrics in Prometheus format."""
        return generate_latest(self.registry)
    
    def get_metric(self, name: str):
        """Get specific metric by name."""
        return self._metrics.get(name)


class HealthCheckManager:
    """
    Health check manager for container orchestration support.
    
    Implements health check endpoints per Section 8.3 for container orchestration
    with comprehensive system health validation.
    """
    
    def __init__(self):
        """Initialize health check manager."""
        self.logger = get_logger(__name__)
        self.checks: Dict[str, Callable] = {}
        self.last_results: Dict[str, HealthCheckResult] = {}
        self._setup_default_checks()
    
    def _setup_default_checks(self):
        """Setup default health checks."""
        self.register_check('database', self._check_database)
        self.register_check('memory', self._check_memory)
        self.register_check('disk', self._check_disk)
        self.register_check('python_runtime', self._check_python_runtime)
        
        if AWS_AVAILABLE:
            self.register_check('aws_connectivity', self._check_aws_connectivity)
    
    def register_check(self, name: str, check_func: Callable):
        """Register a health check function."""
        self.checks[name] = check_func
        self.logger.info(f"Registered health check: {name}")
    
    def run_check(self, name: str) -> HealthCheckResult:
        """Run a specific health check."""
        if name not in self.checks:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"Health check '{name}' not found",
                timestamp=datetime.utcnow(),
                duration_ms=0
            )
        
        start_time = time.time()
        try:
            result = self.checks[name]()
            duration_ms = (time.time() - start_time) * 1000
            
            if isinstance(result, HealthCheckResult):
                result.duration_ms = duration_ms
                result.timestamp = datetime.utcnow()
            else:
                # Convert simple boolean or dict result
                if isinstance(result, bool):
                    status = HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY
                    message = f"Check '{name}' {'passed' if result else 'failed'}"
                else:
                    status = HealthStatus.HEALTHY
                    message = f"Check '{name}' completed"
                
                result = HealthCheckResult(
                    name=name,
                    status=status,
                    message=message,
                    timestamp=datetime.utcnow(),
                    duration_ms=duration_ms,
                    details=result if isinstance(result, dict) else {}
                )
            
            self.last_results[name] = result
            return result
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            result = HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                timestamp=datetime.utcnow(),
                duration_ms=duration_ms,
                details={'error': str(e), 'traceback': traceback.format_exc()}
            )
            self.last_results[name] = result
            self.logger.error(f"Health check '{name}' failed", error=str(e))
            return result
    
    def run_all_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all registered health checks."""
        results = {}
        for name in self.checks.keys():
            results[name] = self.run_check(name)
        return results
    
    def get_overall_status(self) -> HealthStatus:
        """Get overall application health status."""
        results = self.run_all_checks()
        
        if not results:
            return HealthStatus.UNKNOWN
        
        statuses = [result.status for result in results.values()]
        
        if any(status == HealthStatus.UNHEALTHY for status in statuses):
            return HealthStatus.UNHEALTHY
        elif any(status == HealthStatus.DEGRADED for status in statuses):
            return HealthStatus.DEGRADED
        elif all(status == HealthStatus.HEALTHY for status in statuses):
            return HealthStatus.HEALTHY
        else:
            return HealthStatus.UNKNOWN
    
    def _check_database(self) -> HealthCheckResult:
        """Check database connectivity and performance."""
        try:
            # Import here to avoid circular imports
            from flask import current_app
            from flask_sqlalchemy import SQLAlchemy
            
            if not hasattr(current_app, 'db'):
                return HealthCheckResult(
                    name='database',
                    status=HealthStatus.DEGRADED,
                    message='Database not configured',
                    timestamp=datetime.utcnow(),
                    duration_ms=0
                )
            
            db = current_app.db
            start_time = time.time()
            
            # Simple connectivity test
            result = db.engine.execute('SELECT 1').scalar()
            query_time = (time.time() - start_time) * 1000
            
            if result == 1:
                if query_time > 1000:  # 1 second threshold
                    status = HealthStatus.DEGRADED
                    message = f"Database slow (query time: {query_time:.2f}ms)"
                else:
                    status = HealthStatus.HEALTHY
                    message = f"Database healthy (query time: {query_time:.2f}ms)"
                
                return HealthCheckResult(
                    name='database',
                    status=status,
                    message=message,
                    timestamp=datetime.utcnow(),
                    duration_ms=0,
                    details={
                        'query_time_ms': query_time,
                        'connection_pool_size': db.engine.pool.size(),
                        'checked_out_connections': db.engine.pool.checkedout()
                    }
                )
            else:
                return HealthCheckResult(
                    name='database',
                    status=HealthStatus.UNHEALTHY,
                    message='Database query returned unexpected result',
                    timestamp=datetime.utcnow(),
                    duration_ms=0
                )
                
        except Exception as e:
            return HealthCheckResult(
                name='database',
                status=HealthStatus.UNHEALTHY,
                message=f'Database check failed: {str(e)}',
                timestamp=datetime.utcnow(),
                duration_ms=0,
                details={'error': str(e)}
            )
    
    def _check_memory(self) -> HealthCheckResult:
        """Check memory usage."""
        try:
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            if memory_percent > 90:
                status = HealthStatus.UNHEALTHY
                message = f"Critical memory usage: {memory_percent:.1f}%"
            elif memory_percent > 80:
                status = HealthStatus.DEGRADED
                message = f"High memory usage: {memory_percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Memory usage normal: {memory_percent:.1f}%"
            
            return HealthCheckResult(
                name='memory',
                status=status,
                message=message,
                timestamp=datetime.utcnow(),
                duration_ms=0,
                details={
                    'memory_percent': memory_percent,
                    'memory_total_gb': memory.total / (1024**3),
                    'memory_available_gb': memory.available / (1024**3),
                    'memory_used_gb': memory.used / (1024**3)
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                name='memory',
                status=HealthStatus.UNKNOWN,
                message=f'Memory check failed: {str(e)}',
                timestamp=datetime.utcnow(),
                duration_ms=0
            )
    
    def _check_disk(self) -> HealthCheckResult:
        """Check disk usage."""
        try:
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            if disk_percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Critical disk usage: {disk_percent:.1f}%"
            elif disk_percent > 85:
                status = HealthStatus.DEGRADED
                message = f"High disk usage: {disk_percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Disk usage normal: {disk_percent:.1f}%"
            
            return HealthCheckResult(
                name='disk',
                status=status,
                message=message,
                timestamp=datetime.utcnow(),
                duration_ms=0,
                details={
                    'disk_percent': disk_percent,
                    'disk_total_gb': disk.total / (1024**3),
                    'disk_free_gb': disk.free / (1024**3),
                    'disk_used_gb': disk.used / (1024**3)
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                name='disk',
                status=HealthStatus.UNKNOWN,
                message=f'Disk check failed: {str(e)}',
                timestamp=datetime.utcnow(),
                duration_ms=0
            )
    
    def _check_python_runtime(self) -> HealthCheckResult:
        """Check Python runtime health."""
        try:
            import sys
            import gc
            
            # Check Python version
            python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            expected_version = "3.13.3"
            
            if python_version != expected_version:
                status = HealthStatus.DEGRADED
                message = f"Python version mismatch: {python_version} (expected {expected_version})"
            else:
                status = HealthStatus.HEALTHY
                message = f"Python runtime healthy: {python_version}"
            
            # Get garbage collection stats
            gc_stats = gc.get_stats()
            
            return HealthCheckResult(
                name='python_runtime',
                status=status,
                message=message,
                timestamp=datetime.utcnow(),
                duration_ms=0,
                details={
                    'python_version': python_version,
                    'gc_collections': sum(gen['collections'] for gen in gc_stats),
                    'gc_collected': sum(gen['collected'] for gen in gc_stats),
                    'gc_uncollectable': sum(gen['uncollectable'] for gen in gc_stats),
                    'thread_count': threading.active_count(),
                    'recursion_limit': sys.getrecursionlimit()
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                name='python_runtime',
                status=HealthStatus.UNKNOWN,
                message=f'Python runtime check failed: {str(e)}',
                timestamp=datetime.utcnow(),
                duration_ms=0
            )
    
    def _check_aws_connectivity(self) -> HealthCheckResult:
        """Check AWS service connectivity."""
        if not AWS_AVAILABLE:
            return HealthCheckResult(
                name='aws_connectivity',
                status=HealthStatus.DEGRADED,
                message='AWS SDK not available',
                timestamp=datetime.utcnow(),
                duration_ms=0
            )
        
        try:
            # Test basic AWS connectivity with STS
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            
            return HealthCheckResult(
                name='aws_connectivity',
                status=HealthStatus.HEALTHY,
                message='AWS connectivity healthy',
                timestamp=datetime.utcnow(),
                duration_ms=0,
                details={
                    'account_id': response.get('Account'),
                    'arn': response.get('Arn'),
                    'user_id': response.get('UserId')
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                name='aws_connectivity',
                status=HealthStatus.UNHEALTHY,
                message=f'AWS connectivity check failed: {str(e)}',
                timestamp=datetime.utcnow(),
                duration_ms=0,
                details={'error': str(e)}
            )


class PerformanceMonitor:
    """
    Performance monitoring for SLA compliance tracking per Section 5.4.5.
    
    Monitors response times, throughput, and resource utilization to ensure
    the Flask application meets performance requirements.
    """
    
    def __init__(self, window_size: int = 1000):
        """Initialize performance monitor."""
        self.logger = get_logger(__name__)
        self.window_size = window_size
        self.response_times = deque(maxlen=window_size)
        self.request_counts = defaultdict(lambda: deque(maxlen=window_size))
        self.error_counts = defaultdict(lambda: deque(maxlen=window_size))
        self.sla_thresholds = {
            'p95_response_time_ms': 500,  # 95th percentile < 500ms
            'median_response_time_ms': 200,  # Median < 200ms
            'error_rate_percent': 1.0,  # Error rate < 1%
            'availability_percent': 99.9  # 99.9% availability
        }
    
    def record_request(self, endpoint: str, response_time_ms: float, 
                      status_code: int, timestamp: Optional[datetime] = None):
        """Record request performance metrics."""
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        # Record response time
        self.response_times.append({
            'timestamp': timestamp,
            'response_time_ms': response_time_ms,
            'endpoint': endpoint,
            'status_code': status_code
        })
        
        # Record request count
        self.request_counts[endpoint].append({
            'timestamp': timestamp,
            'status_code': status_code
        })
        
        # Record errors
        if status_code >= 400:
            self.error_counts[endpoint].append({
                'timestamp': timestamp,
                'status_code': status_code
            })
    
    def get_performance_metrics(self, window_minutes: int = 5) -> Dict[str, Any]:
        """Get performance metrics for the specified time window."""
        cutoff_time = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        # Filter recent response times
        recent_times = [
            entry['response_time_ms'] for entry in self.response_times
            if entry['timestamp'] > cutoff_time
        ]
        
        if not recent_times:
            return {
                'status': 'no_data',
                'window_minutes': window_minutes,
                'sample_count': 0
            }
        
        # Calculate percentiles
        recent_times.sort()
        p50_index = int(len(recent_times) * 0.5)
        p95_index = int(len(recent_times) * 0.95)
        p99_index = int(len(recent_times) * 0.99)
        
        metrics = {
            'window_minutes': window_minutes,
            'sample_count': len(recent_times),
            'min_response_time_ms': min(recent_times),
            'max_response_time_ms': max(recent_times),
            'avg_response_time_ms': sum(recent_times) / len(recent_times),
            'median_response_time_ms': recent_times[p50_index],
            'p95_response_time_ms': recent_times[p95_index],
            'p99_response_time_ms': recent_times[p99_index],
        }
        
        # Calculate request rate
        total_requests = sum(
            len([req for req in requests if req['timestamp'] > cutoff_time])
            for requests in self.request_counts.values()
        )
        metrics['requests_per_minute'] = total_requests / window_minutes
        
        # Calculate error rate
        total_errors = sum(
            len([err for err in errors if err['timestamp'] > cutoff_time])
            for errors in self.error_counts.values()
        )
        metrics['error_rate_percent'] = (total_errors / total_requests * 100) if total_requests > 0 else 0
        
        # SLA compliance check
        metrics['sla_compliance'] = self._check_sla_compliance(metrics)
        
        return metrics
    
    def _check_sla_compliance(self, metrics: Dict[str, Any]) -> Dict[str, bool]:
        """Check SLA compliance against defined thresholds."""
        compliance = {}
        
        compliance['p95_response_time'] = (
            metrics['p95_response_time_ms'] <= self.sla_thresholds['p95_response_time_ms']
        )
        
        compliance['median_response_time'] = (
            metrics['median_response_time_ms'] <= self.sla_thresholds['median_response_time_ms']
        )
        
        compliance['error_rate'] = (
            metrics['error_rate_percent'] <= self.sla_thresholds['error_rate_percent']
        )
        
        compliance['overall'] = all(compliance.values())
        
        return compliance
    
    def get_sla_report(self) -> Dict[str, Any]:
        """Generate SLA compliance report."""
        metrics_5min = self.get_performance_metrics(5)
        metrics_15min = self.get_performance_metrics(15)
        metrics_60min = self.get_performance_metrics(60)
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'sla_thresholds': self.sla_thresholds,
            'metrics': {
                '5_minutes': metrics_5min,
                '15_minutes': metrics_15min,
                '60_minutes': metrics_60min
            }
        }


class AnomalyDetector:
    """
    Anomaly detection for security and operational monitoring per Section 6.4.6.1.
    
    Implements machine learning-based anomaly detection for identifying unusual
    patterns in request behavior, authentication attempts, and system metrics.
    """
    
    def __init__(self, contamination: float = 0.1, window_size: int = 1000):
        """Initialize anomaly detector."""
        self.logger = get_logger(__name__)
        self.contamination = contamination
        self.window_size = window_size
        self.enabled = ML_AVAILABLE
        
        if not self.enabled:
            self.logger.warning("Machine learning libraries not available, anomaly detection disabled")
            return
        
        # Initialize ML models
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        
        # Data collection
        self.request_patterns = deque(maxlen=window_size)
        self.auth_patterns = deque(maxlen=window_size)
        self.system_metrics = deque(maxlen=window_size)
        
        # Model training flags
        self.models_trained = False
        self.last_training = None
        self.training_interval = timedelta(hours=1)
    
    def record_request_pattern(self, ip_address: str, user_agent: str, 
                             endpoint: str, timestamp: Optional[datetime] = None):
        """Record request pattern for anomaly detection."""
        if not self.enabled:
            return
        
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        pattern = {
            'timestamp': timestamp,
            'ip_address': ip_address,
            'user_agent_length': len(user_agent),
            'endpoint': endpoint,
            'hour_of_day': timestamp.hour,
            'day_of_week': timestamp.weekday()
        }
        
        self.request_patterns.append(pattern)
    
    def record_auth_pattern(self, success: bool, attempts_in_window: int,
                          source_ip: str, timestamp: Optional[datetime] = None):
        """Record authentication pattern for anomaly detection."""
        if not self.enabled:
            return
        
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        pattern = {
            'timestamp': timestamp,
            'success': 1 if success else 0,
            'attempts_in_window': attempts_in_window,
            'source_ip_hash': hash(source_ip) % 10000,  # Simple IP categorization
            'hour_of_day': timestamp.hour,
            'day_of_week': timestamp.weekday()
        }
        
        self.auth_patterns.append(pattern)
    
    def record_system_metrics(self, cpu_percent: float, memory_percent: float,
                            request_rate: float, error_rate: float,
                            timestamp: Optional[datetime] = None):
        """Record system metrics for anomaly detection."""
        if not self.enabled:
            return
        
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        metrics = {
            'timestamp': timestamp,
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'request_rate': request_rate,
            'error_rate': error_rate
        }
        
        self.system_metrics.append(metrics)
    
    def train_models(self) -> bool:
        """Train anomaly detection models."""
        if not self.enabled:
            return False
        
        try:
            # Check if we have enough data
            if (len(self.request_patterns) < 100 or 
                len(self.auth_patterns) < 50 or 
                len(self.system_metrics) < 100):
                self.logger.info("Insufficient data for model training")
                return False
            
            # Prepare training data
            request_features = self._extract_request_features()
            auth_features = self._extract_auth_features()
            system_features = self._extract_system_features()
            
            if request_features.size > 0:
                request_scaled = self.scaler.fit_transform(request_features)
                self.isolation_forest.fit(request_scaled)
                self.models_trained = True
                self.last_training = datetime.utcnow()
                
                self.logger.info("Anomaly detection models trained successfully")
                return True
            
        except Exception as e:
            self.logger.error(f"Model training failed: {str(e)}")
        
        return False
    
    def detect_anomalies(self) -> Dict[str, List[Dict]]:
        """Detect anomalies in recent data."""
        if not self.enabled or not self.models_trained:
            return {'request_anomalies': [], 'auth_anomalies': [], 'system_anomalies': []}
        
        anomalies = {
            'request_anomalies': [],
            'auth_anomalies': [],
            'system_anomalies': []
        }
        
        try:
            # Check recent request patterns
            recent_requests = list(self.request_patterns)[-50:]  # Last 50 requests
            if recent_requests:
                request_features = self._extract_request_features(recent_requests)
                if request_features.size > 0:
                    request_scaled = self.scaler.transform(request_features)
                    anomaly_scores = self.isolation_forest.predict(request_scaled)
                    
                    for i, score in enumerate(anomaly_scores):
                        if score == -1:  # Anomaly detected
                            anomalies['request_anomalies'].append({
                                'type': 'request_pattern',
                                'timestamp': recent_requests[i]['timestamp'].isoformat(),
                                'details': recent_requests[i],
                                'severity': 'medium'
                            })
            
            # Simple rule-based anomaly detection for auth patterns
            recent_auth = list(self.auth_patterns)[-20:]
            failed_auths = [auth for auth in recent_auth if auth['success'] == 0]
            
            if len(failed_auths) > 5:  # More than 5 failed auths recently
                anomalies['auth_anomalies'].append({
                    'type': 'authentication_failure_spike',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': {'failed_count': len(failed_auths)},
                    'severity': 'high'
                })
            
            # System metrics anomaly detection
            recent_system = list(self.system_metrics)[-10:]
            if recent_system:
                avg_cpu = sum(m['cpu_percent'] for m in recent_system) / len(recent_system)
                avg_memory = sum(m['memory_percent'] for m in recent_system) / len(recent_system)
                avg_error_rate = sum(m['error_rate'] for m in recent_system) / len(recent_system)
                
                if avg_cpu > 80 or avg_memory > 85 or avg_error_rate > 5:
                    anomalies['system_anomalies'].append({
                        'type': 'system_performance_degradation',
                        'timestamp': datetime.utcnow().isoformat(),
                        'details': {
                            'avg_cpu_percent': avg_cpu,
                            'avg_memory_percent': avg_memory,
                            'avg_error_rate': avg_error_rate
                        },
                        'severity': 'high' if avg_error_rate > 10 else 'medium'
                    })
        
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {str(e)}")
        
        return anomalies
    
    def _extract_request_features(self, patterns: Optional[List] = None) -> np.ndarray:
        """Extract features from request patterns."""
        if patterns is None:
            patterns = list(self.request_patterns)
        
        if not patterns:
            return np.array([])
        
        features = []
        for pattern in patterns:
            features.append([
                pattern['user_agent_length'],
                pattern['hour_of_day'],
                pattern['day_of_week'],
                hash(pattern['endpoint']) % 1000  # Simple endpoint categorization
            ])
        
        return np.array(features)
    
    def _extract_auth_features(self, patterns: Optional[List] = None) -> np.ndarray:
        """Extract features from authentication patterns."""
        if patterns is None:
            patterns = list(self.auth_patterns)
        
        if not patterns:
            return np.array([])
        
        features = []
        for pattern in patterns:
            features.append([
                pattern['success'],
                pattern['attempts_in_window'],
                pattern['source_ip_hash'],
                pattern['hour_of_day'],
                pattern['day_of_week']
            ])
        
        return np.array(features)
    
    def _extract_system_features(self, metrics: Optional[List] = None) -> np.ndarray:
        """Extract features from system metrics."""
        if metrics is None:
            metrics = list(self.system_metrics)
        
        if not metrics:
            return np.array([])
        
        features = []
        for metric in metrics:
            features.append([
                metric['cpu_percent'],
                metric['memory_percent'],
                metric['request_rate'],
                metric['error_rate']
            ])
        
        return np.array(features)


class CloudWatchIntegration:
    """
    AWS CloudWatch integration for enterprise observability.
    
    Provides integration with AWS CloudWatch for metrics forwarding,
    log aggregation, and alerting capabilities.
    """
    
    def __init__(self, region_name: str = 'us-east-1', namespace: str = 'Flask/Application'):
        """Initialize CloudWatch integration."""
        self.logger = get_logger(__name__)
        self.enabled = AWS_AVAILABLE
        self.region_name = region_name
        self.namespace = namespace
        
        if not self.enabled:
            self.logger.warning("AWS SDK not available, CloudWatch integration disabled")
            return
        
        try:
            self.cloudwatch = boto3.client('cloudwatch', region_name=region_name)
            self.logs_client = boto3.client('logs', region_name=region_name)
        except Exception as e:
            self.logger.error(f"Failed to initialize AWS clients: {str(e)}")
            self.enabled = False
    
    def put_metric(self, metric_name: str, value: float, unit: str = 'Count',
                  dimensions: Optional[Dict[str, str]] = None,
                  timestamp: Optional[datetime] = None):
        """Put custom metric to CloudWatch."""
        if not self.enabled:
            return
        
        try:
            metric_data = {
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit
            }
            
            if timestamp:
                metric_data['Timestamp'] = timestamp
            
            if dimensions:
                metric_data['Dimensions'] = [
                    {'Name': key, 'Value': value} for key, value in dimensions.items()
                ]
            
            self.cloudwatch.put_metric_data(
                Namespace=self.namespace,
                MetricData=[metric_data]
            )
            
        except Exception as e:
            self.logger.error(f"Failed to put CloudWatch metric: {str(e)}")
    
    def put_metrics_batch(self, metrics: List[Dict[str, Any]]):
        """Put multiple metrics to CloudWatch in batch."""
        if not self.enabled or not metrics:
            return
        
        try:
            # CloudWatch allows max 20 metrics per request
            batch_size = 20
            for i in range(0, len(metrics), batch_size):
                batch = metrics[i:i + batch_size]
                self.cloudwatch.put_metric_data(
                    Namespace=self.namespace,
                    MetricData=batch
                )
                
        except Exception as e:
            self.logger.error(f"Failed to put CloudWatch metrics batch: {str(e)}")
    
    def create_log_group(self, log_group_name: str, retention_days: int = 30):
        """Create CloudWatch log group."""
        if not self.enabled:
            return
        
        try:
            self.logs_client.create_log_group(logGroupName=log_group_name)
            self.logs_client.put_retention_policy(
                logGroupName=log_group_name,
                retentionInDays=retention_days
            )
            self.logger.info(f"Created CloudWatch log group: {log_group_name}")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                self.logger.info(f"CloudWatch log group already exists: {log_group_name}")
            else:
                self.logger.error(f"Failed to create log group: {str(e)}")
        except Exception as e:
            self.logger.error(f"Failed to create log group: {str(e)}")


class FlaskMonitoringExtension:
    """
    Flask monitoring extension that integrates all monitoring components.
    
    Provides a unified interface for Flask application monitoring with automatic
    request tracking, health checks, and metrics collection.
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """Initialize Flask monitoring extension."""
        self.app = app
        self.logger = get_logger(__name__)
        
        # Initialize monitoring components
        self.metrics_manager = PrometheusMetricsManager()
        self.health_manager = HealthCheckManager()
        self.performance_monitor = PerformanceMonitor()
        self.anomaly_detector = AnomalyDetector()
        self.cloudwatch = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize monitoring with Flask application."""
        self.app = app
        
        # Store extension in app
        app.monitoring = self
        
        # Initialize CloudWatch if configured
        aws_region = app.config.get('AWS_REGION', 'us-east-1')
        cloudwatch_namespace = app.config.get('CLOUDWATCH_NAMESPACE', 'Flask/Application')
        self.cloudwatch = CloudWatchIntegration(aws_region, cloudwatch_namespace)
        
        # Register request handlers
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        app.teardown_appcontext(self._teardown_request)
        
        # Register routes
        self._register_routes(app)
        
        # Setup periodic tasks
        if app.config.get('MONITORING_BACKGROUND_TASKS', True):
            self._setup_background_tasks()
        
        self.logger.info("Flask monitoring extension initialized")
    
    def _before_request(self):
        """Handle before request monitoring."""
        g.monitoring_start_time = time.time()
        g.request_id = request.headers.get('X-Request-ID', f"req_{int(time.time()*1000)}")
        
        # Record request pattern for anomaly detection
        self.anomaly_detector.record_request_pattern(
            ip_address=request.remote_addr or 'unknown',
            user_agent=request.headers.get('User-Agent', ''),
            endpoint=request.endpoint or 'unknown'
        )
    
    def _after_request(self, response):
        """Handle after request monitoring."""
        if hasattr(g, 'monitoring_start_time'):
            duration = time.time() - g.monitoring_start_time
            
            # Get request details
            method = request.method
            endpoint = request.endpoint or 'unknown'
            blueprint = request.blueprint or 'main'
            status_code = response.status_code
            
            # Calculate sizes
            request_size = len(request.get_data()) if request.content_length else 0
            response_size = len(response.get_data()) if response.content_length else 0
            
            # Track metrics
            self.metrics_manager.track_http_request(
                method=method,
                endpoint=endpoint,
                blueprint=blueprint,
                status_code=status_code,
                duration=duration,
                request_size=request_size,
                response_size=response_size
            )
            
            # Track performance
            self.performance_monitor.record_request(
                endpoint=endpoint,
                response_time_ms=duration * 1000,
                status_code=status_code
            )
            
            # Send to CloudWatch if available
            if self.cloudwatch and self.cloudwatch.enabled:
                self.cloudwatch.put_metric(
                    'RequestDuration',
                    duration * 1000,
                    'Milliseconds',
                    dimensions={
                        'Endpoint': endpoint,
                        'Method': method,
                        'StatusCode': str(status_code)
                    }
                )
        
        return response
    
    def _teardown_request(self, exception):
        """Handle request teardown monitoring."""
        if exception:
            # Track error
            self.metrics_manager.track_python_error(
                error_type=type(exception).__name__,
                blueprint=request.blueprint or 'unknown',
                function=request.endpoint or 'unknown'
            )
            
            # Log error for anomaly detection
            self.logger.error(
                "Request error occurred",
                error_type=type(exception).__name__,
                error_message=str(exception),
                endpoint=request.endpoint,
                method=request.method
            )
    
    def _register_routes(self, app: Flask):
        """Register monitoring routes."""
        
        @app.route('/metrics')
        def metrics_endpoint():
            """Prometheus metrics endpoint."""
            return Response(
                self.metrics_manager.get_metrics(),
                mimetype=CONTENT_TYPE_LATEST
            )
        
        @app.route('/health')
        def health_endpoint():
            """Basic health check endpoint for container orchestration."""
            overall_status = self.health_manager.get_overall_status()
            
            response_data = {
                'status': overall_status.value,
                'timestamp': datetime.utcnow().isoformat(),
                'version': app.config.get('APP_VERSION', '1.0.0'),
                'environment': app.config.get('FLASK_ENV', 'production')
            }
            
            status_code = 200 if overall_status == HealthStatus.HEALTHY else 503
            return jsonify(response_data), status_code
        
        @app.route('/health/detailed')
        def detailed_health_endpoint():
            """Detailed health check endpoint."""
            results = self.health_manager.run_all_checks()
            overall_status = self.health_manager.get_overall_status()
            
            response_data = {
                'status': overall_status.value,
                'timestamp': datetime.utcnow().isoformat(),
                'checks': {
                    name: {
                        'status': result.status.value,
                        'message': result.message,
                        'duration_ms': result.duration_ms,
                        'details': result.details
                    }
                    for name, result in results.items()
                }
            }
            
            status_code = 200 if overall_status == HealthStatus.HEALTHY else 503
            return jsonify(response_data), status_code
        
        @app.route('/monitoring/performance')
        def performance_endpoint():
            """Performance metrics endpoint."""
            if not app.config.get('MONITORING_PERFORMANCE_ENDPOINT', True):
                return jsonify({'error': 'Performance endpoint disabled'}), 404
            
            metrics = self.performance_monitor.get_performance_metrics()
            sla_report = self.performance_monitor.get_sla_report()
            
            return jsonify({
                'current_metrics': metrics,
                'sla_report': sla_report
            })
        
        @app.route('/monitoring/anomalies')
        def anomalies_endpoint():
            """Anomaly detection endpoint."""
            if not app.config.get('MONITORING_ANOMALIES_ENDPOINT', True):
                return jsonify({'error': 'Anomalies endpoint disabled'}), 404
            
            anomalies = self.anomaly_detector.detect_anomalies()
            
            return jsonify({
                'timestamp': datetime.utcnow().isoformat(),
                'anomalies': anomalies,
                'models_trained': self.anomaly_detector.models_trained
            })
    
    def _setup_background_tasks(self):
        """Setup background monitoring tasks."""
        def background_monitor():
            """Background monitoring thread."""
            while True:
                try:
                    # Record system metrics
                    cpu_percent = psutil.cpu_percent()
                    memory_percent = psutil.virtual_memory().percent
                    
                    # Get request rate from performance monitor
                    perf_metrics = self.performance_monitor.get_performance_metrics(1)
                    request_rate = perf_metrics.get('requests_per_minute', 0)
                    error_rate = perf_metrics.get('error_rate_percent', 0)
                    
                    # Record for anomaly detection
                    self.anomaly_detector.record_system_metrics(
                        cpu_percent=cpu_percent,
                        memory_percent=memory_percent,
                        request_rate=request_rate,
                        error_rate=error_rate
                    )
                    
                    # Send to CloudWatch
                    if self.cloudwatch and self.cloudwatch.enabled:
                        self.cloudwatch.put_metrics_batch([
                            {
                                'MetricName': 'CPUUtilization',
                                'Value': cpu_percent,
                                'Unit': 'Percent'
                            },
                            {
                                'MetricName': 'MemoryUtilization',
                                'Value': memory_percent,
                                'Unit': 'Percent'
                            },
                            {
                                'MetricName': 'RequestRate',
                                'Value': request_rate,
                                'Unit': 'Count/Minute'
                            }
                        ])
                    
                    # Train anomaly detection models periodically
                    if (not self.anomaly_detector.models_trained or
                        (self.anomaly_detector.last_training and
                         datetime.utcnow() - self.anomaly_detector.last_training > 
                         self.anomaly_detector.training_interval)):
                        self.anomaly_detector.train_models()
                    
                    time.sleep(60)  # Sleep for 1 minute
                    
                except Exception as e:
                    self.logger.error(f"Background monitoring error: {str(e)}")
                    time.sleep(60)
        
        # Start background thread
        monitor_thread = threading.Thread(target=background_monitor, daemon=True)
        monitor_thread.start()
        self.logger.info("Background monitoring tasks started")


# Monitoring decorators for easy integration

def monitor_performance(metric_name: str = None):
    """Decorator to monitor function performance."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            function_name = metric_name or f"{func.__module__}.{func.__name__}"
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Track success
                if hasattr(current_app, 'monitoring'):
                    current_app.monitoring.metrics_manager.track_business_operation(
                        operation_type='function_call',
                        service=function_name,
                        success=True
                    )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                # Track failure
                if hasattr(current_app, 'monitoring'):
                    current_app.monitoring.metrics_manager.track_business_operation(
                        operation_type='function_call',
                        service=function_name,
                        success=False
                    )
                    
                    current_app.monitoring.metrics_manager.track_python_error(
                        error_type=type(e).__name__,
                        blueprint=getattr(g, 'blueprint_name', 'unknown'),
                        function=function_name
                    )
                
                raise
        
        return wrapper
    return decorator


def monitor_database_operation(operation: str, table: str = None):
    """Decorator to monitor database operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            table_name = table or 'unknown'
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Track successful operation
                if hasattr(current_app, 'monitoring'):
                    current_app.monitoring.metrics_manager.track_database_operation(
                        operation=operation,
                        table=table_name,
                        success=True,
                        duration=duration
                    )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                # Track failed operation
                if hasattr(current_app, 'monitoring'):
                    current_app.monitoring.metrics_manager.track_database_operation(
                        operation=operation,
                        table=table_name,
                        success=False,
                        duration=duration
                    )
                
                raise
        
        return wrapper
    return decorator


def monitor_authentication(method: str = 'password', provider: str = 'local'):
    """Decorator to monitor authentication operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Determine success based on result
                success = bool(result) if isinstance(result, (bool, dict, list)) else True
                
                # Track authentication attempt
                if hasattr(current_app, 'monitoring'):
                    current_app.monitoring.metrics_manager.track_authentication(
                        success=success,
                        method=method,
                        duration=duration,
                        provider=provider
                    )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                # Track failed authentication
                if hasattr(current_app, 'monitoring'):
                    current_app.monitoring.metrics_manager.track_authentication(
                        success=False,
                        method=method,
                        duration=duration,
                        provider=provider
                    )
                
                raise
        
        return wrapper
    return decorator


# Utility functions for easy access

def get_monitoring_extension() -> Optional[FlaskMonitoringExtension]:
    """Get the monitoring extension from the current Flask application."""
    return getattr(current_app, 'monitoring', None)


def track_custom_metric(name: str, value: float, labels: Optional[Dict[str, str]] = None):
    """Track a custom business metric."""
    monitoring = get_monitoring_extension()
    if monitoring and monitoring.cloudwatch and monitoring.cloudwatch.enabled:
        monitoring.cloudwatch.put_metric(
            metric_name=name,
            value=value,
            dimensions=labels
        )


def track_security_event(event_type: str, severity: str = 'info', details: Optional[Dict] = None):
    """Track a security event."""
    monitoring = get_monitoring_extension()
    if monitoring:
        monitoring.metrics_manager.track_security_event(
            event_type=event_type,
            severity=severity
        )
        
        # Log the security event
        monitoring.logger.warning(
            f"Security event: {event_type}",
            severity=severity,
            details=details or {}
        )


def check_application_health() -> Dict[str, Any]:
    """Get current application health status."""
    monitoring = get_monitoring_extension()
    if monitoring:
        results = monitoring.health_manager.run_all_checks()
        overall_status = monitoring.health_manager.get_overall_status()
        
        return {
            'status': overall_status.value,
            'timestamp': datetime.utcnow().isoformat(),
            'checks': {
                name: {
                    'status': result.status.value,
                    'message': result.message,
                    'duration_ms': result.duration_ms
                }
                for name, result in results.items()
            }
        }
    
    return {
        'status': 'unknown',
        'message': 'Monitoring not initialized',
        'timestamp': datetime.utcnow().isoformat()
    }


# Export public interface
__all__ = [
    'FlaskMonitoringExtension',
    'PrometheusMetricsManager',
    'HealthCheckManager',
    'PerformanceMonitor',
    'AnomalyDetector',
    'CloudWatchIntegration',
    'HealthStatus',
    'MetricType',
    'HealthCheckResult',
    'MetricDefinition',
    'monitor_performance',
    'monitor_database_operation',
    'monitor_authentication',
    'get_monitoring_extension',
    'track_custom_metric',
    'track_security_event',
    'check_application_health'
]