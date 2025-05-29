"""
Performance Testing Configuration - conftest.py

This module provides pytest-benchmark 5.1.0 fixtures, performance test utilities, baseline data 
management, and specialized testing infrastructure for comprehensive performance validation of the 
Flask migration. This configuration enables consistent performance test execution, benchmark data 
persistence, and integration with monitoring systems for automated performance regression detection.

Key Features:
- Flask 3.1.1 application factory pattern testing fixtures per Section 5.1.1
- pytest-benchmark 5.1.0 configuration for performance testing capabilities per Section 4.7.1
- OpenTelemetry instrumentation integration for comprehensive metrics collection per Section 6.5.1.3
- Baseline comparison and migration validation per Section 4.7.2
- prometheus_flask_exporter and monitoring infrastructure integration per Section 6.5.1.1
- Automated performance regression detection with threshold validation per Section 4.7.2

Migration Context:
This configuration supports the strategic technology migration from Node.js/Express.js to 
Python 3.13.3/Flask 3.1.1 by providing comprehensive performance validation infrastructure 
that ensures functional parity and performance equivalence during the conversion process.
"""

import asyncio
import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Generator
import statistics
import gc
import psutil
import memory_profiler
from dataclasses import dataclass, field
from unittest.mock import patch

import pytest
import pytest_benchmark
from flask import Flask, current_app, g
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

# OpenTelemetry imports for performance instrumentation per Section 6.5.1.3
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

# Prometheus integration for monitoring per Section 6.5.1.1
try:
    from prometheus_flask_exporter import PrometheusMetrics
    from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Memory profiling imports for comprehensive memory analysis per Section 6.5.2.2
try:
    import pympler.tracker
    import pympler.summary
    MEMORY_PROFILING_AVAILABLE = True
except ImportError:
    MEMORY_PROFILING_AVAILABLE = False


# Performance baseline and threshold configuration per Section 4.7.2
@dataclass
class PerformanceThresholds:
    """
    Performance threshold configuration for migration validation.
    
    These thresholds are based on migration requirements from Section 4.11 and ensure
    that Flask implementation meets or exceeds Node.js baseline performance.
    """
    # API response time thresholds per Section 4.11.1
    api_response_time_max: float = 0.200  # 200ms maximum
    api_response_time_p95: float = 0.150  # 95th percentile at 150ms
    api_response_time_mean: float = 0.100  # Mean response time at 100ms
    
    # Database query thresholds per Section 4.11.1
    database_query_time_max: float = 0.100  # 100ms maximum per Section 6.5.1.1
    database_query_time_p95: float = 0.075  # 95th percentile at 75ms
    database_query_time_mean: float = 0.050  # Mean query time at 50ms
    
    # Authentication thresholds per Section 6.5.2.2
    auth_response_time_max: float = 0.150  # 150ms maximum per Section 6.5.2.2
    auth_response_time_p95: float = 0.100  # 95th percentile at 100ms
    auth_response_time_mean: float = 0.075  # Mean auth time at 75ms
    
    # Memory usage thresholds per Section 6.5.2.5
    memory_usage_baseline_factor: float = 1.10  # 110% of Node.js baseline
    memory_leak_threshold_mb: float = 50.0  # 50MB memory growth threshold
    gc_pause_time_max: float = 0.010  # 10ms maximum GC pause per Section 6.5.1.1
    
    # Concurrent load thresholds per Section 4.7.1
    concurrent_users_min: int = 100  # Minimum concurrent users support
    throughput_requests_per_second: float = 500.0  # Minimum RPS capability
    connection_pool_utilization_max: float = 0.80  # 80% max pool utilization
    
    # Performance regression detection per Section 4.7.2
    regression_threshold_percent: float = 5.0  # 5% performance degradation alert
    baseline_comparison_tolerance: float = 0.02  # 2% tolerance for baseline comparison


@dataclass
class BaselineMetrics:
    """
    Node.js baseline metrics storage for migration validation per Section 4.7.2.
    
    This class maintains Node.js performance baseline data for comparison with
    Flask implementation to ensure migration success criteria are met.
    """
    # API performance baseline from Node.js system
    api_response_times: Dict[str, List[float]] = field(default_factory=dict)
    api_throughput: Dict[str, float] = field(default_factory=dict)
    api_error_rates: Dict[str, float] = field(default_factory=dict)
    
    # Database performance baseline
    database_query_times: Dict[str, List[float]] = field(default_factory=dict)
    database_connection_pool_stats: Dict[str, Any] = field(default_factory=dict)
    
    # Authentication performance baseline
    auth_flow_times: Dict[str, List[float]] = field(default_factory=dict)
    session_management_stats: Dict[str, Any] = field(default_factory=dict)
    
    # Memory and resource usage baseline
    memory_usage_stats: Dict[str, Any] = field(default_factory=dict)
    cpu_utilization_stats: Dict[str, Any] = field(default_factory=dict)
    
    # Concurrent load baseline
    concurrent_load_stats: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    collection_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    node_version: str = ""
    system_specs: Dict[str, Any] = field(default_factory=dict)


class PerformanceDataManager:
    """
    Manages baseline data persistence and comparison for migration validation.
    
    This class handles Node.js baseline metrics storage, Flask performance data collection,
    and automated comparison analysis per Section 4.7.2 requirements.
    """
    
    def __init__(self, baseline_data_path: Optional[Path] = None):
        """Initialize performance data manager with baseline storage location."""
        self.baseline_data_path = baseline_data_path or Path(tempfile.gettempdir()) / "performance_baselines"
        self.baseline_data_path.mkdir(parents=True, exist_ok=True)
        self.baseline_metrics: Optional[BaselineMetrics] = None
        self.performance_history: List[Dict[str, Any]] = []
        
    def load_baseline_data(self, baseline_file: str = "nodejs_baseline.json") -> BaselineMetrics:
        """
        Load Node.js baseline performance data for comparison validation.
        
        Args:
            baseline_file: JSON file containing Node.js baseline metrics
            
        Returns:
            BaselineMetrics object with loaded baseline data
            
        Per Section 4.7.2: Baseline comparison against Node.js system performance metrics
        """
        baseline_path = self.baseline_data_path / baseline_file
        
        if baseline_path.exists():
            with open(baseline_path, 'r') as f:
                baseline_data = json.load(f)
                self.baseline_metrics = BaselineMetrics(**baseline_data)
        else:
            # Create default baseline if not found - in production this would be populated
            # with actual Node.js performance data per Section 4.7.2
            self.baseline_metrics = BaselineMetrics()
            self._create_default_baseline()
            
        return self.baseline_metrics
    
    def _create_default_baseline(self):
        """Create default baseline metrics for testing purposes."""
        # Default API response times (simulating Node.js baseline)
        self.baseline_metrics.api_response_times = {
            "GET /api/health": [0.025, 0.030, 0.028, 0.032, 0.027],
            "GET /api/users": [0.085, 0.092, 0.088, 0.095, 0.090],
            "POST /api/users": [0.120, 0.135, 0.125, 0.140, 0.130],
            "PUT /api/users/:id": [0.110, 0.125, 0.115, 0.130, 0.120],
            "DELETE /api/users/:id": [0.095, 0.105, 0.100, 0.110, 0.102]
        }
        
        # Default database query times (simulating MongoDB baseline)
        self.baseline_metrics.database_query_times = {
            "SELECT users": [0.045, 0.050, 0.048, 0.052, 0.049],
            "INSERT user": [0.065, 0.070, 0.068, 0.072, 0.069],
            "UPDATE user": [0.055, 0.060, 0.058, 0.062, 0.059],
            "DELETE user": [0.050, 0.055, 0.053, 0.057, 0.054]
        }
        
        # Default authentication flow times
        self.baseline_metrics.auth_flow_times = {
            "login": [0.095, 0.105, 0.100, 0.110, 0.102],
            "token_validation": [0.025, 0.030, 0.028, 0.032, 0.029],
            "session_refresh": [0.035, 0.040, 0.038, 0.042, 0.039]
        }
        
    def save_baseline_data(self, baseline_file: str = "nodejs_baseline.json"):
        """Save baseline metrics to persistent storage."""
        if self.baseline_metrics:
            baseline_path = self.baseline_data_path / baseline_file
            
            # Convert dataclass to dict for JSON serialization
            baseline_dict = {
                'api_response_times': self.baseline_metrics.api_response_times,
                'api_throughput': self.baseline_metrics.api_throughput,
                'api_error_rates': self.baseline_metrics.api_error_rates,
                'database_query_times': self.baseline_metrics.database_query_times,
                'database_connection_pool_stats': self.baseline_metrics.database_connection_pool_stats,
                'auth_flow_times': self.baseline_metrics.auth_flow_times,
                'session_management_stats': self.baseline_metrics.session_management_stats,
                'memory_usage_stats': self.baseline_metrics.memory_usage_stats,
                'cpu_utilization_stats': self.baseline_metrics.cpu_utilization_stats,
                'concurrent_load_stats': self.baseline_metrics.concurrent_load_stats,
                'collection_timestamp': self.baseline_metrics.collection_timestamp.isoformat(),
                'node_version': self.baseline_metrics.node_version,
                'system_specs': self.baseline_metrics.system_specs
            }
            
            with open(baseline_path, 'w') as f:
                json.dump(baseline_dict, f, indent=2)
    
    def compare_performance(self, test_name: str, flask_metrics: List[float], 
                          baseline_key: str = None) -> Dict[str, Any]:
        """
        Compare Flask performance metrics against Node.js baseline per Section 4.7.2.
        
        Args:
            test_name: Name of the performance test
            flask_metrics: List of Flask performance measurements
            baseline_key: Key to lookup baseline metrics (defaults to test_name)
            
        Returns:
            Comparison analysis with statistical validation
        """
        if not self.baseline_metrics:
            self.load_baseline_data()
            
        baseline_key = baseline_key or test_name
        comparison_result = {
            'test_name': test_name,
            'flask_metrics': {
                'count': len(flask_metrics),
                'mean': statistics.mean(flask_metrics),
                'median': statistics.median(flask_metrics),
                'std_dev': statistics.stdev(flask_metrics) if len(flask_metrics) > 1 else 0.0,
                'min': min(flask_metrics),
                'max': max(flask_metrics),
                'p95': self._calculate_percentile(flask_metrics, 95),
                'p99': self._calculate_percentile(flask_metrics, 99)
            },
            'baseline_available': False,
            'performance_improvement': None,
            'regression_detected': False,
            'meets_requirements': True
        }
        
        # Compare against baseline if available
        baseline_data = None
        if hasattr(self.baseline_metrics, 'api_response_times') and baseline_key in self.baseline_metrics.api_response_times:
            baseline_data = self.baseline_metrics.api_response_times[baseline_key]
        elif hasattr(self.baseline_metrics, 'database_query_times') and baseline_key in self.baseline_metrics.database_query_times:
            baseline_data = self.baseline_metrics.database_query_times[baseline_key]
        elif hasattr(self.baseline_metrics, 'auth_flow_times') and baseline_key in self.baseline_metrics.auth_flow_times:
            baseline_data = self.baseline_metrics.auth_flow_times[baseline_key]
            
        if baseline_data:
            baseline_mean = statistics.mean(baseline_data)
            flask_mean = comparison_result['flask_metrics']['mean']
            
            comparison_result['baseline_available'] = True
            comparison_result['baseline_metrics'] = {
                'count': len(baseline_data),
                'mean': baseline_mean,
                'median': statistics.median(baseline_data),
                'std_dev': statistics.stdev(baseline_data) if len(baseline_data) > 1 else 0.0,
                'min': min(baseline_data),
                'max': max(baseline_data),
                'p95': self._calculate_percentile(baseline_data, 95),
                'p99': self._calculate_percentile(baseline_data, 99)
            }
            
            # Calculate performance improvement/regression
            improvement_percent = ((baseline_mean - flask_mean) / baseline_mean) * 100
            comparison_result['performance_improvement'] = improvement_percent
            
            # Detect regression per Section 4.7.2
            thresholds = PerformanceThresholds()
            if improvement_percent < -thresholds.regression_threshold_percent:
                comparison_result['regression_detected'] = True
                
        return comparison_result
    
    def _calculate_percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile for performance metrics."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = (percentile / 100.0) * (len(sorted_data) - 1)
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))


class OpenTelemetryManager:
    """
    OpenTelemetry instrumentation manager for comprehensive performance metrics collection.
    
    This class configures OpenTelemetry Python SDK integration per Section 6.5.1.3 with
    automatic instrumentation for Flask, SQLAlchemy, and external service interactions.
    """
    
    def __init__(self, service_name: str = "flask-performance-tests"):
        """Initialize OpenTelemetry with performance testing configuration."""
        self.service_name = service_name
        self.tracer_provider = None
        self.meter_provider = None
        self.tracer = None
        self.meter = None
        self.instrumentors = []
        
    def setup_instrumentation(self, app: Flask = None) -> None:
        """
        Configure comprehensive OpenTelemetry instrumentation per Section 6.5.1.3.
        
        Args:
            app: Flask application instance for instrumentation
            
        Sets up:
        - Flask auto-instrumentation with blueprint context
        - SQLAlchemy database query performance tracking
        - External service tracing for Auth0 and AWS interactions
        - Metrics collection pipeline for performance analysis
        """
        # Configure tracer provider for distributed tracing
        self.tracer_provider = TracerProvider()
        trace.set_tracer_provider(self.tracer_provider)
        
        # Configure OTLP exporters for production integration
        if os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT'):
            otlp_exporter = OTLPSpanExporter(
                endpoint=os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT'),
                headers={"Authorization": f"Bearer {os.getenv('OTEL_API_KEY', '')}"}
            )
            span_processor = BatchSpanProcessor(otlp_exporter)
            self.tracer_provider.add_span_processor(span_processor)
        
        # Configure Jaeger exporter for detailed trace analysis
        if os.getenv('JAEGER_ENDPOINT'):
            jaeger_exporter = JaegerExporter(
                agent_host_name=os.getenv('JAEGER_HOST', 'localhost'),
                agent_port=int(os.getenv('JAEGER_PORT', '6831'))
            )
            self.tracer_provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))
        
        # Fallback to console exporter for development
        console_exporter = ConsoleSpanExporter()
        self.tracer_provider.add_span_processor(BatchSpanProcessor(console_exporter))
        
        # Configure meter provider for metrics collection
        metric_reader = PeriodicExportingMetricReader(
            ConsoleMetricExporter(),
            export_interval_millis=5000
        )
        
        if os.getenv('OTEL_EXPORTER_OTLP_METRICS_ENDPOINT'):
            otlp_metric_exporter = OTLPMetricExporter(
                endpoint=os.getenv('OTEL_EXPORTER_OTLP_METRICS_ENDPOINT')
            )
            metric_reader = PeriodicExportingMetricReader(
                otlp_metric_exporter,
                export_interval_millis=5000
            )
        
        self.meter_provider = MeterProvider(metric_readers=[metric_reader])
        metrics.set_meter_provider(self.meter_provider)
        
        # Get tracer and meter instances
        self.tracer = trace.get_tracer(self.service_name)
        self.meter = metrics.get_meter(self.service_name)
        
        # Setup Flask instrumentation
        if app:
            flask_instrumentor = FlaskInstrumentor()
            flask_instrumentor.instrument_app(app)
            self.instrumentors.append(flask_instrumentor)
        
        # Setup SQLAlchemy instrumentation
        sqlalchemy_instrumentor = SQLAlchemyInstrumentor()
        sqlalchemy_instrumentor.instrument()
        self.instrumentors.append(sqlalchemy_instrumentor)
        
        # Setup requests instrumentation for external API calls
        requests_instrumentor = RequestsInstrumentor()
        requests_instrumentor.instrument()
        self.instrumentors.append(requests_instrumentor)
        
    def cleanup_instrumentation(self):
        """Clean up OpenTelemetry instrumentation after testing."""
        for instrumentor in self.instrumentors:
            if hasattr(instrumentor, 'uninstrument'):
                instrumentor.uninstrument()
        self.instrumentors.clear()
        
    @contextmanager
    def trace_performance(self, operation_name: str) -> Generator[Any, None, None]:
        """
        Context manager for tracing performance of specific operations.
        
        Args:
            operation_name: Name of the operation being traced
            
        Yields:
            Span context for additional attribute setting
        """
        if self.tracer:
            with self.tracer.start_as_current_span(operation_name) as span:
                start_time = time.perf_counter()
                try:
                    yield span
                finally:
                    duration = time.perf_counter() - start_time
                    span.set_attribute("performance.duration_ms", duration * 1000)
        else:
            yield None


class DatabasePerformanceMonitor:
    """
    SQLAlchemy event listener for comprehensive database performance monitoring.
    
    This class implements SQLAlchemy event listeners per Section 6.5.1.1 to capture
    query execution times, connection pool utilization, and database transaction metrics.
    """
    
    def __init__(self):
        """Initialize database performance monitoring."""
        self.query_times: Dict[str, List[float]] = {}
        self.connection_stats = {
            'total_connections': 0,
            'active_connections': 0,
            'pool_size': 0,
            'checked_out': 0,
            'checked_in': 0,
            'connection_errors': 0
        }
        self.query_count = 0
        self.total_query_time = 0.0
        self.slow_queries: List[Dict[str, Any]] = []
        
    def setup_monitoring(self, engine: Engine):
        """
        Setup SQLAlchemy event listeners for performance monitoring.
        
        Args:
            engine: SQLAlchemy engine instance to monitor
            
        Per Section 6.5.1.1: SQLAlchemy query execution time monitoring
        """
        @event.listens_for(engine, "before_cursor_execute")
        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Record query start time."""
            context._query_start_time = time.perf_counter()
            
        @event.listens_for(engine, "after_cursor_execute")
        def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Record query completion and calculate execution time."""
            if hasattr(context, '_query_start_time'):
                total_time = time.perf_counter() - context._query_start_time
                
                # Normalize statement for grouping
                normalized_statement = self._normalize_sql_statement(statement)
                
                if normalized_statement not in self.query_times:
                    self.query_times[normalized_statement] = []
                
                self.query_times[normalized_statement].append(total_time)
                self.query_count += 1
                self.total_query_time += total_time
                
                # Track slow queries per Section 4.11.1 (>100ms threshold)
                if total_time > 0.100:  # 100ms threshold
                    self.slow_queries.append({
                        'statement': normalized_statement,
                        'execution_time': total_time,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'parameters': str(parameters)[:200]  # Truncate for safety
                    })
        
        @event.listens_for(engine, "connect")
        def on_connect(dbapi_connection, connection_record):
            """Track connection pool statistics."""
            self.connection_stats['total_connections'] += 1
            
        @event.listens_for(engine, "checkout")
        def on_checkout(dbapi_connection, connection_record, connection_proxy):
            """Track connection pool checkout."""
            self.connection_stats['checked_out'] += 1
            self.connection_stats['active_connections'] += 1
            
        @event.listens_for(engine, "checkin")
        def on_checkin(dbapi_connection, connection_record):
            """Track connection pool checkin."""
            self.connection_stats['checked_in'] += 1
            self.connection_stats['active_connections'] = max(0, self.connection_stats['active_connections'] - 1)
            
    def _normalize_sql_statement(self, statement: str) -> str:
        """Normalize SQL statement for grouping and analysis."""
        # Remove extra whitespace and normalize case
        normalized = ' '.join(statement.split()).upper()
        
        # Group common patterns
        if normalized.startswith('SELECT'):
            return 'SELECT'
        elif normalized.startswith('INSERT'):
            return 'INSERT'
        elif normalized.startswith('UPDATE'):
            return 'UPDATE'
        elif normalized.startswith('DELETE'):
            return 'DELETE'
        else:
            return normalized[:50]  # Truncate long statements
            
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Generate comprehensive database performance summary.
        
        Returns:
            Dictionary containing database performance statistics
        """
        if not self.query_times:
            return {'no_queries': True}
            
        all_query_times = []
        for times in self.query_times.values():
            all_query_times.extend(times)
            
        summary = {
            'total_queries': self.query_count,
            'total_execution_time': self.total_query_time,
            'average_query_time': self.total_query_time / self.query_count if self.query_count > 0 else 0,
            'query_distribution': {},
            'connection_stats': self.connection_stats.copy(),
            'slow_queries_count': len(self.slow_queries),
            'slow_queries': self.slow_queries[-10:],  # Last 10 slow queries
            'performance_percentiles': {}
        }
        
        # Calculate query distribution
        for statement, times in self.query_times.items():
            summary['query_distribution'][statement] = {
                'count': len(times),
                'total_time': sum(times),
                'average_time': statistics.mean(times),
                'min_time': min(times),
                'max_time': max(times)
            }
            
        # Calculate percentiles if we have data
        if all_query_times:
            summary['performance_percentiles'] = {
                'p50': self._calculate_percentile(all_query_times, 50),
                'p95': self._calculate_percentile(all_query_times, 95),
                'p99': self._calculate_percentile(all_query_times, 99)
            }
            
        return summary
        
    def _calculate_percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile for query performance data."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = (percentile / 100.0) * (len(sorted_data) - 1)
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))
    
    def reset_statistics(self):
        """Reset all performance statistics for clean test runs."""
        self.query_times.clear()
        self.connection_stats = {
            'total_connections': 0,
            'active_connections': 0,
            'pool_size': 0,
            'checked_out': 0,
            'checked_in': 0,
            'connection_errors': 0
        }
        self.query_count = 0
        self.total_query_time = 0.0
        self.slow_queries.clear()


class MemoryProfiler:
    """
    Memory profiling and monitoring for Python GC performance analysis.
    
    This class provides comprehensive memory profiling capabilities per Section 6.5.2.2
    including Python garbage collection monitoring, memory leak detection, and memory
    allocator statistics for performance optimization insights.
    """
    
    def __init__(self):
        """Initialize memory profiling capabilities."""
        self.initial_memory = 0
        self.peak_memory = 0
        self.gc_statistics = []
        self.memory_snapshots = []
        self.pympler_tracker = None
        
        if MEMORY_PROFILING_AVAILABLE:
            self.pympler_tracker = pympler.tracker.SummaryTracker()
            
    def start_profiling(self):
        """Start comprehensive memory profiling session."""
        self.initial_memory = self._get_memory_usage()
        self.peak_memory = self.initial_memory
        
        # Enable garbage collection debugging
        gc.set_debug(gc.DEBUG_STATS)
        
        # Reset pympler tracker if available
        if self.pympler_tracker:
            self.pympler_tracker.print_diff()  # Clear baseline
            
    def take_memory_snapshot(self, label: str = ""):
        """
        Take memory usage snapshot for analysis.
        
        Args:
            label: Label for the memory snapshot
        """
        current_memory = self._get_memory_usage()
        self.peak_memory = max(self.peak_memory, current_memory)
        
        snapshot = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'label': label,
            'memory_usage_mb': current_memory,
            'memory_diff_mb': current_memory - self.initial_memory,
            'gc_stats': self._get_gc_statistics()
        }
        
        if MEMORY_PROFILING_AVAILABLE and self.pympler_tracker:
            # Get memory diff from pympler
            summary = self.pympler_tracker.create_summary()
            snapshot['memory_objects'] = self._format_pympler_summary(summary)
            
        self.memory_snapshots.append(snapshot)
        
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024  # Convert to MB
        
    def _get_gc_statistics(self) -> Dict[str, Any]:
        """Get Python garbage collection statistics."""
        gc_stats = gc.get_stats()
        return {
            'collections': gc.get_count(),
            'generation_stats': gc_stats,
            'total_objects': len(gc.get_objects()),
            'referrers_count': len(gc.garbage)
        }
        
    def _format_pympler_summary(self, summary) -> List[Dict[str, Any]]:
        """Format pympler summary for serialization."""
        if not MEMORY_PROFILING_AVAILABLE:
            return []
            
        formatted = []
        for item in summary[:10]:  # Top 10 memory consumers
            formatted.append({
                'type': str(item[2]),
                'count': item[0],
                'total_size': item[1]
            })
        return formatted
        
    def measure_gc_pause_time(self, func, *args, **kwargs):
        """
        Measure garbage collection pause time during function execution.
        
        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Tuple of (function_result, gc_pause_time_ms)
        """
        # Force garbage collection before measurement
        gc.collect()
        
        gc_start_time = time.perf_counter()
        gc_collections_before = sum(gc.get_count())
        
        # Execute function
        result = func(*args, **kwargs)
        
        # Measure GC impact
        gc_collections_after = sum(gc.get_count())
        
        # Force GC to measure pause time
        gc_pause_start = time.perf_counter()
        gc.collect()
        gc_pause_end = time.perf_counter()
        
        gc_pause_time_ms = (gc_pause_end - gc_pause_start) * 1000
        
        self.gc_statistics.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'gc_pause_time_ms': gc_pause_time_ms,
            'collections_triggered': gc_collections_after - gc_collections_before,
            'memory_before_mb': self._get_memory_usage()
        })
        
        return result, gc_pause_time_ms
        
    def detect_memory_leaks(self, threshold_mb: float = 50.0) -> Dict[str, Any]:
        """
        Detect potential memory leaks based on memory growth patterns.
        
        Args:
            threshold_mb: Memory growth threshold in MB for leak detection
            
        Returns:
            Memory leak analysis report
        """
        if len(self.memory_snapshots) < 2:
            return {'insufficient_data': True}
            
        initial_memory = self.memory_snapshots[0]['memory_usage_mb']
        final_memory = self.memory_snapshots[-1]['memory_usage_mb']
        memory_growth = final_memory - initial_memory
        
        leak_detected = memory_growth > threshold_mb
        
        return {
            'leak_detected': leak_detected,
            'memory_growth_mb': memory_growth,
            'threshold_mb': threshold_mb,
            'initial_memory_mb': initial_memory,
            'final_memory_mb': final_memory,
            'peak_memory_mb': self.peak_memory,
            'snapshots_count': len(self.memory_snapshots),
            'gc_pause_times': [stat['gc_pause_time_ms'] for stat in self.gc_statistics],
            'average_gc_pause_ms': statistics.mean([stat['gc_pause_time_ms'] for stat in self.gc_statistics]) if self.gc_statistics else 0
        }
        
    def get_memory_report(self) -> Dict[str, Any]:
        """Generate comprehensive memory profiling report."""
        return {
            'initial_memory_mb': self.initial_memory,
            'peak_memory_mb': self.peak_memory,
            'memory_snapshots': self.memory_snapshots,
            'gc_statistics': self.gc_statistics,
            'leak_analysis': self.detect_memory_leaks()
        }


# Global performance manager instances
performance_data_manager = PerformanceDataManager()
otel_manager = OpenTelemetryManager()
db_performance_monitor = DatabasePerformanceMonitor()
memory_profiler = MemoryProfiler()


# pytest configuration per Section 4.7.1
def pytest_configure(config):
    """
    Configure pytest for performance testing with benchmark integration.
    
    This function sets up pytest-benchmark 5.1.0 configuration and registers
    custom markers for performance test categorization per Section 4.7.1.
    """
    # Register custom markers for performance test organization
    config.addinivalue_line(
        "markers", "performance: mark test as performance benchmark"
    )
    config.addinivalue_line(
        "markers", "api_performance: mark test as API performance benchmark"
    )
    config.addinivalue_line(
        "markers", "database_performance: mark test as database performance benchmark"
    )
    config.addinivalue_line(
        "markers", "auth_performance: mark test as authentication performance benchmark"
    )
    config.addinivalue_line(
        "markers", "memory_performance: mark test as memory profiling benchmark"
    )
    config.addinivalue_line(
        "markers", "concurrent_performance: mark test as concurrent load benchmark"
    )
    config.addinivalue_line(
        "markers", "baseline_comparison: mark test as Node.js baseline comparison"
    )
    config.addinivalue_line(
        "markers", "regression_test: mark test as performance regression validation"
    )


def pytest_benchmark_update_json(config, benchmarks, output_json):
    """
    Update benchmark JSON output with additional metadata per Section 4.7.2.
    
    This function enhances pytest-benchmark output with migration validation
    metadata and baseline comparison results.
    """
    # Add migration context metadata
    output_json['migration_context'] = {
        'source_system': 'Node.js/Express.js',
        'target_system': 'Python 3.13.3/Flask 3.1.1',
        'migration_phase': os.getenv('MIGRATION_PHASE', 'development'),
        'baseline_available': performance_data_manager.baseline_metrics is not None,
        'test_environment': os.getenv('TEST_ENVIRONMENT', 'local')
    }
    
    # Add performance thresholds for reference
    thresholds = PerformanceThresholds()
    output_json['performance_thresholds'] = {
        'api_response_time_max': thresholds.api_response_time_max,
        'database_query_time_max': thresholds.database_query_time_max,
        'auth_response_time_max': thresholds.auth_response_time_max,
        'regression_threshold_percent': thresholds.regression_threshold_percent
    }


# Flask Application Factory Fixtures per Section 5.1.1
@pytest.fixture(scope="session")
def flask_app_factory():
    """
    Flask application factory fixture for performance testing.
    
    This fixture creates a Flask application using the application factory pattern
    per Section 5.1.1 with performance testing configuration and OpenTelemetry
    instrumentation per Section 6.5.1.3.
    
    Returns:
        Flask application instance configured for performance testing
    """
    from src.app import create_app  # Import Flask application factory
    
    # Configure for performance testing
    test_config = {
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'poolclass': StaticPool,
            'connect_args': {'check_same_thread': False},
            'echo': False  # Disable SQL logging for performance testing
        },
        'SECRET_KEY': 'performance-testing-secret-key',
        # OpenTelemetry configuration per Section 6.5.1.3
        'OTEL_SERVICE_NAME': 'flask-performance-tests',
        'OTEL_INSTRUMENTATION_ENABLED': True
    }
    
    app = create_app(config=test_config)
    
    # Setup OpenTelemetry instrumentation per Section 6.5.1.3
    otel_manager.setup_instrumentation(app)
    
    # Setup Prometheus metrics if available per Section 6.5.1.1
    if PROMETHEUS_AVAILABLE:
        registry = CollectorRegistry()
        metrics = PrometheusMetrics(app, registry=registry)
        metrics.info('app_info', 'Application info', version='1.0.0')
        app.prometheus_registry = registry
        
    # Setup database performance monitoring
    with app.app_context():
        from flask_sqlalchemy import SQLAlchemy
        db = app.extensions.get('sqlalchemy')
        if db and hasattr(db, 'engine'):
            db_performance_monitor.setup_monitoring(db.engine)
            
    return app


@pytest.fixture(scope="function")
def flask_client(flask_app_factory):
    """
    Flask test client fixture with performance monitoring.
    
    This fixture provides a Flask test client with integrated performance
    monitoring and OpenTelemetry tracing per Section 6.5.1.3.
    
    Args:
        flask_app_factory: Flask application factory fixture
        
    Returns:
        Flask test client with performance monitoring
    """
    app = flask_app_factory
    
    with app.test_client() as client:
        with app.app_context():
            # Initialize database tables for testing
            from flask_sqlalchemy import SQLAlchemy
            db = app.extensions.get('sqlalchemy')
            if db:
                db.create_all()
                
            # Reset performance monitoring for clean test runs
            db_performance_monitor.reset_statistics()
            
            yield client
            
            # Cleanup after test
            if db:
                db.drop_all()


@pytest.fixture(scope="function")
def performance_monitor():
    """
    Performance monitoring fixture providing access to monitoring utilities.
    
    This fixture provides access to performance monitoring utilities including
    database performance monitoring, memory profiling, and OpenTelemetry tracing.
    
    Returns:
        Dictionary containing performance monitoring utilities
    """
    return {
        'db_monitor': db_performance_monitor,
        'memory_profiler': memory_profiler,
        'otel_manager': otel_manager,
        'data_manager': performance_data_manager
    }


# Performance Benchmarking Fixtures per Section 4.7.1
@pytest.fixture(scope="function")
def benchmark_config():
    """
    pytest-benchmark configuration fixture for performance testing.
    
    This fixture configures pytest-benchmark 5.1.0 with migration-specific
    settings and baseline comparison capabilities per Section 4.7.1.
    
    Returns:
        Benchmark configuration for performance testing
    """
    return {
        'min_rounds': 5,
        'max_time': 10.0,  # Maximum 10 seconds per benchmark
        'min_time': 0.001,  # Minimum 1ms per round
        'timer': time.perf_counter,
        'disable_gc': False,  # Keep GC enabled to measure real-world performance
        'warmup': True,
        'warmup_iterations': 3,
        'sort': 'mean',
        'histogram': True,
        'save': 'performance_benchmarks.json',
        'save_data': True,
        'autosave': True
    }


@pytest.fixture(scope="function")
def api_performance_benchmark(benchmark, flask_client, performance_monitor):
    """
    API performance benchmarking fixture with baseline comparison.
    
    This fixture provides API performance benchmarking capabilities with
    automatic baseline comparison against Node.js metrics per Section 4.7.2.
    
    Args:
        benchmark: pytest-benchmark fixture
        flask_client: Flask test client fixture
        performance_monitor: Performance monitoring utilities
        
    Returns:
        API benchmarking function with baseline comparison
    """
    def benchmark_api_endpoint(endpoint_path: str, method: str = 'GET', 
                             data: Optional[Dict] = None, 
                             headers: Optional[Dict] = None,
                             expected_status: int = 200,
                             baseline_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Benchmark API endpoint performance with baseline comparison.
        
        Args:
            endpoint_path: API endpoint path to benchmark
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request data for POST/PUT requests
            headers: Request headers
            expected_status: Expected HTTP status code
            baseline_key: Key for baseline comparison (defaults to endpoint_path)
            
        Returns:
            Benchmark results with baseline comparison analysis
        """
        # Prepare request function
        def make_request():
            if method.upper() == 'GET':
                response = flask_client.get(endpoint_path, headers=headers)
            elif method.upper() == 'POST':
                response = flask_client.post(endpoint_path, json=data, headers=headers)
            elif method.upper() == 'PUT':
                response = flask_client.put(endpoint_path, json=data, headers=headers)
            elif method.upper() == 'DELETE':
                response = flask_client.delete(endpoint_path, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
                
            assert response.status_code == expected_status
            return response
            
        # Execute benchmark
        result = benchmark(make_request)
        
        # Collect performance metrics
        performance_metrics = []
        if hasattr(result, 'stats') and hasattr(result.stats, 'data'):
            performance_metrics = result.stats.data
        
        # Compare with baseline
        baseline_key = baseline_key or f"{method} {endpoint_path}"
        comparison = performance_data_manager.compare_performance(
            test_name=f"api_{method.lower()}_{endpoint_path.replace('/', '_')}",
            flask_metrics=performance_metrics,
            baseline_key=baseline_key
        )
        
        # Validate against performance thresholds
        thresholds = PerformanceThresholds()
        if performance_metrics:
            mean_response_time = statistics.mean(performance_metrics)
            comparison['meets_response_time_threshold'] = mean_response_time <= thresholds.api_response_time_max
            comparison['meets_p95_threshold'] = performance_data_manager._calculate_percentile(
                performance_metrics, 95) <= thresholds.api_response_time_p95
                
        return comparison
        
    return benchmark_api_endpoint


@pytest.fixture(scope="function")
def database_performance_benchmark(benchmark, flask_client, performance_monitor):
    """
    Database performance benchmarking fixture with SQLAlchemy monitoring.
    
    This fixture provides database query performance benchmarking with
    SQLAlchemy event listener integration per Section 6.5.1.1.
    
    Args:
        benchmark: pytest-benchmark fixture
        flask_client: Flask test client fixture
        performance_monitor: Performance monitoring utilities
        
    Returns:
        Database benchmarking function with query analysis
    """
    def benchmark_database_operation(operation_func, 
                                   operation_name: str,
                                   baseline_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Benchmark database operation performance.
        
        Args:
            operation_func: Function that performs database operation
            operation_name: Name of the database operation
            baseline_key: Key for baseline comparison
            
        Returns:
            Benchmark results with database performance analysis
        """
        # Reset database monitoring
        db_monitor = performance_monitor['db_monitor']
        db_monitor.reset_statistics()
        
        # Execute benchmark
        result = benchmark(operation_func)
        
        # Get database performance summary
        db_summary = db_monitor.get_performance_summary()
        
        # Extract query times for comparison
        query_times = []
        if 'query_distribution' in db_summary:
            for statement, stats in db_summary['query_distribution'].items():
                query_times.extend([stats['average_time']])
                
        # Compare with baseline
        baseline_key = baseline_key or operation_name
        comparison = performance_data_manager.compare_performance(
            test_name=f"database_{operation_name}",
            flask_metrics=query_times,
            baseline_key=baseline_key
        )
        
        # Add database-specific metrics
        comparison['database_metrics'] = db_summary
        
        # Validate against database performance thresholds
        thresholds = PerformanceThresholds()
        if query_times:
            mean_query_time = statistics.mean(query_times)
            comparison['meets_query_time_threshold'] = mean_query_time <= thresholds.database_query_time_max
            comparison['slow_queries_detected'] = len(db_summary.get('slow_queries', [])) > 0
            
        return comparison
        
    return benchmark_database_operation


@pytest.fixture(scope="function")
def authentication_performance_benchmark(benchmark, flask_client, performance_monitor):
    """
    Authentication performance benchmarking fixture with ItsDangerous monitoring.
    
    This fixture provides authentication flow performance benchmarking with
    Flask decorator and ItsDangerous session management analysis per Section 5.1.1.
    
    Args:
        benchmark: pytest-benchmark fixture
        flask_client: Flask test client fixture
        performance_monitor: Performance monitoring utilities
        
    Returns:
        Authentication benchmarking function with security performance analysis
    """
    def benchmark_auth_operation(auth_func,
                                operation_name: str,
                                baseline_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Benchmark authentication operation performance.
        
        Args:
            auth_func: Function that performs authentication operation
            operation_name: Name of the authentication operation
            baseline_key: Key for baseline comparison
            
        Returns:
            Benchmark results with authentication performance analysis
        """
        # Execute benchmark with OpenTelemetry tracing
        otel_manager = performance_monitor['otel_manager']
        
        with otel_manager.trace_performance(f"auth_{operation_name}") as span:
            result = benchmark(auth_func)
            
            if span:
                span.set_attribute("auth.operation", operation_name)
                span.set_attribute("auth.framework", "Flask + ItsDangerous")
                
        # Collect authentication performance metrics
        auth_metrics = []
        if hasattr(result, 'stats') and hasattr(result.stats, 'data'):
            auth_metrics = result.stats.data
            
        # Compare with baseline
        baseline_key = baseline_key or operation_name
        comparison = performance_data_manager.compare_performance(
            test_name=f"auth_{operation_name}",
            flask_metrics=auth_metrics,
            baseline_key=baseline_key
        )
        
        # Validate against authentication performance thresholds
        thresholds = PerformanceThresholds()
        if auth_metrics:
            mean_auth_time = statistics.mean(auth_metrics)
            comparison['meets_auth_time_threshold'] = mean_auth_time <= thresholds.auth_response_time_max
            comparison['meets_auth_p95_threshold'] = performance_data_manager._calculate_percentile(
                auth_metrics, 95) <= thresholds.auth_response_time_p95
                
        return comparison
        
    return benchmark_auth_operation


@pytest.fixture(scope="function")
def memory_performance_benchmark(benchmark, performance_monitor):
    """
    Memory performance benchmarking fixture with GC monitoring.
    
    This fixture provides memory profiling and garbage collection performance
    analysis per Section 6.5.2.2 with Python-specific memory optimization insights.
    
    Args:
        benchmark: pytest-benchmark fixture
        performance_monitor: Performance monitoring utilities
        
    Returns:
        Memory benchmarking function with leak detection and GC analysis
    """
    def benchmark_memory_operation(memory_func,
                                 operation_name: str,
                                 leak_threshold_mb: float = 50.0) -> Dict[str, Any]:
        """
        Benchmark memory usage and garbage collection performance.
        
        Args:
            memory_func: Function to profile for memory usage
            operation_name: Name of the memory operation
            leak_threshold_mb: Memory leak detection threshold in MB
            
        Returns:
            Benchmark results with memory profiling analysis
        """
        mem_profiler = performance_monitor['memory_profiler']
        
        # Start memory profiling
        mem_profiler.start_profiling()
        mem_profiler.take_memory_snapshot(f"before_{operation_name}")
        
        # Execute benchmark with GC pause measurement
        def measured_func():
            return mem_profiler.measure_gc_pause_time(memory_func)
            
        result = benchmark(measured_func)
        
        # Take final memory snapshot
        mem_profiler.take_memory_snapshot(f"after_{operation_name}")
        
        # Generate memory analysis report
        memory_report = mem_profiler.get_memory_report()
        leak_analysis = mem_profiler.detect_memory_leaks(leak_threshold_mb)
        
        # Validate against memory performance thresholds
        thresholds = PerformanceThresholds()
        gc_pause_times = [stat['gc_pause_time_ms'] for stat in memory_report['gc_statistics']]
        
        analysis = {
            'operation_name': operation_name,
            'memory_report': memory_report,
            'leak_analysis': leak_analysis,
            'meets_gc_threshold': all(t <= thresholds.gc_pause_time_max * 1000 for t in gc_pause_times),
            'meets_memory_threshold': not leak_analysis.get('leak_detected', False),
            'average_gc_pause_ms': statistics.mean(gc_pause_times) if gc_pause_times else 0
        }
        
        return analysis
        
    return benchmark_memory_operation


@pytest.fixture(scope="function")
def concurrent_load_benchmark(benchmark, flask_client, performance_monitor):
    """
    Concurrent load testing fixture with thread pool monitoring.
    
    This fixture provides concurrent user simulation and load testing capabilities
    with thread pool utilization monitoring per Section 6.5.2.5.
    
    Args:
        benchmark: pytest-benchmark fixture
        flask_client: Flask test client fixture
        performance_monitor: Performance monitoring utilities
        
    Returns:
        Concurrent load benchmarking function with scalability analysis
    """
    def benchmark_concurrent_load(load_func,
                                test_name: str,
                                concurrent_users: int = 10,
                                requests_per_user: int = 5) -> Dict[str, Any]:
        """
        Benchmark concurrent load performance.
        
        Args:
            load_func: Function to execute under concurrent load
            test_name: Name of the load test
            concurrent_users: Number of concurrent users to simulate
            requests_per_user: Number of requests per user
            
        Returns:
            Benchmark results with concurrent load analysis
        """
        response_times = []
        errors = []
        
        def user_simulation():
            """Simulate individual user requests."""
            user_response_times = []
            for _ in range(requests_per_user):
                try:
                    start_time = time.perf_counter()
                    load_func()
                    end_time = time.perf_counter()
                    user_response_times.append(end_time - start_time)
                except Exception as e:
                    errors.append(str(e))
            return user_response_times
            
        def concurrent_execution():
            """Execute concurrent user simulation."""
            threads = []
            
            # Create and start threads for concurrent users
            for _ in range(concurrent_users):
                thread = threading.Thread(target=lambda: response_times.extend(user_simulation()))
                threads.append(thread)
                thread.start()
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return response_times
            
        # Execute concurrent load benchmark
        result = benchmark(concurrent_execution)
        
        # Analyze concurrent load performance
        total_requests = concurrent_users * requests_per_user
        successful_requests = len(response_times)
        error_rate = len(errors) / total_requests if total_requests > 0 else 0
        
        # Calculate throughput metrics
        if response_times:
            total_time = max(response_times) if response_times else 0
            throughput_rps = successful_requests / total_time if total_time > 0 else 0
            
            analysis = {
                'test_name': test_name,
                'concurrent_users': concurrent_users,
                'requests_per_user': requests_per_user,
                'total_requests': total_requests,
                'successful_requests': successful_requests,
                'error_rate': error_rate,
                'throughput_rps': throughput_rps,
                'response_time_stats': {
                    'mean': statistics.mean(response_times),
                    'median': statistics.median(response_times),
                    'min': min(response_times),
                    'max': max(response_times),
                    'p95': performance_data_manager._calculate_percentile(response_times, 95),
                    'p99': performance_data_manager._calculate_percentile(response_times, 99)
                }
            }
            
            # Validate against concurrent load thresholds
            thresholds = PerformanceThresholds()
            analysis['meets_throughput_threshold'] = throughput_rps >= thresholds.throughput_requests_per_second
            analysis['meets_concurrent_users_threshold'] = concurrent_users >= thresholds.concurrent_users_min
            analysis['meets_response_time_threshold'] = statistics.mean(response_times) <= thresholds.api_response_time_max
            
        else:
            analysis = {
                'test_name': test_name,
                'error': 'No successful requests completed',
                'total_errors': len(errors),
                'error_list': errors[:10]  # First 10 errors for debugging
            }
            
        return analysis
        
    return benchmark_concurrent_load


# Baseline Comparison Fixtures per Section 4.7.2
@pytest.fixture(scope="session")
def baseline_data():
    """
    Baseline data fixture for Node.js performance comparison.
    
    This fixture loads Node.js baseline performance data for migration
    validation and comparative testing per Section 4.7.2.
    
    Returns:
        BaselineMetrics object with Node.js performance data
    """
    return performance_data_manager.load_baseline_data()


@pytest.fixture(scope="function")
def baseline_comparison(baseline_data):
    """
    Baseline comparison fixture for migration validation.
    
    This fixture provides utilities for comparing Flask performance
    against Node.js baseline metrics per Section 4.7.2.
    
    Args:
        baseline_data: Node.js baseline metrics
        
    Returns:
        Baseline comparison function
    """
    def compare_with_baseline(test_name: str, 
                            flask_metrics: List[float],
                            baseline_key: Optional[str] = None,
                            tolerance_percent: float = 5.0) -> Dict[str, Any]:
        """
        Compare Flask performance with Node.js baseline.
        
        Args:
            test_name: Name of the performance test
            flask_metrics: Flask performance measurements
            baseline_key: Key for baseline lookup
            tolerance_percent: Performance tolerance percentage
            
        Returns:
            Detailed comparison analysis with pass/fail status
        """
        comparison = performance_data_manager.compare_performance(
            test_name=test_name,
            flask_metrics=flask_metrics,
            baseline_key=baseline_key
        )
        
        # Add tolerance-based validation
        if comparison.get('baseline_available') and comparison.get('performance_improvement') is not None:
            improvement = comparison['performance_improvement']
            comparison['within_tolerance'] = abs(improvement) <= tolerance_percent
            comparison['tolerance_percent'] = tolerance_percent
            
            # Determine overall test result
            if improvement >= 0:
                comparison['result'] = 'IMPROVEMENT'
            elif abs(improvement) <= tolerance_percent:
                comparison['result'] = 'ACCEPTABLE'
            else:
                comparison['result'] = 'REGRESSION'
        else:
            comparison['result'] = 'NO_BASELINE'
            
        return comparison
        
    return compare_with_baseline


# Performance Regression Detection per Section 4.7.2
@pytest.fixture(scope="function")
def regression_detector():
    """
    Performance regression detection fixture with threshold validation.
    
    This fixture provides automated performance regression detection
    capabilities with configurable thresholds per Section 4.7.2.
    
    Returns:
        Regression detection function with alerting
    """
    def detect_regression(test_results: Dict[str, Any],
                        custom_thresholds: Optional[PerformanceThresholds] = None) -> Dict[str, Any]:
        """
        Detect performance regressions in test results.
        
        Args:
            test_results: Performance test results to analyze
            custom_thresholds: Custom performance thresholds
            
        Returns:
            Regression detection analysis with recommendations
        """
        thresholds = custom_thresholds or PerformanceThresholds()
        
        regression_analysis = {
            'regressions_detected': [],
            'warnings': [],
            'recommendations': [],
            'overall_status': 'PASS'
        }
        
        # Check API response time regressions
        if 'flask_metrics' in test_results and test_results['flask_metrics']:
            mean_time = test_results['flask_metrics']['mean']
            p95_time = test_results['flask_metrics'].get('p95', 0)
            
            if mean_time > thresholds.api_response_time_max:
                regression_analysis['regressions_detected'].append({
                    'metric': 'api_response_time_mean',
                    'value': mean_time,
                    'threshold': thresholds.api_response_time_max,
                    'severity': 'HIGH'
                })
                
            if p95_time > thresholds.api_response_time_p95:
                regression_analysis['regressions_detected'].append({
                    'metric': 'api_response_time_p95',
                    'value': p95_time,
                    'threshold': thresholds.api_response_time_p95,
                    'severity': 'MEDIUM'
                })
                
        # Check baseline comparison regressions
        if test_results.get('regression_detected'):
            improvement = test_results.get('performance_improvement', 0)
            regression_analysis['regressions_detected'].append({
                'metric': 'baseline_comparison',
                'value': improvement,
                'threshold': -thresholds.regression_threshold_percent,
                'severity': 'HIGH'
            })
            
        # Generate recommendations
        if regression_analysis['regressions_detected']:
            regression_analysis['overall_status'] = 'FAIL'
            regression_analysis['recommendations'].extend([
                'Review Flask application configuration for optimization opportunities',
                'Analyze SQLAlchemy query performance and connection pooling',
                'Consider Gunicorn worker configuration tuning',
                'Validate OpenTelemetry instrumentation overhead impact'
            ])
        elif regression_analysis['warnings']:
            regression_analysis['overall_status'] = 'WARNING'
            
        return regression_analysis
        
    return detect_regression


# Monitoring Integration Fixtures per Section 6.5.1.1
@pytest.fixture(scope="session")
def prometheus_metrics():
    """
    Prometheus metrics fixture for monitoring integration.
    
    This fixture provides access to Prometheus metrics collection
    capabilities per Section 6.5.1.1 if prometheus_flask_exporter is available.
    
    Returns:
        Prometheus metrics utilities or None if not available
    """
    if not PROMETHEUS_AVAILABLE:
        pytest.skip("prometheus_flask_exporter not available")
        
    registry = CollectorRegistry()
    
    # Create performance monitoring metrics
    api_request_duration = Histogram(
        'flask_api_request_duration_seconds',
        'Time spent processing API requests',
        ['method', 'endpoint', 'status'],
        registry=registry
    )
    
    database_query_duration = Histogram(
        'flask_database_query_duration_seconds',
        'Time spent executing database queries',
        ['operation', 'table'],
        registry=registry
    )
    
    auth_operation_duration = Histogram(
        'flask_auth_operation_duration_seconds',
        'Time spent on authentication operations',
        ['operation', 'provider'],
        registry=registry
    )
    
    memory_usage_gauge = Gauge(
        'flask_memory_usage_bytes',
        'Memory usage of Flask application',
        registry=registry
    )
    
    gc_pause_duration = Histogram(
        'flask_gc_pause_duration_seconds',
        'Garbage collection pause duration',
        registry=registry
    )
    
    return {
        'registry': registry,
        'api_request_duration': api_request_duration,
        'database_query_duration': database_query_duration,
        'auth_operation_duration': auth_operation_duration,
        'memory_usage_gauge': memory_usage_gauge,
        'gc_pause_duration': gc_pause_duration
    }


@pytest.fixture(scope="function")
def performance_report_generator():
    """
    Performance report generation fixture for comprehensive test reporting.
    
    This fixture provides utilities for generating comprehensive performance
    test reports with charts, statistics, and recommendations.
    
    Returns:
        Report generation function
    """
    def generate_performance_report(test_results: List[Dict[str, Any]],
                                  report_name: str = "performance_test_report") -> Dict[str, Any]:
        """
        Generate comprehensive performance test report.
        
        Args:
            test_results: List of performance test results
            report_name: Name of the report
            
        Returns:
            Comprehensive performance report with analysis
        """
        report = {
            'report_name': report_name,
            'generation_timestamp': datetime.now(timezone.utc).isoformat(),
            'test_summary': {
                'total_tests': len(test_results),
                'passed_tests': 0,
                'failed_tests': 0,
                'warning_tests': 0
            },
            'performance_overview': {},
            'regression_analysis': {},
            'recommendations': [],
            'detailed_results': test_results
        }
        
        # Analyze test results
        all_response_times = []
        all_database_times = []
        all_auth_times = []
        
        for result in test_results:
            # Categorize test results
            if result.get('overall_status') == 'PASS':
                report['test_summary']['passed_tests'] += 1
            elif result.get('overall_status') == 'FAIL':
                report['test_summary']['failed_tests'] += 1
            else:
                report['test_summary']['warning_tests'] += 1
                
            # Collect performance metrics
            if 'flask_metrics' in result:
                if 'api' in result.get('test_name', ''):
                    all_response_times.extend([result['flask_metrics']['mean']])
                elif 'database' in result.get('test_name', ''):
                    all_database_times.extend([result['flask_metrics']['mean']])
                elif 'auth' in result.get('test_name', ''):
                    all_auth_times.extend([result['flask_metrics']['mean']])
                    
        # Generate performance overview
        if all_response_times:
            report['performance_overview']['api_performance'] = {
                'mean_response_time': statistics.mean(all_response_times),
                'p95_response_time': performance_data_manager._calculate_percentile(all_response_times, 95),
                'fastest_response': min(all_response_times),
                'slowest_response': max(all_response_times)
            }
            
        if all_database_times:
            report['performance_overview']['database_performance'] = {
                'mean_query_time': statistics.mean(all_database_times),
                'p95_query_time': performance_data_manager._calculate_percentile(all_database_times, 95),
                'fastest_query': min(all_database_times),
                'slowest_query': max(all_database_times)
            }
            
        if all_auth_times:
            report['performance_overview']['auth_performance'] = {
                'mean_auth_time': statistics.mean(all_auth_times),
                'p95_auth_time': performance_data_manager._calculate_percentile(all_auth_times, 95),
                'fastest_auth': min(all_auth_times),
                'slowest_auth': max(all_auth_times)
            }
            
        # Generate recommendations based on results
        if report['test_summary']['failed_tests'] > 0:
            report['recommendations'].extend([
                'Investigate failed performance tests for optimization opportunities',
                'Review Flask application configuration and middleware stack',
                'Analyze database query patterns and indexing strategies',
                'Consider horizontal scaling or caching implementation'
            ])
            
        if report['test_summary']['warning_tests'] > 0:
            report['recommendations'].extend([
                'Monitor warning tests for potential performance degradation trends',
                'Implement proactive performance monitoring and alerting'
            ])
            
        return report
        
    return generate_performance_report


# Cleanup Fixtures
@pytest.fixture(scope="session", autouse=True)
def performance_test_cleanup():
    """
    Automatic cleanup fixture for performance testing resources.
    
    This fixture ensures proper cleanup of OpenTelemetry instrumentation,
    performance monitoring resources, and temporary data files.
    """
    yield
    
    # Cleanup OpenTelemetry instrumentation
    otel_manager.cleanup_instrumentation()
    
    # Reset performance monitoring
    db_performance_monitor.reset_statistics()
    
    # Save final performance data
    performance_data_manager.save_baseline_data("final_performance_baseline.json")


# Export key components for use in performance tests
__all__ = [
    'PerformanceThresholds',
    'BaselineMetrics', 
    'PerformanceDataManager',
    'OpenTelemetryManager',
    'DatabasePerformanceMonitor',
    'MemoryProfiler',
    'flask_app_factory',
    'flask_client',
    'performance_monitor',
    'benchmark_config',
    'api_performance_benchmark',
    'database_performance_benchmark',
    'authentication_performance_benchmark',
    'memory_performance_benchmark',
    'concurrent_load_benchmark',
    'baseline_data',
    'baseline_comparison',
    'regression_detector',
    'prometheus_metrics',
    'performance_report_generator'
]