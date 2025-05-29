"""
Database Query Performance Benchmarking Test Suite - test_database_query_benchmarks.py

This module provides comprehensive database query performance benchmarking using pytest-benchmark 5.1.0
and SQLAlchemy event listeners to validate sub-100ms query response times and database connection pool 
efficiency. The test suite ensures Flask-SQLAlchemy performance meets or exceeds original MongoDB 
query performance while providing comprehensive database operation analysis and optimization insights.

Key Features:
- SQLAlchemy event listener instrumentation for comprehensive query performance tracking per Section 6.5.1.1
- pytest-benchmark fixtures validating sub-100ms SQLAlchemy query response times per Section 4.11.1
- Database connection pool utilization monitoring with performance benchmarking per Section 6.5.2.2
- MongoDB to Flask-SQLAlchemy performance comparison framework per Section 0.2.1
- Automated database query optimization validation with connection pooling efficiency per Section 4.7.1
- OpenTelemetry database instrumentation integration for comprehensive query analysis per Section 6.5.1.3

Migration Context:
This test suite supports the strategic technology migration from MongoDB to PostgreSQL 15.x with 
Flask-SQLAlchemy 3.1.1 by providing comprehensive database performance validation that ensures 
sub-100ms query response times and optimal connection pool utilization during the conversion process.
"""

import asyncio
import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Generator, Callable
import statistics
import gc
import psutil
import random
import string
from dataclasses import dataclass, field
from unittest.mock import patch

import pytest
import pytest_benchmark
from flask import Flask, current_app, g
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, text, func, select, and_, or_
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool, QueuePool
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import sqltypes

# Import application models for testing
from src.models import User, UserSession, BusinessEntity, EntityRelationship
from src.models.base import BaseModel

# OpenTelemetry imports for database instrumentation per Section 6.5.1.3
from opentelemetry import trace, metrics
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.semantic_conventions.trace import SpanAttributes

# Memory profiling for database operation analysis
try:
    import memory_profiler
    MEMORY_PROFILING_AVAILABLE = True
except ImportError:
    MEMORY_PROFILING_AVAILABLE = False

# Connection pooling analysis
try:
    import psycopg2
    import psycopg2.pool
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False


@dataclass
class DatabasePerformanceThresholds:
    """
    Database-specific performance thresholds for migration validation per Section 4.11.1.
    
    These thresholds ensure Flask-SQLAlchemy performance meets or exceeds MongoDB baseline
    performance while maintaining sub-100ms query response times per Section 6.5.1.1.
    """
    # Query response time thresholds per Section 4.11.1
    simple_query_max_ms: float = 100.0  # Simple SELECT operations < 100ms
    simple_query_p95_ms: float = 75.0   # 95th percentile at 75ms
    simple_query_mean_ms: float = 50.0  # Mean response time at 50ms
    
    # Complex query thresholds per Section 6.2.5.1
    complex_query_max_ms: float = 2000.0  # Complex JOIN operations < 2000ms
    complex_query_p95_ms: float = 1500.0  # 95th percentile at 1500ms
    complex_query_mean_ms: float = 1000.0 # Mean complex query time at 1000ms
    
    # Write operation thresholds
    insert_operation_max_ms: float = 300.0  # INSERT operations < 300ms
    update_operation_max_ms: float = 300.0  # UPDATE operations < 300ms
    delete_operation_max_ms: float = 300.0  # DELETE operations < 300ms
    
    # Batch operation thresholds
    batch_operation_max_ms: float = 5000.0  # Batch operations < 5000ms
    bulk_insert_max_ms: float = 8000.0      # Bulk insert operations < 8000ms
    
    # Connection pool thresholds per Section 6.5.2.2
    connection_pool_utilization_max: float = 0.80  # 80% max pool utilization
    connection_pool_wait_time_max_ms: float = 100.0 # 100ms max wait time
    connection_pool_efficiency_min: float = 0.90   # 90% minimum efficiency
    
    # Query optimization thresholds
    slow_query_threshold_ms: float = 100.0  # Queries exceeding 100ms are slow
    n_plus_one_detection_threshold: int = 5  # More than 5 similar queries indicates N+1
    connection_leak_threshold: int = 5      # More than 5 unclosed connections
    
    # MongoDB baseline comparison tolerances per Section 0.2.1
    mongodb_baseline_tolerance_percent: float = 5.0  # 5% tolerance for baseline comparison
    performance_regression_threshold_percent: float = 10.0  # 10% regression alert threshold


@dataclass
class QueryPerformanceMetrics:
    """
    Comprehensive query performance metrics for analysis and comparison.
    
    This class captures detailed query execution metrics for performance
    validation and optimization insights per Section 6.5.1.1.
    """
    # Basic timing metrics
    execution_time_ms: float
    preparation_time_ms: float = 0.0
    fetch_time_ms: float = 0.0
    total_time_ms: float = 0.0
    
    # Query characteristics
    query_type: str = ""  # SELECT, INSERT, UPDATE, DELETE
    table_name: str = ""
    row_count: int = 0
    result_size_bytes: int = 0
    
    # Connection pool metrics
    pool_size: int = 0
    active_connections: int = 0
    checked_out_connections: int = 0
    pool_utilization_percent: float = 0.0
    
    # OpenTelemetry trace information
    trace_id: str = ""
    span_id: str = ""
    
    # Memory usage during query
    memory_before_mb: float = 0.0
    memory_after_mb: float = 0.0
    memory_delta_mb: float = 0.0
    
    # Error information
    error_occurred: bool = False
    error_message: str = ""
    error_type: str = ""
    
    # Metadata
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    environment: str = "test"
    database_engine: str = "postgresql"


class DatabaseQueryBenchmarkSuite:
    """
    Comprehensive database query benchmarking suite with SQLAlchemy event listener integration.
    
    This class provides enterprise-grade database performance testing capabilities including
    query execution timing, connection pool monitoring, memory usage analysis, and MongoDB
    baseline comparison per Section 6.5.1.1 and Section 0.2.1.
    """
    
    def __init__(self, app: Flask, db: SQLAlchemy):
        """
        Initialize database query benchmark suite.
        
        Args:
            app: Flask application instance
            db: SQLAlchemy database instance
        """
        self.app = app
        self.db = db
        self.engine = db.engine
        self.thresholds = DatabasePerformanceThresholds()
        
        # Performance tracking
        self.query_metrics: List[QueryPerformanceMetrics] = []
        self.connection_pool_stats = {}
        self.baseline_metrics = {}
        
        # OpenTelemetry instrumentation
        self.tracer = trace.get_tracer(__name__)
        self.meter = metrics.get_meter(__name__)
        
        # Performance counters
        self.query_counter = 0
        self.slow_query_counter = 0
        self.connection_errors = 0
        
        # Setup event listeners
        self._setup_sqlalchemy_event_listeners()
        self._setup_opentelemetry_instrumentation()
        
    def _setup_sqlalchemy_event_listeners(self):
        """
        Setup comprehensive SQLAlchemy event listeners for query performance tracking.
        
        Per Section 6.5.1.1: SQLAlchemy event listeners for comprehensive database 
        query performance tracking with SQL statement correlation.
        """
        @event.listens_for(self.engine, "before_cursor_execute")
        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Record query start time and context."""
            context._query_start_time = time.perf_counter()
            context._memory_before = self._get_memory_usage()
            context._connection_id = id(conn)
            
            # Update connection pool statistics
            self._update_connection_pool_stats()
            
            # Create OpenTelemetry span for query tracing
            if hasattr(context, '_otel_span'):
                context._otel_span.set_attribute("db.statement", statement[:200])  # Truncate for safety
                context._otel_span.set_attribute("db.operation", self._extract_query_operation(statement))
                
        @event.listens_for(self.engine, "after_cursor_execute")
        def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Record query completion and calculate comprehensive metrics."""
            if not hasattr(context, '_query_start_time'):
                return
                
            # Calculate timing metrics
            total_time = time.perf_counter() - context._query_start_time
            total_time_ms = total_time * 1000
            
            # Get memory usage after query
            memory_after = self._get_memory_usage()
            memory_delta = memory_after - context._memory_before
            
            # Extract query characteristics
            query_type = self._extract_query_operation(statement)
            table_name = self._extract_table_name(statement)
            row_count = cursor.rowcount if hasattr(cursor, 'rowcount') else 0
            
            # Create performance metrics record
            metrics = QueryPerformanceMetrics(
                execution_time_ms=total_time_ms,
                total_time_ms=total_time_ms,
                query_type=query_type,
                table_name=table_name,
                row_count=row_count,
                memory_before_mb=context._memory_before,
                memory_after_mb=memory_after,
                memory_delta_mb=memory_delta,
                **self._get_connection_pool_metrics()
            )
            
            # Add OpenTelemetry trace information
            if hasattr(context, '_otel_span'):
                span_context = context._otel_span.get_span_context()
                metrics.trace_id = format(span_context.trace_id, '032x')
                metrics.span_id = format(span_context.span_id, '016x')
                
                # Set span attributes
                context._otel_span.set_attribute("db.response_time_ms", total_time_ms)
                context._otel_span.set_attribute("db.row_count", row_count)
                context._otel_span.set_attribute("db.memory_delta_mb", memory_delta)
                
            self.query_metrics.append(metrics)
            self.query_counter += 1
            
            # Track slow queries per Section 4.11.1
            if total_time_ms > self.thresholds.slow_query_threshold_ms:
                self.slow_query_counter += 1
                self._log_slow_query(statement, total_time_ms, parameters)
                
        @event.listens_for(self.engine, "handle_error")
        def handle_error(exception_context):
            """Track database errors and connection issues."""
            self.connection_errors += 1
            
            # Create error metrics record
            error_metrics = QueryPerformanceMetrics(
                execution_time_ms=0,
                error_occurred=True,
                error_message=str(exception_context.original_exception),
                error_type=type(exception_context.original_exception).__name__
            )
            
            self.query_metrics.append(error_metrics)
            
        @event.listens_for(self.engine, "connect")
        def on_connect(dbapi_connection, connection_record):
            """Track new database connections."""
            if 'total_connections' not in self.connection_pool_stats:
                self.connection_pool_stats['total_connections'] = 0
            self.connection_pool_stats['total_connections'] += 1
            
        @event.listens_for(self.engine, "checkout")
        def on_checkout(dbapi_connection, connection_record, connection_proxy):
            """Track connection pool checkout operations."""
            if 'checkouts' not in self.connection_pool_stats:
                self.connection_pool_stats['checkouts'] = 0
            self.connection_pool_stats['checkouts'] += 1
            
        @event.listens_for(self.engine, "checkin")
        def on_checkin(dbapi_connection, connection_record):
            """Track connection pool checkin operations."""
            if 'checkins' not in self.connection_pool_stats:
                self.connection_pool_stats['checkins'] = 0
            self.connection_pool_stats['checkins'] += 1
            
    def _setup_opentelemetry_instrumentation(self):
        """
        Setup OpenTelemetry database instrumentation per Section 6.5.1.3.
        
        Configures comprehensive database query tracing and metrics collection
        with automatic instrumentation for Flask-SQLAlchemy operations.
        """
        # Instrument SQLAlchemy if not already instrumented
        if not hasattr(self.engine, '_otel_instrumented'):
            SQLAlchemyInstrumentor().instrument(engine=self.engine)
            self.engine._otel_instrumented = True
            
    def _extract_query_operation(self, statement: str) -> str:
        """Extract query operation type from SQL statement."""
        statement_upper = statement.strip().upper()
        if statement_upper.startswith('SELECT'):
            return 'SELECT'
        elif statement_upper.startswith('INSERT'):
            return 'INSERT'
        elif statement_upper.startswith('UPDATE'):
            return 'UPDATE'
        elif statement_upper.startswith('DELETE'):
            return 'DELETE'
        elif statement_upper.startswith('CREATE'):
            return 'CREATE'
        elif statement_upper.startswith('DROP'):
            return 'DROP'
        else:
            return 'OTHER'
            
    def _extract_table_name(self, statement: str) -> str:
        """Extract primary table name from SQL statement."""
        try:
            statement_upper = statement.strip().upper()
            
            if statement_upper.startswith('SELECT'):
                # Extract table name from FROM clause
                from_index = statement_upper.find('FROM')
                if from_index != -1:
                    from_clause = statement_upper[from_index + 4:].strip()
                    table_name = from_clause.split()[0]
                    return table_name.strip('"\'`').lower()
                    
            elif statement_upper.startswith(('INSERT', 'UPDATE', 'DELETE')):
                # Extract table name from INSERT INTO, UPDATE, or DELETE FROM
                if 'INTO' in statement_upper:
                    into_index = statement_upper.find('INTO')
                    table_part = statement_upper[into_index + 4:].strip()
                elif 'UPDATE' in statement_upper:
                    update_index = statement_upper.find('UPDATE')
                    table_part = statement_upper[update_index + 6:].strip()
                elif 'FROM' in statement_upper:
                    from_index = statement_upper.find('FROM')
                    table_part = statement_upper[from_index + 4:].strip()
                else:
                    return 'unknown'
                    
                table_name = table_part.split()[0]
                return table_name.strip('"\'`').lower()
                
        except Exception:
            pass
            
        return 'unknown'
        
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            process = psutil.Process(os.getpid())
            return process.memory_info().rss / 1024 / 1024
        except Exception:
            return 0.0
            
    def _update_connection_pool_stats(self):
        """Update connection pool utilization statistics."""
        if hasattr(self.engine.pool, 'size'):
            pool = self.engine.pool
            self.connection_pool_stats.update({
                'pool_size': getattr(pool, 'size', 0),
                'checked_out': getattr(pool, 'checkedout', 0),
                'checked_in': getattr(pool, 'checkedin', 0),
                'overflow': getattr(pool, 'overflow', 0),
                'invalid': getattr(pool, 'invalidated', 0)
            })
            
    def _get_connection_pool_metrics(self) -> Dict[str, Any]:
        """Get current connection pool metrics for performance analysis."""
        metrics = {}
        
        if hasattr(self.engine.pool, 'size'):
            pool = self.engine.pool
            pool_size = getattr(pool, 'size', 0)
            checked_out = getattr(pool, 'checkedout', 0)
            
            metrics.update({
                'pool_size': pool_size,
                'active_connections': checked_out,
                'checked_out_connections': checked_out,
                'pool_utilization_percent': (checked_out / pool_size * 100) if pool_size > 0 else 0
            })
            
        return metrics
        
    def _log_slow_query(self, statement: str, execution_time_ms: float, parameters: Any):
        """Log slow query for analysis and optimization."""
        slow_query_info = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'execution_time_ms': execution_time_ms,
            'statement': statement[:500],  # Truncate for safety
            'parameters': str(parameters)[:200] if parameters else None,
            'query_type': self._extract_query_operation(statement),
            'table_name': self._extract_table_name(statement)
        }
        
        # In production, this would be sent to logging infrastructure
        print(f"SLOW QUERY DETECTED: {slow_query_info}")
        
    @contextmanager
    def trace_query_performance(self, operation_name: str) -> Generator[QueryPerformanceMetrics, None, None]:
        """
        Context manager for tracing database query performance with OpenTelemetry.
        
        Args:
            operation_name: Name of the database operation being traced
            
        Yields:
            QueryPerformanceMetrics object for additional attribute setting
        """
        with self.tracer.start_as_current_span(f"db.{operation_name}") as span:
            start_time = time.perf_counter()
            start_memory = self._get_memory_usage()
            
            # Initialize metrics object
            metrics = QueryPerformanceMetrics(
                execution_time_ms=0,
                memory_before_mb=start_memory
            )
            
            try:
                span.set_attribute(SpanAttributes.DB_SYSTEM, "postgresql")
                span.set_attribute(SpanAttributes.DB_NAME, self.app.config.get('DATABASE_NAME', 'flask_app'))
                span.set_attribute("db.operation_name", operation_name)
                
                yield metrics
                
            finally:
                end_time = time.perf_counter()
                end_memory = self._get_memory_usage()
                
                execution_time_ms = (end_time - start_time) * 1000
                metrics.execution_time_ms = execution_time_ms
                metrics.total_time_ms = execution_time_ms
                metrics.memory_after_mb = end_memory
                metrics.memory_delta_mb = end_memory - start_memory
                
                # Update span attributes
                span.set_attribute("db.response_time_ms", execution_time_ms)
                span.set_attribute("db.memory_delta_mb", metrics.memory_delta_mb)
                
                # Add connection pool metrics
                pool_metrics = self._get_connection_pool_metrics()
                metrics.__dict__.update(pool_metrics)
                
                # Store metrics for analysis
                self.query_metrics.append(metrics)
                
    def reset_metrics(self):
        """Reset all performance metrics for clean test runs."""
        self.query_metrics.clear()
        self.connection_pool_stats.clear()
        self.query_counter = 0
        self.slow_query_counter = 0
        self.connection_errors = 0
        
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Generate comprehensive database performance summary.
        
        Returns:
            Dictionary containing detailed performance analysis and statistics
        """
        if not self.query_metrics:
            return {'status': 'no_queries_executed'}
            
        # Filter successful queries for analysis
        successful_queries = [m for m in self.query_metrics if not m.error_occurred]
        
        if not successful_queries:
            return {'status': 'no_successful_queries'}
            
        # Calculate timing statistics
        execution_times = [m.execution_time_ms for m in successful_queries]
        
        summary = {
            'total_queries': len(self.query_metrics),
            'successful_queries': len(successful_queries),
            'failed_queries': len(self.query_metrics) - len(successful_queries),
            'slow_queries': self.slow_query_counter,
            'connection_errors': self.connection_errors,
            'timing_statistics': {
                'mean_ms': statistics.mean(execution_times),
                'median_ms': statistics.median(execution_times),
                'min_ms': min(execution_times),
                'max_ms': max(execution_times),
                'std_dev_ms': statistics.stdev(execution_times) if len(execution_times) > 1 else 0,
                'p95_ms': self._calculate_percentile(execution_times, 95),
                'p99_ms': self._calculate_percentile(execution_times, 99)
            },
            'query_distribution': {},
            'connection_pool_analysis': self._analyze_connection_pool_performance(),
            'memory_analysis': self._analyze_memory_usage(),
            'threshold_compliance': self._check_threshold_compliance(execution_times),
            'optimization_recommendations': self._generate_optimization_recommendations()
        }
        
        # Analyze query distribution by type
        query_types = {}
        for metric in successful_queries:
            query_type = metric.query_type
            if query_type not in query_types:
                query_types[query_type] = []
            query_types[query_type].append(metric.execution_time_ms)
            
        for query_type, times in query_types.items():
            summary['query_distribution'][query_type] = {
                'count': len(times),
                'mean_ms': statistics.mean(times),
                'median_ms': statistics.median(times),
                'min_ms': min(times),
                'max_ms': max(times),
                'p95_ms': self._calculate_percentile(times, 95)
            }
            
        return summary
        
    def _calculate_percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile for performance data analysis."""
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
            
    def _analyze_connection_pool_performance(self) -> Dict[str, Any]:
        """Analyze connection pool utilization and efficiency."""
        if not self.connection_pool_stats:
            return {'status': 'no_pool_data'}
            
        pool_analysis = {
            'total_connections_created': self.connection_pool_stats.get('total_connections', 0),
            'total_checkouts': self.connection_pool_stats.get('checkouts', 0),
            'total_checkins': self.connection_pool_stats.get('checkins', 0),
            'current_pool_size': self.connection_pool_stats.get('pool_size', 0),
            'current_checked_out': self.connection_pool_stats.get('checked_out', 0),
            'overflow_connections': self.connection_pool_stats.get('overflow', 0),
            'invalidated_connections': self.connection_pool_stats.get('invalid', 0)
        }
        
        # Calculate efficiency metrics
        total_checkouts = pool_analysis['total_checkouts']
        total_checkins = pool_analysis['total_checkins']
        
        if total_checkouts > 0:
            pool_analysis['checkout_efficiency'] = total_checkins / total_checkouts
            pool_analysis['connection_reuse_ratio'] = total_checkouts / max(1, pool_analysis['total_connections_created'])
            
        # Calculate current utilization
        current_pool_size = pool_analysis['current_pool_size']
        current_checked_out = pool_analysis['current_checked_out']
        
        if current_pool_size > 0:
            pool_analysis['current_utilization_percent'] = (current_checked_out / current_pool_size) * 100
            
        # Check threshold compliance
        pool_analysis['meets_utilization_threshold'] = (
            pool_analysis.get('current_utilization_percent', 0) <= 
            self.thresholds.connection_pool_utilization_max * 100
        )
        
        pool_analysis['meets_efficiency_threshold'] = (
            pool_analysis.get('checkout_efficiency', 0) >= 
            self.thresholds.connection_pool_efficiency_min
        )
        
        return pool_analysis
        
    def _analyze_memory_usage(self) -> Dict[str, Any]:
        """Analyze memory usage patterns during database operations."""
        memory_deltas = [m.memory_delta_mb for m in self.query_metrics if not m.error_occurred]
        
        if not memory_deltas:
            return {'status': 'no_memory_data'}
            
        memory_analysis = {
            'total_memory_operations': len(memory_deltas),
            'memory_growth_operations': len([d for d in memory_deltas if d > 0]),
            'memory_reduction_operations': len([d for d in memory_deltas if d < 0]),
            'neutral_memory_operations': len([d for d in memory_deltas if d == 0]),
            'total_memory_delta_mb': sum(memory_deltas),
            'average_memory_delta_mb': statistics.mean(memory_deltas),
            'max_memory_increase_mb': max(memory_deltas),
            'max_memory_decrease_mb': min(memory_deltas),
            'memory_leak_indicators': []
        }
        
        # Detect potential memory leaks
        positive_deltas = [d for d in memory_deltas if d > 0]
        if positive_deltas:
            memory_analysis['average_memory_growth_mb'] = statistics.mean(positive_deltas)
            
            # Check for consistent memory growth pattern
            if len(positive_deltas) > len(memory_deltas) * 0.7:  # More than 70% operations increase memory
                memory_analysis['memory_leak_indicators'].append('Consistent memory growth pattern detected')
                
        # Check for large memory spikes
        large_spikes = [d for d in memory_deltas if abs(d) > 10.0]  # >10MB changes
        if large_spikes:
            memory_analysis['large_memory_spikes'] = len(large_spikes)
            memory_analysis['memory_leak_indicators'].append(f'{len(large_spikes)} large memory spikes detected')
            
        return memory_analysis
        
    def _check_threshold_compliance(self, execution_times: List[float]) -> Dict[str, Any]:
        """Check compliance with performance thresholds per Section 4.11.1."""
        if not execution_times:
            return {'status': 'no_data'}
            
        mean_time = statistics.mean(execution_times)
        max_time = max(execution_times)
        p95_time = self._calculate_percentile(execution_times, 95)
        
        compliance = {
            'mean_time_ms': mean_time,
            'max_time_ms': max_time,
            'p95_time_ms': p95_time,
            'meets_simple_query_mean_threshold': mean_time <= self.thresholds.simple_query_mean_ms,
            'meets_simple_query_max_threshold': max_time <= self.thresholds.simple_query_max_ms,
            'meets_simple_query_p95_threshold': p95_time <= self.thresholds.simple_query_p95_ms,
            'overall_compliance': True
        }
        
        # Check overall compliance
        compliance['overall_compliance'] = (
            compliance['meets_simple_query_mean_threshold'] and
            compliance['meets_simple_query_max_threshold'] and
            compliance['meets_simple_query_p95_threshold']
        )
        
        # Add threshold values for reference
        compliance['thresholds'] = {
            'simple_query_mean_ms': self.thresholds.simple_query_mean_ms,
            'simple_query_max_ms': self.thresholds.simple_query_max_ms,
            'simple_query_p95_ms': self.thresholds.simple_query_p95_ms
        }
        
        return compliance
        
    def _generate_optimization_recommendations(self) -> List[str]:
        """Generate database optimization recommendations based on performance analysis."""
        recommendations = []
        
        # Check for slow queries
        if self.slow_query_counter > 0:
            recommendations.append(
                f"Optimize {self.slow_query_counter} slow queries exceeding {self.thresholds.slow_query_threshold_ms}ms"
            )
            
        # Check connection pool utilization
        pool_stats = self.connection_pool_stats
        if pool_stats:
            current_utilization = pool_stats.get('checked_out', 0) / max(1, pool_stats.get('pool_size', 1))
            if current_utilization > self.thresholds.connection_pool_utilization_max:
                recommendations.append(
                    f"Connection pool utilization ({current_utilization:.1%}) exceeds threshold "
                    f"({self.thresholds.connection_pool_utilization_max:.1%}). Consider increasing pool size."
                )
                
        # Check for connection errors
        if self.connection_errors > 0:
            recommendations.append(
                f"Investigate {self.connection_errors} connection errors for stability improvements"
            )
            
        # Analyze query patterns
        query_types = {}
        for metric in self.query_metrics:
            if not metric.error_occurred:
                query_types[metric.query_type] = query_types.get(metric.query_type, 0) + 1
                
        # Check for N+1 query problems
        if query_types.get('SELECT', 0) > self.thresholds.n_plus_one_detection_threshold:
            select_count = query_types['SELECT']
            total_queries = sum(query_types.values())
            if select_count / total_queries > 0.8:  # More than 80% SELECT queries
                recommendations.append(
                    f"Potential N+1 query problem detected with {select_count} SELECT queries. "
                    "Consider using eager loading or query optimization."
                )
                
        # Memory usage recommendations
        memory_deltas = [m.memory_delta_mb for m in self.query_metrics if not m.error_occurred]
        if memory_deltas:
            avg_memory_delta = statistics.mean(memory_deltas)
            if avg_memory_delta > 5.0:  # Average memory growth > 5MB
                recommendations.append(
                    f"High memory usage detected (avg {avg_memory_delta:.1f}MB per query). "
                    "Consider query result optimization or caching strategies."
                )
                
        if not recommendations:
            recommendations.append("Database performance is within acceptable thresholds")
            
        return recommendations
        
    def compare_with_mongodb_baseline(self, baseline_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare Flask-SQLAlchemy performance with MongoDB baseline per Section 0.2.1.
        
        Args:
            baseline_metrics: MongoDB baseline performance data
            
        Returns:
            Detailed comparison analysis with migration validation results
        """
        current_summary = self.get_performance_summary()
        
        if 'timing_statistics' not in current_summary:
            return {'error': 'No current performance data available'}
            
        current_stats = current_summary['timing_statistics']
        
        comparison = {
            'migration_validation': {
                'source_system': 'MongoDB',
                'target_system': 'PostgreSQL + Flask-SQLAlchemy',
                'comparison_timestamp': datetime.now(timezone.utc).isoformat()
            },
            'performance_comparison': {},
            'threshold_compliance': current_summary.get('threshold_compliance', {}),
            'migration_success_criteria': {},
            'recommendations': []
        }
        
        # Compare key performance metrics
        metrics_to_compare = ['mean_ms', 'median_ms', 'p95_ms', 'max_ms']
        
        for metric in metrics_to_compare:
            if metric in baseline_metrics and metric in current_stats:
                baseline_value = baseline_metrics[metric]
                current_value = current_stats[metric]
                
                improvement_percent = ((baseline_value - current_value) / baseline_value) * 100
                
                comparison['performance_comparison'][metric] = {
                    'baseline_value': baseline_value,
                    'current_value': current_value,
                    'improvement_percent': improvement_percent,
                    'performance_change': 'improvement' if improvement_percent > 0 else 'regression',
                    'within_tolerance': abs(improvement_percent) <= self.thresholds.mongodb_baseline_tolerance_percent
                }
                
        # Evaluate migration success criteria per Section 0.2.1
        success_criteria = {
            'functional_parity': True,  # Assumed for database operations
            'performance_parity': True,
            'sub_100ms_compliance': current_stats.get('mean_ms', 0) <= 100.0,
            'no_significant_regression': True,
            'connection_pool_efficiency': True
        }
        
        # Check performance parity
        performance_regressions = []
        for metric, comparison_data in comparison['performance_comparison'].items():
            if (comparison_data['improvement_percent'] < -self.thresholds.performance_regression_threshold_percent):
                performance_regressions.append(f"{metric}: {comparison_data['improvement_percent']:.1f}% regression")
                success_criteria['performance_parity'] = False
                success_criteria['no_significant_regression'] = False
                
        # Evaluate overall migration success
        migration_success = all(success_criteria.values())
        
        comparison['migration_success_criteria'] = success_criteria
        comparison['migration_success'] = migration_success
        
        # Generate migration-specific recommendations
        if performance_regressions:
            comparison['recommendations'].extend([
                f"Address performance regressions: {', '.join(performance_regressions)}",
                "Review SQLAlchemy query optimization and indexing strategies",
                "Consider PostgreSQL-specific performance tuning"
            ])
        else:
            comparison['recommendations'].append(
                "Migration performance meets or exceeds MongoDB baseline requirements"
            )
            
        if not success_criteria['sub_100ms_compliance']:
            comparison['recommendations'].append(
                f"Optimize queries to meet sub-100ms requirement (current: {current_stats.get('mean_ms', 0):.1f}ms)"
            )
            
        return comparison


class DatabaseFixtureManager:
    """
    Database fixture management for comprehensive performance testing.
    
    This class provides utilities for setting up test data, managing database
    state, and creating realistic performance testing scenarios.
    """
    
    def __init__(self, db: SQLAlchemy):
        """Initialize database fixture manager."""
        self.db = db
        self.created_entities = []
        
    def create_test_users(self, count: int = 100) -> List[User]:
        """
        Create test users for database performance testing.
        
        Args:
            count: Number of test users to create
            
        Returns:
            List of created User instances
        """
        users = []
        for i in range(count):
            user = User(
                username=f"test_user_{i:04d}",
                email=f"user{i:04d}@performance-test.com",
                password_hash=f"hashed_password_{i}",
                is_active=random.choice([True, False])
            )
            self.db.session.add(user)
            users.append(user)
            
        self.db.session.commit()
        self.created_entities.extend(users)
        return users
        
    def create_test_business_entities(self, users: List[User], count: int = 500) -> List[BusinessEntity]:
        """
        Create test business entities for complex query testing.
        
        Args:
            users: List of users to assign as owners
            count: Number of business entities to create
            
        Returns:
            List of created BusinessEntity instances
        """
        entities = []
        statuses = ['active', 'inactive', 'pending', 'archived']
        
        for i in range(count):
            entity = BusinessEntity(
                name=f"Business Entity {i:04d}",
                description=f"Test business entity for performance testing {i}",
                owner=random.choice(users),
                status=random.choice(statuses)
            )
            self.db.session.add(entity)
            entities.append(entity)
            
        self.db.session.commit()
        self.created_entities.extend(entities)
        return entities
        
    def create_test_entity_relationships(self, entities: List[BusinessEntity], count: int = 1000) -> List[EntityRelationship]:
        """
        Create test entity relationships for complex JOIN testing.
        
        Args:
            entities: List of business entities to create relationships between
            count: Number of relationships to create
            
        Returns:
            List of created EntityRelationship instances
        """
        relationships = []
        relationship_types = ['parent_child', 'depends_on', 'related_to', 'part_of']
        
        for i in range(count):
            source_entity = random.choice(entities)
            target_entity = random.choice([e for e in entities if e.id != source_entity.id])
            
            relationship = EntityRelationship(
                source_entity=source_entity,
                target_entity=target_entity,
                relationship_type=random.choice(relationship_types),
                is_active=random.choice([True, False])
            )
            self.db.session.add(relationship)
            relationships.append(relationship)
            
        self.db.session.commit()
        self.created_entities.extend(relationships)
        return relationships
        
    def create_test_user_sessions(self, users: List[User], count: int = 200) -> List[UserSession]:
        """
        Create test user sessions for authentication performance testing.
        
        Args:
            users: List of users to create sessions for
            count: Number of sessions to create
            
        Returns:
            List of created UserSession instances
        """
        sessions = []
        
        for i in range(count):
            user = random.choice(users)
            session = UserSession(
                user=user,
                session_token=f"session_token_{i:04d}_{random.randint(1000, 9999)}",
                expires_at=datetime.now(timezone.utc) + timedelta(days=random.randint(1, 30)),
                is_valid=random.choice([True, False])
            )
            self.db.session.add(session)
            sessions.append(session)
            
        self.db.session.commit()
        self.created_entities.extend(sessions)
        return sessions
        
    def cleanup_test_data(self):
        """Clean up all created test data."""
        try:
            # Delete in reverse order to handle foreign key constraints
            for entity in reversed(self.created_entities):
                if entity in self.db.session:
                    self.db.session.delete(entity)
                    
            self.db.session.commit()
            self.created_entities.clear()
            
        except Exception as e:
            self.db.session.rollback()
            print(f"Error during cleanup: {e}")
            
    def get_test_data_summary(self) -> Dict[str, Any]:
        """Get summary of created test data for performance analysis."""
        entity_counts = {}
        for entity in self.created_entities:
            entity_type = type(entity).__name__
            entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1
            
        return {
            'total_entities': len(self.created_entities),
            'entity_breakdown': entity_counts,
            'database_size_estimate_mb': len(self.created_entities) * 0.001  # Rough estimate
        }


# Pytest test classes and fixtures
@pytest.mark.database_performance
@pytest.mark.performance
class TestDatabaseQueryBenchmarks:
    """
    Comprehensive database query performance benchmarking test class.
    
    This test class provides enterprise-grade database performance validation
    ensuring Flask-SQLAlchemy meets or exceeds MongoDB baseline performance
    while maintaining sub-100ms query response times per Section 4.11.1.
    """
    
    @pytest.fixture(scope="class")
    def benchmark_suite(self, flask_app_factory):
        """Initialize database benchmark suite for testing."""
        app = flask_app_factory
        
        with app.app_context():
            db = app.extensions.get('sqlalchemy')
            if not db:
                pytest.skip("SQLAlchemy not configured")
                
            suite = DatabaseQueryBenchmarkSuite(app, db)
            yield suite
            
    @pytest.fixture(scope="class")
    def fixture_manager(self, flask_app_factory):
        """Initialize database fixture manager for test data creation."""
        app = flask_app_factory
        
        with app.app_context():
            db = app.extensions.get('sqlalchemy')
            if not db:
                pytest.skip("SQLAlchemy not configured")
                
            manager = DatabaseFixtureManager(db)
            yield manager
            
            # Cleanup after all tests in class
            manager.cleanup_test_data()
            
    @pytest.fixture(scope="function")
    def test_data(self, fixture_manager):
        """Create comprehensive test data for database performance testing."""
        # Create test users
        users = fixture_manager.create_test_users(count=50)
        
        # Create business entities
        entities = fixture_manager.create_test_business_entities(users, count=200)
        
        # Create entity relationships
        relationships = fixture_manager.create_test_entity_relationships(entities, count=300)
        
        # Create user sessions
        sessions = fixture_manager.create_test_user_sessions(users, count=100)
        
        test_data = {
            'users': users,
            'entities': entities,
            'relationships': relationships,
            'sessions': sessions,
            'summary': fixture_manager.get_test_data_summary()
        }
        
        return test_data
        
    def test_simple_select_query_performance(self, benchmark, benchmark_suite, test_data):
        """
        Test simple SELECT query performance against sub-100ms threshold per Section 4.11.1.
        
        This test validates that basic user lookups meet performance requirements
        and establishes baseline performance metrics for simple queries.
        """
        benchmark_suite.reset_metrics()
        
        def execute_simple_select():
            """Execute simple user SELECT query."""
            with benchmark_suite.trace_query_performance("simple_select_user") as metrics:
                user = User.query.filter_by(username="test_user_0001").first()
                metrics.query_type = "SELECT"
                metrics.table_name = "user"
                metrics.row_count = 1 if user else 0
                return user
                
        # Benchmark the query execution
        result = benchmark(execute_simple_select)
        
        # Analyze performance results
        performance_summary = benchmark_suite.get_performance_summary()
        
        # Validate against thresholds per Section 4.11.1
        assert performance_summary['timing_statistics']['mean_ms'] <= 100.0, (
            f"Simple SELECT query mean time {performance_summary['timing_statistics']['mean_ms']:.2f}ms "
            f"exceeds 100ms threshold"
        )
        
        assert performance_summary['timing_statistics']['p95_ms'] <= 75.0, (
            f"Simple SELECT query 95th percentile {performance_summary['timing_statistics']['p95_ms']:.2f}ms "
            f"exceeds 75ms threshold"
        )
        
        # Validate query success
        assert performance_summary['successful_queries'] > 0, "No successful queries executed"
        assert performance_summary['failed_queries'] == 0, "Query failures detected"
        
        # Validate connection pool efficiency per Section 6.5.2.2
        pool_analysis = performance_summary['connection_pool_analysis']
        assert pool_analysis['meets_utilization_threshold'], (
            "Connection pool utilization exceeds threshold"
        )
        
        return performance_summary
        
    def test_complex_join_query_performance(self, benchmark, benchmark_suite, test_data):
        """
        Test complex JOIN query performance against sub-2000ms threshold per Section 6.2.5.1.
        
        This test validates that complex entity relationship queries with multiple
        JOINs meet performance requirements for business logic operations.
        """
        benchmark_suite.reset_metrics()
        
        def execute_complex_join():
            """Execute complex multi-table JOIN query."""
            with benchmark_suite.trace_query_performance("complex_join_query") as metrics:
                # Complex query joining users, entities, and relationships
                result = (
                    self.db.session.query(User, BusinessEntity, EntityRelationship)
                    .join(BusinessEntity, User.id == BusinessEntity.owner_id)
                    .join(EntityRelationship, BusinessEntity.id == EntityRelationship.source_entity_id)
                    .filter(User.is_active == True)
                    .filter(BusinessEntity.status == 'active')
                    .filter(EntityRelationship.is_active == True)
                    .limit(50)
                    .all()
                )
                
                metrics.query_type = "SELECT"
                metrics.table_name = "user_entity_relationship"
                metrics.row_count = len(result)
                return result
                
        # Benchmark the complex query execution
        result = benchmark(execute_complex_join)
        
        # Analyze performance results
        performance_summary = benchmark_suite.get_performance_summary()
        
        # Validate against complex query thresholds per Section 6.2.5.1
        assert performance_summary['timing_statistics']['mean_ms'] <= 2000.0, (
            f"Complex JOIN query mean time {performance_summary['timing_statistics']['mean_ms']:.2f}ms "
            f"exceeds 2000ms threshold"
        )
        
        assert performance_summary['timing_statistics']['p95_ms'] <= 1500.0, (
            f"Complex JOIN query 95th percentile {performance_summary['timing_statistics']['p95_ms']:.2f}ms "
            f"exceeds 1500ms threshold"
        )
        
        # Validate query optimization
        optimization_recommendations = performance_summary['optimization_recommendations']
        slow_query_detected = any('slow queries' in rec.lower() for rec in optimization_recommendations)
        
        if slow_query_detected:
            pytest.fail(f"Slow queries detected in complex JOIN operations: {optimization_recommendations}")
            
        return performance_summary
        
    def test_insert_operation_performance(self, benchmark, benchmark_suite, test_data):
        """
        Test INSERT operation performance against sub-300ms threshold per Section 4.11.1.
        
        This test validates that user creation operations meet performance
        requirements for write-heavy workloads.
        """
        benchmark_suite.reset_metrics()
        
        def execute_insert_operation():
            """Execute user INSERT operation."""
            with benchmark_suite.trace_query_performance("insert_user") as metrics:
                # Create new user with unique identifier
                timestamp = int(time.time() * 1000000)  # Microsecond timestamp
                new_user = User(
                    username=f"benchmark_user_{timestamp}",
                    email=f"benchmark{timestamp}@test.com",
                    password_hash=f"hash_{timestamp}",
                    is_active=True
                )
                
                benchmark_suite.db.session.add(new_user)
                benchmark_suite.db.session.commit()
                
                metrics.query_type = "INSERT"
                metrics.table_name = "user"
                metrics.row_count = 1
                
                # Clean up the test user
                benchmark_suite.db.session.delete(new_user)
                benchmark_suite.db.session.commit()
                
                return new_user.id
                
        # Benchmark the INSERT operation
        result = benchmark(execute_insert_operation)
        
        # Analyze performance results
        performance_summary = benchmark_suite.get_performance_summary()
        
        # Validate against INSERT thresholds per Section 4.11.1
        insert_queries = [m for m in benchmark_suite.query_metrics if m.query_type == "INSERT"]
        if insert_queries:
            insert_times = [m.execution_time_ms for m in insert_queries]
            mean_insert_time = statistics.mean(insert_times)
            
            assert mean_insert_time <= 300.0, (
                f"INSERT operation mean time {mean_insert_time:.2f}ms exceeds 300ms threshold"
            )
            
        # Validate transaction integrity
        assert performance_summary['failed_queries'] == 0, "INSERT operation failures detected"
        
        # Validate memory efficiency
        memory_analysis = performance_summary['memory_analysis']
        if 'memory_leak_indicators' in memory_analysis:
            assert len(memory_analysis['memory_leak_indicators']) == 0, (
                f"Memory leak indicators detected: {memory_analysis['memory_leak_indicators']}"
            )
            
        return performance_summary
        
    def test_update_operation_performance(self, benchmark, benchmark_suite, test_data):
        """
        Test UPDATE operation performance against sub-300ms threshold per Section 4.11.1.
        
        This test validates that user modification operations meet performance
        requirements for data update workloads.
        """
        benchmark_suite.reset_metrics()
        
        # Get a test user to update
        test_user = test_data['users'][0]
        original_email = test_user.email
        
        def execute_update_operation():
            """Execute user UPDATE operation."""
            with benchmark_suite.trace_query_performance("update_user") as metrics:
                # Update user email
                timestamp = int(time.time() * 1000000)
                test_user.email = f"updated_{timestamp}@test.com"
                
                benchmark_suite.db.session.commit()
                
                metrics.query_type = "UPDATE"
                metrics.table_name = "user"
                metrics.row_count = 1
                
                # Reset email to original value
                test_user.email = original_email
                benchmark_suite.db.session.commit()
                
                return test_user.id
                
        # Benchmark the UPDATE operation
        result = benchmark(execute_update_operation)
        
        # Analyze performance results
        performance_summary = benchmark_suite.get_performance_summary()
        
        # Validate against UPDATE thresholds per Section 4.11.1
        update_queries = [m for m in benchmark_suite.query_metrics if m.query_type == "UPDATE"]
        if update_queries:
            update_times = [m.execution_time_ms for m in update_queries]
            mean_update_time = statistics.mean(update_times)
            
            assert mean_update_time <= 300.0, (
                f"UPDATE operation mean time {mean_update_time:.2f}ms exceeds 300ms threshold"
            )
            
        # Validate query success
        assert performance_summary['successful_queries'] > 0, "No successful UPDATE queries executed"
        
        return performance_summary
        
    def test_delete_operation_performance(self, benchmark, benchmark_suite, test_data):
        """
        Test DELETE operation performance against sub-300ms threshold per Section 4.11.1.
        
        This test validates that entity deletion operations meet performance
        requirements for data cleanup workloads.
        """
        benchmark_suite.reset_metrics()
        
        def execute_delete_operation():
            """Execute entity DELETE operation."""
            with benchmark_suite.trace_query_performance("delete_entity") as metrics:
                # Create a temporary entity to delete
                timestamp = int(time.time() * 1000000)
                temp_entity = BusinessEntity(
                    name=f"temp_entity_{timestamp}",
                    description="Temporary entity for delete testing",
                    owner=test_data['users'][0],
                    status='temporary'
                )
                
                benchmark_suite.db.session.add(temp_entity)
                benchmark_suite.db.session.commit()
                entity_id = temp_entity.id
                
                # Delete the entity
                benchmark_suite.db.session.delete(temp_entity)
                benchmark_suite.db.session.commit()
                
                metrics.query_type = "DELETE"
                metrics.table_name = "business_entity"
                metrics.row_count = 1
                
                return entity_id
                
        # Benchmark the DELETE operation
        result = benchmark(execute_delete_operation)
        
        # Analyze performance results
        performance_summary = benchmark_suite.get_performance_summary()
        
        # Validate against DELETE thresholds per Section 4.11.1
        delete_queries = [m for m in benchmark_suite.query_metrics if m.query_type == "DELETE"]
        if delete_queries:
            delete_times = [m.execution_time_ms for m in delete_queries]
            mean_delete_time = statistics.mean(delete_times)
            
            assert mean_delete_time <= 300.0, (
                f"DELETE operation mean time {mean_delete_time:.2f}ms exceeds 300ms threshold"
            )
            
        # Validate referential integrity maintenance
        assert performance_summary['failed_queries'] == 0, "DELETE operation failures detected"
        
        return performance_summary
        
    def test_batch_operation_performance(self, benchmark, benchmark_suite, test_data):
        """
        Test batch operation performance against sub-5000ms threshold per Section 4.11.1.
        
        This test validates that bulk data operations meet performance requirements
        for large-scale data processing workloads.
        """
        benchmark_suite.reset_metrics()
        
        def execute_batch_operation():
            """Execute batch entity creation operation."""
            with benchmark_suite.trace_query_performance("batch_insert_entities") as metrics:
                # Create batch of entities
                batch_size = 50
                batch_entities = []
                
                for i in range(batch_size):
                    timestamp = int(time.time() * 1000000)
                    entity = BusinessEntity(
                        name=f"batch_entity_{timestamp}_{i}",
                        description=f"Batch entity {i} for performance testing",
                        owner=random.choice(test_data['users']),
                        status='batch_created'
                    )
                    batch_entities.append(entity)
                    benchmark_suite.db.session.add(entity)
                    
                benchmark_suite.db.session.commit()
                
                # Clean up batch entities
                for entity in batch_entities:
                    benchmark_suite.db.session.delete(entity)
                benchmark_suite.db.session.commit()
                
                metrics.query_type = "BATCH_INSERT"
                metrics.table_name = "business_entity"
                metrics.row_count = batch_size
                
                return len(batch_entities)
                
        # Benchmark the batch operation
        result = benchmark(execute_batch_operation)
        
        # Analyze performance results
        performance_summary = benchmark_suite.get_performance_summary()
        
        # Validate against batch operation thresholds per Section 4.11.1
        assert performance_summary['timing_statistics']['mean_ms'] <= 5000.0, (
            f"Batch operation mean time {performance_summary['timing_statistics']['mean_ms']:.2f}ms "
            f"exceeds 5000ms threshold"
        )
        
        # Validate batch efficiency
        connection_pool_analysis = performance_summary['connection_pool_analysis']
        assert connection_pool_analysis['meets_utilization_threshold'], (
            "Batch operation exceeded connection pool utilization threshold"
        )
        
        return performance_summary
        
    def test_connection_pool_efficiency(self, benchmark, benchmark_suite, test_data):
        """
        Test connection pool utilization and efficiency per Section 6.5.2.2.
        
        This test validates that database connection pooling operates efficiently
        under concurrent load with optimal resource utilization.
        """
        benchmark_suite.reset_metrics()
        
        def execute_concurrent_queries():
            """Execute multiple concurrent queries to test connection pooling."""
            def query_worker():
                """Worker function for concurrent query execution."""
                with benchmark_suite.trace_query_performance("concurrent_query") as metrics:
                    # Execute a mix of query types
                    user_count = User.query.count()
                    entity_count = BusinessEntity.query.filter_by(status='active').count()
                    session_count = UserSession.query.filter_by(is_valid=True).count()
                    
                    metrics.query_type = "SELECT"
                    metrics.table_name = "mixed_queries"
                    metrics.row_count = user_count + entity_count + session_count
                    
                    return user_count, entity_count, session_count
                    
            # Execute concurrent queries using threading
            threads = []
            results = []
            concurrent_count = 10
            
            def thread_worker():
                try:
                    result = query_worker()
                    results.append(result)
                except Exception as e:
                    results.append(f"Error: {e}")
                    
            # Start concurrent threads
            for _ in range(concurrent_count):
                thread = threading.Thread(target=thread_worker)
                threads.append(thread)
                thread.start()
                
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
                
            return results
            
        # Benchmark concurrent query execution
        result = benchmark(execute_concurrent_queries)
        
        # Analyze connection pool performance
        performance_summary = benchmark_suite.get_performance_summary()
        connection_pool_analysis = performance_summary['connection_pool_analysis']
        
        # Validate connection pool efficiency per Section 6.5.2.2
        assert connection_pool_analysis['meets_utilization_threshold'], (
            f"Connection pool utilization exceeds threshold: "
            f"{connection_pool_analysis.get('current_utilization_percent', 0):.1f}%"
        )
        
        assert connection_pool_analysis['meets_efficiency_threshold'], (
            f"Connection pool efficiency below threshold: "
            f"{connection_pool_analysis.get('checkout_efficiency', 0):.1%}"
        )
        
        # Validate concurrent query performance
        assert performance_summary['timing_statistics']['mean_ms'] <= 200.0, (
            f"Concurrent query mean time {performance_summary['timing_statistics']['mean_ms']:.2f}ms "
            f"exceeds 200ms threshold under concurrent load"
        )
        
        # Validate no connection errors
        assert performance_summary['connection_errors'] == 0, (
            f"Connection errors detected during concurrent execution: {performance_summary['connection_errors']}"
        )
        
        return performance_summary
        
    def test_memory_efficiency_during_queries(self, benchmark, benchmark_suite, test_data):
        """
        Test memory efficiency during database operations per Section 6.5.2.2.
        
        This test validates that database queries maintain efficient memory usage
        without memory leaks or excessive memory growth patterns.
        """
        benchmark_suite.reset_metrics()
        
        def execute_memory_intensive_queries():
            """Execute queries that potentially consume significant memory."""
            with benchmark_suite.trace_query_performance("memory_intensive_queries") as metrics:
                # Execute large result set query
                all_entities = BusinessEntity.query.limit(100).all()
                
                # Execute aggregation query
                entity_counts = (
                    benchmark_suite.db.session.query(
                        BusinessEntity.status,
                        func.count(BusinessEntity.id).label('count')
                    )
                    .group_by(BusinessEntity.status)
                    .all()
                )
                
                # Execute relationship query with eager loading
                users_with_entities = (
                    User.query
                    .join(BusinessEntity)
                    .options(db.joinedload(User.business_entities))
                    .limit(20)
                    .all()
                )
                
                metrics.query_type = "SELECT"
                metrics.table_name = "memory_test"
                metrics.row_count = len(all_entities) + len(entity_counts) + len(users_with_entities)
                
                return len(all_entities), len(entity_counts), len(users_with_entities)
                
        # Benchmark memory-intensive queries
        result = benchmark(execute_memory_intensive_queries)
        
        # Analyze memory usage patterns
        performance_summary = benchmark_suite.get_performance_summary()
        memory_analysis = performance_summary['memory_analysis']
        
        # Validate memory efficiency
        if 'total_memory_delta_mb' in memory_analysis:
            total_memory_delta = memory_analysis['total_memory_delta_mb']
            assert total_memory_delta <= 100.0, (
                f"Excessive memory growth detected: {total_memory_delta:.1f}MB. "
                "Consider query optimization or result streaming."
            )
            
        # Check for memory leak indicators
        if 'memory_leak_indicators' in memory_analysis:
            leak_indicators = memory_analysis['memory_leak_indicators']
            assert len(leak_indicators) == 0, (
                f"Memory leak indicators detected: {leak_indicators}"
            )
            
        # Validate query performance under memory constraints
        assert performance_summary['timing_statistics']['mean_ms'] <= 300.0, (
            f"Memory-intensive query mean time {performance_summary['timing_statistics']['mean_ms']:.2f}ms "
            f"exceeds 300ms threshold"
        )
        
        return performance_summary
        
    def test_mongodb_baseline_comparison(self, benchmark, benchmark_suite, test_data, baseline_data):
        """
        Test Flask-SQLAlchemy performance against MongoDB baseline per Section 0.2.1.
        
        This test validates that the migration from MongoDB to PostgreSQL with
        Flask-SQLAlchemy meets or exceeds original system performance requirements.
        """
        benchmark_suite.reset_metrics()
        
        # Execute comprehensive query suite for baseline comparison
        def execute_baseline_comparison_queries():
            """Execute queries representative of original MongoDB operations."""
            query_results = {}
            
            # User lookup (equivalent to MongoDB findOne)
            with benchmark_suite.trace_query_performance("user_lookup") as metrics:
                user = User.query.filter_by(username="test_user_0001").first()
                query_results['user_lookup'] = user.id if user else None
                
            # Entity search (equivalent to MongoDB find with filter)
            with benchmark_suite.trace_query_performance("entity_search") as metrics:
                entities = BusinessEntity.query.filter_by(status='active').limit(10).all()
                query_results['entity_search'] = len(entities)
                
            # Relationship aggregation (equivalent to MongoDB aggregation pipeline)
            with benchmark_suite.trace_query_performance("relationship_aggregation") as metrics:
                relationship_counts = (
                    benchmark_suite.db.session.query(
                        EntityRelationship.relationship_type,
                        func.count(EntityRelationship.id).label('count')
                    )
                    .filter_by(is_active=True)
                    .group_by(EntityRelationship.relationship_type)
                    .all()
                )
                query_results['relationship_aggregation'] = len(relationship_counts)
                
            # Session validation (equivalent to MongoDB session lookup)
            with benchmark_suite.trace_query_performance("session_validation") as metrics:
                active_sessions = UserSession.query.filter_by(is_valid=True).count()
                query_results['session_validation'] = active_sessions
                
            return query_results
            
        # Benchmark baseline comparison queries
        result = benchmark(execute_baseline_comparison_queries)
        
        # Get performance summary
        performance_summary = benchmark_suite.get_performance_summary()
        
        # Simulate MongoDB baseline metrics (in production, these would be real baseline data)
        mongodb_baseline = {
            'mean_ms': 85.0,      # MongoDB average query time
            'median_ms': 70.0,    # MongoDB median query time
            'p95_ms': 120.0,      # MongoDB 95th percentile
            'max_ms': 200.0       # MongoDB maximum query time
        }
        
        # Compare with MongoDB baseline
        comparison_result = benchmark_suite.compare_with_mongodb_baseline(mongodb_baseline)
        
        # Validate migration success criteria per Section 0.2.1
        assert comparison_result['migration_success'], (
            f"Migration validation failed: {comparison_result['migration_success_criteria']}"
        )
        
        # Validate performance parity
        performance_comparison = comparison_result['performance_comparison']
        
        for metric, comparison_data in performance_comparison.items():
            assert comparison_data['within_tolerance'], (
                f"Performance metric {metric} outside tolerance: "
                f"{comparison_data['improvement_percent']:.1f}% change"
            )
            
        # Validate sub-100ms compliance per Section 4.11.1
        current_mean = performance_summary['timing_statistics']['mean_ms']
        assert current_mean <= 100.0, (
            f"Flask-SQLAlchemy mean query time {current_mean:.2f}ms exceeds 100ms requirement"
        )
        
        # Log successful migration validation
        print(f"Migration validation successful:")
        print(f"  Flask-SQLAlchemy mean time: {current_mean:.2f}ms")
        print(f"  MongoDB baseline mean time: {mongodb_baseline['mean_ms']:.2f}ms")
        print(f"  Performance improvement: {comparison_result['performance_comparison'].get('mean_ms', {}).get('improvement_percent', 0):.1f}%")
        
        return comparison_result
        
    def test_query_optimization_detection(self, benchmark, benchmark_suite, test_data):
        """
        Test automated query optimization detection and recommendations per Section 4.7.1.
        
        This test validates that the system can automatically detect and recommend
        query optimization opportunities for improved database performance.
        """
        benchmark_suite.reset_metrics()
        
        def execute_suboptimal_queries():
            """Execute potentially suboptimal queries to test optimization detection."""
            optimization_results = {}
            
            # N+1 query pattern simulation
            with benchmark_suite.trace_query_performance("n_plus_one_simulation") as metrics:
                users = User.query.limit(10).all()
                entity_counts = []
                
                # This creates N+1 queries (1 for users, N for each user's entities)
                for user in users:
                    count = BusinessEntity.query.filter_by(owner_id=user.id).count()
                    entity_counts.append(count)
                    
                optimization_results['n_plus_one'] = sum(entity_counts)
                
            # Large result set without pagination
            with benchmark_suite.trace_query_performance("large_result_set") as metrics:
                # Query large result set without LIMIT
                all_relationships = EntityRelationship.query.all()
                optimization_results['large_result_set'] = len(all_relationships)
                
            # Complex query without proper indexing hints
            with benchmark_suite.trace_query_performance("complex_unoptimized") as metrics:
                # Complex query that could benefit from optimization
                complex_result = (
                    benchmark_suite.db.session.query(User, BusinessEntity, EntityRelationship)
                    .select_from(User)
                    .join(BusinessEntity, User.id == BusinessEntity.owner_id)
                    .join(EntityRelationship, BusinessEntity.id == EntityRelationship.source_entity_id)
                    .filter(User.email.like('%test%'))
                    .filter(BusinessEntity.description.like('%performance%'))
                    .all()
                )
                optimization_results['complex_unoptimized'] = len(complex_result)
                
            return optimization_results
            
        # Benchmark suboptimal query execution
        result = benchmark(execute_suboptimal_queries)
        
        # Analyze optimization opportunities
        performance_summary = benchmark_suite.get_performance_summary()
        optimization_recommendations = performance_summary['optimization_recommendations']
        
        # Validate optimization detection
        n_plus_one_detected = any('N+1' in rec or 'eager loading' in rec for rec in optimization_recommendations)
        slow_query_detected = any('slow queries' in rec.lower() for rec in optimization_recommendations)
        
        # The test should detect optimization opportunities
        assert len(optimization_recommendations) > 1, (
            f"Expected multiple optimization recommendations, got: {optimization_recommendations}"
        )
        
        # Validate specific optimization detections
        if benchmark_suite.slow_query_counter > 0:
            assert slow_query_detected, (
                "Slow queries detected but not included in optimization recommendations"
            )
            
        # Validate threshold compliance analysis
        threshold_compliance = performance_summary['threshold_compliance']
        if not threshold_compliance['overall_compliance']:
            print(f"Performance thresholds not met:")
            print(f"  Mean time: {threshold_compliance['mean_time_ms']:.2f}ms")
            print(f"  Max time: {threshold_compliance['max_time_ms']:.2f}ms")
            print(f"  P95 time: {threshold_compliance['p95_time_ms']:.2f}ms")
            print(f"Optimization recommendations: {optimization_recommendations}")
            
        return performance_summary
        
    def test_connection_pool_scaling_performance(self, benchmark, benchmark_suite, test_data):
        """
        Test connection pool scaling under varying load conditions per Section 6.5.2.5.
        
        This test validates that connection pool configuration automatically adapts
        to different load patterns while maintaining optimal performance.
        """
        benchmark_suite.reset_metrics()
        
        def execute_scaling_load_test():
            """Execute queries with varying concurrency levels."""
            scaling_results = {}
            
            # Test different concurrency levels
            concurrency_levels = [1, 5, 10, 15]
            
            for concurrency in concurrency_levels:
                level_start_time = time.perf_counter()
                
                def concurrent_worker():
                    """Worker function for concurrent query execution."""
                    with benchmark_suite.trace_query_performance(f"scaling_query_c{concurrency}") as metrics:
                        # Execute a representative query
                        entities = (
                            BusinessEntity.query
                            .join(User)
                            .filter(User.is_active == True)
                            .limit(5)
                            .all()
                        )
                        
                        metrics.query_type = "SELECT"
                        metrics.table_name = "scaling_test"
                        metrics.row_count = len(entities)
                        
                        return len(entities)
                        
                # Execute concurrent queries
                threads = []
                thread_results = []
                
                for _ in range(concurrency):
                    def thread_wrapper():
                        try:
                            result = concurrent_worker()
                            thread_results.append(result)
                        except Exception as e:
                            thread_results.append(f"Error: {e}")
                            
                    thread = threading.Thread(target=thread_wrapper)
                    threads.append(thread)
                    thread.start()
                    
                # Wait for completion
                for thread in threads:
                    thread.join()
                    
                level_duration = time.perf_counter() - level_start_time
                
                scaling_results[f'concurrency_{concurrency}'] = {
                    'duration_ms': level_duration * 1000,
                    'successful_operations': len([r for r in thread_results if isinstance(r, int)]),
                    'failed_operations': len([r for r in thread_results if isinstance(r, str)]),
                    'throughput_ops_per_sec': concurrency / level_duration if level_duration > 0 else 0
                }
                
            return scaling_results
            
        # Benchmark scaling performance
        result = benchmark(execute_scaling_load_test)
        
        # Analyze scaling performance
        performance_summary = benchmark_suite.get_performance_summary()
        connection_pool_analysis = performance_summary['connection_pool_analysis']
        
        # Validate connection pool scaling efficiency
        assert connection_pool_analysis['meets_utilization_threshold'], (
            f"Connection pool utilization failed under scaling load: "
            f"{connection_pool_analysis.get('current_utilization_percent', 0):.1f}%"
        )
        
        # Validate no connection errors during scaling
        assert performance_summary['connection_errors'] == 0, (
            f"Connection errors detected during scaling test: {performance_summary['connection_errors']}"
        )
        
        # Validate throughput maintains reasonable levels
        throughput_results = []
        for concurrency_level, results in result.items():
            if isinstance(results, dict) and 'throughput_ops_per_sec' in results:
                throughput_results.append(results['throughput_ops_per_sec'])
                
        if throughput_results:
            min_throughput = min(throughput_results)
            assert min_throughput > 1.0, (
                f"Minimum throughput {min_throughput:.2f} ops/sec too low for production use"
            )
            
        # Validate response time consistency across load levels
        assert performance_summary['timing_statistics']['max_ms'] <= 500.0, (
            f"Maximum response time {performance_summary['timing_statistics']['max_ms']:.2f}ms "
            f"exceeds acceptable threshold under scaling load"
        )
        
        return performance_summary
        
    def test_opentelemetry_database_instrumentation(self, benchmark, benchmark_suite, test_data):
        """
        Test OpenTelemetry database instrumentation integration per Section 6.5.1.3.
        
        This test validates that OpenTelemetry instrumentation correctly captures
        database operation metrics without significant performance overhead.
        """
        benchmark_suite.reset_metrics()
        
        def execute_instrumented_queries():
            """Execute queries with full OpenTelemetry instrumentation."""
            instrumentation_results = {}
            
            # Execute queries with manual span creation
            with benchmark_suite.tracer.start_as_current_span("manual_instrumented_query") as span:
                span.set_attribute("db.system", "postgresql")
                span.set_attribute("db.operation", "select")
                
                with benchmark_suite.trace_query_performance("instrumented_user_query") as metrics:
                    users = User.query.filter(User.is_active == True).limit(10).all()
                    
                    metrics.query_type = "SELECT"
                    metrics.table_name = "user"
                    metrics.row_count = len(users)
                    
                    span.set_attribute("db.rows_affected", len(users))
                    instrumentation_results['user_query'] = len(users)
                    
            # Execute complex query with instrumentation
            with benchmark_suite.tracer.start_as_current_span("complex_instrumented_query") as span:
                span.set_attribute("db.system", "postgresql")
                span.set_attribute("db.operation", "select_join")
                
                with benchmark_suite.trace_query_performance("instrumented_join_query") as metrics:
                    complex_result = (
                        benchmark_suite.db.session.query(User, BusinessEntity)
                        .join(BusinessEntity)
                        .filter(BusinessEntity.status == 'active')
                        .limit(20)
                        .all()
                    )
                    
                    metrics.query_type = "SELECT"
                    metrics.table_name = "user_business_entity"
                    metrics.row_count = len(complex_result)
                    
                    span.set_attribute("db.rows_affected", len(complex_result))
                    instrumentation_results['join_query'] = len(complex_result)
                    
            return instrumentation_results
            
        # Benchmark instrumented query execution
        result = benchmark(execute_instrumented_queries)
        
        # Analyze instrumentation overhead
        performance_summary = benchmark_suite.get_performance_summary()
        
        # Validate trace information is captured
        instrumented_queries = [m for m in benchmark_suite.query_metrics if m.trace_id]
        assert len(instrumented_queries) > 0, "No trace information captured in query metrics"
        
        # Validate instrumentation overhead is minimal
        mean_time = performance_summary['timing_statistics']['mean_ms']
        instrumentation_overhead_threshold = 150.0  # 50% overhead allowance
        
        assert mean_time <= instrumentation_overhead_threshold, (
            f"OpenTelemetry instrumentation overhead too high: {mean_time:.2f}ms mean time"
        )
        
        # Validate trace correlation
        unique_trace_ids = set(m.trace_id for m in instrumented_queries if m.trace_id)
        assert len(unique_trace_ids) > 0, "No unique trace IDs found in instrumented queries"
        
        # Validate span attributes are set correctly
        queries_with_span_ids = [m for m in instrumented_queries if m.span_id]
        assert len(queries_with_span_ids) > 0, "No span IDs captured in query metrics"
        
        # Check that performance is still within acceptable bounds
        threshold_compliance = performance_summary['threshold_compliance']
        assert threshold_compliance['meets_simple_query_mean_threshold'], (
            f"Instrumented queries exceed performance thresholds: {mean_time:.2f}ms mean time"
        )
        
        return performance_summary


# Additional utility functions for test integration
def create_mongodb_baseline_data() -> Dict[str, Any]:
    """
    Create simulated MongoDB baseline data for comparison testing.
    
    In production, this would be replaced with actual MongoDB performance
    metrics collected from the original system per Section 0.2.1.
    
    Returns:
        Dictionary containing MongoDB baseline performance metrics
    """
    return {
        'user_lookup': [45.2, 52.1, 48.7, 50.3, 46.8],  # milliseconds
        'entity_search': [78.5, 85.2, 82.1, 79.8, 81.3],
        'relationship_aggregation': [156.7, 142.3, 148.9, 151.2, 147.6],
        'session_validation': [28.4, 31.2, 29.8, 30.1, 27.9],
        'batch_operations': [2847.3, 2921.8, 2889.2, 2856.7, 2903.1],
        'complex_joins': [1247.8, 1189.3, 1223.6, 1256.2, 1198.7]
    }


def generate_performance_report(test_results: List[Dict[str, Any]], 
                              output_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Generate comprehensive database performance test report.
    
    Args:
        test_results: List of test result dictionaries
        output_path: Optional path to save the report
        
    Returns:
        Comprehensive performance report
    """
    report = {
        'report_metadata': {
            'generation_timestamp': datetime.now(timezone.utc).isoformat(),
            'test_count': len(test_results),
            'report_version': '1.0.0'
        },
        'executive_summary': {},
        'performance_analysis': {},
        'migration_validation': {},
        'optimization_recommendations': [],
        'detailed_results': test_results
    }
    
    # Analyze overall performance
    all_response_times = []
    successful_tests = 0
    failed_tests = 0
    
    for result in test_results:
        if 'timing_statistics' in result:
            all_response_times.append(result['timing_statistics']['mean_ms'])
            successful_tests += 1
        else:
            failed_tests += 1
            
    if all_response_times:
        report['executive_summary'] = {
            'total_tests': len(test_results),
            'successful_tests': successful_tests,
            'failed_tests': failed_tests,
            'overall_mean_response_ms': statistics.mean(all_response_times),
            'overall_p95_response_ms': DatabaseQueryBenchmarkSuite._calculate_percentile(
                None, all_response_times, 95
            ),
            'sub_100ms_compliance': all(t <= 100.0 for t in all_response_times),
            'performance_grade': 'PASS' if all(t <= 100.0 for t in all_response_times) else 'FAIL'
        }
        
    # Generate migration validation summary
    migration_successes = sum(1 for r in test_results if r.get('migration_success', False))
    
    report['migration_validation'] = {
        'migration_tests_passed': migration_successes,
        'migration_tests_total': len([r for r in test_results if 'migration_success' in r]),
        'migration_success_rate': migration_successes / max(1, len(test_results)),
        'baseline_comparison_available': any('baseline_comparison' in r for r in test_results)
    }
    
    # Save report if path provided
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
            
    return report


# Export key components for test execution
__all__ = [
    'DatabasePerformanceThresholds',
    'QueryPerformanceMetrics',
    'DatabaseQueryBenchmarkSuite',
    'DatabaseFixtureManager',
    'TestDatabaseQueryBenchmarks',
    'create_mongodb_baseline_data',
    'generate_performance_report'
]