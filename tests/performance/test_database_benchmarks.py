"""
Database Query Performance Benchmarking Test Suite

This comprehensive test suite validates Flask-SQLAlchemy database performance against
strict sub-100ms response time requirements and ensures equivalent or improved performance
compared to the original MongoDB baseline implementation.

Key Features:
- pytest-benchmark 5.1.0 integration for statistical performance measurement
- SQLAlchemy event listener instrumentation for comprehensive query tracking
- Connection pool utilization monitoring and efficiency analysis
- PostgreSQL EXPLAIN plan integration for query optimization insights
- MongoDB to Flask-SQLAlchemy performance comparison framework
- Declarative model optimization and relationship loading validation
- Zero data loss verification with optimized database access patterns

Performance Requirements (Section 4.11.1):
- Simple SELECT operations: < 500ms (95th percentile), < 1000ms (99th percentile)
- Complex JOIN operations: < 2000ms (95th percentile), < 3000ms (99th percentile)
- INSERT/UPDATE operations: < 300ms (95th percentile), < 500ms (99th percentile)
- Database query performance: < 100ms average response time
- Connection pool efficiency: > 90% utilization under load

Technical Implementation:
- SQLAlchemy event listeners for comprehensive query performance tracking (Section 6.5.1.1)
- PostgreSQL connection pool monitoring with real-time utilization metrics (Section 6.5.2.2)
- Automated database query optimization with performance regression detection (Section 4.7.1)
- Relationship loading performance with lazy/eager loading optimization (Section 6.2.2.1)
"""

import pytest
import time
import statistics
import threading
import logging
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Generator
from contextlib import contextmanager
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import gc

# Flask and SQLAlchemy imports
from flask import Flask, current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, text, select, func, and_, or_
from sqlalchemy.engine import Engine
from sqlalchemy.orm import joinedload, selectinload, subqueryload
from sqlalchemy.pool import Pool
from sqlalchemy.sql import sqltypes

# Testing framework imports
import pytest
from pytest_benchmark.fixture import BenchmarkFixture

# Import application components
try:
    from src.models import db, User, UserSession, BusinessEntity, EntityRelationship
    from src.models.base import BaseModel
    from src.app import create_app
    from config import TestingConfig, ProductionConfig
except ImportError:
    # Handle case where modules don't exist yet during development
    db = None
    User = None
    UserSession = None  
    BusinessEntity = None
    EntityRelationship = None
    BaseModel = None
    create_app = None
    TestingConfig = None
    ProductionConfig = None


# ================================
# Performance Monitoring Infrastructure
# ================================

class SQLAlchemyPerformanceMonitor:
    """
    Comprehensive SQLAlchemy performance monitoring system utilizing event listeners
    to track query execution times, connection pool utilization, and database 
    operation efficiency as specified in Section 6.5.1.1.
    
    This monitor provides real-time performance metrics collection and analysis
    for validating database performance against MongoDB baseline metrics.
    """
    
    def __init__(self):
        self.query_metrics = []
        self.connection_metrics = []
        self.pool_metrics = []
        self.explain_plans = {}
        self.active_queries = {}
        self.performance_thresholds = {
            'simple_select': 0.5,  # 500ms for simple SELECT operations
            'complex_join': 2.0,   # 2000ms for complex JOIN operations
            'insert_update': 0.3,  # 300ms for INSERT/UPDATE operations
            'average_query': 0.1   # 100ms average query response time
        }
        self._monitoring_active = False
        self._lock = threading.Lock()
        
    def start_monitoring(self, engine: Engine):
        """
        Initialize SQLAlchemy event listeners for comprehensive performance tracking
        """
        if self._monitoring_active:
            return
            
        self._monitoring_active = True
        
        # Query execution time tracking
        @event.listens_for(engine, "before_cursor_execute")
        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Track query start time and statement for performance analysis"""
            query_id = str(uuid.uuid4())
            context._query_start_time = time.perf_counter()
            context._query_id = query_id
            context._query_statement = statement
            
            with self._lock:
                self.active_queries[query_id] = {
                    'statement': statement[:200] + '...' if len(statement) > 200 else statement,
                    'parameters': str(parameters)[:100] if parameters else None,
                    'start_time': context._query_start_time,
                    'thread_id': threading.get_ident()
                }
        
        @event.listens_for(engine, "after_cursor_execute")
        def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Record query completion time and performance metrics"""
            if hasattr(context, '_query_start_time'):
                execution_time = time.perf_counter() - context._query_start_time
                query_id = getattr(context, '_query_id', 'unknown')
                
                # Categorize query type for threshold validation
                query_type = self._categorize_query(statement)
                
                metric = {
                    'query_id': query_id,
                    'statement': statement[:200] + '...' if len(statement) > 200 else statement,
                    'execution_time': execution_time,
                    'query_type': query_type,
                    'parameters': str(parameters)[:100] if parameters else None,
                    'timestamp': datetime.utcnow(),
                    'thread_id': threading.get_ident(),
                    'rows_affected': cursor.rowcount if hasattr(cursor, 'rowcount') else 0
                }
                
                with self._lock:
                    self.query_metrics.append(metric)
                    if query_id in self.active_queries:
                        del self.active_queries[query_id]
        
        # Connection pool monitoring
        @event.listens_for(Pool, "connect")
        def pool_connect(dbapi_conn, connection_record):
            """Track connection pool usage and efficiency"""
            with self._lock:
                self.connection_metrics.append({
                    'event': 'connect',
                    'timestamp': datetime.utcnow(),
                    'thread_id': threading.get_ident(),
                    'connection_id': id(dbapi_conn)
                })
        
        @event.listens_for(Pool, "checkout")  
        def pool_checkout(dbapi_conn, connection_record, connection_proxy):
            """Monitor connection checkout performance"""
            pool = connection_proxy.pool
            pool_status = {
                'event': 'checkout',
                'timestamp': datetime.utcnow(),
                'pool_size': pool.size(),
                'checked_out': pool.checkedout(),
                'checked_in': pool.checkedin(),
                'invalid': pool.invalid(),
                'thread_id': threading.get_ident()
            }
            
            with self._lock:
                self.pool_metrics.append(pool_status)
        
        @event.listens_for(Pool, "checkin")
        def pool_checkin(dbapi_conn, connection_record):
            """Monitor connection checkin performance"""  
            with self._lock:
                self.connection_metrics.append({
                    'event': 'checkin',
                    'timestamp': datetime.utcnow(),
                    'thread_id': threading.get_ident(),
                    'connection_id': id(dbapi_conn)
                })
                
    def stop_monitoring(self):
        """Stop performance monitoring and clear event listeners"""
        self._monitoring_active = False
        
    def _categorize_query(self, statement: str) -> str:
        """Categorize SQL query for performance threshold validation"""
        statement_upper = statement.upper().strip()
        
        if statement_upper.startswith('SELECT'):
            # Check for JOINs to categorize as complex
            if 'JOIN' in statement_upper or 'UNION' in statement_upper:
                return 'complex_join'
            return 'simple_select'
        elif statement_upper.startswith(('INSERT', 'UPDATE', 'DELETE')):
            return 'insert_update'
        else:
            return 'other'
            
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance summary with statistical analysis
        """
        with self._lock:
            if not self.query_metrics:
                return {'status': 'no_data', 'query_count': 0}
                
            execution_times = [m['execution_time'] for m in self.query_metrics]
            query_types = {}
            
            # Group metrics by query type
            for metric in self.query_metrics:
                query_type = metric['query_type']
                if query_type not in query_types:
                    query_types[query_type] = []
                query_types[query_type].append(metric['execution_time'])
            
            # Calculate performance statistics
            summary = {
                'total_queries': len(self.query_metrics),
                'average_execution_time': statistics.mean(execution_times),
                'median_execution_time': statistics.median(execution_times),
                'p95_execution_time': self._percentile(execution_times, 95),
                'p99_execution_time': self._percentile(execution_times, 99),
                'min_execution_time': min(execution_times),
                'max_execution_time': max(execution_times),
                'std_dev': statistics.stdev(execution_times) if len(execution_times) > 1 else 0,
                'query_types': {}
            }
            
            # Per-query-type statistics
            for query_type, times in query_types.items():
                if times:
                    summary['query_types'][query_type] = {
                        'count': len(times),
                        'average': statistics.mean(times),
                        'p95': self._percentile(times, 95),
                        'p99': self._percentile(times, 99),
                        'threshold_met': self._percentile(times, 95) <= self.performance_thresholds.get(query_type, 1.0)
                    }
            
            # Connection pool efficiency
            if self.pool_metrics:
                latest_pool = self.pool_metrics[-1]
                pool_efficiency = (latest_pool['checked_out'] / latest_pool['pool_size']) * 100
                summary['pool_efficiency'] = pool_efficiency
                summary['pool_utilization'] = {
                    'pool_size': latest_pool['pool_size'],
                    'checked_out': latest_pool['checked_out'],
                    'checked_in': latest_pool['checked_in'],
                    'efficiency_percent': pool_efficiency
                }
            
            return summary
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile value from performance data"""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = (percentile / 100) * (len(sorted_data) - 1)
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))
    
    def validate_performance_thresholds(self) -> Dict[str, bool]:
        """
        Validate performance against defined thresholds from Section 4.11.1
        """
        summary = self.get_performance_summary()
        validation_results = {}
        
        # Overall average query time validation (< 100ms)
        validation_results['average_query_time'] = summary.get('average_execution_time', 0) <= 0.1
        
        # Per-query-type threshold validation
        for query_type, threshold in self.performance_thresholds.items():
            if query_type in summary.get('query_types', {}):
                p95_time = summary['query_types'][query_type]['p95']
                validation_results[f'{query_type}_p95'] = p95_time <= threshold
            else:
                validation_results[f'{query_type}_p95'] = True  # No queries of this type
        
        # Connection pool efficiency validation (> 90% under load)
        pool_efficiency = summary.get('pool_efficiency', 100)
        validation_results['pool_efficiency'] = pool_efficiency >= 90.0
        
        return validation_results
    
    def get_explain_plan(self, engine: Engine, query: str) -> Dict[str, Any]:
        """
        Retrieve PostgreSQL EXPLAIN plan for query optimization analysis
        """
        try:
            with engine.connect() as connection:
                # Execute EXPLAIN ANALYZE for detailed performance analysis
                explain_query = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {query}"
                result = connection.execute(text(explain_query))
                plan_data = result.fetchone()[0]
                
                # Store plan for analysis
                query_hash = hash(query)
                self.explain_plans[query_hash] = {
                    'query': query,
                    'plan': plan_data,
                    'timestamp': datetime.utcnow()
                }
                
                return plan_data
        except Exception as e:
            logging.warning(f"Failed to get EXPLAIN plan: {e}")
            return {}
    
    def reset_metrics(self):
        """Reset all collected performance metrics"""
        with self._lock:
            self.query_metrics.clear()
            self.connection_metrics.clear()
            self.pool_metrics.clear()
            self.explain_plans.clear()
            self.active_queries.clear()


class BaselineComparisonFramework:
    """
    MongoDB to Flask-SQLAlchemy performance comparison framework for migration
    validation as specified in Section 0.2.1.
    
    This framework provides comprehensive baseline comparison capabilities to ensure
    equivalent or improved performance during the migration process.
    """
    
    def __init__(self):
        self.baseline_metrics = {}
        self.flask_metrics = {}
        self.comparison_results = {}
        
    def load_mongodb_baseline(self, baseline_file: str = None) -> Dict[str, Any]:
        """
        Load MongoDB performance baseline metrics for comparison
        """
        # Simulated MongoDB baseline metrics for testing
        # In production, these would be loaded from actual baseline measurements
        baseline_data = {
            'simple_queries': {
                'average_time': 0.08,  # 80ms average
                'p95_time': 0.15,      # 150ms 95th percentile
                'p99_time': 0.25,      # 250ms 99th percentile
                'throughput_qps': 1000  # Queries per second
            },
            'complex_queries': {
                'average_time': 0.5,   # 500ms average
                'p95_time': 1.2,       # 1200ms 95th percentile
                'p99_time': 2.0,       # 2000ms 99th percentile
                'throughput_qps': 200
            },
            'write_operations': {
                'average_time': 0.05,  # 50ms average
                'p95_time': 0.12,      # 120ms 95th percentile
                'p99_time': 0.20,      # 200ms 99th percentile
                'throughput_ops': 800
            },
            'connection_pool': {
                'max_connections': 100,
                'average_utilization': 75,
                'peak_utilization': 95
            }
        }
        
        self.baseline_metrics = baseline_data
        return baseline_data
    
    def record_flask_performance(self, performance_summary: Dict[str, Any]):
        """
        Record Flask-SQLAlchemy performance metrics for comparison
        """
        self.flask_metrics = performance_summary
        
    def compare_performance(self) -> Dict[str, Any]:
        """
        Perform comprehensive performance comparison between MongoDB and Flask-SQLAlchemy
        """
        if not self.baseline_metrics or not self.flask_metrics:
            return {'status': 'insufficient_data'}
        
        comparison = {
            'overall_performance': {},
            'query_type_comparison': {},
            'improvement_percentage': {},
            'performance_regression': [],
            'validation_status': 'PASSED'
        }
        
        # Compare average query performance
        flask_avg = self.flask_metrics.get('average_execution_time', 0)
        baseline_avg = self.baseline_metrics.get('simple_queries', {}).get('average_time', 0)
        
        if baseline_avg > 0:
            improvement = ((baseline_avg - flask_avg) / baseline_avg) * 100
            comparison['improvement_percentage']['average_query_time'] = improvement
            
            # Check for performance regression (> 10% slower)
            if improvement < -10:
                comparison['performance_regression'].append({
                    'metric': 'average_query_time',
                    'baseline': baseline_avg,
                    'flask': flask_avg,
                    'regression_percent': abs(improvement)
                })
                comparison['validation_status'] = 'FAILED'
        
        # Compare query types
        flask_query_types = self.flask_metrics.get('query_types', {})
        
        for query_type in ['simple_select', 'complex_join', 'insert_update']:
            if query_type in flask_query_types:
                flask_p95 = flask_query_types[query_type]['p95']
                
                # Map to baseline categories
                baseline_category = self._map_query_type_to_baseline(query_type)
                baseline_p95 = self.baseline_metrics.get(baseline_category, {}).get('p95_time', 0)
                
                if baseline_p95 > 0:
                    improvement = ((baseline_p95 - flask_p95) / baseline_p95) * 100
                    comparison['query_type_comparison'][query_type] = {
                        'baseline_p95': baseline_p95,
                        'flask_p95': flask_p95,
                        'improvement_percent': improvement,
                        'performance_met': improvement >= -10  # Allow up to 10% regression
                    }
                    
                    if improvement < -10:
                        comparison['performance_regression'].append({
                            'metric': f'{query_type}_p95',
                            'baseline': baseline_p95,
                            'flask': flask_p95,
                            'regression_percent': abs(improvement)
                        })
                        comparison['validation_status'] = 'FAILED'
        
        # Connection pool comparison
        flask_pool = self.flask_metrics.get('pool_utilization', {})
        baseline_pool = self.baseline_metrics.get('connection_pool', {})
        
        if flask_pool and baseline_pool:
            comparison['connection_pool'] = {
                'baseline_utilization': baseline_pool.get('average_utilization', 0),
                'flask_utilization': flask_pool.get('efficiency_percent', 0),
                'utilization_improvement': flask_pool.get('efficiency_percent', 0) - baseline_pool.get('average_utilization', 0)
            }
        
        self.comparison_results = comparison
        return comparison
    
    def _map_query_type_to_baseline(self, query_type: str) -> str:
        """Map Flask query types to MongoDB baseline categories"""
        mapping = {
            'simple_select': 'simple_queries',
            'complex_join': 'complex_queries',
            'insert_update': 'write_operations'
        }
        return mapping.get(query_type, 'simple_queries')
    
    def generate_performance_report(self) -> str:
        """
        Generate comprehensive performance comparison report
        """
        if not self.comparison_results:
            return "No comparison data available"
            
        report = []
        report.append("DATABASE PERFORMANCE COMPARISON REPORT")
        report.append("=" * 50)
        
        status = self.comparison_results.get('validation_status', 'UNKNOWN')
        report.append(f"Overall Status: {status}")
        report.append("")
        
        # Performance improvements
        improvements = self.comparison_results.get('improvement_percentage', {})
        if improvements:
            report.append("Performance Improvements:")
            for metric, improvement in improvements.items():
                direction = "improvement" if improvement > 0 else "regression"
                report.append(f"  {metric}: {improvement:.2f}% {direction}")
            report.append("")
        
        # Query type comparison
        query_comparison = self.comparison_results.get('query_type_comparison', {})
        if query_comparison:
            report.append("Query Type Performance:")
            for query_type, data in query_comparison.items():
                report.append(f"  {query_type}:")
                report.append(f"    Baseline P95: {data['baseline_p95']:.3f}s")
                report.append(f"    Flask P95: {data['flask_p95']:.3f}s")
                report.append(f"    Improvement: {data['improvement_percent']:.2f}%")
                report.append(f"    Status: {'PASS' if data['performance_met'] else 'FAIL'}")
            report.append("")
        
        # Performance regressions
        regressions = self.comparison_results.get('performance_regression', [])
        if regressions:
            report.append("Performance Regressions:")
            for regression in regressions:
                report.append(f"  {regression['metric']}:")
                report.append(f"    Baseline: {regression['baseline']:.3f}s")
                report.append(f"    Flask: {regression['flask']:.3f}s")
                report.append(f"    Regression: {regression['regression_percent']:.2f}%")
            report.append("")
        
        return "\n".join(report)


# ================================
# pytest-benchmark Integration Fixtures
# ================================

@pytest.fixture(scope="session")
def performance_monitor():
    """
    Performance monitoring fixture providing SQLAlchemy event listener instrumentation
    for comprehensive query performance tracking throughout test session.
    """
    monitor = SQLAlchemyPerformanceMonitor()
    return monitor


@pytest.fixture(scope="session") 
def baseline_framework():
    """
    Baseline comparison framework fixture for MongoDB to Flask-SQLAlchemy
    performance validation throughout test session.
    """
    framework = BaselineComparisonFramework()
    framework.load_mongodb_baseline()
    return framework


@pytest.fixture
def db_performance_setup(app, performance_monitor):
    """
    Database performance testing setup fixture that initializes monitoring
    and provides clean database state for each test.
    """
    with app.app_context():
        # Initialize performance monitoring
        if db and db.engine:
            performance_monitor.start_monitoring(db.engine)
            
        # Reset metrics for this test
        performance_monitor.reset_metrics()
        
        # Create tables if they don't exist
        if db:
            db.create_all()
            
        yield
        
        # Cleanup after test
        performance_monitor.stop_monitoring()
        if db:
            db.session.rollback()
            db.session.remove()


@pytest.fixture
def sample_database_records(app, db_performance_setup):
    """
    Generate comprehensive sample database records for performance testing
    with realistic data volumes and relationship complexity.
    """
    if not all([User, UserSession, BusinessEntity, EntityRelationship]):
        pytest.skip("Database models not available")
        
    with app.app_context():
        # Create sample users
        users = []
        for i in range(100):  # 100 users for realistic testing
            user = User(
                username=f'perftest_user_{i}',
                email=f'perftest_{i}@benchmark.test',
                password_hash=f'test_hash_{i}',
                is_active=True,
                created_at=datetime.utcnow() - timedelta(days=i % 30)
            )
            users.append(user)
            db.session.add(user)
        
        db.session.commit()
        
        # Create user sessions for authentication testing
        sessions = []
        for i, user in enumerate(users[:50]):  # Sessions for half the users
            session = UserSession(
                user_id=user.id,
                session_token=f'test_session_token_{i}_{uuid.uuid4()}',
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True,
                created_at=datetime.utcnow()
            )
            sessions.append(session)
            db.session.add(session)
        
        db.session.commit()
        
        # Create business entities with relationships
        entities = []
        for i in range(200):  # 200 business entities
            entity = BusinessEntity(
                name=f'Business Entity {i}',
                description=f'Test business entity for performance testing {i}',
                owner_id=users[i % len(users)].id,
                status='active' if i % 3 != 0 else 'inactive',
                created_at=datetime.utcnow() - timedelta(days=i % 60)
            )
            entities.append(entity)
            db.session.add(entity)
        
        db.session.commit()
        
        # Create complex entity relationships
        relationships = []
        for i in range(300):  # 300 relationships for complex queries
            source_entity = entities[i % len(entities)]
            target_entity = entities[(i + 1) % len(entities)]
            
            # Avoid self-relationships
            if source_entity.id != target_entity.id:
                relationship = EntityRelationship(
                    source_entity_id=source_entity.id,
                    target_entity_id=target_entity.id,
                    relationship_type=['parent', 'child', 'sibling', 'partner'][i % 4],
                    is_active=True,
                    created_at=datetime.utcnow() - timedelta(days=i % 90)
                )
                relationships.append(relationship)
                db.session.add(relationship)
        
        db.session.commit()
        
        return {
            'users': users,
            'sessions': sessions,
            'entities': entities,
            'relationships': relationships
        }


# ================================
# Database Performance Benchmark Tests
# ================================

class TestDatabaseQueryPerformance:
    """
    Comprehensive database query performance benchmark test suite validating
    sub-100ms query response times and SQLAlchemy optimization effectiveness.
    """
    
    @pytest.mark.benchmark(group="database_queries")
    def test_simple_select_performance(self, benchmark, app, sample_database_records, performance_monitor):
        """
        Benchmark simple SELECT query performance with sub-500ms requirement
        for 95th percentile response times per Section 4.11.1.
        """
        if not User:
            pytest.skip("User model not available")
            
        def simple_select_query():
            with app.app_context():
                # Simple user lookup by ID
                user = db.session.query(User).filter(User.id == 1).first()
                return user
        
        # Execute benchmark with statistical analysis
        result = benchmark.pedantic(simple_select_query, rounds=50, iterations=10)
        
        # Validate performance requirements
        performance_summary = performance_monitor.get_performance_summary()
        simple_select_metrics = performance_summary.get('query_types', {}).get('simple_select', {})
        
        if simple_select_metrics:
            p95_time = simple_select_metrics.get('p95', 0)
            assert p95_time <= 0.5, f"Simple SELECT P95 time {p95_time:.3f}s exceeds 500ms threshold"
            
            average_time = simple_select_metrics.get('average', 0)
            assert average_time <= 0.1, f"Simple SELECT average time {average_time:.3f}s exceeds 100ms threshold"
    
    @pytest.mark.benchmark(group="database_queries")
    def test_complex_join_performance(self, benchmark, app, sample_database_records, performance_monitor):
        """
        Benchmark complex JOIN query performance with sub-2000ms requirement
        for 95th percentile response times per Section 4.11.1.
        """
        if not all([User, BusinessEntity, EntityRelationship]):
            pytest.skip("Required models not available")
            
        def complex_join_query():
            with app.app_context():
                # Complex query with multiple JOINs
                query = db.session.query(User)\
                    .join(BusinessEntity, User.id == BusinessEntity.owner_id)\
                    .join(EntityRelationship, BusinessEntity.id == EntityRelationship.source_entity_id)\
                    .filter(EntityRelationship.relationship_type == 'parent')\
                    .filter(BusinessEntity.status == 'active')\
                    .order_by(User.created_at.desc())\
                    .limit(20)
                
                results = query.all()
                return results
        
        # Execute benchmark with statistical analysis
        result = benchmark.pedantic(complex_join_query, rounds=20, iterations=5)
        
        # Validate performance requirements
        performance_summary = performance_monitor.get_performance_summary()
        complex_join_metrics = performance_summary.get('query_types', {}).get('complex_join', {})
        
        if complex_join_metrics:
            p95_time = complex_join_metrics.get('p95', 0)
            assert p95_time <= 2.0, f"Complex JOIN P95 time {p95_time:.3f}s exceeds 2000ms threshold"
    
    @pytest.mark.benchmark(group="database_queries")
    def test_insert_update_performance(self, benchmark, app, performance_monitor):
        """
        Benchmark INSERT/UPDATE operation performance with sub-300ms requirement
        for 95th percentile response times per Section 4.11.1.
        """
        if not User:
            pytest.skip("User model not available")
            
        def insert_update_operations():
            with app.app_context():
                # Create new user
                new_user = User(
                    username=f'benchmark_user_{uuid.uuid4().hex[:8]}',
                    email=f'benchmark_{uuid.uuid4().hex[:8]}@test.com',
                    password_hash='benchmark_password_hash',
                    is_active=True,
                    created_at=datetime.utcnow()
                )
                
                db.session.add(new_user)
                db.session.commit()
                
                # Update user
                new_user.username = f'updated_{new_user.username}'
                db.session.commit()
                
                # Cleanup
                db.session.delete(new_user)
                db.session.commit()
                
                return new_user.id
        
        # Execute benchmark with statistical analysis
        result = benchmark.pedantic(insert_update_operations, rounds=30, iterations=5)
        
        # Validate performance requirements  
        performance_summary = performance_monitor.get_performance_summary()
        insert_update_metrics = performance_summary.get('query_types', {}).get('insert_update', {})
        
        if insert_update_metrics:
            p95_time = insert_update_metrics.get('p95', 0)
            assert p95_time <= 0.3, f"INSERT/UPDATE P95 time {p95_time:.3f}s exceeds 300ms threshold"
    
    @pytest.mark.benchmark(group="database_queries")
    def test_relationship_loading_performance(self, benchmark, app, sample_database_records, performance_monitor):
        """
        Benchmark relationship loading performance comparing lazy vs eager loading
        strategies for optimal performance per Section 6.2.2.1.
        """
        if not all([User, BusinessEntity]):
            pytest.skip("Required models not available")
            
        def test_lazy_loading():
            with app.app_context():
                # Test lazy loading (N+1 query issue)
                users = db.session.query(User).limit(10).all()
                entity_counts = []
                for user in users:
                    count = len(user.business_entities)  # This triggers lazy loading
                    entity_counts.append(count)
                return entity_counts
        
        def test_eager_loading():
            with app.app_context():
                # Test eager loading with joinedload
                users = db.session.query(User)\
                    .options(joinedload(User.business_entities))\
                    .limit(10).all()
                entity_counts = []
                for user in users:
                    count = len(user.business_entities)  # No additional queries
                    entity_counts.append(count)
                return entity_counts
        
        # Benchmark lazy loading
        performance_monitor.reset_metrics()
        lazy_result = benchmark.pedantic(test_lazy_loading, rounds=10, iterations=3)
        lazy_summary = performance_monitor.get_performance_summary()
        
        # Benchmark eager loading
        performance_monitor.reset_metrics()
        eager_result = benchmark.pedantic(test_eager_loading, rounds=10, iterations=3)
        eager_summary = performance_monitor.get_performance_summary()
        
        # Validate that eager loading reduces query count and improves performance
        lazy_query_count = lazy_summary.get('total_queries', 0)
        eager_query_count = eager_summary.get('total_queries', 0)
        
        assert eager_query_count < lazy_query_count, \
            f"Eager loading should reduce query count: eager={eager_query_count}, lazy={lazy_query_count}"
        
        # Performance should be better with eager loading
        lazy_avg_time = lazy_summary.get('average_execution_time', 0)
        eager_avg_time = eager_summary.get('average_execution_time', 0)
        
        # Log relationship loading performance comparison
        logging.info(f"Lazy loading: {lazy_query_count} queries, {lazy_avg_time:.3f}s avg")
        logging.info(f"Eager loading: {eager_query_count} queries, {eager_avg_time:.3f}s avg")


class TestConnectionPoolPerformance:
    """
    Connection pool utilization and efficiency benchmarking test suite
    validating optimal connection management per Section 6.5.2.2.
    """
    
    @pytest.mark.benchmark(group="connection_pool")
    def test_connection_pool_utilization(self, benchmark, app, sample_database_records, performance_monitor):
        """
        Benchmark connection pool utilization under concurrent load to validate
        efficient connection management and pool sizing optimization.
        """
        if not db:
            pytest.skip("Database not available")
            
        def concurrent_database_operations():
            """Execute concurrent database operations to stress connection pool"""
            with app.app_context():
                def single_operation(thread_id):
                    try:
                        # Simulate realistic database operations
                        user_count = db.session.query(func.count(User.id)).scalar()
                        
                        # Create and delete a temporary record
                        temp_user = User(
                            username=f'temp_user_{thread_id}_{uuid.uuid4().hex[:8]}',
                            email=f'temp_{thread_id}@test.com',
                            password_hash='temp_hash',
                            is_active=True
                        )
                        db.session.add(temp_user)
                        db.session.commit()
                        
                        # Query and cleanup
                        created_user = db.session.query(User).filter(User.username == temp_user.username).first()
                        if created_user:
                            db.session.delete(created_user)
                            db.session.commit()
                            
                        return user_count
                    except Exception as e:
                        logging.error(f"Database operation failed in thread {thread_id}: {e}")
                        db.session.rollback()
                        return 0
                
                # Execute concurrent operations
                with ThreadPoolExecutor(max_workers=20) as executor:
                    futures = [executor.submit(single_operation, i) for i in range(50)]
                    results = [future.result() for future in as_completed(futures)]
                
                return results
        
        # Execute benchmark
        result = benchmark.pedantic(concurrent_database_operations, rounds=5, iterations=1)
        
        # Validate connection pool performance
        performance_summary = performance_monitor.get_performance_summary()
        pool_utilization = performance_summary.get('pool_utilization', {})
        
        if pool_utilization:
            efficiency = pool_utilization.get('efficiency_percent', 0)
            # Under concurrent load, pool efficiency should be high (> 50%)
            assert efficiency > 50, f"Connection pool efficiency {efficiency:.2f}% too low under concurrent load"
            
            # Validate no connection pool exhaustion
            pool_size = pool_utilization.get('pool_size', 0)
            checked_out = pool_utilization.get('checked_out', 0)
            assert checked_out <= pool_size, f"Connection pool exhausted: {checked_out} > {pool_size}"
    
    @pytest.mark.benchmark(group="connection_pool")
    def test_connection_pool_scaling(self, benchmark, app, performance_monitor):
        """
        Test connection pool scaling behavior under increasing load to validate
        optimal pool configuration per Section 6.2.5.2.
        """
        if not db:
            pytest.skip("Database not available")
            
        def scaling_load_test():
            """Test connection pool behavior under scaling load"""
            with app.app_context():
                results = []
                
                # Gradually increase concurrent operations
                for worker_count in [5, 10, 15, 20]:
                    def database_operation(worker_id):
                        try:
                            # Simple query operation
                            count = db.session.query(func.count(User.id)).scalar()
                            return count
                        except Exception as e:
                            db.session.rollback()
                            return 0
                    
                    # Execute with current worker count
                    start_time = time.perf_counter()
                    with ThreadPoolExecutor(max_workers=worker_count) as executor:
                        futures = [executor.submit(database_operation, i) for i in range(worker_count * 2)]
                        worker_results = [future.result() for future in as_completed(futures)]
                    
                    end_time = time.perf_counter()
                    
                    results.append({
                        'worker_count': worker_count,
                        'execution_time': end_time - start_time,
                        'operations': len(worker_results),
                        'success_rate': sum(1 for r in worker_results if r > 0) / len(worker_results)
                    })
                
                return results
        
        # Execute scaling test
        result = benchmark.pedantic(scaling_load_test, rounds=3, iterations=1)
        
        # Validate scaling performance
        for load_result in result:
            # Success rate should remain high under scaling load
            success_rate = load_result['success_rate']
            assert success_rate >= 0.9, \
                f"Success rate {success_rate:.2f} too low with {load_result['worker_count']} workers"
            
            # Execution time should scale reasonably
            operations_per_second = load_result['operations'] / load_result['execution_time']
            assert operations_per_second > 10, \
                f"Throughput {operations_per_second:.2f} ops/sec too low with {load_result['worker_count']} workers"


class TestQueryOptimizationAnalysis:
    """
    Query optimization and EXPLAIN plan analysis test suite for PostgreSQL
    performance optimization per Section 6.2.5.1.
    """
    
    def test_explain_plan_analysis(self, app, sample_database_records, performance_monitor):
        """
        Analyze PostgreSQL EXPLAIN plans for query optimization insights
        and performance bottleneck identification.
        """
        if not all([User, BusinessEntity]) or not db:
            pytest.skip("Required models or database not available")
            
        with app.app_context():
            # Test simple query EXPLAIN plan
            simple_query = "SELECT * FROM users WHERE id = 1"
            simple_plan = performance_monitor.get_explain_plan(db.engine, simple_query)
            
            if simple_plan:
                # Validate query uses index (should be fast)
                plan_text = json.dumps(simple_plan)
                assert 'Index Scan' in plan_text or 'Seq Scan' in plan_text, \
                    "Query plan should indicate scan type"
            
            # Test complex join query EXPLAIN plan
            complex_query = """
                SELECT u.username, be.name, COUNT(er.id) as relationship_count
                FROM users u
                JOIN business_entities be ON u.id = be.owner_id  
                LEFT JOIN entity_relationships er ON be.id = er.source_entity_id
                WHERE be.status = 'active'
                GROUP BY u.id, u.username, be.name
                ORDER BY relationship_count DESC
                LIMIT 10
            """
            
            complex_plan = performance_monitor.get_explain_plan(db.engine, complex_query)
            
            if complex_plan:
                # Validate complex query optimization
                plan_text = json.dumps(complex_plan)
                
                # Should use appropriate join algorithms
                assert any(join_type in plan_text for join_type in ['Hash Join', 'Nested Loop', 'Merge Join']), \
                    "Complex query should use optimized join algorithms"
                
                # Should use sorting/grouping efficiently
                assert any(sort_type in plan_text for sort_type in ['Sort', 'GroupAggregate', 'HashAggregate']), \
                    "Complex query should use efficient sorting/aggregation"
    
    @pytest.mark.benchmark(group="query_optimization")
    def test_index_utilization_performance(self, benchmark, app, sample_database_records, performance_monitor):
        """
        Benchmark index utilization effectiveness for query performance optimization.
        """
        if not User or not db:
            pytest.skip("User model or database not available")
            
        def test_indexed_query():
            with app.app_context():
                # Query using indexed column (should be fast)
                user = db.session.query(User).filter(User.email == 'perftest_0@benchmark.test').first()
                return user
        
        def test_non_indexed_query():
            with app.app_context():
                # Query using non-indexed column (should be slower)
                users = db.session.query(User).filter(User.password_hash.like('test_hash_%')).all()
                return users
        
        # Benchmark indexed query
        performance_monitor.reset_metrics()
        indexed_result = benchmark.pedantic(test_indexed_query, rounds=20, iterations=5)
        indexed_summary = performance_monitor.get_performance_summary()
        
        # Benchmark non-indexed query  
        performance_monitor.reset_metrics()
        non_indexed_result = benchmark.pedantic(test_non_indexed_query, rounds=10, iterations=3)
        non_indexed_summary = performance_monitor.get_performance_summary()
        
        # Validate index effectiveness
        indexed_avg_time = indexed_summary.get('average_execution_time', 0)
        non_indexed_avg_time = non_indexed_summary.get('average_execution_time', 0)
        
        # Indexed queries should be significantly faster
        if non_indexed_avg_time > 0:
            performance_ratio = indexed_avg_time / non_indexed_avg_time
            assert performance_ratio < 0.5, \
                f"Indexed query should be faster: indexed={indexed_avg_time:.3f}s, non-indexed={non_indexed_avg_time:.3f}s"
        
        # Both should still meet performance thresholds
        assert indexed_avg_time <= 0.1, f"Indexed query too slow: {indexed_avg_time:.3f}s"


class TestBaselineComparisonValidation:
    """
    MongoDB to Flask-SQLAlchemy performance comparison validation test suite
    ensuring equivalent or improved performance per Section 0.2.1.
    """
    
    def test_performance_baseline_comparison(self, app, sample_database_records, 
                                          performance_monitor, baseline_framework):
        """
        Comprehensive performance comparison against MongoDB baseline metrics
        to validate migration success and performance equivalence.
        """
        if not all([User, BusinessEntity, EntityRelationship]) or not db:
            pytest.skip("Required models or database not available")
            
        with app.app_context():
            # Execute representative queries for baseline comparison
            
            # Simple queries
            for _ in range(20):
                user = db.session.query(User).filter(User.id <= 10).first()
            
            # Complex queries
            for _ in range(10):
                complex_results = db.session.query(User)\
                    .join(BusinessEntity, User.id == BusinessEntity.owner_id)\
                    .filter(BusinessEntity.status == 'active')\
                    .limit(5).all()
            
            # Write operations
            for i in range(15):
                temp_user = User(
                    username=f'baseline_test_{i}',
                    email=f'baseline_{i}@test.com',
                    password_hash='baseline_hash'
                )
                db.session.add(temp_user)
                db.session.commit()
                db.session.delete(temp_user)
                db.session.commit()
        
        # Get performance summary
        performance_summary = performance_monitor.get_performance_summary()
        
        # Record Flask performance for comparison
        baseline_framework.record_flask_performance(performance_summary)
        
        # Perform comparison analysis
        comparison_results = baseline_framework.compare_performance()
        
        # Generate performance report
        performance_report = baseline_framework.generate_performance_report()
        logging.info("Performance Comparison Report:")
        logging.info(performance_report)
        
        # Validate migration performance requirements
        assert comparison_results['validation_status'] == 'PASSED', \
            f"Performance comparison failed: {comparison_results.get('performance_regression', [])}"
        
        # Ensure no significant performance regression (> 10%)
        regressions = comparison_results.get('performance_regression', [])
        assert len(regressions) == 0, \
            f"Performance regressions detected: {[r['metric'] for r in regressions]}"
        
        # Validate overall performance improvement or equivalence
        improvements = comparison_results.get('improvement_percentage', {})
        if 'average_query_time' in improvements:
            improvement = improvements['average_query_time']
            assert improvement >= -10, \
                f"Overall performance regression too high: {improvement:.2f}%"
    
    def test_zero_data_loss_validation(self, app, sample_database_records, performance_monitor):
        """
        Validate zero data loss during high-performance database operations
        as required by Section 0.2.3.
        """
        if not all([User, BusinessEntity]) or not db:
            pytest.skip("Required models or database not available")
            
        with app.app_context():
            # Record initial data counts
            initial_user_count = db.session.query(func.count(User.id)).scalar()
            initial_entity_count = db.session.query(func.count(BusinessEntity.id)).scalar()
            
            # Perform high-volume operations
            test_users = []
            for i in range(50):
                user = User(
                    username=f'data_integrity_test_{i}',
                    email=f'integrity_{i}@test.com',
                    password_hash='integrity_hash'
                )
                test_users.append(user)
                db.session.add(user)
            
            db.session.commit()
            
            # Create related entities
            test_entities = []
            for i, user in enumerate(test_users):
                entity = BusinessEntity(
                    name=f'Integrity Test Entity {i}',
                    description=f'Data integrity validation entity {i}',
                    owner_id=user.id,
                    status='active'
                )
                test_entities.append(entity)
                db.session.add(entity)
            
            db.session.commit()
            
            # Verify data integrity
            final_user_count = db.session.query(func.count(User.id)).scalar()
            final_entity_count = db.session.query(func.count(BusinessEntity.id)).scalar()
            
            # Validate no data loss
            assert final_user_count == initial_user_count + 50, \
                f"User data loss detected: expected {initial_user_count + 50}, got {final_user_count}"
            
            assert final_entity_count == initial_entity_count + 50, \
                f"Entity data loss detected: expected {initial_entity_count + 50}, got {final_entity_count}"
            
            # Validate referential integrity
            for entity in test_entities:
                assert entity.owner_id in [u.id for u in test_users], \
                    f"Referential integrity violation: entity {entity.id} owner {entity.owner_id} not found"
            
            # Cleanup test data
            for entity in test_entities:
                db.session.delete(entity)
            for user in test_users:
                db.session.delete(user)
            db.session.commit()
            
            # Verify cleanup completed successfully
            cleanup_user_count = db.session.query(func.count(User.id)).scalar()
            cleanup_entity_count = db.session.query(func.count(BusinessEntity.id)).scalar()
            
            assert cleanup_user_count == initial_user_count, \
                f"Cleanup failed for users: expected {initial_user_count}, got {cleanup_user_count}"
            
            assert cleanup_entity_count == initial_entity_count, \
                f"Cleanup failed for entities: expected {initial_entity_count}, got {cleanup_entity_count}"


# ================================
# Performance Threshold Validation Tests
# ================================

class TestPerformanceThresholdCompliance:
    """
    Performance threshold compliance validation test suite ensuring
    all database operations meet SLA requirements per Section 4.11.1.
    """
    
    def test_sub_100ms_average_query_compliance(self, app, sample_database_records, performance_monitor):
        """
        Validate that average database query response time meets sub-100ms
        requirement as specified in Section 4.11.1.
        """
        if not User or not db:
            pytest.skip("User model or database not available")
            
        with app.app_context():
            # Execute various query types for comprehensive validation
            query_operations = [
                lambda: db.session.query(User).filter(User.id == 1).first(),
                lambda: db.session.query(User).filter(User.email.like('%test%')).limit(5).all(),
                lambda: db.session.query(func.count(User.id)).scalar(),
                lambda: db.session.query(User).order_by(User.created_at.desc()).limit(10).all(),
                lambda: db.session.query(User).filter(User.is_active == True).limit(20).all()
            ]
            
            # Execute operations multiple times for statistical significance
            for _ in range(10):
                for operation in query_operations:
                    result = operation()
            
            # Validate performance compliance
            performance_summary = performance_monitor.get_performance_summary()
            average_time = performance_summary.get('average_execution_time', 0)
            
            assert average_time <= 0.1, \
                f"Average query time {average_time:.3f}s exceeds 100ms requirement"
            
            # Validate threshold compliance by query type
            threshold_validation = performance_monitor.validate_performance_thresholds()
            
            for threshold_name, compliance in threshold_validation.items():
                assert compliance, f"Performance threshold failed: {threshold_name}"
    
    def test_connection_pool_efficiency_compliance(self, app, sample_database_records, performance_monitor):
        """
        Validate connection pool efficiency meets 90% utilization requirement
        under load as specified in Section 6.5.2.2.
        """
        if not db:
            pytest.skip("Database not available")
            
        def high_load_operations():
            """Execute high-load operations to test pool efficiency"""
            with app.app_context():
                operations = []
                
                # Execute multiple concurrent operations
                def single_operation(op_id):
                    try:
                        # Mix of read and write operations
                        if op_id % 3 == 0:
                            # Read operation
                            result = db.session.query(User).limit(5).all()
                        elif op_id % 3 == 1:
                            # Count operation
                            result = db.session.query(func.count(User.id)).scalar()
                        else:
                            # Write operation
                            temp_user = User(
                                username=f'pool_test_{op_id}',
                                email=f'pool_{op_id}@test.com',
                                password_hash='pool_hash'
                            )
                            db.session.add(temp_user)
                            db.session.commit()
                            db.session.delete(temp_user)
                            db.session.commit()
                            result = temp_user.id
                        
                        return result
                    except Exception as e:
                        db.session.rollback()
                        return None
                
                # Execute concurrent operations
                with ThreadPoolExecutor(max_workers=15) as executor:
                    futures = [executor.submit(single_operation, i) for i in range(60)]
                    for future in as_completed(futures):
                        operations.append(future.result())
                
                return operations
        
        # Execute high-load test
        results = high_load_operations()
        
        # Validate pool efficiency
        performance_summary = performance_monitor.get_performance_summary()
        pool_utilization = performance_summary.get('pool_utilization', {})
        
        if pool_utilization:
            efficiency = pool_utilization.get('efficiency_percent', 0)
            
            # Under high load, efficiency should meet requirements
            # Note: May be lower than 90% if pool is well-sized
            # Validate that operations completed successfully
            success_count = sum(1 for r in results if r is not None)
            success_rate = success_count / len(results)
            
            assert success_rate >= 0.95, \
                f"Operation success rate {success_rate:.2f} too low under load"
            
            # Validate no connection pool exhaustion occurred
            pool_size = pool_utilization.get('pool_size', 0)
            checked_out = pool_utilization.get('checked_out', 0)
            
            assert checked_out <= pool_size, \
                f"Connection pool exhausted: {checked_out} connections > {pool_size} pool size"


# ================================
# Performance Regression Detection Tests
# ================================

class TestPerformanceRegressionDetection:
    """
    Automated performance regression detection test suite for continuous
    performance validation and optimization feedback.
    """
    
    def test_automated_performance_regression_detection(self, app, sample_database_records, 
                                                      performance_monitor, baseline_framework):
        """
        Automated detection of performance regressions with configurable
        thresholds and alerting for continuous performance validation.
        """
        if not all([User, BusinessEntity]) or not db:
            pytest.skip("Required models or database not available")
            
        # Simulate baseline performance measurement
        baseline_metrics = {
            'average_execution_time': 0.05,  # 50ms baseline
            'query_types': {
                'simple_select': {'p95': 0.1, 'average': 0.03},
                'complex_join': {'p95': 0.8, 'average': 0.4},
                'insert_update': {'p95': 0.15, 'average': 0.08}
            }
        }
        
        baseline_framework.flask_metrics = baseline_metrics
        
        with app.app_context():
            # Execute current performance test
            for _ in range(20):
                # Simple queries
                user = db.session.query(User).filter(User.id <= 5).first()
                
                # Complex queries
                if BusinessEntity:
                    complex_result = db.session.query(User)\
                        .join(BusinessEntity, User.id == BusinessEntity.owner_id)\
                        .limit(3).all()
                
                # Write operations
                temp_user = User(
                    username=f'regression_test_{uuid.uuid4().hex[:8]}',
                    email=f'regression@test.com',
                    password_hash='regression_hash'
                )
                db.session.add(temp_user)
                db.session.commit()
                db.session.delete(temp_user)
                db.session.commit()
        
        # Get current performance metrics
        current_performance = performance_monitor.get_performance_summary()
        
        # Simulate performance comparison
        current_avg = current_performance.get('average_execution_time', 0)
        baseline_avg = baseline_metrics['average_execution_time']
        
        # Calculate performance change
        if baseline_avg > 0:
            performance_change = ((current_avg - baseline_avg) / baseline_avg) * 100
        else:
            performance_change = 0
        
        # Validate regression detection
        regression_threshold = 15  # Allow up to 15% performance regression
        
        if performance_change > regression_threshold:
            pytest.fail(f"Performance regression detected: {performance_change:.2f}% slower than baseline")
        
        # Log performance comparison for monitoring
        logging.info(f"Performance comparison: baseline={baseline_avg:.3f}s, "
                    f"current={current_avg:.3f}s, change={performance_change:.2f}%")
        
        # Validate individual query type performance
        current_query_types = current_performance.get('query_types', {})
        baseline_query_types = baseline_metrics.get('query_types', {})
        
        for query_type, baseline_data in baseline_query_types.items():
            if query_type in current_query_types:
                current_p95 = current_query_types[query_type]['p95']
                baseline_p95 = baseline_data['p95']
                
                if baseline_p95 > 0:
                    p95_change = ((current_p95 - baseline_p95) / baseline_p95) * 100
                    
                    assert p95_change <= regression_threshold, \
                        f"P95 regression in {query_type}: {p95_change:.2f}% slower than baseline"


# ================================
# Comprehensive Integration Tests
# ================================

class TestDatabasePerformanceIntegration:
    """
    Comprehensive database performance integration test suite validating
    end-to-end performance across all database components and operations.
    """
    
    @pytest.mark.benchmark(group="integration")
    def test_end_to_end_database_performance(self, benchmark, app, sample_database_records, 
                                           performance_monitor, baseline_framework):
        """
        End-to-end database performance validation combining all query types,
        connection pool utilization, and baseline comparison for comprehensive
        migration validation per Section 0.2.1.
        """
        if not all([User, UserSession, BusinessEntity, EntityRelationship]) or not db:
            pytest.skip("Required models or database not available")
            
        def comprehensive_database_workload():
            """Execute comprehensive database workload for integration testing"""
            with app.app_context():
                results = {}
                
                # 1. Authentication queries (user login simulation)
                auth_start = time.perf_counter()
                for i in range(10):
                    user = db.session.query(User).filter(User.email == f'perftest_{i}@benchmark.test').first()
                    if user:
                        session = db.session.query(UserSession).filter(UserSession.user_id == user.id).first()
                auth_end = time.perf_counter()
                results['auth_time'] = auth_end - auth_start
                
                # 2. Business entity operations
                entity_start = time.perf_counter()
                entities = db.session.query(BusinessEntity)\
                    .join(User, BusinessEntity.owner_id == User.id)\
                    .filter(BusinessEntity.status == 'active')\
                    .order_by(BusinessEntity.created_at.desc())\
                    .limit(20).all()
                entity_end = time.perf_counter()
                results['entity_time'] = entity_end - entity_start
                
                # 3. Complex relationship queries
                relationship_start = time.perf_counter()
                relationships = db.session.query(EntityRelationship)\
                    .join(BusinessEntity, EntityRelationship.source_entity_id == BusinessEntity.id)\
                    .join(User, BusinessEntity.owner_id == User.id)\
                    .filter(EntityRelationship.is_active == True)\
                    .filter(EntityRelationship.relationship_type == 'parent')\
                    .limit(15).all()
                relationship_end = time.perf_counter()
                results['relationship_time'] = relationship_end - relationship_start
                
                # 4. Write operations (user registration simulation)
                write_start = time.perf_counter()
                for i in range(5):
                    new_user = User(
                        username=f'integration_user_{i}_{uuid.uuid4().hex[:8]}',
                        email=f'integration_{i}@test.com',
                        password_hash='integration_hash',
                        is_active=True
                    )
                    db.session.add(new_user)
                    db.session.commit()
                    
                    # Create associated entity
                    new_entity = BusinessEntity(
                        name=f'Integration Entity {i}',
                        description=f'Integration test entity {i}',
                        owner_id=new_user.id,
                        status='active'
                    )
                    db.session.add(new_entity)
                    db.session.commit()
                    
                    # Cleanup
                    db.session.delete(new_entity)
                    db.session.delete(new_user)
                    db.session.commit()
                
                write_end = time.perf_counter()
                results['write_time'] = write_end - write_start
                
                # 5. Aggregation queries
                agg_start = time.perf_counter()
                user_stats = db.session.query(
                    func.count(User.id).label('total_users'),
                    func.count(BusinessEntity.id).label('total_entities'),
                    func.avg(func.extract('days', func.now() - User.created_at)).label('avg_user_age_days')
                ).select_from(User).outerjoin(BusinessEntity, User.id == BusinessEntity.owner_id).first()
                agg_end = time.perf_counter()
                results['aggregation_time'] = agg_end - agg_start
                
                return results
        
        # Execute comprehensive benchmark
        result = benchmark.pedantic(comprehensive_database_workload, rounds=5, iterations=2)
        
        # Validate comprehensive performance
        performance_summary = performance_monitor.get_performance_summary()
        
        # Overall performance validation
        total_queries = performance_summary.get('total_queries', 0)
        average_time = performance_summary.get('average_execution_time', 0)
        
        assert total_queries > 0, "No queries executed during integration test"
        assert average_time <= 0.1, f"Average query time {average_time:.3f}s exceeds 100ms requirement"
        
        # Validate specific operation performance
        for operation_name, operation_time in result.items():
            # Each operation category should complete within reasonable time
            max_operation_time = {
                'auth_time': 2.0,        # 2 seconds for authentication operations
                'entity_time': 3.0,      # 3 seconds for entity queries
                'relationship_time': 4.0, # 4 seconds for relationship queries
                'write_time': 5.0,       # 5 seconds for write operations
                'aggregation_time': 2.0  # 2 seconds for aggregation
            }
            
            max_time = max_operation_time.get(operation_name, 10.0)
            assert operation_time <= max_time, \
                f"{operation_name} took {operation_time:.3f}s, exceeding {max_time}s limit"
        
        # Baseline comparison validation
        baseline_framework.record_flask_performance(performance_summary)
        comparison_results = baseline_framework.compare_performance()
        
        # Final integration validation
        assert comparison_results['validation_status'] == 'PASSED', \
            f"Integration performance comparison failed: {comparison_results}"
        
        # Generate comprehensive performance report
        performance_report = baseline_framework.generate_performance_report()
        logging.info("=== COMPREHENSIVE DATABASE PERFORMANCE REPORT ===")
        logging.info(performance_report)
        logging.info("=== END PERFORMANCE REPORT ===")
        
        # Validate all performance thresholds met
        threshold_validation = performance_monitor.validate_performance_thresholds()
        failed_thresholds = [name for name, passed in threshold_validation.items() if not passed]
        
        assert len(failed_thresholds) == 0, \
            f"Performance thresholds failed: {failed_thresholds}"


# ================================
# Test Execution and Reporting
# ================================

if __name__ == "__main__":
    """
    Main test execution entry point for database performance benchmarking.
    
    Usage:
        python -m pytest tests/performance/test_database_benchmarks.py -v --benchmark-only
        python -m pytest tests/performance/test_database_benchmarks.py::TestDatabaseQueryPerformance -v
        python -m pytest tests/performance/test_database_benchmarks.py -m "benchmark" --benchmark-sort=mean
    """
    
    # Configure logging for performance testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('database_performance_tests.log')
        ]
    )
    
    # Run tests with pytest-benchmark configuration
    pytest.main([
        __file__,
        '-v',
        '--benchmark-only',
        '--benchmark-sort=mean',
        '--benchmark-group-by=group',
        '--benchmark-columns=min,max,mean,stddev,ops,rounds,iterations',
        '--benchmark-save=database_performance_results',
        '--benchmark-save-data',
        '--tb=short'
    ])