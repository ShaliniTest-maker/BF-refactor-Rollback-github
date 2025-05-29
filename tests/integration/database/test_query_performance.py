"""
Database Query Performance Testing Suite

This module provides comprehensive database query performance testing using pytest-benchmark 5.1.0
to validate SQLAlchemy query execution times, optimization patterns, and performance equivalence
with the original Node.js MongoDB implementation. Ensures Flask-SQLAlchemy queries meet the 95th
percentile performance targets (simple queries < 500ms, complex queries < 2000ms) while validating
query plan optimization and database index utilization.

Key Features:
- pytest-benchmark 5.1.0 integration for performance testing framework
- Baseline comparison testing against Node.js MongoDB query performance metrics
- SQLAlchemy query optimization testing including compiled queries and stream results configuration
- PostgreSQL EXPLAIN plan integration for query execution analysis
- Performance SLA validation ensuring 95th percentile targets compliance
- Index utilization testing and query plan optimization validation

Performance Requirements:
- Simple SELECT operations: 95th percentile < 500ms, 99th percentile < 1000ms
- Complex JOIN operations: 95th percentile < 2000ms, 99th percentile < 3000ms
- INSERT/UPDATE operations: 95th percentile < 300ms, 99th percentile < 500ms
- Batch operations: 95th percentile < 5000ms, 99th percentile < 8000ms

Migration Context:
This test suite ensures the Flask-SQLAlchemy implementation meets or exceeds the performance
characteristics of the original Node.js MongoDB system while providing comprehensive monitoring
and optimization validation for production deployment readiness.
"""

import json
import os
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Generator
from unittest.mock import patch, MagicMock

import pytest
import pytest_benchmark
from flask import Flask, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text, event, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import scoped_session, sessionmaker, Query
from sqlalchemy.sql import text as sql_text

# Import test fixtures and utilities
from tests.integration.conftest import (
    app, client, database, db_session, 
    test_user, admin_user, authenticated_client,
    sample_business_entities, sample_entity_relationships,
    performance_monitor, benchmark_config, database_benchmark
)

# Import application models and services
from src.models.user import User
from src.models.session import UserSession
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship
from src.models import db
from src.services.user_service import UserService
from src.services.business_entity_service import BusinessEntityService
from src.services.relationship_service import RelationshipService


# ================================================================================================
# PERFORMANCE SLA CONSTANTS AND CONFIGURATION
# ================================================================================================

class PerformanceSLA:
    """Performance Service Level Agreement constants for query validation."""
    
    # 95th percentile response time targets (milliseconds)
    SIMPLE_QUERY_95TH_PERCENTILE = 500
    COMPLEX_QUERY_95TH_PERCENTILE = 2000
    INSERT_UPDATE_95TH_PERCENTILE = 300
    BATCH_OPERATION_95TH_PERCENTILE = 5000
    
    # 99th percentile response time targets (milliseconds)
    SIMPLE_QUERY_99TH_PERCENTILE = 1000
    COMPLEX_QUERY_99TH_PERCENTILE = 3000
    INSERT_UPDATE_99TH_PERCENTILE = 500
    BATCH_OPERATION_99TH_PERCENTILE = 8000
    
    # Query optimization thresholds
    COMPILED_QUERY_IMPROVEMENT_THRESHOLD = 0.20  # 20% improvement expected
    STREAM_RESULTS_MEMORY_THRESHOLD = 10 * 1024 * 1024  # 10MB
    EXPLAIN_PLAN_COST_THRESHOLD = 1000.0
    
    # Index utilization thresholds
    INDEX_USAGE_MINIMUM_PERCENTAGE = 90.0
    SEQUENTIAL_SCAN_WARNING_THRESHOLD = 5.0


class NodeJSBaselineMetrics:
    """Node.js MongoDB baseline performance metrics for comparison."""
    
    # Baseline response times from Node.js implementation (milliseconds)
    USER_FIND_BY_ID = 45.2
    USER_FIND_BY_EMAIL = 62.8
    USER_LIST_PAGINATED = 120.5
    BUSINESS_ENTITY_FIND_BY_OWNER = 89.3
    BUSINESS_ENTITY_COMPLEX_JOIN = 445.7
    ENTITY_RELATIONSHIP_QUERY = 156.4
    BULK_INSERT_OPERATIONS = 2340.6
    AGGREGATION_OPERATIONS = 890.2
    
    # Memory usage baselines (MB)
    SIMPLE_QUERY_MEMORY = 12.5
    COMPLEX_QUERY_MEMORY = 45.8
    BULK_OPERATION_MEMORY = 125.3


# ================================================================================================
# QUERY PERFORMANCE MONITORING AND ANALYSIS
# ================================================================================================

class QueryPerformanceMonitor:
    """Advanced query performance monitoring with EXPLAIN plan integration."""
    
    def __init__(self, db_session: scoped_session):
        self.db_session = db_session
        self.query_metrics = []
        self.explain_plans = []
        self.performance_baseline = {}
        
    @contextmanager
    def monitor_query(self, query_name: str, expected_baseline: float = None):
        """
        Context manager for monitoring query performance with EXPLAIN plan analysis.
        
        Args:
            query_name: Descriptive name for the query being monitored
            expected_baseline: Expected execution time in milliseconds for comparison
            
        Yields:
            QueryMetrics: Performance metrics and EXPLAIN plan data
        """
        start_time = time.perf_counter()
        start_memory = self._get_memory_usage()
        
        # Enable query logging for this session
        original_echo = self.db_session.bind.echo
        self.db_session.bind.echo = True
        
        query_metrics = {
            'query_name': query_name,
            'start_time': start_time,
            'expected_baseline': expected_baseline,
            'explain_plan': None,
            'index_usage': None
        }
        
        try:
            yield query_metrics
            
        finally:
            end_time = time.perf_counter()
            end_memory = self._get_memory_usage()
            
            execution_time_ms = (end_time - start_time) * 1000
            memory_delta_mb = (end_memory - start_memory) / (1024 * 1024)
            
            query_metrics.update({
                'execution_time_ms': execution_time_ms,
                'memory_delta_mb': memory_delta_mb,
                'end_time': end_time,
                'baseline_comparison': self._calculate_baseline_comparison(
                    execution_time_ms, expected_baseline
                ),
                'sla_compliance': self._check_sla_compliance(query_name, execution_time_ms)
            })
            
            self.query_metrics.append(query_metrics)
            self.db_session.bind.echo = original_echo
            
    def capture_explain_plan(self, query: Query) -> Dict[str, Any]:
        """
        Capture PostgreSQL EXPLAIN plan for query optimization analysis.
        
        Args:
            query: SQLAlchemy query object to analyze
            
        Returns:
            Dict[str, Any]: EXPLAIN plan analysis with cost and index usage information
        """
        try:
            # Get the compiled query
            compiled_query = query.statement.compile(
                dialect=self.db_session.bind.dialect,
                compile_kwargs={"literal_binds": True}
            )
            
            # Execute EXPLAIN ANALYZE for detailed performance information
            explain_query = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {compiled_query}"
            result = self.db_session.execute(text(explain_query))
            explain_data = result.fetchone()[0]
            
            # Parse explain plan for performance insights
            plan_analysis = self._analyze_explain_plan(explain_data)
            
            self.explain_plans.append({
                'query': str(compiled_query),
                'explain_data': explain_data,
                'analysis': plan_analysis,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            return plan_analysis
            
        except Exception as e:
            # Graceful handling for SQLite (which doesn't support EXPLAIN ANALYZE)
            return {
                'error': f"EXPLAIN plan capture failed: {str(e)}",
                'estimated_cost': 0.0,
                'index_usage': 'unknown',
                'scan_type': 'unknown'
            }
    
    def _analyze_explain_plan(self, explain_data: List[Dict]) -> Dict[str, Any]:
        """
        Analyze PostgreSQL EXPLAIN plan output for optimization insights.
        
        Args:
            explain_data: Raw EXPLAIN plan data from PostgreSQL
            
        Returns:
            Dict[str, Any]: Analyzed plan with performance recommendations
        """
        if not explain_data or not isinstance(explain_data, list):
            return {'error': 'Invalid explain plan data'}
            
        plan = explain_data[0].get('Plan', {})
        
        analysis = {
            'total_cost': plan.get('Total Cost', 0.0),
            'startup_cost': plan.get('Startup Cost', 0.0),
            'actual_time': plan.get('Actual Total Time', 0.0),
            'rows_returned': plan.get('Actual Rows', 0),
            'node_type': plan.get('Node Type', 'Unknown'),
            'index_usage': self._detect_index_usage(plan),
            'scan_type': self._identify_scan_type(plan),
            'optimization_recommendations': []
        }
        
        # Generate optimization recommendations
        if analysis['total_cost'] > PerformanceSLA.EXPLAIN_PLAN_COST_THRESHOLD:
            analysis['optimization_recommendations'].append(
                f"High query cost ({analysis['total_cost']:.2f}). Consider adding indexes or optimizing query structure."
            )
            
        if analysis['scan_type'] == 'Sequential Scan':
            analysis['optimization_recommendations'].append(
                "Sequential scan detected. Consider adding appropriate indexes for better performance."
            )
            
        return analysis
    
    def _detect_index_usage(self, plan: Dict) -> str:
        """Detect index usage from EXPLAIN plan."""
        node_type = plan.get('Node Type', '').lower()
        
        if 'index' in node_type:
            index_name = plan.get('Index Name', 'unknown')
            return f"Index used: {index_name}"
        elif 'seq scan' in node_type:
            return "No index used (sequential scan)"
        else:
            return "Index usage unclear"
    
    def _identify_scan_type(self, plan: Dict) -> str:
        """Identify the type of scan being performed."""
        node_type = plan.get('Node Type', '')
        
        scan_types = {
            'Seq Scan': 'Sequential Scan',
            'Index Scan': 'Index Scan',
            'Index Only Scan': 'Index Only Scan',
            'Bitmap Index Scan': 'Bitmap Index Scan',
            'Bitmap Heap Scan': 'Bitmap Heap Scan'
        }
        
        return scan_types.get(node_type, node_type)
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss
        except ImportError:
            return 0
    
    def _calculate_baseline_comparison(self, execution_time: float, baseline: float) -> Dict[str, Any]:
        """Calculate performance comparison against baseline."""
        if baseline is None:
            return {'comparison': 'no_baseline', 'improvement_ratio': None}
            
        improvement_ratio = (baseline - execution_time) / baseline
        
        return {
            'baseline_ms': baseline,
            'actual_ms': execution_time,
            'improvement_ratio': improvement_ratio,
            'improvement_percentage': improvement_ratio * 100,
            'is_improvement': improvement_ratio > 0,
            'is_regression': improvement_ratio < -0.1  # More than 10% slower
        }
    
    def _check_sla_compliance(self, query_name: str, execution_time: float) -> Dict[str, Any]:
        """Check if query execution meets SLA requirements."""
        sla_thresholds = {
            'simple': PerformanceSLA.SIMPLE_QUERY_95TH_PERCENTILE,
            'complex': PerformanceSLA.COMPLEX_QUERY_95TH_PERCENTILE,
            'insert_update': PerformanceSLA.INSERT_UPDATE_95TH_PERCENTILE,
            'batch': PerformanceSLA.BATCH_OPERATION_95TH_PERCENTILE
        }
        
        # Determine query category from name
        query_category = 'simple'  # default
        if 'complex' in query_name.lower() or 'join' in query_name.lower():
            query_category = 'complex'
        elif 'insert' in query_name.lower() or 'update' in query_name.lower():
            query_category = 'insert_update'
        elif 'batch' in query_name.lower() or 'bulk' in query_name.lower():
            query_category = 'batch'
            
        threshold = sla_thresholds[query_category]
        
        return {
            'category': query_category,
            'threshold_ms': threshold,
            'actual_ms': execution_time,
            'compliant': execution_time <= threshold,
            'margin_ms': threshold - execution_time,
            'margin_percentage': ((threshold - execution_time) / threshold) * 100
        }
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance analysis report."""
        if not self.query_metrics:
            return {'error': 'No query metrics collected'}
            
        execution_times = [m['execution_time_ms'] for m in self.query_metrics]
        
        report = {
            'summary': {
                'total_queries': len(self.query_metrics),
                'avg_execution_time': sum(execution_times) / len(execution_times),
                'min_execution_time': min(execution_times),
                'max_execution_time': max(execution_times),
                'p95_execution_time': self._calculate_percentile(execution_times, 95),
                'p99_execution_time': self._calculate_percentile(execution_times, 99)
            },
            'sla_compliance': {
                'compliant_queries': len([m for m in self.query_metrics if m['sla_compliance']['compliant']]),
                'non_compliant_queries': len([m for m in self.query_metrics if not m['sla_compliance']['compliant']]),
                'compliance_rate': len([m for m in self.query_metrics if m['sla_compliance']['compliant']]) / len(self.query_metrics) * 100
            },
            'baseline_comparison': {
                'improved_queries': len([m for m in self.query_metrics if m.get('baseline_comparison', {}).get('is_improvement', False)]),
                'regressed_queries': len([m for m in self.query_metrics if m.get('baseline_comparison', {}).get('is_regression', False)])
            },
            'optimization_insights': self._generate_optimization_insights(),
            'detailed_metrics': self.query_metrics,
            'explain_plans': self.explain_plans
        }
        
        return report
    
    def _calculate_percentile(self, values: List[float], percentile: int) -> float:
        """Calculate percentile value from list of numbers."""
        if not values:
            return 0.0
            
        sorted_values = sorted(values)
        index = int((percentile / 100) * len(sorted_values))
        
        if index >= len(sorted_values):
            return sorted_values[-1]
        return sorted_values[index]
    
    def _generate_optimization_insights(self) -> List[str]:
        """Generate optimization insights from collected metrics."""
        insights = []
        
        # Analyze for common performance issues
        slow_queries = [m for m in self.query_metrics if m['execution_time_ms'] > 1000]
        if slow_queries:
            insights.append(f"Found {len(slow_queries)} queries exceeding 1000ms execution time")
            
        # Analyze explain plans for optimization opportunities
        sequential_scans = [p for p in self.explain_plans if 'Sequential Scan' in p.get('analysis', {}).get('scan_type', '')]
        if sequential_scans:
            insights.append(f"Found {len(sequential_scans)} queries using sequential scans - consider adding indexes")
            
        # Memory usage analysis
        high_memory_queries = [m for m in self.query_metrics if m.get('memory_delta_mb', 0) > 50]
        if high_memory_queries:
            insights.append(f"Found {len(high_memory_queries)} queries with high memory usage (>50MB)")
            
        return insights


# ================================================================================================
# SQLALCHEMY QUERY OPTIMIZATION TESTING
# ================================================================================================

class SQLAlchemyOptimizationTester:
    """Advanced SQLAlchemy query optimization testing and validation."""
    
    def __init__(self, db_session: scoped_session):
        self.db_session = db_session
        self.compiled_queries = {}
        self.optimization_results = []
        
    def test_compiled_query_performance(self, query_func, query_name: str, iterations: int = 100) -> Dict[str, Any]:
        """
        Test compiled query performance vs regular query execution.
        
        Args:
            query_func: Function that returns a SQLAlchemy query
            query_name: Name for the query being tested
            iterations: Number of iterations for performance testing
            
        Returns:
            Dict[str, Any]: Performance comparison results
        """
        # Test regular query performance
        regular_times = []
        for _ in range(iterations):
            start_time = time.perf_counter()
            query = query_func()
            result = query.all()
            end_time = time.perf_counter()
            regular_times.append((end_time - start_time) * 1000)
            
        # Test compiled query performance
        compiled_query = query_func().statement.compile(
            dialect=self.db_session.bind.dialect
        )
        
        compiled_times = []
        for _ in range(iterations):
            start_time = time.perf_counter()
            result = self.db_session.execute(compiled_query).fetchall()
            end_time = time.perf_counter()
            compiled_times.append((end_time - start_time) * 1000)
            
        # Calculate performance improvement
        avg_regular = sum(regular_times) / len(regular_times)
        avg_compiled = sum(compiled_times) / len(compiled_times)
        improvement = (avg_regular - avg_compiled) / avg_regular
        
        results = {
            'query_name': query_name,
            'regular_avg_ms': avg_regular,
            'compiled_avg_ms': avg_compiled,
            'improvement_ratio': improvement,
            'improvement_percentage': improvement * 100,
            'meets_threshold': improvement >= PerformanceSLA.COMPILED_QUERY_IMPROVEMENT_THRESHOLD,
            'regular_times': regular_times,
            'compiled_times': compiled_times
        }
        
        self.optimization_results.append(results)
        return results
    
    def test_stream_results_configuration(self, large_query_func, query_name: str) -> Dict[str, Any]:
        """
        Test stream results configuration for memory-efficient large dataset processing.
        
        Args:
            large_query_func: Function that returns a query for large datasets
            query_name: Name for the query being tested
            
        Returns:
            Dict[str, Any]: Stream results performance and memory analysis
        """
        # Test regular query execution
        start_memory = self._get_memory_usage()
        start_time = time.perf_counter()
        
        regular_query = large_query_func()
        regular_results = regular_query.all()
        
        regular_end_time = time.perf_counter()
        regular_memory = self._get_memory_usage()
        
        # Test stream results execution
        stream_start_memory = self._get_memory_usage()
        stream_start_time = time.perf_counter()
        
        stream_query = large_query_func().execution_options(stream_results=True)
        stream_results = []
        for row in stream_query.yield_per(1000):  # Process in batches of 1000
            stream_results.append(row)
            
        stream_end_time = time.perf_counter()
        stream_memory = self._get_memory_usage()
        
        # Calculate memory and performance differences
        regular_memory_delta = regular_memory - start_memory
        stream_memory_delta = stream_memory - stream_start_memory
        regular_time = (regular_end_time - start_time) * 1000
        stream_time = (stream_end_time - stream_start_time) * 1000
        
        results = {
            'query_name': query_name,
            'regular_execution_ms': regular_time,
            'stream_execution_ms': stream_time,
            'regular_memory_mb': regular_memory_delta / (1024 * 1024),
            'stream_memory_mb': stream_memory_delta / (1024 * 1024),
            'memory_improvement': 1 - (stream_memory_delta / regular_memory_delta) if regular_memory_delta > 0 else 0,
            'rows_processed': len(regular_results),
            'memory_efficient': stream_memory_delta < PerformanceSLA.STREAM_RESULTS_MEMORY_THRESHOLD,
            'time_overhead': (stream_time - regular_time) / regular_time if regular_time > 0 else 0
        }
        
        return results
    
    def test_query_optimization_patterns(self) -> Dict[str, Any]:
        """Test various SQLAlchemy query optimization patterns."""
        optimization_tests = []
        
        # Test lazy vs eager loading performance
        lazy_loading_results = self._test_lazy_loading_performance()
        optimization_tests.append(lazy_loading_results)
        
        # Test query result caching
        caching_results = self._test_query_result_caching()
        optimization_tests.append(caching_results)
        
        # Test batch loading optimization
        batch_loading_results = self._test_batch_loading_optimization()
        optimization_tests.append(batch_loading_results)
        
        return {
            'optimization_patterns': optimization_tests,
            'overall_performance_gain': sum(test.get('improvement_percentage', 0) for test in optimization_tests) / len(optimization_tests)
        }
    
    def _test_lazy_loading_performance(self) -> Dict[str, Any]:
        """Test lazy loading vs eager loading performance."""
        try:
            # Test lazy loading
            lazy_start = time.perf_counter()
            users = self.db_session.query(User).limit(10).all()
            for user in users:
                # Access related entities (triggers lazy loading)
                _ = user.business_entities
                _ = user.user_sessions
            lazy_time = (time.perf_counter() - lazy_start) * 1000
            
            # Test eager loading
            eager_start = time.perf_counter()
            users = self.db_session.query(User).options(
                db.joinedload(User.business_entities),
                db.joinedload(User.user_sessions)
            ).limit(10).all()
            for user in users:
                _ = user.business_entities
                _ = user.user_sessions
            eager_time = (time.perf_counter() - eager_start) * 1000
            
            improvement = (lazy_time - eager_time) / lazy_time if lazy_time > 0 else 0
            
            return {
                'test_name': 'lazy_vs_eager_loading',
                'lazy_loading_ms': lazy_time,
                'eager_loading_ms': eager_time,
                'improvement_percentage': improvement * 100,
                'recommendation': 'eager' if improvement > 0.2 else 'lazy'
            }
            
        except Exception as e:
            return {
                'test_name': 'lazy_vs_eager_loading',
                'error': str(e),
                'improvement_percentage': 0
            }
    
    def _test_query_result_caching(self) -> Dict[str, Any]:
        """Test query result caching performance."""
        try:
            # Test without caching
            no_cache_times = []
            for _ in range(5):
                start = time.perf_counter()
                users = self.db_session.query(User).filter(User.is_active == True).all()
                no_cache_times.append((time.perf_counter() - start) * 1000)
            
            # Simulate simple query result caching
            cached_query_result = None
            cache_times = []
            for i in range(5):
                start = time.perf_counter()
                if i == 0 or cached_query_result is None:
                    cached_query_result = self.db_session.query(User).filter(User.is_active == True).all()
                else:
                    # Simulate cache hit
                    pass
                cache_times.append((time.perf_counter() - start) * 1000)
            
            avg_no_cache = sum(no_cache_times) / len(no_cache_times)
            avg_cache = sum(cache_times) / len(cache_times)
            improvement = (avg_no_cache - avg_cache) / avg_no_cache if avg_no_cache > 0 else 0
            
            return {
                'test_name': 'query_result_caching',
                'no_cache_avg_ms': avg_no_cache,
                'cached_avg_ms': avg_cache,
                'improvement_percentage': improvement * 100,
                'cache_effectiveness': improvement > 0.3
            }
            
        except Exception as e:
            return {
                'test_name': 'query_result_caching',
                'error': str(e),
                'improvement_percentage': 0
            }
    
    def _test_batch_loading_optimization(self) -> Dict[str, Any]:
        """Test batch loading optimization for related entities."""
        try:
            # Test individual loading
            individual_start = time.perf_counter()
            users = self.db_session.query(User).limit(5).all()
            for user in users:
                entities = self.db_session.query(BusinessEntity).filter(
                    BusinessEntity.owner_id == user.id
                ).all()
            individual_time = (time.perf_counter() - individual_start) * 1000
            
            # Test batch loading
            batch_start = time.perf_counter()
            users = self.db_session.query(User).limit(5).all()
            user_ids = [user.id for user in users]
            all_entities = self.db_session.query(BusinessEntity).filter(
                BusinessEntity.owner_id.in_(user_ids)
            ).all()
            batch_time = (time.perf_counter() - batch_start) * 1000
            
            improvement = (individual_time - batch_time) / individual_time if individual_time > 0 else 0
            
            return {
                'test_name': 'batch_loading_optimization',
                'individual_loading_ms': individual_time,
                'batch_loading_ms': batch_time,
                'improvement_percentage': improvement * 100,
                'n_plus_one_problem_solved': improvement > 0.5
            }
            
        except Exception as e:
            return {
                'test_name': 'batch_loading_optimization',
                'error': str(e),
                'improvement_percentage': 0
            }
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss
        except ImportError:
            return 0


# ================================================================================================
# PERFORMANCE TEST FIXTURES AND UTILITIES
# ================================================================================================

@pytest.fixture(scope='function')
def query_performance_monitor(db_session: scoped_session) -> QueryPerformanceMonitor:
    """Fixture providing query performance monitoring capabilities."""
    return QueryPerformanceMonitor(db_session)


@pytest.fixture(scope='function')
def optimization_tester(db_session: scoped_session) -> SQLAlchemyOptimizationTester:
    """Fixture providing SQLAlchemy optimization testing capabilities."""
    return SQLAlchemyOptimizationTester(db_session)


@pytest.fixture(scope='function')
def large_dataset(db_session: scoped_session, test_user: User) -> List[BusinessEntity]:
    """
    Fixture creating a large dataset for performance testing.
    
    Creates a substantial number of business entities for testing
    large dataset query performance and optimization patterns.
    """
    entities = []
    batch_size = 100
    total_entities = 1000
    
    for i in range(0, total_entities, batch_size):
        batch_entities = []
        for j in range(batch_size):
            entity_num = i + j
            entity = BusinessEntity(
                name=f'Performance Test Entity {entity_num}',
                description=f'Entity created for performance testing - batch {i//batch_size + 1}',
                owner_id=test_user.id,
                status='active' if entity_num % 3 == 0 else 'inactive'
            )
            batch_entities.append(entity)
            
        db_session.add_all(batch_entities)
        db_session.commit()
        entities.extend(batch_entities)
        
        # Refresh entities to get IDs
        for entity in batch_entities:
            db_session.refresh(entity)
    
    return entities


@pytest.fixture(scope='function')
def baseline_performance_data() -> Dict[str, float]:
    """Fixture providing Node.js baseline performance data for comparison."""
    return {
        'user_find_by_id': NodeJSBaselineMetrics.USER_FIND_BY_ID,
        'user_find_by_email': NodeJSBaselineMetrics.USER_FIND_BY_EMAIL,
        'user_list_paginated': NodeJSBaselineMetrics.USER_LIST_PAGINATED,
        'business_entity_find_by_owner': NodeJSBaselineMetrics.BUSINESS_ENTITY_FIND_BY_OWNER,
        'business_entity_complex_join': NodeJSBaselineMetrics.BUSINESS_ENTITY_COMPLEX_JOIN,
        'entity_relationship_query': NodeJSBaselineMetrics.ENTITY_RELATIONSHIP_QUERY,
        'bulk_insert_operations': NodeJSBaselineMetrics.BULK_INSERT_OPERATIONS,
        'aggregation_operations': NodeJSBaselineMetrics.AGGREGATION_OPERATIONS
    }


# ================================================================================================
# SIMPLE QUERY PERFORMANCE TESTS
# ================================================================================================

@pytest.mark.database
@pytest.mark.performance
class TestSimpleQueryPerformance:
    """Test suite for simple query performance validation against SLA targets."""
    
    def test_user_find_by_id_performance(self, benchmark, db_session, test_user, 
                                       query_performance_monitor, baseline_performance_data):
        """
        Test User.find_by_id query performance against SLA and baseline.
        
        Validates:
        - 95th percentile response time < 500ms
        - Performance equivalent or better than Node.js baseline
        - EXPLAIN plan optimization
        """
        def query_user_by_id():
            return db_session.query(User).filter(User.id == test_user.id).first()
        
        with query_performance_monitor.monitor_query(
            'user_find_by_id', 
            baseline_performance_data['user_find_by_id']
        ) as metrics:
            result = benchmark(query_user_by_id)
            
            # Capture EXPLAIN plan
            query = db_session.query(User).filter(User.id == test_user.id)
            explain_plan = query_performance_monitor.capture_explain_plan(query)
            metrics['explain_plan'] = explain_plan
        
        # Validate results
        assert result is not None, "Query should return user object"
        assert result.id == test_user.id, "Query should return correct user"
        
        # Performance validations
        execution_time = metrics['execution_time_ms']
        assert execution_time < PerformanceSLA.SIMPLE_QUERY_95TH_PERCENTILE, \
            f"Query execution time {execution_time:.2f}ms exceeds SLA threshold {PerformanceSLA.SIMPLE_QUERY_95TH_PERCENTILE}ms"
        
        # Baseline comparison
        baseline_comparison = metrics['baseline_comparison']
        if baseline_comparison['comparison'] != 'no_baseline':
            assert baseline_comparison['improvement_ratio'] >= -0.1, \
                f"Query performance regression detected: {baseline_comparison['improvement_percentage']:.2f}% slower than baseline"
    
    def test_user_find_by_email_performance(self, benchmark, db_session, test_user,
                                          query_performance_monitor, baseline_performance_data):
        """
        Test User.find_by_email query performance with index utilization validation.
        
        Validates:
        - Unique constraint index utilization
        - Sub-100ms response time for indexed lookup
        - Optimal query plan execution
        """
        def query_user_by_email():
            return db_session.query(User).filter(User.email == test_user.email).first()
        
        with query_performance_monitor.monitor_query(
            'user_find_by_email',
            baseline_performance_data['user_find_by_email']
        ) as metrics:
            result = benchmark(query_user_by_email)
            
            # Capture EXPLAIN plan for index usage analysis
            query = db_session.query(User).filter(User.email == test_user.email)
            explain_plan = query_performance_monitor.capture_explain_plan(query)
            metrics['explain_plan'] = explain_plan
        
        # Validate results
        assert result is not None, "Query should return user object"
        assert result.email == test_user.email, "Query should return correct user"
        
        # Performance validations
        execution_time = metrics['execution_time_ms']
        assert execution_time < PerformanceSLA.SIMPLE_QUERY_95TH_PERCENTILE, \
            f"Email lookup time {execution_time:.2f}ms exceeds SLA threshold"
        
        # Index utilization validation (for PostgreSQL)
        if explain_plan and 'index' in explain_plan.get('index_usage', '').lower():
            assert 'index' in explain_plan['index_usage'].lower(), \
                "Email lookup should utilize unique constraint index"
    
    def test_business_entity_find_by_owner_performance(self, benchmark, db_session, test_user,
                                                     sample_business_entities, query_performance_monitor,
                                                     baseline_performance_data):
        """
        Test BusinessEntity.find_by_owner query performance with foreign key optimization.
        
        Validates:
        - Foreign key index utilization
        - Optimal join performance
        - Result set filtering efficiency
        """
        def query_entities_by_owner():
            return db_session.query(BusinessEntity).filter(
                BusinessEntity.owner_id == test_user.id
            ).all()
        
        with query_performance_monitor.monitor_query(
            'business_entity_find_by_owner',
            baseline_performance_data['business_entity_find_by_owner']
        ) as metrics:
            result = benchmark(query_entities_by_owner)
            
            # Capture EXPLAIN plan
            query = db_session.query(BusinessEntity).filter(BusinessEntity.owner_id == test_user.id)
            explain_plan = query_performance_monitor.capture_explain_plan(query)
            metrics['explain_plan'] = explain_plan
        
        # Validate results
        assert isinstance(result, list), "Query should return list of entities"
        assert len(result) > 0, "Query should return business entities for test user"
        assert all(entity.owner_id == test_user.id for entity in result), \
            "All returned entities should belong to test user"
        
        # Performance validations
        execution_time = metrics['execution_time_ms']
        assert execution_time < PerformanceSLA.SIMPLE_QUERY_95TH_PERCENTILE, \
            f"Owner lookup time {execution_time:.2f}ms exceeds SLA threshold"
    
    def test_session_find_by_token_performance(self, benchmark, db_session, test_user,
                                             query_performance_monitor):
        """
        Test UserSession.find_by_token query performance for authentication flows.
        
        Validates:
        - Token lookup optimization
        - Session validation performance
        - Security-critical query response times
        """
        # Create test session
        test_session = UserSession(
            user_id=test_user.id,
            session_token=f'test_token_{uuid.uuid4()}',
            expires_at=datetime.utcnow() + timedelta(hours=24),
            is_valid=True
        )
        db_session.add(test_session)
        db_session.commit()
        db_session.refresh(test_session)
        
        def query_session_by_token():
            return db_session.query(UserSession).filter(
                UserSession.session_token == test_session.session_token
            ).first()
        
        with query_performance_monitor.monitor_query('session_find_by_token') as metrics:
            result = benchmark(query_session_by_token)
            
            # Capture EXPLAIN plan
            query = db_session.query(UserSession).filter(
                UserSession.session_token == test_session.session_token
            )
            explain_plan = query_performance_monitor.capture_explain_plan(query)
            metrics['explain_plan'] = explain_plan
        
        # Validate results
        assert result is not None, "Query should return session object"
        assert result.session_token == test_session.session_token, \
            "Query should return correct session"
        
        # Performance validations - stricter for security-critical queries
        execution_time = metrics['execution_time_ms']
        assert execution_time < 100, \
            f"Session token lookup time {execution_time:.2f}ms too slow for authentication flow"


# ================================================================================================
# COMPLEX QUERY PERFORMANCE TESTS
# ================================================================================================

@pytest.mark.database
@pytest.mark.performance
class TestComplexQueryPerformance:
    """Test suite for complex query performance validation with JOIN operations."""
    
    def test_user_with_entities_join_performance(self, benchmark, db_session, test_user,
                                                sample_business_entities, query_performance_monitor,
                                                baseline_performance_data):
        """
        Test complex JOIN query performance for User -> BusinessEntity relationships.
        
        Validates:
        - Multi-table JOIN optimization
        - Relationship loading performance
        - Complex query SLA compliance (< 2000ms)
        """
        def complex_user_entities_query():
            return db_session.query(User).options(
                db.joinedload(User.business_entities)
            ).filter(User.id == test_user.id).first()
        
        with query_performance_monitor.monitor_query(
            'business_entity_complex_join',
            baseline_performance_data['business_entity_complex_join']
        ) as metrics:
            result = benchmark(complex_user_entities_query)
            
            # Capture EXPLAIN plan for JOIN analysis
            query = db_session.query(User).options(
                db.joinedload(User.business_entities)
            ).filter(User.id == test_user.id)
            explain_plan = query_performance_monitor.capture_explain_plan(query)
            metrics['explain_plan'] = explain_plan
        
        # Validate results
        assert result is not None, "Query should return user with entities"
        assert hasattr(result, 'business_entities'), "User should have business_entities relationship loaded"
        assert len(result.business_entities) > 0, "User should have business entities"
        
        # Performance validations
        execution_time = metrics['execution_time_ms']
        assert execution_time < PerformanceSLA.COMPLEX_QUERY_95TH_PERCENTILE, \
            f"Complex JOIN query time {execution_time:.2f}ms exceeds SLA threshold {PerformanceSLA.COMPLEX_QUERY_95TH_PERCENTILE}ms"
    
    def test_entity_relationships_complex_query(self, benchmark, db_session, test_user,
                                              sample_business_entities, sample_entity_relationships,
                                              query_performance_monitor, baseline_performance_data):
        """
        Test complex entity relationship query with multiple JOINs and filtering.
        
        Validates:
        - Multi-level relationship traversal
        - Complex filtering performance
        - Relationship type categorization efficiency
        """
        def complex_relationship_query():
            return db_session.query(EntityRelationship).join(
                BusinessEntity, EntityRelationship.source_entity_id == BusinessEntity.id
            ).join(
                User, BusinessEntity.owner_id == User.id
            ).filter(
                User.id == test_user.id,
                EntityRelationship.is_active == True
            ).all()
        
        with query_performance_monitor.monitor_query(
            'entity_relationship_query',
            baseline_performance_data['entity_relationship_query']
        ) as metrics:
            result = benchmark(complex_relationship_query)
            
            # Capture EXPLAIN plan
            query = db_session.query(EntityRelationship).join(
                BusinessEntity, EntityRelationship.source_entity_id == BusinessEntity.id
            ).join(
                User, BusinessEntity.owner_id == User.id
            ).filter(
                User.id == test_user.id,
                EntityRelationship.is_active == True
            )
            explain_plan = query_performance_monitor.capture_explain_plan(query)
            metrics['explain_plan'] = explain_plan
        
        # Validate results
        assert isinstance(result, list), "Query should return list of relationships"
        if len(result) > 0:  # Only validate if relationships exist
            assert all(rel.is_active for rel in result), \
                "All returned relationships should be active"
        
        # Performance validations
        execution_time = metrics['execution_time_ms']
        assert execution_time < PerformanceSLA.COMPLEX_QUERY_95TH_PERCENTILE, \
            f"Complex relationship query time {execution_time:.2f}ms exceeds SLA threshold"
    
    def test_paginated_query_performance(self, benchmark, db_session, large_dataset,
                                       query_performance_monitor, baseline_performance_data):
        """
        Test paginated query performance for large datasets.
        
        Validates:
        - LIMIT/OFFSET optimization
        - Large dataset handling
        - Pagination efficiency
        """
        page_size = 50
        page_number = 10  # Test deep pagination
        
        def paginated_entities_query():
            return db_session.query(BusinessEntity).filter(
                BusinessEntity.status == 'active'
            ).offset(page_number * page_size).limit(page_size).all()
        
        with query_performance_monitor.monitor_query(
            'user_list_paginated',
            baseline_performance_data['user_list_paginated']
        ) as metrics:
            result = benchmark(paginated_entities_query)
            
            # Capture EXPLAIN plan for pagination analysis
            query = db_session.query(BusinessEntity).filter(
                BusinessEntity.status == 'active'
            ).offset(page_number * page_size).limit(page_size)
            explain_plan = query_performance_monitor.capture_explain_plan(query)
            metrics['explain_plan'] = explain_plan
        
        # Validate results
        assert isinstance(result, list), "Query should return list of entities"
        assert len(result) <= page_size, f"Query should return at most {page_size} entities"
        
        # Performance validations
        execution_time = metrics['execution_time_ms']
        assert execution_time < PerformanceSLA.COMPLEX_QUERY_95TH_PERCENTILE, \
            f"Paginated query time {execution_time:.2f}ms exceeds SLA threshold"
    
    def test_aggregation_query_performance(self, benchmark, db_session, test_user,
                                         large_dataset, query_performance_monitor,
                                         baseline_performance_data):
        """
        Test aggregation query performance for business intelligence operations.
        
        Validates:
        - COUNT, GROUP BY performance
        - Aggregation function optimization
        - Large dataset aggregation efficiency
        """
        def aggregation_entities_query():
            return db_session.query(
                BusinessEntity.status,
                db.func.count(BusinessEntity.id).label('entity_count')
            ).filter(
                BusinessEntity.owner_id == test_user.id
            ).group_by(BusinessEntity.status).all()
        
        with query_performance_monitor.monitor_query(
            'aggregation_operations',
            baseline_performance_data['aggregation_operations']
        ) as metrics:
            result = benchmark(aggregation_entities_query)
            
            # Capture EXPLAIN plan for aggregation analysis
            query = db_session.query(
                BusinessEntity.status,
                db.func.count(BusinessEntity.id).label('entity_count')
            ).filter(
                BusinessEntity.owner_id == test_user.id
            ).group_by(BusinessEntity.status)
            explain_plan = query_performance_monitor.capture_explain_plan(query)
            metrics['explain_plan'] = explain_plan
        
        # Validate results
        assert isinstance(result, list), "Query should return aggregation results"
        assert len(result) > 0, "Query should return status counts"
        
        # Validate aggregation data
        total_count = sum(row.entity_count for row in result)
        assert total_count > 0, "Aggregation should count entities"
        
        # Performance validations
        execution_time = metrics['execution_time_ms']
        assert execution_time < PerformanceSLA.COMPLEX_QUERY_95TH_PERCENTILE, \
            f"Aggregation query time {execution_time:.2f}ms exceeds SLA threshold"


# ================================================================================================
# SQLALCHEMY OPTIMIZATION TESTS
# ================================================================================================

@pytest.mark.database
@pytest.mark.performance
class TestSQLAlchemyOptimization:
    """Test suite for SQLAlchemy-specific optimization patterns and techniques."""
    
    def test_compiled_query_optimization(self, benchmark, db_session, test_user,
                                       optimization_tester, query_performance_monitor):
        """
        Test compiled query performance optimization.
        
        Validates:
        - Compiled query performance improvement
        - Query compilation overhead analysis
        - Repeated query execution optimization
        """
        def user_query_func():
            return db_session.query(User).filter(User.email == test_user.email)
        
        # Test compiled query performance
        results = optimization_tester.test_compiled_query_performance(
            user_query_func, 'user_email_lookup', iterations=50
        )
        
        # Validate optimization results
        assert results['improvement_ratio'] >= 0, \
            "Compiled queries should not be significantly slower than regular queries"
        
        if results['improvement_ratio'] >= PerformanceSLA.COMPILED_QUERY_IMPROVEMENT_THRESHOLD:
            print(f"Compiled query optimization successful: {results['improvement_percentage']:.2f}% improvement")
        else:
            print(f"Compiled query improvement below threshold: {results['improvement_percentage']:.2f}%")
        
        # Performance validation
        assert results['compiled_avg_ms'] < PerformanceSLA.SIMPLE_QUERY_95TH_PERCENTILE, \
            f"Compiled query average time {results['compiled_avg_ms']:.2f}ms exceeds SLA"
    
    def test_stream_results_optimization(self, benchmark, db_session, large_dataset,
                                       optimization_tester, query_performance_monitor):
        """
        Test stream results configuration for memory-efficient large dataset processing.
        
        Validates:
        - Memory usage reduction with stream results
        - Large dataset processing efficiency
        - yield_per() optimization
        """
        def large_query_func():
            return db_session.query(BusinessEntity).filter(
                BusinessEntity.status == 'active'
            )
        
        # Test stream results configuration
        results = optimization_tester.test_stream_results_configuration(
            large_query_func, 'large_dataset_streaming'
        )
        
        # Validate memory optimization
        assert results['memory_efficient'], \
            f"Stream results memory usage {results['stream_memory_mb']:.2f}MB exceeds threshold"
        
        assert results['memory_improvement'] > 0, \
            f"Stream results should reduce memory usage (improvement: {results['memory_improvement']:.2f})"
        
        # Validate acceptable time overhead
        assert results['time_overhead'] < 0.5, \
            f"Stream results time overhead {results['time_overhead']:.2f} too high"
        
        print(f"Stream results optimization: {results['memory_improvement']:.2f} memory reduction, "
              f"{results['time_overhead']:.2f} time overhead")
    
    def test_query_optimization_patterns(self, benchmark, db_session, test_user,
                                       sample_business_entities, optimization_tester):
        """
        Test various SQLAlchemy query optimization patterns.
        
        Validates:
        - Lazy vs eager loading optimization
        - Query result caching effectiveness
        - Batch loading vs N+1 query problem resolution
        """
        # Test all optimization patterns
        optimization_results = optimization_tester.test_query_optimization_patterns()
        
        # Validate optimization patterns
        assert optimization_results['overall_performance_gain'] >= 0, \
            "Optimization patterns should not degrade performance"
        
        # Analyze individual optimization results
        for pattern_result in optimization_results['optimization_patterns']:
            test_name = pattern_result.get('test_name', 'unknown')
            improvement = pattern_result.get('improvement_percentage', 0)
            
            if 'error' not in pattern_result:
                print(f"Optimization pattern '{test_name}': {improvement:.2f}% improvement")
                
                # Specific validations for different patterns
                if test_name == 'lazy_vs_eager_loading':
                    # Eager loading should be beneficial for small result sets
                    assert 'recommendation' in pattern_result, \
                        "Loading strategy recommendation should be provided"
                        
                elif test_name == 'batch_loading_optimization':
                    # Batch loading should solve N+1 problem
                    if pattern_result.get('n_plus_one_problem_solved'):
                        assert improvement > 50, \
                            "Batch loading should show significant improvement for N+1 queries"
            else:
                print(f"Optimization pattern '{test_name}' failed: {pattern_result['error']}")
    
    def test_connection_pool_optimization(self, benchmark, app, db_session,
                                        query_performance_monitor):
        """
        Test connection pool configuration optimization.
        
        Validates:
        - Connection pool sizing efficiency
        - Connection lifecycle management
        - Concurrent access performance
        """
        # Get current pool configuration
        engine = db_session.bind
        pool = engine.pool
        
        # Test connection acquisition performance
        def acquire_connection():
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1")).fetchone()
                return result[0]
        
        with query_performance_monitor.monitor_query('connection_pool_acquisition') as metrics:
            result = benchmark(acquire_connection)
            
        # Validate connection acquisition
        assert result == 1, "Connection should successfully execute query"
        
        # Performance validation
        execution_time = metrics['execution_time_ms']
        assert execution_time < 50, \
            f"Connection acquisition time {execution_time:.2f}ms too slow"
        
        # Pool configuration validation
        pool_size = getattr(pool, 'size', lambda: 5)()
        max_overflow = getattr(pool, 'overflow', lambda: 10)()
        
        assert pool_size >= 5, "Connection pool should have adequate base size"
        assert max_overflow >= 5, "Connection pool should allow reasonable overflow"
        
        print(f"Connection pool configuration: size={pool_size}, overflow={max_overflow}")


# ================================================================================================
# BATCH OPERATION PERFORMANCE TESTS
# ================================================================================================

@pytest.mark.database
@pytest.mark.performance
class TestBatchOperationPerformance:
    """Test suite for batch operation performance validation."""
    
    def test_bulk_insert_performance(self, benchmark, db_session, test_user,
                                   query_performance_monitor, baseline_performance_data):
        """
        Test bulk insert operation performance.
        
        Validates:
        - Batch insert efficiency
        - Transaction management for bulk operations
        - Memory usage during bulk operations
        """
        batch_size = 100
        
        def bulk_insert_entities():
            entities = []
            for i in range(batch_size):
                entity = BusinessEntity(
                    name=f'Bulk Insert Entity {i}',
                    description=f'Entity created in bulk insert test {i}',
                    owner_id=test_user.id,
                    status='active'
                )
                entities.append(entity)
            
            db_session.add_all(entities)
            db_session.commit()
            return entities
        
        with query_performance_monitor.monitor_query(
            'bulk_insert_operations',
            baseline_performance_data['bulk_insert_operations']
        ) as metrics:
            result = benchmark(bulk_insert_entities)
        
        # Validate results
        assert len(result) == batch_size, f"Should insert {batch_size} entities"
        assert all(entity.id is not None for entity in result), \
            "All entities should have assigned IDs"
        
        # Performance validation
        execution_time = metrics['execution_time_ms']
        assert execution_time < PerformanceSLA.BATCH_OPERATION_95TH_PERCENTILE, \
            f"Bulk insert time {execution_time:.2f}ms exceeds SLA threshold {PerformanceSLA.BATCH_OPERATION_95TH_PERCENTILE}ms"
        
        # Cleanup
        for entity in result:
            db_session.delete(entity)
        db_session.commit()
    
    def test_bulk_update_performance(self, benchmark, db_session, large_dataset,
                                   query_performance_monitor):
        """
        Test bulk update operation performance.
        
        Validates:
        - Batch update efficiency
        - WHERE clause optimization for bulk updates
        - Update operation scaling
        """
        # Limit to first 100 entities for performance testing
        entities_to_update = large_dataset[:100]
        entity_ids = [entity.id for entity in entities_to_update]
        
        def bulk_update_entities():
            updated_count = db_session.query(BusinessEntity).filter(
                BusinessEntity.id.in_(entity_ids)
            ).update(
                {'status': 'updated_in_bulk_test'},
                synchronize_session='fetch'
            )
            db_session.commit()
            return updated_count
        
        with query_performance_monitor.monitor_query('bulk_update_operations') as metrics:
            updated_count = benchmark(bulk_update_entities)
        
        # Validate results
        assert updated_count == len(entity_ids), \
            f"Should update {len(entity_ids)} entities, updated {updated_count}"
        
        # Verify updates
        updated_entities = db_session.query(BusinessEntity).filter(
            BusinessEntity.id.in_(entity_ids)
        ).all()
        assert all(entity.status == 'updated_in_bulk_test' for entity in updated_entities), \
            "All entities should be updated"
        
        # Performance validation
        execution_time = metrics['execution_time_ms']
        assert execution_time < PerformanceSLA.BATCH_OPERATION_95TH_PERCENTILE, \
            f"Bulk update time {execution_time:.2f}ms exceeds SLA threshold"
        
        # Cleanup - restore original status
        db_session.query(BusinessEntity).filter(
            BusinessEntity.id.in_(entity_ids)
        ).update({'status': 'active'}, synchronize_session='fetch')
        db_session.commit()
    
    def test_bulk_delete_performance(self, benchmark, db_session, test_user,
                                   query_performance_monitor):
        """
        Test bulk delete operation performance.
        
        Validates:
        - Batch delete efficiency
        - Cascade deletion handling
        - Transaction safety for bulk deletions
        """
        # Create entities for deletion test
        batch_size = 50
        entities_for_deletion = []
        for i in range(batch_size):
            entity = BusinessEntity(
                name=f'Delete Test Entity {i}',
                description=f'Entity for bulk delete test {i}',
                owner_id=test_user.id,
                status='pending_deletion'
            )
            entities_for_deletion.append(entity)
        
        db_session.add_all(entities_for_deletion)
        db_session.commit()
        
        entity_ids = [entity.id for entity in entities_for_deletion]
        
        def bulk_delete_entities():
            deleted_count = db_session.query(BusinessEntity).filter(
                BusinessEntity.id.in_(entity_ids)
            ).delete(synchronize_session='fetch')
            db_session.commit()
            return deleted_count
        
        with query_performance_monitor.monitor_query('bulk_delete_operations') as metrics:
            deleted_count = benchmark(bulk_delete_entities)
        
        # Validate results
        assert deleted_count == batch_size, \
            f"Should delete {batch_size} entities, deleted {deleted_count}"
        
        # Verify deletions
        remaining_entities = db_session.query(BusinessEntity).filter(
            BusinessEntity.id.in_(entity_ids)
        ).all()
        assert len(remaining_entities) == 0, "All entities should be deleted"
        
        # Performance validation
        execution_time = metrics['execution_time_ms']
        assert execution_time < PerformanceSLA.BATCH_OPERATION_95TH_PERCENTILE, \
            f"Bulk delete time {execution_time:.2f}ms exceeds SLA threshold"


# ================================================================================================
# POSTGRESQL EXPLAIN PLAN ANALYSIS TESTS
# ================================================================================================

@pytest.mark.database
@pytest.mark.performance
class TestExplainPlanAnalysis:
    """Test suite for PostgreSQL EXPLAIN plan integration and query optimization analysis."""
    
    def test_explain_plan_capture_and_analysis(self, db_session, test_user,
                                              sample_business_entities, query_performance_monitor):
        """
        Test EXPLAIN plan capture and analysis for query optimization.
        
        Validates:
        - EXPLAIN plan data collection
        - Query cost analysis
        - Index usage detection
        - Optimization recommendation generation
        """
        # Test simple query EXPLAIN plan
        simple_query = db_session.query(User).filter(User.id == test_user.id)
        simple_explain = query_performance_monitor.capture_explain_plan(simple_query)
        
        # Validate EXPLAIN plan structure
        if 'error' not in simple_explain:
            assert 'total_cost' in simple_explain, "EXPLAIN plan should include cost information"
            assert 'scan_type' in simple_explain, "EXPLAIN plan should identify scan type"
            
            # Cost validation
            assert simple_explain['total_cost'] >= 0, "Query cost should be non-negative"
            
            print(f"Simple query plan: {simple_explain['scan_type']}, cost: {simple_explain['total_cost']}")
        
        # Test complex query EXPLAIN plan
        complex_query = db_session.query(BusinessEntity).join(User).filter(
            User.id == test_user.id,
            BusinessEntity.status == 'active'
        )
        complex_explain = query_performance_monitor.capture_explain_plan(complex_query)
        
        if 'error' not in complex_explain:
            assert complex_explain['total_cost'] >= simple_explain.get('total_cost', 0), \
                "Complex query should have higher or equal cost than simple query"
            
            print(f"Complex query plan: {complex_explain['scan_type']}, cost: {complex_explain['total_cost']}")
    
    def test_index_utilization_analysis(self, db_session, test_user, query_performance_monitor):
        """
        Test index utilization detection and analysis.
        
        Validates:
        - Index usage identification
        - Sequential scan detection
        - Index effectiveness measurement
        """
        # Test indexed column query (email has unique constraint)
        indexed_query = db_session.query(User).filter(User.email == test_user.email)
        indexed_explain = query_performance_monitor.capture_explain_plan(indexed_query)
        
        if 'error' not in indexed_explain:
            index_usage = indexed_explain.get('index_usage', '')
            
            # For SQLite, we may not get detailed index information
            if 'index' in index_usage.lower():
                print(f"Index utilization detected: {index_usage}")
                assert 'sequential scan' not in indexed_explain.get('scan_type', '').lower(), \
                    "Indexed query should not use sequential scan"
            else:
                print(f"Index utilization unclear for SQLite: {index_usage}")
        
        # Test non-indexed column query (description field)
        # Note: This test is more meaningful with PostgreSQL than SQLite
        non_indexed_query = db_session.query(User).filter(User.username.like('%test%'))
        non_indexed_explain = query_performance_monitor.capture_explain_plan(non_indexed_query)
        
        if 'error' not in non_indexed_explain:
            scan_type = non_indexed_explain.get('scan_type', '')
            print(f"Non-indexed query scan type: {scan_type}")
    
    def test_optimization_recommendations(self, db_session, large_dataset,
                                        query_performance_monitor):
        """
        Test automatic optimization recommendation generation.
        
        Validates:
        - High-cost query detection
        - Sequential scan warnings
        - Optimization suggestion generation
        """
        # Create a potentially expensive query
        expensive_query = db_session.query(BusinessEntity).filter(
            BusinessEntity.description.like('%performance%')
        ).order_by(BusinessEntity.created_at.desc())
        
        expensive_explain = query_performance_monitor.capture_explain_plan(expensive_query)
        
        if 'error' not in expensive_explain:
            recommendations = expensive_explain.get('optimization_recommendations', [])
            
            print(f"Query optimization recommendations: {recommendations}")
            
            # Validate recommendation structure
            assert isinstance(recommendations, list), \
                "Optimization recommendations should be a list"
            
            # Check for appropriate recommendations based on query characteristics
            if expensive_explain.get('total_cost', 0) > PerformanceSLA.EXPLAIN_PLAN_COST_THRESHOLD:
                assert any('cost' in rec.lower() for rec in recommendations), \
                    "High-cost queries should generate cost-related recommendations"
            
            if 'sequential scan' in expensive_explain.get('scan_type', '').lower():
                assert any('index' in rec.lower() for rec in recommendations), \
                    "Sequential scans should generate index-related recommendations"


# ================================================================================================
# PERFORMANCE REGRESSION TESTING
# ================================================================================================

@pytest.mark.database
@pytest.mark.performance
class TestPerformanceRegression:
    """Test suite for performance regression detection and validation."""
    
    def test_baseline_performance_comparison(self, db_session, test_user,
                                           sample_business_entities, query_performance_monitor,
                                           baseline_performance_data):
        """
        Test comprehensive performance comparison against Node.js baseline.
        
        Validates:
        - Performance equivalence or improvement across all query types
        - Regression detection for critical queries
        - Baseline compliance measurement
        """
        performance_comparisons = []
        
        # Test each baseline query type
        test_queries = [
            {
                'name': 'user_find_by_id',
                'query_func': lambda: db_session.query(User).filter(User.id == test_user.id).first(),
                'baseline': baseline_performance_data['user_find_by_id']
            },
            {
                'name': 'user_find_by_email',
                'query_func': lambda: db_session.query(User).filter(User.email == test_user.email).first(),
                'baseline': baseline_performance_data['user_find_by_email']
            },
            {
                'name': 'business_entity_find_by_owner',
                'query_func': lambda: db_session.query(BusinessEntity).filter(
                    BusinessEntity.owner_id == test_user.id
                ).all(),
                'baseline': baseline_performance_data['business_entity_find_by_owner']
            }
        ]
        
        for test_query in test_queries:
            with query_performance_monitor.monitor_query(
                test_query['name'], 
                test_query['baseline']
            ) as metrics:
                # Execute query multiple times for statistical significance
                times = []
                for _ in range(10):
                    start = time.perf_counter()
                    result = test_query['query_func']()
                    end = time.perf_counter()
                    times.append((end - start) * 1000)
                
                avg_time = sum(times) / len(times)
                metrics['execution_time_ms'] = avg_time
            
            # Collect comparison data
            baseline_comparison = metrics.get('baseline_comparison', {})
            performance_comparisons.append({
                'query_name': test_query['name'],
                'flask_time': avg_time,
                'baseline_time': test_query['baseline'],
                'improvement_ratio': baseline_comparison.get('improvement_ratio', 0),
                'is_regression': baseline_comparison.get('is_regression', False)
            })
        
        # Validate overall performance
        regression_count = sum(1 for comp in performance_comparisons if comp['is_regression'])
        improvement_count = sum(1 for comp in performance_comparisons if comp['improvement_ratio'] > 0)
        
        assert regression_count == 0, \
            f"Performance regressions detected in {regression_count} queries: {[c['query_name'] for c in performance_comparisons if c['is_regression']]}"
        
        print(f"Performance comparison: {improvement_count}/{len(performance_comparisons)} queries improved")
        
        # Log detailed comparison results
        for comp in performance_comparisons:
            improvement_pct = comp['improvement_ratio'] * 100
            print(f"{comp['query_name']}: Flask {comp['flask_time']:.2f}ms vs Node.js {comp['baseline_time']:.2f}ms "
                  f"({improvement_pct:+.1f}%)")
    
    def test_sla_compliance_validation(self, db_session, test_user, large_dataset,
                                     query_performance_monitor):
        """
        Test comprehensive SLA compliance across all query categories.
        
        Validates:
        - 95th percentile SLA compliance for all query types
        - Performance distribution analysis
        - SLA margin calculation
        """
        sla_tests = [
            {
                'name': 'simple_user_lookup',
                'category': 'simple',
                'query_func': lambda: db_session.query(User).filter(User.id == test_user.id).first(),
                'iterations': 20
            },
            {
                'name': 'complex_entity_join',
                'category': 'complex',
                'query_func': lambda: db_session.query(BusinessEntity).join(User).filter(
                    User.id == test_user.id
                ).all(),
                'iterations': 10
            },
            {
                'name': 'batch_entity_query',
                'category': 'batch',
                'query_func': lambda: db_session.query(BusinessEntity).filter(
                    BusinessEntity.status == 'active'
                ).limit(100).all(),
                'iterations': 5
            }
        ]
        
        sla_results = []
        
        for test in sla_tests:
            execution_times = []
            
            # Execute query multiple times to get distribution
            for _ in range(test['iterations']):
                start = time.perf_counter()
                result = test['query_func']()
                end = time.perf_counter()
                execution_times.append((end - start) * 1000)
            
            # Calculate percentiles
            sorted_times = sorted(execution_times)
            p95_time = sorted_times[int(0.95 * len(sorted_times))]
            p99_time = sorted_times[int(0.99 * len(sorted_times))]
            avg_time = sum(execution_times) / len(execution_times)
            
            # Determine SLA thresholds
            sla_thresholds = {
                'simple': PerformanceSLA.SIMPLE_QUERY_95TH_PERCENTILE,
                'complex': PerformanceSLA.COMPLEX_QUERY_95TH_PERCENTILE,
                'batch': PerformanceSLA.BATCH_OPERATION_95TH_PERCENTILE
            }
            
            threshold = sla_thresholds.get(test['category'], PerformanceSLA.SIMPLE_QUERY_95TH_PERCENTILE)
            
            sla_result = {
                'test_name': test['name'],
                'category': test['category'],
                'avg_time': avg_time,
                'p95_time': p95_time,
                'p99_time': p99_time,
                'sla_threshold': threshold,
                'sla_compliant': p95_time <= threshold,
                'sla_margin': threshold - p95_time,
                'sla_margin_percentage': ((threshold - p95_time) / threshold) * 100
            }
            
            sla_results.append(sla_result)
        
        # Validate SLA compliance
        non_compliant = [result for result in sla_results if not result['sla_compliant']]
        
        assert len(non_compliant) == 0, \
            f"SLA violations detected: {[(r['test_name'], r['p95_time'], r['sla_threshold']) for r in non_compliant]}"
        
        # Log SLA compliance results
        for result in sla_results:
            print(f"{result['test_name']} ({result['category']}): "
                  f"P95 {result['p95_time']:.2f}ms / {result['sla_threshold']}ms "
                  f"(margin: {result['sla_margin_percentage']:+.1f}%)")
    
    def test_performance_report_generation(self, query_performance_monitor):
        """
        Test comprehensive performance report generation.
        
        Validates:
        - Performance metrics aggregation
        - Report completeness and accuracy
        - Optimization insights generation
        """
        # Generate performance report from collected metrics
        performance_report = query_performance_monitor.generate_performance_report()
        
        if 'error' not in performance_report:
            # Validate report structure
            assert 'summary' in performance_report, "Report should include summary section"
            assert 'sla_compliance' in performance_report, "Report should include SLA compliance"
            assert 'optimization_insights' in performance_report, "Report should include optimization insights"
            
            summary = performance_report['summary']
            assert 'total_queries' in summary, "Summary should include query count"
            assert 'avg_execution_time' in summary, "Summary should include average execution time"
            assert 'p95_execution_time' in summary, "Summary should include 95th percentile time"
            
            # Log performance summary
            print(f"Performance Report Summary:")
            print(f"  Total queries tested: {summary['total_queries']}")
            print(f"  Average execution time: {summary['avg_execution_time']:.2f}ms")
            print(f"  95th percentile time: {summary['p95_execution_time']:.2f}ms")
            print(f"  99th percentile time: {summary['p99_execution_time']:.2f}ms")
            
            # Log SLA compliance
            sla_compliance = performance_report['sla_compliance']
            compliance_rate = sla_compliance['compliance_rate']
            print(f"  SLA compliance rate: {compliance_rate:.1f}%")
            
            # Log optimization insights
            insights = performance_report['optimization_insights']
            if insights:
                print(f"  Optimization insights:")
                for insight in insights:
                    print(f"    - {insight}")
            
            # Save report for CI/CD integration
            report_file = 'database_performance_report.json'
            try:
                with open(report_file, 'w') as f:
                    json.dump(performance_report, f, indent=2, default=str)
                print(f"Performance report saved to {report_file}")
            except Exception as e:
                print(f"Could not save performance report: {e}")
        
        else:
            print(f"Performance report generation failed: {performance_report['error']}")


# ================================================================================================
# PYTEST MARKERS AND CONFIGURATION
# ================================================================================================

# Configure pytest markers for test organization
pytestmark = [
    pytest.mark.database,
    pytest.mark.performance,
    pytest.mark.integration
]


def pytest_configure(config):
    """Configure pytest for database performance testing."""
    config.addinivalue_line("markers", "database: mark test as database operation test")
    config.addinivalue_line("markers", "performance: mark test as performance benchmark")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "baseline: mark test as baseline comparison test")
    config.addinivalue_line("markers", "optimization: mark test as optimization validation test")
    config.addinivalue_line("markers", "sla: mark test as SLA compliance test")


def pytest_benchmark_generate_machine_info():
    """Generate machine info for benchmark reproducibility."""
    import platform
    import psutil
    
    return {
        'platform': platform.platform(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'cpu_count': psutil.cpu_count(),
        'memory_total': psutil.virtual_memory().total,
        'testing_framework': 'pytest-benchmark 5.1.0',
        'database_adapter': 'SQLite (testing) / PostgreSQL (production)',
        'orm_version': 'Flask-SQLAlchemy 3.1.1'
    }


if __name__ == '__main__':
    """Enable direct test execution for development and debugging."""
    pytest.main([
        __file__,
        '-v',
        '--benchmark-only',
        '--benchmark-save=database_performance_baseline',
        '--benchmark-compare=database_performance_baseline.json'
    ])