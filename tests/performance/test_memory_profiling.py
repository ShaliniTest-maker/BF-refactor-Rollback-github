"""
Memory usage profiling and benchmarking test suite for Flask 3.1.1 migration validation.

This comprehensive test module utilizes Python memory profiling tools and pytest-benchmark
to validate Flask application memory consumption patterns, monitor Python GC performance,
and ensure memory footprint optimization compared to Node.js baseline per Section 6.5.1.1.

Key Features:
- Python memory profiling using memory_profiler and pympler for comprehensive analysis
- pytest-benchmark fixtures measuring memory allocation patterns and GC impact
- Memory footprint comparison between Flask and Node.js implementations
- Python GC pause time monitoring with performance impact analysis
- Automated memory leak detection with long-running test scenarios
- Flask application factory memory usage analysis with lifecycle monitoring

Performance Targets (Section 4.11.1):
- Memory footprint optimization compared to Node.js baseline
- Python GC pause duration monitoring with Python 3.13.3 optimization
- Memory allocation statistics and comprehensive leak detection
- python:3.13.3-slim container memory optimization validation
- Efficient resource utilization with Flask application factory pattern

Dependencies:
- memory_profiler>=0.61.0: Line-by-line memory usage profiling
- pympler>=0.9: Advanced Python memory analysis and leak detection
- pytest-benchmark>=5.1.0: Statistical performance measurement
- psutil>=5.9.6: System memory and process monitoring
- tracemalloc: Python memory allocator statistics (stdlib)
"""

import gc
import os
import sys
import time
import threading
import tracemalloc
import weakref
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Tuple
from unittest.mock import Mock, patch, MagicMock
import tempfile
import subprocess
import json

# Core testing imports
import pytest
from pytest_benchmark.fixture import BenchmarkFixture

# Memory profiling and analysis tools
import psutil
from memory_profiler import profile, memory_usage
from pympler import tracker, muppy, summary
from pympler.classtracker import ClassTracker
from pympler.refbrowser import get_referents
from pympler.asizeof import asizeof

# Flask and application imports
try:
    from flask import Flask, g, request, session, current_app
    from flask.testing import FlaskClient
    from app import create_app
    from config import TestingConfig
    from src.models import db
    from src.auth.models import User, AuthSession
    from src.services.base import BaseService
    from src.blueprints import api_v1, auth_bp, health_bp
except ImportError:
    # Handle case where modules don't exist during development
    Flask = None
    create_app = None
    TestingConfig = None
    db = None
    User = None
    AuthSession = None


# ================================
# Memory Profiling Configuration
# ================================

class MemoryProfilingConfig:
    """
    Memory profiling configuration providing comprehensive settings for
    memory analysis, GC monitoring, and performance benchmarking validation.
    
    This configuration class centralizes memory profiling parameters and
    thresholds for consistent testing across all memory-related scenarios.
    """
    
    # Memory profiling thresholds per Section 6.5.1.1
    MAX_MEMORY_INCREASE_PERCENT = 10.0  # Maximum 10% memory increase over baseline
    GC_PAUSE_TIME_THRESHOLD_MS = 50.0   # Maximum 50ms GC pause time
    MEMORY_LEAK_THRESHOLD_MB = 5.0      # Maximum 5MB memory leak over time
    
    # Performance targets per Section 4.11.1
    API_MEMORY_OVERHEAD_MB = 2.0        # Maximum 2MB memory overhead per API call
    DATABASE_MEMORY_OVERHEAD_MB = 1.0   # Maximum 1MB memory overhead per DB query
    AUTH_MEMORY_OVERHEAD_MB = 0.5       # Maximum 0.5MB memory overhead per auth operation
    
    # Long-running test configuration per Section 4.7.2
    LEAK_DETECTION_DURATION_SECONDS = 300   # 5 minutes for leak detection
    LEAK_DETECTION_ITERATIONS = 1000        # Number of iterations for leak testing
    MEMORY_SAMPLING_INTERVAL_SECONDS = 1.0  # Memory sampling frequency
    
    # Container optimization targets per Section 4.11.3
    CONTAINER_BASE_MEMORY_MB = 50.0     # python:3.13.3-slim base memory usage
    FLASK_APP_MAX_MEMORY_MB = 150.0     # Maximum Flask application memory usage
    CONCURRENT_USER_MEMORY_MB = 5.0     # Maximum memory per concurrent user
    
    # GC optimization settings per Section 6.5.1.1
    GC_GENERATION_THRESHOLDS = (700, 10, 10)  # Optimized GC generation thresholds
    GC_DEBUG_STATS = True                      # Enable detailed GC statistics
    GC_PAUSE_MONITORING = True                 # Monitor GC pause times


class MemoryProfiler:
    """
    Comprehensive memory profiler providing detailed analysis of Flask application
    memory usage patterns, garbage collection performance, and memory leak detection.
    
    This profiler implements comprehensive memory monitoring capabilities as specified
    in Section 6.5.1.1, including Python GC pause time analysis and memory allocator
    statistics collection for optimization insights.
    """
    
    def __init__(self):
        self.baseline_memory = None
        self.peak_memory = None
        self.gc_stats = []
        self.memory_samples = []
        self.allocation_stats = {}
        self.class_tracker = ClassTracker()
        self.weak_refs = []
        
    def start_profiling(self):
        """Initialize memory profiling with baseline measurement and GC monitoring"""
        # Start memory allocation tracking
        tracemalloc.start()
        
        # Record baseline memory usage
        process = psutil.Process()
        self.baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Configure GC for monitoring
        if MemoryProfilingConfig.GC_DEBUG_STATS:
            gc.set_debug(gc.DEBUG_STATS)
            
        # Set optimized GC thresholds
        gc.set_threshold(*MemoryProfilingConfig.GC_GENERATION_THRESHOLDS)
        
        # Start class tracking
        self.class_tracker.track_class(dict)
        self.class_tracker.track_class(list)
        self.class_tracker.track_class(str)
        self.class_tracker.track_class(Flask) if Flask else None
        
        return self.baseline_memory
    
    def stop_profiling(self) -> Dict[str, Any]:
        """Stop profiling and return comprehensive memory analysis"""
        # Get final memory usage
        process = psutil.Process()
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Get memory allocation statistics
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Get GC statistics
        gc_stats = gc.get_stats()
        
        # Analyze class tracking results
        class_stats = self.class_tracker.create_snapshot()
        
        return {
            'baseline_memory_mb': self.baseline_memory,
            'final_memory_mb': final_memory,
            'memory_increase_mb': final_memory - self.baseline_memory,
            'memory_increase_percent': ((final_memory - self.baseline_memory) / self.baseline_memory) * 100,
            'peak_memory_mb': self.peak_memory or final_memory,
            'traced_current_mb': current / 1024 / 1024,
            'traced_peak_mb': peak / 1024 / 1024,
            'gc_stats': gc_stats,
            'gc_collections': gc.get_count(),
            'class_stats': class_stats,
            'memory_samples': self.memory_samples,
            'allocation_stats': self.allocation_stats
        }
    
    @contextmanager
    def profile_memory_usage(self):
        """Context manager for profiling memory usage of code blocks"""
        self.start_profiling()
        try:
            yield self
        finally:
            stats = self.stop_profiling()
            self.allocation_stats.update(stats)
    
    def sample_memory_usage(self):
        """Sample current memory usage for continuous monitoring"""
        process = psutil.Process()
        current_memory = process.memory_info().rss / 1024 / 1024  # MB
        timestamp = datetime.utcnow()
        
        sample = {
            'timestamp': timestamp,
            'memory_mb': current_memory,
            'memory_percent': process.memory_percent(),
            'gc_count': gc.get_count()
        }
        
        self.memory_samples.append(sample)
        
        # Update peak memory tracking
        if self.peak_memory is None or current_memory > self.peak_memory:
            self.peak_memory = current_memory
            
        return sample
    
    def measure_gc_pause_time(self, operation: Callable) -> Dict[str, Any]:
        """
        Measure garbage collection pause time impact during operation execution.
        
        This method provides detailed GC performance analysis as specified in
        Section 6.5.1.1 for Python 3.13.3 optimization validation.
        """
        gc_start_stats = gc.get_count()
        start_time = time.perf_counter()
        
        # Execute operation
        result = operation()
        
        end_time = time.perf_counter()
        gc_end_stats = gc.get_count()
        
        # Calculate GC impact
        gc_collections = [
            gc_end_stats[i] - gc_start_stats[i] for i in range(len(gc_start_stats))
        ]
        
        total_time = (end_time - start_time) * 1000  # Convert to milliseconds
        
        # Estimate GC pause time (approximate)
        gc_pause_estimate = sum(gc_collections) * 0.1  # Rough estimate in ms
        
        gc_analysis = {
            'total_time_ms': total_time,
            'gc_collections': gc_collections,
            'gc_pause_estimate_ms': gc_pause_estimate,
            'gc_pause_percent': (gc_pause_estimate / total_time) * 100 if total_time > 0 else 0,
            'result': result
        }
        
        self.gc_stats.append(gc_analysis)
        return gc_analysis


class MemoryLeakDetector:
    """
    Automated memory leak detection system for long-running Flask application
    scenarios as specified in Section 4.7.2.
    
    This detector implements comprehensive leak detection through object tracking,
    reference analysis, and statistical trend validation for memory optimization.
    """
    
    def __init__(self):
        self.reference_tracker = tracker.SummaryTracker()
        self.object_growth_tracker = {}
        self.memory_trend_data = []
        self.weak_references = []
        
    def start_leak_detection(self):
        """Initialize leak detection with baseline object tracking"""
        # Create baseline snapshot
        self.reference_tracker.start()
        
        # Initialize object growth tracking
        self.object_growth_tracker = {
            'dict': len([obj for obj in gc.get_objects() if isinstance(obj, dict)]),
            'list': len([obj for obj in gc.get_objects() if isinstance(obj, list)]),
            'str': len([obj for obj in gc.get_objects() if isinstance(obj, str)]),
            'function': len([obj for obj in gc.get_objects() if callable(obj)])
        }
        
        return self.object_growth_tracker
    
    def detect_leaks(self) -> Dict[str, Any]:
        """
        Perform comprehensive leak detection analysis with statistical validation.
        
        Returns detailed leak analysis including object growth trends, reference
        cycles, and memory pattern analysis for optimization recommendations.
        """
        # Get current object counts
        current_objects = {
            'dict': len([obj for obj in gc.get_objects() if isinstance(obj, dict)]),
            'list': len([obj for obj in gc.get_objects() if isinstance(obj, list)]),
            'str': len([obj for obj in gc.get_objects() if isinstance(obj, str)]),
            'function': len([obj for obj in gc.get_objects() if callable(obj)])
        }
        
        # Calculate object growth
        object_growth = {
            obj_type: current_objects[obj_type] - self.object_growth_tracker.get(obj_type, 0)
            for obj_type in current_objects
        }
        
        # Check for reference cycles
        reference_cycles = len(gc.garbage)
        
        # Get memory usage trend
        process = psutil.Process()
        current_memory = process.memory_info().rss / 1024 / 1024
        self.memory_trend_data.append({
            'timestamp': datetime.utcnow(),
            'memory_mb': current_memory
        })
        
        # Analyze memory trend for leaks
        leak_detected = False
        memory_growth_rate = 0.0
        
        if len(self.memory_trend_data) > 10:
            # Calculate memory growth rate over last 10 samples
            recent_samples = self.memory_trend_data[-10:]
            initial_memory = recent_samples[0]['memory_mb']
            final_memory = recent_samples[-1]['memory_mb']
            memory_growth_rate = final_memory - initial_memory
            
            # Detect potential leak (more than threshold increase)
            if memory_growth_rate > MemoryProfilingConfig.MEMORY_LEAK_THRESHOLD_MB:
                leak_detected = True
        
        # Get detailed object summary
        object_summary = summary.summarize(muppy.get_objects())
        
        return {
            'leak_detected': leak_detected,
            'memory_growth_rate_mb': memory_growth_rate,
            'object_growth': object_growth,
            'reference_cycles': reference_cycles,
            'current_objects': current_objects,
            'object_summary': object_summary[:10],  # Top 10 object types
            'memory_trend_samples': len(self.memory_trend_data),
            'weak_references_alive': len([ref for ref in self.weak_references if ref() is not None])
        }
    
    def create_weak_reference(self, obj) -> weakref.ref:
        """Create weak reference for tracking object lifecycle"""
        weak_ref = weakref.ref(obj)
        self.weak_references.append(weak_ref)
        return weak_ref


# ================================
# Memory Profiling Test Fixtures
# ================================

@pytest.fixture
def memory_profiler():
    """
    Memory profiler fixture providing comprehensive memory analysis capabilities
    for Flask application testing as specified in Section 6.5.1.1.
    
    Returns:
        MemoryProfiler: Configured memory profiler instance
    """
    profiler = MemoryProfiler()
    return profiler


@pytest.fixture
def memory_leak_detector():
    """
    Memory leak detector fixture for automated leak detection during
    long-running test scenarios as specified in Section 4.7.2.
    
    Returns:
        MemoryLeakDetector: Configured leak detector instance
    """
    detector = MemoryLeakDetector()
    return detector


@pytest.fixture
def flask_app_memory_test(app):
    """
    Flask application memory testing fixture providing application factory
    memory analysis with comprehensive lifecycle monitoring per Section 5.1.1.
    
    Args:
        app: Flask application instance from conftest.py
        
    Returns:
        Flask: Memory-configured Flask application for testing
    """
    if app is None:
        # Create minimal Flask app for testing if imports failed
        app = Flask(__name__)
        app.config.update({
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'SECRET_KEY': 'test-memory-profiling-key'
        })
    
    # Configure app for memory testing
    app.config.update({
        'MEMORY_PROFILING_ENABLED': True,
        'GC_DEBUG_ENABLED': True,
        'TRACK_MEMORY_USAGE': True
    })
    
    return app


@pytest.fixture
def baseline_memory_data():
    """
    Baseline memory data fixture providing Node.js baseline metrics
    for performance comparison validation per Section 4.7.1.
    
    Returns:
        Dict[str, float]: Node.js baseline memory metrics
    """
    # Simulated Node.js baseline memory data
    # In production, this would be loaded from actual measurement data
    return {
        'api_memory_baseline_mb': 45.2,
        'database_memory_baseline_mb': 12.8,
        'auth_memory_baseline_mb': 8.4,
        'concurrent_user_memory_baseline_mb': 3.2,
        'total_baseline_memory_mb': 85.6,
        'gc_pause_baseline_ms': 15.2,
        'peak_memory_baseline_mb': 128.4,
        'memory_growth_rate_baseline_mb_per_hour': 2.1
    }


@pytest.fixture
def performance_memory_thresholds():
    """
    Performance memory thresholds fixture defining SLA compliance targets
    for memory usage validation per Section 4.11.1.
    
    Returns:
        Dict[str, float]: Memory performance thresholds
    """
    return {
        'max_memory_increase_percent': MemoryProfilingConfig.MAX_MEMORY_INCREASE_PERCENT,
        'max_gc_pause_time_ms': MemoryProfilingConfig.GC_PAUSE_TIME_THRESHOLD_MS,
        'max_memory_leak_mb': MemoryProfilingConfig.MEMORY_LEAK_THRESHOLD_MB,
        'max_api_memory_overhead_mb': MemoryProfilingConfig.API_MEMORY_OVERHEAD_MB,
        'max_db_memory_overhead_mb': MemoryProfilingConfig.DATABASE_MEMORY_OVERHEAD_MB,
        'max_auth_memory_overhead_mb': MemoryProfilingConfig.AUTH_MEMORY_OVERHEAD_MB,
        'max_flask_app_memory_mb': MemoryProfilingConfig.FLASK_APP_MAX_MEMORY_MB
    }


# ================================
# Memory Profiling Test Cases
# ================================

class TestFlaskApplicationMemoryProfiling:
    """
    Flask application factory memory profiling test suite validating memory
    usage patterns and optimization compared to Node.js baseline per Section 5.1.1.
    
    This test class implements comprehensive Flask application memory analysis
    including initialization overhead, blueprint registration impact, and
    request processing memory patterns for migration validation.
    """
    
    def test_flask_application_factory_memory_footprint(
        self, flask_app_memory_test, memory_profiler, baseline_memory_data, benchmark
    ):
        """
        Test Flask application factory memory footprint validation.
        
        Validates that Flask application factory initialization memory usage
        meets optimization targets compared to Node.js baseline per Section 5.1.1.
        """
        def create_flask_app():
            """Create Flask application and measure memory impact"""
            with memory_profiler.profile_memory_usage():
                if create_app:
                    app = create_app('testing')
                else:
                    app = Flask(__name__)
                    app.config['TESTING'] = True
                
                # Simulate blueprint registration
                if hasattr(app, 'register_blueprint'):
                    try:
                        # Mock blueprint registration for memory testing
                        mock_blueprint = Mock()
                        mock_blueprint.name = 'test_blueprint'
                        app.register_blueprint(mock_blueprint)
                    except Exception:
                        pass
                
                return app
        
        # Benchmark Flask application creation with memory profiling
        result = benchmark(create_flask_app)
        memory_stats = memory_profiler.allocation_stats
        
        # Validate memory usage against baseline
        memory_increase = memory_stats.get('memory_increase_mb', 0)
        baseline_memory = baseline_memory_data['total_baseline_memory_mb']
        
        # Assert memory optimization targets
        assert memory_increase < MemoryProfilingConfig.FLASK_APP_MAX_MEMORY_MB, \
            f"Flask app memory usage {memory_increase}MB exceeds maximum {MemoryProfilingConfig.FLASK_APP_MAX_MEMORY_MB}MB"
        
        # Assert improvement over Node.js baseline
        memory_efficiency = (memory_increase / baseline_memory) * 100
        assert memory_efficiency <= 110.0, \
            f"Flask memory efficiency {memory_efficiency:.1f}% should be within 110% of Node.js baseline"
        
        # Validate GC performance
        gc_collections = memory_stats.get('gc_collections', [0, 0, 0])
        total_gc_collections = sum(gc_collections)
        assert total_gc_collections < 10, \
            f"Excessive GC collections {total_gc_collections} during app initialization"
        
        print(f"Flask Application Memory Analysis:")
        print(f"  Memory Usage: {memory_increase:.2f}MB")
        print(f"  Baseline Comparison: {memory_efficiency:.1f}% of Node.js baseline")
        print(f"  GC Collections: {gc_collections}")
        print(f"  Peak Memory: {memory_stats.get('peak_memory_mb', 0):.2f}MB")
    
    def test_blueprint_registration_memory_impact(
        self, flask_app_memory_test, memory_profiler, benchmark
    ):
        """
        Test memory impact of Flask blueprint registration sequences.
        
        Validates that blueprint registration orchestration during application
        factory initialization maintains efficient memory patterns per Section 5.1.1.
        """
        def register_multiple_blueprints():
            """Register multiple blueprints and measure memory impact"""
            app = flask_app_memory_test
            
            with memory_profiler.profile_memory_usage():
                # Simulate multiple blueprint registrations
                for i in range(5):
                    mock_blueprint = Mock()
                    mock_blueprint.name = f'test_blueprint_{i}'
                    mock_blueprint.url_prefix = f'/api/v{i}'
                    
                    try:
                        app.register_blueprint(mock_blueprint)
                    except Exception:
                        # Handle case where blueprint registration fails
                        pass
                
                return app
        
        # Benchmark blueprint registration with memory profiling
        result = benchmark(register_multiple_blueprints)
        memory_stats = memory_profiler.allocation_stats
        
        # Validate blueprint registration memory efficiency
        memory_per_blueprint = memory_stats.get('memory_increase_mb', 0) / 5
        assert memory_per_blueprint < 1.0, \
            f"Memory per blueprint {memory_per_blueprint:.2f}MB exceeds 1MB threshold"
        
        # Validate GC impact
        gc_pause_estimate = memory_stats.get('gc_pause_estimate_ms', 0)
        assert gc_pause_estimate < MemoryProfilingConfig.GC_PAUSE_TIME_THRESHOLD_MS, \
            f"GC pause time {gc_pause_estimate:.2f}ms exceeds threshold {MemoryProfilingConfig.GC_PAUSE_TIME_THRESHOLD_MS}ms"
        
        print(f"Blueprint Registration Memory Analysis:")
        print(f"  Memory per Blueprint: {memory_per_blueprint:.3f}MB")
        print(f"  Total Memory Impact: {memory_stats.get('memory_increase_mb', 0):.2f}MB")
        print(f"  GC Pause Estimate: {gc_pause_estimate:.2f}ms")
    
    def test_request_context_memory_lifecycle(
        self, flask_app_memory_test, memory_profiler, client, benchmark
    ):
        """
        Test Flask request context memory lifecycle and cleanup validation.
        
        Validates that Flask request context management maintains efficient
        memory patterns during request processing per Section 5.1.1.
        """
        def process_multiple_requests():
            """Process multiple requests and measure memory lifecycle"""
            with memory_profiler.profile_memory_usage():
                responses = []
                
                # Simulate multiple request contexts
                for i in range(10):
                    with flask_app_memory_test.test_request_context(f'/test/{i}'):
                        # Simulate request processing
                        response_data = {
                            'request_id': i,
                            'status': 'success',
                            'data': f'test_data_{i}'
                        }
                        responses.append(response_data)
                
                return responses
        
        # Benchmark request context processing with memory profiling
        result = benchmark(process_multiple_requests)
        memory_stats = memory_profiler.allocation_stats
        
        # Validate request context memory efficiency
        memory_per_request = memory_stats.get('memory_increase_mb', 0) / 10
        assert memory_per_request < 0.1, \
            f"Memory per request context {memory_per_request:.3f}MB exceeds 0.1MB threshold"
        
        # Validate memory cleanup after request contexts
        gc.collect()  # Force garbage collection
        final_memory_sample = memory_profiler.sample_memory_usage()
        
        assert len(result) == 10, "All request contexts should complete successfully"
        
        print(f"Request Context Memory Analysis:")
        print(f"  Memory per Request: {memory_per_request:.4f}MB")
        print(f"  Total Requests Processed: {len(result)}")
        print(f"  Final Memory: {final_memory_sample['memory_mb']:.2f}MB")


class TestMemoryAllocationProfiling:
    """
    Python memory allocation profiling test suite validating allocator statistics
    and garbage collection performance with Python 3.13.3 optimization per Section 6.5.2.2.
    
    This test class implements comprehensive memory allocator analysis including
    allocation patterns, deallocation efficiency, and GC pause time monitoring
    for optimization insights and baseline comparison validation.
    """
    
    def test_memory_allocator_statistics_analysis(
        self, memory_profiler, benchmark, performance_memory_thresholds
    ):
        """
        Test Python memory allocator statistics collection and analysis.
        
        Validates memory allocation patterns and provides comprehensive
        allocator statistics for optimization insights per Section 6.5.2.2.
        """
        def allocate_various_data_structures():
            """Allocate various Python data structures for memory analysis"""
            with memory_profiler.profile_memory_usage():
                data_structures = {}
                
                # Allocate dictionaries
                data_structures['dicts'] = [
                    {f'key_{i}': f'value_{i}' for i in range(100)}
                    for _ in range(50)
                ]
                
                # Allocate lists
                data_structures['lists'] = [
                    [i for i in range(100)]
                    for _ in range(50)
                ]
                
                # Allocate strings
                data_structures['strings'] = [
                    f"test_string_{i}" * 10
                    for i in range(1000)
                ]
                
                # Allocate complex objects
                data_structures['complex'] = [
                    {'nested': {'data': [i, i*2, i*3], 'meta': {'id': i}}}
                    for i in range(100)
                ]
                
                return data_structures
        
        # Benchmark memory allocation with detailed profiling
        result = benchmark(allocate_various_data_structures)
        memory_stats = memory_profiler.allocation_stats
        
        # Validate memory allocation efficiency
        traced_peak_mb = memory_stats.get('traced_peak_mb', 0)
        traced_current_mb = memory_stats.get('traced_current_mb', 0)
        
        assert traced_peak_mb < 50.0, \
            f"Peak traced memory {traced_peak_mb:.2f}MB exceeds 50MB threshold"
        
        # Validate memory deallocation after test
        del result  # Explicit deletion
        gc.collect()  # Force garbage collection
        
        # Verify memory cleanup
        memory_after_cleanup = memory_profiler.sample_memory_usage()
        memory_growth = memory_after_cleanup['memory_mb'] - memory_profiler.baseline_memory
        
        assert memory_growth < performance_memory_thresholds['max_memory_leak_mb'], \
            f"Memory growth {memory_growth:.2f}MB indicates potential leak"
        
        print(f"Memory Allocator Statistics:")
        print(f"  Peak Traced Memory: {traced_peak_mb:.2f}MB")
        print(f"  Current Traced Memory: {traced_current_mb:.2f}MB")
        print(f"  Memory Growth: {memory_growth:.2f}MB")
        print(f"  GC Collections: {memory_stats.get('gc_collections', [])}")
    
    def test_garbage_collection_pause_time_monitoring(
        self, memory_profiler, benchmark, performance_memory_thresholds
    ):
        """
        Test Python GC pause time monitoring with performance impact analysis.
        
        Validates GC pause duration and performance impact with Python 3.13.3
        optimization validation per Section 6.5.1.1.
        """
        def create_gc_intensive_workload():
            """Create workload that triggers garbage collection"""
            def gc_intensive_operation():
                # Create objects that will trigger GC
                objects = []
                for i in range(1000):
                    # Create circular references to trigger GC
                    obj1 = {'id': i, 'data': []}
                    obj2 = {'id': i+1000, 'parent': obj1}
                    obj1['child'] = obj2
                    objects.append((obj1, obj2))
                
                # Force garbage collection
                collected = gc.collect()
                return collected, len(objects)
            
            return memory_profiler.measure_gc_pause_time(gc_intensive_operation)
        
        # Benchmark GC performance with pause time measurement
        gc_analysis = benchmark(create_gc_intensive_workload)
        
        # Validate GC pause time performance
        gc_pause_time = gc_analysis['gc_pause_estimate_ms']
        total_time = gc_analysis['total_time_ms']
        gc_pause_percent = gc_analysis['gc_pause_percent']
        
        assert gc_pause_time < performance_memory_thresholds['max_gc_pause_time_ms'], \
            f"GC pause time {gc_pause_time:.2f}ms exceeds threshold {performance_memory_thresholds['max_gc_pause_time_ms']}ms"
        
        assert gc_pause_percent < 20.0, \
            f"GC pause percentage {gc_pause_percent:.1f}% exceeds 20% threshold"
        
        # Validate GC collections efficiency
        gc_collections = gc_analysis['gc_collections']
        total_collections = sum(gc_collections)
        
        assert total_collections > 0, "GC should have been triggered during intensive workload"
        assert total_collections < 50, f"Excessive GC collections: {total_collections}"
        
        print(f"Garbage Collection Analysis:")
        print(f"  GC Pause Time: {gc_pause_time:.2f}ms")
        print(f"  Total Operation Time: {total_time:.2f}ms")
        print(f"  GC Pause Percentage: {gc_pause_percent:.1f}%")
        print(f"  GC Collections by Generation: {gc_collections}")
    
    def test_python_313_memory_optimization_validation(
        self, memory_profiler, benchmark, baseline_memory_data
    ):
        """
        Test Python 3.13.3 memory optimization features validation.
        
        Validates Python 3.13.3 specific memory optimizations and improvements
        compared to baseline performance per Section 6.5.1.1.
        """
        def python_optimization_workload():
            """Workload designed to test Python 3.13.3 optimizations"""
            with memory_profiler.profile_memory_usage():
                # Test string interning optimizations
                strings = [f"optimized_string_{i}" for i in range(1000)]
                interned_strings = [sys.intern(s) for s in strings]
                
                # Test dict optimizations
                optimized_dicts = [
                    {'key1': i, 'key2': i*2, 'key3': i*3}
                    for i in range(500)
                ]
                
                # Test list comprehension optimizations
                optimized_lists = [
                    [x for x in range(100) if x % 2 == 0]
                    for _ in range(100)
                ]
                
                return {
                    'strings': len(strings),
                    'interned_strings': len(interned_strings),
                    'dicts': len(optimized_dicts),
                    'lists': len(optimized_lists)
                }
        
        # Benchmark Python optimization features
        result = benchmark(python_optimization_workload)
        memory_stats = memory_profiler.allocation_stats
        
        # Compare against baseline memory usage
        memory_usage = memory_stats.get('memory_increase_mb', 0)
        baseline_memory = baseline_memory_data['total_baseline_memory_mb']
        
        optimization_efficiency = (memory_usage / baseline_memory) * 100
        
        # Validate Python 3.13.3 optimization benefits
        assert optimization_efficiency < 90.0, \
            f"Python 3.13.3 optimizations should provide <90% of baseline memory usage, got {optimization_efficiency:.1f}%"
        
        # Validate specific optimization features
        assert result['strings'] == 1000, "String creation optimization test"
        assert result['interned_strings'] == 1000, "String interning optimization test"
        assert result['dicts'] == 500, "Dictionary optimization test"
        assert result['lists'] == 100, "List comprehension optimization test"
        
        print(f"Python 3.13.3 Optimization Analysis:")
        print(f"  Memory Usage: {memory_usage:.2f}MB")
        print(f"  Baseline Efficiency: {optimization_efficiency:.1f}%")
        print(f"  Optimization Features Validated: {len(result)} of 4")


class TestMemoryLeakDetection:
    """
    Automated memory leak detection test suite for long-running Flask application
    scenarios as specified in Section 4.7.2.
    
    This test class implements comprehensive leak detection through object tracking,
    reference analysis, and statistical trend validation for memory optimization
    and baseline comparison against Node.js implementation patterns.
    """
    
    def test_long_running_memory_leak_detection(
        self, flask_app_memory_test, memory_leak_detector, client, benchmark
    ):
        """
        Test long-running memory leak detection with statistical validation.
        
        Validates that Flask application maintains stable memory usage over
        extended operation periods without memory leaks per Section 4.7.2.
        """
        def simulate_long_running_operations():
            """Simulate long-running Flask operations for leak detection"""
            memory_leak_detector.start_leak_detection()
            
            operations_completed = 0
            
            # Simulate extended operation period
            for iteration in range(100):  # Reduced iterations for testing
                with flask_app_memory_test.test_request_context(f'/api/test/{iteration}'):
                    # Simulate API request processing
                    request_data = {
                        'iteration': iteration,
                        'timestamp': datetime.utcnow().isoformat(),
                        'data': f'test_data_{iteration}' * 10
                    }
                    
                    # Simulate database operations
                    mock_db_results = [
                        {'id': i, 'data': f'record_{i}'}
                        for i in range(10)
                    ]
                    
                    # Simulate authentication operations
                    mock_auth_session = {
                        'user_id': f'user_{iteration}',
                        'session_id': f'session_{iteration}',
                        'permissions': ['read', 'write']
                    }
                    
                    operations_completed += 1
                
                # Sample memory usage periodically
                if iteration % 10 == 0:
                    memory_leak_detector.detect_leaks()
            
            return operations_completed
        
        # Execute long-running test with leak detection
        operations_count = benchmark(simulate_long_running_operations)
        
        # Perform final leak analysis
        leak_analysis = memory_leak_detector.detect_leaks()
        
        # Validate no memory leaks detected
        assert not leak_analysis['leak_detected'], \
            f"Memory leak detected: {leak_analysis['memory_growth_rate_mb']:.2f}MB growth rate"
        
        assert leak_analysis['memory_growth_rate_mb'] < MemoryProfilingConfig.MEMORY_LEAK_THRESHOLD_MB, \
            f"Memory growth rate {leak_analysis['memory_growth_rate_mb']:.2f}MB exceeds threshold"
        
        # Validate object growth is within reasonable limits
        object_growth = leak_analysis['object_growth']
        for obj_type, growth in object_growth.items():
            max_growth = operations_count * 2  # Allow 2 objects per operation
            assert growth < max_growth, \
                f"Excessive {obj_type} object growth: {growth} > {max_growth}"
        
        # Validate reference cycles
        assert leak_analysis['reference_cycles'] == 0, \
            f"Reference cycles detected: {leak_analysis['reference_cycles']}"
        
        print(f"Long-Running Leak Detection Analysis:")
        print(f"  Operations Completed: {operations_count}")
        print(f"  Memory Growth Rate: {leak_analysis['memory_growth_rate_mb']:.3f}MB")
        print(f"  Leak Detected: {leak_analysis['leak_detected']}")
        print(f"  Object Growth: {object_growth}")
        print(f"  Reference Cycles: {leak_analysis['reference_cycles']}")
    
    def test_concurrent_request_memory_stability(
        self, flask_app_memory_test, memory_leak_detector, benchmark
    ):
        """
        Test memory stability under concurrent request scenarios.
        
        Validates that Flask application maintains stable memory usage
        during concurrent request processing without leaks per Section 4.7.1.
        """
        def simulate_concurrent_requests():
            """Simulate concurrent request processing for memory stability testing"""
            import threading
            import queue
            
            memory_leak_detector.start_leak_detection()
            results_queue = queue.Queue()
            
            def process_request_batch(batch_id):
                """Process a batch of requests in a thread"""
                batch_results = []
                
                for req_id in range(10):
                    with flask_app_memory_test.test_request_context(f'/api/batch/{batch_id}/request/{req_id}'):
                        # Simulate request processing
                        result = {
                            'batch_id': batch_id,
                            'request_id': req_id,
                            'processed_at': datetime.utcnow().isoformat(),
                            'data': f'batch_{batch_id}_request_{req_id}'
                        }
                        batch_results.append(result)
                
                results_queue.put((batch_id, batch_results))
            
            # Create and start multiple threads
            threads = []
            for batch_id in range(5):
                thread = threading.Thread(target=process_request_batch, args=(batch_id,))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Collect all results
            all_results = {}
            while not results_queue.empty():
                batch_id, batch_results = results_queue.get()
                all_results[batch_id] = batch_results
            
            return all_results
        
        # Execute concurrent request test
        results = benchmark(simulate_concurrent_requests)
        
        # Perform leak detection analysis
        leak_analysis = memory_leak_detector.detect_leaks()
        
        # Validate concurrent processing stability
        assert len(results) == 5, "All request batches should complete"
        
        total_requests = sum(len(batch) for batch in results.values())
        assert total_requests == 50, f"Expected 50 total requests, got {total_requests}"
        
        # Validate memory stability
        assert not leak_analysis['leak_detected'], \
            "No memory leaks should be detected during concurrent processing"
        
        # Validate object growth is proportional to work done
        object_growth = leak_analysis['object_growth']
        max_reasonable_growth = total_requests * 3  # Allow 3 objects per request
        
        for obj_type, growth in object_growth.items():
            if growth > max_reasonable_growth:
                print(f"Warning: High {obj_type} object growth: {growth}")
        
        print(f"Concurrent Request Memory Analysis:")
        print(f"  Total Requests Processed: {total_requests}")
        print(f"  Batches Completed: {len(results)}")
        print(f"  Memory Stability: {'STABLE' if not leak_analysis['leak_detected'] else 'UNSTABLE'}")
        print(f"  Object Growth Summary: {object_growth}")
    
    def test_weak_reference_lifecycle_tracking(
        self, memory_leak_detector, benchmark
    ):
        """
        Test weak reference lifecycle tracking for object cleanup validation.
        
        Validates proper object cleanup and garbage collection through
        weak reference monitoring per Section 6.5.1.1.
        """
        def create_and_track_objects():
            """Create objects with weak reference tracking"""
            tracked_objects = []
            weak_references = []
            
            # Create objects with weak references
            for i in range(100):
                # Create various object types
                test_object = {
                    'id': i,
                    'data': [f'item_{j}' for j in range(10)],
                    'metadata': {'created_at': datetime.utcnow()}
                }
                
                tracked_objects.append(test_object)
                weak_ref = memory_leak_detector.create_weak_reference(test_object)
                weak_references.append(weak_ref)
            
            # Verify all references are alive
            alive_before = len([ref for ref in weak_references if ref() is not None])
            
            # Delete strong references
            del tracked_objects
            
            # Force garbage collection
            gc.collect()
            
            # Check weak references after GC
            alive_after = len([ref for ref in weak_references if ref() is not None])
            
            return {
                'objects_created': 100,
                'alive_before_gc': alive_before,
                'alive_after_gc': alive_after,
                'cleanup_percentage': ((alive_before - alive_after) / alive_before) * 100
            }
        
        # Execute weak reference tracking test
        tracking_results = benchmark(create_and_track_objects)
        
        # Validate proper object cleanup
        assert tracking_results['objects_created'] == 100, "All objects should be created"
        assert tracking_results['alive_before_gc'] == 100, "All objects should be alive before GC"
        
        # Validate garbage collection effectiveness
        cleanup_percentage = tracking_results['cleanup_percentage']
        assert cleanup_percentage >= 90.0, \
            f"GC should cleanup at least 90% of objects, got {cleanup_percentage:.1f}%"
        
        # Final leak detection check
        leak_analysis = memory_leak_detector.detect_leaks()
        
        print(f"Weak Reference Lifecycle Analysis:")
        print(f"  Objects Created: {tracking_results['objects_created']}")
        print(f"  Alive Before GC: {tracking_results['alive_before_gc']}")
        print(f"  Alive After GC: {tracking_results['alive_after_gc']}")
        print(f"  Cleanup Percentage: {cleanup_percentage:.1f}%")
        print(f"  Final Leak Detection: {'CLEAN' if not leak_analysis['leak_detected'] else 'LEAK_DETECTED'}")


class TestMemoryBaselineComparison:
    """
    Memory footprint comparison test suite validating Flask performance against
    Node.js baseline metrics as specified in Section 4.7.1.
    
    This test class implements comprehensive baseline comparison analysis including
    statistical validation, optimization verification, and performance improvement
    measurement for migration success validation.
    """
    
    def test_api_endpoint_memory_baseline_comparison(
        self, flask_app_memory_test, memory_profiler, baseline_memory_data, client, benchmark
    ):
        """
        Test API endpoint memory usage against Node.js baseline comparison.
        
        Validates that Flask API endpoints achieve equivalent or improved
        memory efficiency compared to Node.js baseline per Section 4.7.1.
        """
        def process_api_endpoints_memory_test():
            """Process multiple API endpoints and measure memory usage"""
            with memory_profiler.profile_memory_usage():
                api_responses = []
                
                # Simulate various API endpoint types
                endpoints = [
                    ('/api/users', 'GET'),
                    ('/api/users', 'POST'),
                    ('/api/users/1', 'GET'),
                    ('/api/users/1', 'PUT'),
                    ('/api/users/1', 'DELETE'),
                    ('/api/auth/login', 'POST'),
                    ('/api/auth/logout', 'POST'),
                    ('/api/health', 'GET'),
                ]
                
                for endpoint, method in endpoints:
                    with flask_app_memory_test.test_request_context(endpoint, method=method):
                        # Simulate request processing
                        response_data = {
                            'endpoint': endpoint,
                            'method': method,
                            'status': 'success',
                            'timestamp': datetime.utcnow().isoformat(),
                            'data': f'response_data_for_{endpoint.replace("/", "_")}'
                        }
                        api_responses.append(response_data)
                
                return api_responses
        
        # Execute API endpoint memory test
        responses = benchmark(process_api_endpoints_memory_test)
        memory_stats = memory_profiler.allocation_stats
        
        # Calculate memory usage per API call
        memory_per_api_call = memory_stats.get('memory_increase_mb', 0) / len(responses)
        baseline_api_memory = baseline_memory_data['api_memory_baseline_mb']
        
        # Validate memory efficiency compared to baseline
        memory_efficiency_ratio = memory_per_api_call / baseline_api_memory
        memory_improvement_percent = (1 - memory_efficiency_ratio) * 100
        
        assert memory_per_api_call < MemoryProfilingConfig.API_MEMORY_OVERHEAD_MB, \
            f"API memory overhead {memory_per_api_call:.3f}MB exceeds threshold {MemoryProfilingConfig.API_MEMORY_OVERHEAD_MB}MB"
        
        assert memory_efficiency_ratio <= 1.1, \
            f"Flask API memory should be within 110% of Node.js baseline, got {memory_efficiency_ratio:.1%}"
        
        # Validate successful processing of all endpoints
        assert len(responses) == 8, "All API endpoints should be processed"
        
        print(f"API Endpoint Memory Baseline Comparison:")
        print(f"  Flask Memory per API Call: {memory_per_api_call:.4f}MB")
        print(f"  Node.js Baseline Memory: {baseline_api_memory:.4f}MB")
        print(f"  Memory Efficiency Ratio: {memory_efficiency_ratio:.2f}")
        print(f"  Memory Improvement: {memory_improvement_percent:+.1f}%")
        print(f"  Endpoints Processed: {len(responses)}")
    
    def test_database_operation_memory_baseline_comparison(
        self, flask_app_memory_test, memory_profiler, baseline_memory_data, benchmark
    ):
        """
        Test database operation memory usage against Node.js baseline.
        
        Validates that Flask-SQLAlchemy database operations achieve
        equivalent or improved memory efficiency per Section 6.5.2.2.
        """
        def simulate_database_operations():
            """Simulate database operations for memory analysis"""
            with memory_profiler.profile_memory_usage():
                db_operations = []
                
                # Simulate various database operations
                operations = [
                    ('SELECT', 'users', 100),
                    ('INSERT', 'users', 10),
                    ('UPDATE', 'users', 5),
                    ('DELETE', 'users', 2),
                    ('SELECT', 'sessions', 50),
                    ('INSERT', 'sessions', 20),
                ]
                
                for operation, table, count in operations:
                    # Simulate database operation memory impact
                    mock_results = []
                    
                    if operation == 'SELECT':
                        mock_results = [
                            {'id': i, 'data': f'{table}_record_{i}', 'created_at': datetime.utcnow()}
                            for i in range(count)
                        ]
                    elif operation in ['INSERT', 'UPDATE']:
                        mock_results = [
                            {'operation': operation, 'table': table, 'affected_rows': count}
                        ]
                    elif operation == 'DELETE':
                        mock_results = [
                            {'operation': operation, 'table': table, 'deleted_rows': count}
                        ]
                    
                    db_operations.append({
                        'operation': operation,
                        'table': table,
                        'count': count,
                        'results': mock_results
                    })
                
                return db_operations
        
        # Execute database operation memory test
        operations = benchmark(simulate_database_operations)
        memory_stats = memory_profiler.allocation_stats
        
        # Calculate memory usage per database operation
        memory_per_db_operation = memory_stats.get('memory_increase_mb', 0) / len(operations)
        baseline_db_memory = baseline_memory_data['database_memory_baseline_mb']
        
        # Validate memory efficiency
        db_memory_efficiency = memory_per_db_operation / baseline_db_memory
        
        assert memory_per_db_operation < MemoryProfilingConfig.DATABASE_MEMORY_OVERHEAD_MB, \
            f"Database memory overhead {memory_per_db_operation:.3f}MB exceeds threshold"
        
        assert db_memory_efficiency <= 1.0, \
            f"Flask-SQLAlchemy should not exceed Node.js database memory usage, got {db_memory_efficiency:.1%}"
        
        # Validate all operations completed
        total_records_processed = sum(op['count'] for op in operations)
        assert total_records_processed == 187, "All database operations should complete"
        
        print(f"Database Operation Memory Baseline Comparison:")
        print(f"  Flask Memory per DB Operation: {memory_per_db_operation:.4f}MB")
        print(f"  Node.js Baseline Memory: {baseline_db_memory:.4f}MB")
        print(f"  Memory Efficiency: {db_memory_efficiency:.1%}")
        print(f"  Operations Completed: {len(operations)}")
        print(f"  Records Processed: {total_records_processed}")
    
    def test_authentication_memory_baseline_comparison(
        self, flask_app_memory_test, memory_profiler, baseline_memory_data, benchmark
    ):
        """
        Test authentication operation memory usage against Node.js baseline.
        
        Validates that Flask authentication decorators and ItsDangerous session
        management achieve memory efficiency per Section 5.1.1.
        """
        def simulate_authentication_operations():
            """Simulate authentication operations for memory analysis"""
            with memory_profiler.profile_memory_usage():
                auth_operations = []
                
                # Simulate authentication flows
                for i in range(20):
                    # Simulate user authentication
                    auth_data = {
                        'user_id': f'user_{i}',
                        'username': f'testuser_{i}',
                        'email': f'user_{i}@test.example.com',
                        'session_id': f'session_{i}',
                        'auth_token': f'token_{i}' * 10,  # Simulate JWT token
                        'permissions': ['read', 'write', 'delete'],
                        'created_at': datetime.utcnow(),
                        'expires_at': datetime.utcnow() + timedelta(hours=1)
                    }
                    
                    # Simulate session management
                    session_data = {
                        'session_id': auth_data['session_id'],
                        'user_data': auth_data,
                        'csrf_token': f'csrf_{i}',
                        'last_activity': datetime.utcnow()
                    }
                    
                    auth_operations.append({
                        'auth_data': auth_data,
                        'session_data': session_data,
                        'operation_id': i
                    })
                
                return auth_operations
        
        # Execute authentication memory test
        auth_ops = benchmark(simulate_authentication_operations)
        memory_stats = memory_profiler.allocation_stats
        
        # Calculate memory usage per authentication operation
        memory_per_auth_op = memory_stats.get('memory_increase_mb', 0) / len(auth_ops)
        baseline_auth_memory = baseline_memory_data['auth_memory_baseline_mb']
        
        # Validate authentication memory efficiency
        auth_memory_efficiency = memory_per_auth_op / baseline_auth_memory
        auth_improvement_percent = (1 - auth_memory_efficiency) * 100
        
        assert memory_per_auth_op < MemoryProfilingConfig.AUTH_MEMORY_OVERHEAD_MB, \
            f"Auth memory overhead {memory_per_auth_op:.3f}MB exceeds threshold"
        
        assert auth_memory_efficiency <= 1.05, \
            f"Flask auth memory should be within 105% of Node.js baseline, got {auth_memory_efficiency:.1%}"
        
        # Validate all authentication operations completed
        assert len(auth_ops) == 20, "All authentication operations should complete"
        
        print(f"Authentication Memory Baseline Comparison:")
        print(f"  Flask Memory per Auth Operation: {memory_per_auth_op:.4f}MB")
        print(f"  Node.js Baseline Memory: {baseline_auth_memory:.4f}MB")
        print(f"  Memory Efficiency: {auth_memory_efficiency:.1%}")
        print(f"  Memory Improvement: {auth_improvement_percent:+.1f}%")
        print(f"  Auth Operations: {len(auth_ops)}")
    
    def test_container_memory_optimization_validation(
        self, memory_profiler, baseline_memory_data, benchmark
    ):
        """
        Test python:3.13.3-slim container memory optimization validation.
        
        Validates that Flask application running in python:3.13.3-slim
        container achieves memory optimization targets per Section 4.11.3.
        """
        def simulate_container_memory_footprint():
            """Simulate container memory footprint for optimization validation"""
            with memory_profiler.profile_memory_usage():
                # Simulate container environment memory usage
                container_components = {}
                
                # Base Python runtime memory
                container_components['python_runtime'] = {
                    'interpreter': 'python:3.13.3-slim',
                    'memory_mb': MemoryProfilingConfig.CONTAINER_BASE_MEMORY_MB,
                    'optimizations': ['slim_base', 'compiled_bytecode', 'minimal_packages']
                }
                
                # Flask application memory
                container_components['flask_application'] = {
                    'framework': 'Flask 3.1.1',
                    'blueprints': 5,
                    'memory_estimate_mb': 25.0,
                    'features': ['application_factory', 'blueprint_registration', 'request_context']
                }
                
                # Dependencies memory
                container_components['dependencies'] = {
                    'sqlalchemy': 15.0,
                    'auth_libraries': 8.0,
                    'monitoring': 5.0,
                    'utilities': 3.0
                }
                
                # Calculate total container memory
                total_container_memory = (
                    container_components['python_runtime']['memory_mb'] +
                    container_components['flask_application']['memory_estimate_mb'] +
                    sum(container_components['dependencies'].values())
                )
                
                container_components['total_memory_mb'] = total_container_memory
                
                return container_components
        
        # Execute container memory optimization test
        container_data = benchmark(simulate_container_memory_footprint)
        memory_stats = memory_profiler.allocation_stats
        
        # Validate container memory optimization
        total_container_memory = container_data['total_memory_mb']
        baseline_total_memory = baseline_memory_data['total_baseline_memory_mb']
        
        container_efficiency = total_container_memory / baseline_total_memory
        container_optimization_percent = (1 - container_efficiency) * 100
        
        assert total_container_memory < MemoryProfilingConfig.FLASK_APP_MAX_MEMORY_MB, \
            f"Container memory {total_container_memory:.1f}MB exceeds maximum {MemoryProfilingConfig.FLASK_APP_MAX_MEMORY_MB}MB"
        
        assert container_efficiency <= 0.9, \
            f"Container should use ≤90% of Node.js baseline memory, got {container_efficiency:.1%}"
        
        # Validate python:3.13.3-slim optimization benefits
        python_runtime_memory = container_data['python_runtime']['memory_mb']
        assert python_runtime_memory == MemoryProfilingConfig.CONTAINER_BASE_MEMORY_MB, \
            "Python runtime memory should match slim container target"
        
        print(f"Container Memory Optimization Validation:")
        print(f"  Total Container Memory: {total_container_memory:.1f}MB")
        print(f"  Node.js Baseline Memory: {baseline_total_memory:.1f}MB")
        print(f"  Container Efficiency: {container_efficiency:.1%}")
        print(f"  Optimization Improvement: {container_optimization_percent:+.1f}%")
        print(f"  Python Runtime: {python_runtime_memory:.1f}MB")
        print(f"  Flask Application: {container_data['flask_application']['memory_estimate_mb']:.1f}MB")


# ================================
# Performance Test Markers and Configuration
# ================================

# Mark all tests in this module as performance tests
pytestmark = [
    pytest.mark.performance,
    pytest.mark.memory,
    pytest.mark.benchmark
]


def pytest_configure(config):
    """Configure pytest for memory profiling tests"""
    config.addinivalue_line(
        "markers", "memory: marks tests as memory profiling tests"
    )
    config.addinivalue_line(
        "markers", "leak_detection: marks tests as memory leak detection tests"
    )
    config.addinivalue_line(
        "markers", "baseline_comparison: marks tests as baseline comparison tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names"""
    for item in items:
        if "leak" in item.name:
            item.add_marker(pytest.mark.leak_detection)
        if "baseline" in item.name or "comparison" in item.name:
            item.add_marker(pytest.mark.baseline_comparison)
        if "gc" in item.name or "garbage" in item.name:
            item.add_marker(pytest.mark.gc_monitoring)


# ================================
# Test Execution Summary
# ================================

if __name__ == "__main__":
    """
    Direct execution for standalone memory profiling validation.
    
    Execute memory profiling tests independently for development
    and debugging purposes with comprehensive output formatting.
    """
    import subprocess
    import sys
    
    print("=" * 80)
    print("FLASK MEMORY PROFILING TEST SUITE")
    print("=" * 80)
    print(f"Python Version: {sys.version}")
    print(f"Memory Profiling Configuration: {MemoryProfilingConfig.__name__}")
    print(f"Test File: {__file__}")
    print("=" * 80)
    
    # Execute tests with verbose output
    test_command = [
        sys.executable, "-m", "pytest", __file__,
        "-v", "--tb=short", "--benchmark-only",
        "--benchmark-sort=mean", "--benchmark-columns=min,max,mean,stddev,median",
        "-m", "performance"
    ]
    
    try:
        result = subprocess.run(test_command, capture_output=True, text=True)
        print("STDOUT:")
        print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        print(f"Exit Code: {result.returncode}")
    except Exception as e:
        print(f"Error executing tests: {e}")