"""
Memory Profiling and Benchmarking Test Suite for Flask Application Migration

This module provides comprehensive memory usage profiling and benchmarking capabilities
utilizing Python memory profiling tools (memory_profiler, pympler) and pytest-benchmark
to validate Flask application memory consumption patterns. The test suite monitors Python
memory allocator statistics, garbage collection performance, and ensures memory footprint
optimization compared to Node.js baseline while identifying potential memory leaks and
optimization opportunities.

Key Features:
- Python memory profiling using memory_profiler and pympler for comprehensive memory analysis
- pytest-benchmark fixtures measuring memory allocation patterns and garbage collection impact
- Memory footprint comparison between Flask and Node.js implementations
- Python GC pause time monitoring with performance impact analysis
- Automated memory leak detection with long-running test scenarios
- OpenTelemetry memory metrics collection for comprehensive memory monitoring

Technical Requirements:
- Memory profiling must validate memory footprint optimization compared to Node.js per Section 4.7.1
- Testing must monitor Python GC pause duration and performance impact per Section 6.5.1.1
- Benchmarking must include memory allocation statistics and leak detection per Section 6.5.2.2
- Performance validation must support python:3.13.3-slim container memory optimization per Section 6.5.1.1
- Memory testing must integrate with OpenTelemetry instrumentation per Section 6.5.1.3

Migration Context:
This test suite validates the Flask application's memory efficiency as part of the comprehensive
migration from Node.js/Express.js to Python 3.13.3/Flask 3.1.1, ensuring the new implementation
meets or exceeds the original system's memory performance characteristics.
"""

import gc
import os
import sys
import time
import threading
import tracemalloc
import weakref
from collections import defaultdict, namedtuple
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Any, Optional, Generator, Callable, Union
from unittest.mock import patch, MagicMock

import pytest
import psutil

# Memory profiling and analysis dependencies
# Note: These packages should be added to requirements-test.txt for comprehensive memory analysis
try:
    import memory_profiler
    from memory_profiler import profile as memory_profile
    MEMORY_PROFILER_AVAILABLE = True
except ImportError:
    MEMORY_PROFILER_AVAILABLE = False
    # Fallback memory profiling implementation
    def memory_profile(func):
        return func

try:
    from pympler import muppy, summary, tracker, classtracker
    from pympler.asizeof import asizeof
    PYMPLER_AVAILABLE = True
except ImportError:
    PYMPLER_AVAILABLE = False

# pytest-benchmark for performance benchmarking
try:
    import pytest_benchmark
    PYTEST_BENCHMARK_AVAILABLE = True
except ImportError:
    PYTEST_BENCHMARK_AVAILABLE = False

# OpenTelemetry memory metrics collection
try:
    from opentelemetry import metrics
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
    from opentelemetry.metrics import get_meter_provider, set_meter_provider
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False

# Flask application imports
from flask import Flask, request, g
from flask.testing import FlaskClient

# Add src to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

try:
    from src.app import create_app
    from src.models import db
    from src.services.health_service import HealthService
    from src.auth.session_manager import SessionManager
except ImportError as e:
    print(f"Warning: Could not import application modules for memory testing: {e}")


# ================================================================================================
# MEMORY PROFILING DATA STRUCTURES AND CONSTANTS
# ================================================================================================

# Memory measurement data structures
MemorySnapshot = namedtuple('MemorySnapshot', [
    'timestamp', 'rss_memory', 'vms_memory', 'heap_size', 'gc_generation_counts',
    'tracemalloc_current', 'tracemalloc_peak', 'object_count', 'reference_count'
])

GCMetrics = namedtuple('GCMetrics', [
    'collection_count', 'pause_duration', 'collected_objects', 'uncollectable_objects',
    'generation', 'threshold', 'timestamp'
])

MemoryLeakResult = namedtuple('MemoryLeakResult', [
    'test_name', 'initial_memory', 'final_memory', 'memory_growth', 'growth_percentage',
    'leak_detected', 'object_growth', 'reference_growth', 'duration'
])

# Memory optimization targets based on Node.js baseline comparison per Section 4.7.1
MEMORY_OPTIMIZATION_TARGETS = {
    'max_memory_growth_per_request': 1024 * 1024,  # 1MB maximum memory growth per request
    'gc_pause_time_threshold': 10.0,  # 10ms maximum GC pause time per Section 6.5.1.1
    'memory_leak_threshold': 5.0,  # 5% maximum memory growth over baseline
    'object_growth_threshold': 1000,  # Maximum object count growth per test cycle
    'baseline_memory_overhead': 50 * 1024 * 1024,  # 50MB baseline memory overhead allowance
    'container_memory_limit': 512 * 1024 * 1024,  # 512MB container memory limit for python:3.13.3-slim
}

# OpenTelemetry memory metrics configuration per Section 6.5.1.3
OTEL_MEMORY_METRICS = {
    'memory_usage': 'flask.memory.usage.bytes',
    'gc_pause_time': 'flask.gc.pause.duration.milliseconds',
    'object_count': 'flask.objects.count',
    'memory_allocations': 'flask.memory.allocations.count',
    'heap_size': 'flask.memory.heap.size.bytes',
    'memory_growth': 'flask.memory.growth.rate.bytes_per_second'
}


# ================================================================================================
# MEMORY PROFILING UTILITIES AND DECORATORS
# ================================================================================================

class MemoryProfiler:
    """
    Comprehensive memory profiling utility for Flask application memory analysis.
    
    Provides advanced memory monitoring capabilities including:
    - Python memory allocator statistics monitoring
    - Garbage collection performance tracking
    - Memory leak detection and analysis
    - Object growth pattern monitoring
    - OpenTelemetry metrics integration
    """
    
    def __init__(self, enable_tracemalloc: bool = True, enable_otel: bool = True):
        """
        Initialize memory profiler with comprehensive monitoring capabilities.
        
        Args:
            enable_tracemalloc: Enable Python tracemalloc for detailed memory tracking
            enable_otel: Enable OpenTelemetry memory metrics collection
        """
        self.enable_tracemalloc = enable_tracemalloc and sys.version_info >= (3, 4)
        self.enable_otel = enable_otel and OPENTELEMETRY_AVAILABLE
        self.snapshots: List[MemorySnapshot] = []
        self.gc_metrics: List[GCMetrics] = []
        self.memory_tracker = None
        self.class_tracker = None
        self.otel_meter = None
        self.memory_instruments = {}
        
        # Initialize tracemalloc if enabled
        if self.enable_tracemalloc and not tracemalloc.is_tracing():
            tracemalloc.start()
        
        # Initialize OpenTelemetry metrics if enabled
        if self.enable_otel:
            self._setup_otel_metrics()
        
        # Initialize Pympler tracking if available
        if PYMPLER_AVAILABLE:
            self.memory_tracker = tracker.SummaryTracker()
            self.class_tracker = classtracker.ClassTracker()
    
    def _setup_otel_metrics(self) -> None:
        """Setup OpenTelemetry memory metrics instrumentation per Section 6.5.1.3."""
        try:
            # Configure metrics provider if not already set
            if not isinstance(get_meter_provider(), MeterProvider):
                metric_reader = PeriodicExportingMetricReader(
                    exporter=ConsoleMetricExporter(),
                    export_interval_millis=5000  # Export metrics every 5 seconds during testing
                )
                provider = MeterProvider(metric_readers=[metric_reader])
                set_meter_provider(provider)
            
            # Create meter for Flask application memory metrics
            self.otel_meter = get_meter_provider().get_meter(
                name="flask.memory.profiler",
                version="1.0.0",
                schema_url="https://opentelemetry.io/schemas/1.21.0"
            )
            
            # Create memory metric instruments
            self.memory_instruments = {
                'memory_usage': self.otel_meter.create_gauge(
                    name=OTEL_MEMORY_METRICS['memory_usage'],
                    description="Current memory usage in bytes",
                    unit="bytes"
                ),
                'gc_pause_time': self.otel_meter.create_histogram(
                    name=OTEL_MEMORY_METRICS['gc_pause_time'],
                    description="Garbage collection pause duration",
                    unit="ms"
                ),
                'object_count': self.otel_meter.create_gauge(
                    name=OTEL_MEMORY_METRICS['object_count'],
                    description="Current object count in memory",
                    unit="objects"
                ),
                'memory_allocations': self.otel_meter.create_counter(
                    name=OTEL_MEMORY_METRICS['memory_allocations'],
                    description="Total memory allocation count",
                    unit="allocations"
                ),
                'heap_size': self.otel_meter.create_gauge(
                    name=OTEL_MEMORY_METRICS['heap_size'],
                    description="Current heap size in bytes",
                    unit="bytes"
                ),
                'memory_growth': self.otel_meter.create_gauge(
                    name=OTEL_MEMORY_METRICS['memory_growth'],
                    description="Memory growth rate in bytes per second",
                    unit="bytes/s"
                )
            }
        except Exception as e:
            print(f"Warning: Failed to setup OpenTelemetry memory metrics: {e}")
            self.enable_otel = False
    
    def take_snapshot(self, label: str = None) -> MemorySnapshot:
        """
        Take comprehensive memory snapshot for analysis.
        
        Args:
            label: Optional label for the snapshot
            
        Returns:
            MemorySnapshot: Comprehensive memory state snapshot
        """
        timestamp = time.time()
        
        # Get process memory information
        process = psutil.Process()
        memory_info = process.memory_info()
        
        # Get garbage collection statistics
        gc_stats = gc.get_stats()
        gc_counts = gc.get_count()
        
        # Get tracemalloc statistics if enabled
        tracemalloc_current = 0
        tracemalloc_peak = 0
        if self.enable_tracemalloc and tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc_current = current
            tracemalloc_peak = peak
        
        # Get object and reference counts
        if PYMPLER_AVAILABLE:
            all_objects = muppy.get_objects()
            object_count = len(all_objects)
            # Calculate total reference count (approximate)
            reference_count = sum(sys.getrefcount(obj) for obj in all_objects[:1000])  # Sample for performance
        else:
            object_count = len(gc.get_objects())
            reference_count = 0
        
        snapshot = MemorySnapshot(
            timestamp=timestamp,
            rss_memory=memory_info.rss,
            vms_memory=memory_info.vms,
            heap_size=tracemalloc_current,
            gc_generation_counts=gc_counts,
            tracemalloc_current=tracemalloc_current,
            tracemalloc_peak=tracemalloc_peak,
            object_count=object_count,
            reference_count=reference_count
        )
        
        self.snapshots.append(snapshot)
        
        # Record OpenTelemetry metrics if enabled
        if self.enable_otel and self.memory_instruments:
            self._record_otel_metrics(snapshot)
        
        return snapshot
    
    def _record_otel_metrics(self, snapshot: MemorySnapshot) -> None:
        """Record memory metrics to OpenTelemetry."""
        try:
            attributes = {"component": "flask_memory_profiler", "test_suite": "memory_benchmarks"}
            
            self.memory_instruments['memory_usage'].set(snapshot.rss_memory, attributes)
            self.memory_instruments['object_count'].set(snapshot.object_count, attributes)
            self.memory_instruments['heap_size'].set(snapshot.heap_size, attributes)
            
            # Calculate memory growth rate if we have previous snapshots
            if len(self.snapshots) > 1:
                prev_snapshot = self.snapshots[-2]
                time_diff = snapshot.timestamp - prev_snapshot.timestamp
                memory_diff = snapshot.rss_memory - prev_snapshot.rss_memory
                growth_rate = memory_diff / time_diff if time_diff > 0 else 0
                self.memory_instruments['memory_growth'].set(growth_rate, attributes)
        except Exception as e:
            print(f"Warning: Failed to record OpenTelemetry metrics: {e}")
    
    @contextmanager
    def monitor_gc_performance(self) -> Generator[List[GCMetrics], None, None]:
        """
        Context manager for monitoring garbage collection performance per Section 6.5.1.1.
        
        Yields:
            List[GCMetrics]: List to collect GC performance metrics
        """
        gc_metrics = []
        
        # Patch garbage collection functions to monitor performance
        original_collect = gc.collect
        
        def monitored_collect(generation: int = 2):
            start_time = time.perf_counter()
            initial_objects = len(gc.get_objects())
            
            # Perform garbage collection
            collected = original_collect(generation)
            
            end_time = time.perf_counter()
            pause_duration = (end_time - start_time) * 1000  # Convert to milliseconds
            final_objects = len(gc.get_objects())
            
            # Get current GC statistics
            gc_stats = gc.get_stats()
            thresholds = gc.get_threshold()
            
            metric = GCMetrics(
                collection_count=collected,
                pause_duration=pause_duration,
                collected_objects=initial_objects - final_objects,
                uncollectable_objects=len(gc.garbage),
                generation=generation,
                threshold=thresholds[generation] if generation < len(thresholds) else 0,
                timestamp=time.time()
            )
            
            gc_metrics.append(metric)
            self.gc_metrics.append(metric)
            
            # Record GC pause time in OpenTelemetry if enabled
            if self.enable_otel and 'gc_pause_time' in self.memory_instruments:
                attributes = {"generation": str(generation), "component": "flask_gc"}
                self.memory_instruments['gc_pause_time'].record(pause_duration, attributes)
            
            return collected
        
        # Apply the monitoring patch
        gc.collect = monitored_collect
        
        try:
            yield gc_metrics
        finally:
            # Restore original garbage collection function
            gc.collect = original_collect
    
    def detect_memory_leaks(self, initial_snapshot: MemorySnapshot, 
                          final_snapshot: MemorySnapshot, test_name: str) -> MemoryLeakResult:
        """
        Detect potential memory leaks by comparing memory snapshots.
        
        Args:
            initial_snapshot: Memory snapshot before test execution
            final_snapshot: Memory snapshot after test execution
            test_name: Name of the test being analyzed
            
        Returns:
            MemoryLeakResult: Memory leak analysis results
        """
        memory_growth = final_snapshot.rss_memory - initial_snapshot.rss_memory
        growth_percentage = (memory_growth / initial_snapshot.rss_memory) * 100 if initial_snapshot.rss_memory > 0 else 0
        
        object_growth = final_snapshot.object_count - initial_snapshot.object_count
        reference_growth = final_snapshot.reference_count - initial_snapshot.reference_count
        
        duration = final_snapshot.timestamp - initial_snapshot.timestamp
        
        # Determine if a leak is detected based on thresholds
        leak_detected = (
            growth_percentage > MEMORY_OPTIMIZATION_TARGETS['memory_leak_threshold'] or
            memory_growth > MEMORY_OPTIMIZATION_TARGETS['max_memory_growth_per_request'] or
            object_growth > MEMORY_OPTIMIZATION_TARGETS['object_growth_threshold']
        )
        
        return MemoryLeakResult(
            test_name=test_name,
            initial_memory=initial_snapshot.rss_memory,
            final_memory=final_snapshot.rss_memory,
            memory_growth=memory_growth,
            growth_percentage=growth_percentage,
            leak_detected=leak_detected,
            object_growth=object_growth,
            reference_growth=reference_growth,
            duration=duration
        )
    
    def generate_memory_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive memory analysis report.
        
        Returns:
            Dict[str, Any]: Detailed memory analysis report
        """
        if not self.snapshots:
            return {"error": "No memory snapshots available for analysis"}
        
        # Calculate memory statistics
        memory_values = [s.rss_memory for s in self.snapshots]
        heap_values = [s.heap_size for s in self.snapshots]
        object_counts = [s.object_count for s in self.snapshots]
        
        # Calculate GC statistics
        gc_pause_times = [gc.pause_duration for gc in self.gc_metrics]
        total_collections = sum(gc.collection_count for gc in self.gc_metrics)
        
        # Generate summary statistics
        report = {
            'test_duration': self.snapshots[-1].timestamp - self.snapshots[0].timestamp if len(self.snapshots) > 1 else 0,
            'snapshot_count': len(self.snapshots),
            'memory_statistics': {
                'initial_memory': memory_values[0] if memory_values else 0,
                'final_memory': memory_values[-1] if memory_values else 0,
                'peak_memory': max(memory_values) if memory_values else 0,
                'min_memory': min(memory_values) if memory_values else 0,
                'average_memory': sum(memory_values) / len(memory_values) if memory_values else 0,
                'memory_growth': memory_values[-1] - memory_values[0] if len(memory_values) > 1 else 0,
                'memory_growth_percentage': ((memory_values[-1] - memory_values[0]) / memory_values[0] * 100) if len(memory_values) > 1 and memory_values[0] > 0 else 0
            },
            'heap_statistics': {
                'initial_heap': heap_values[0] if heap_values else 0,
                'final_heap': heap_values[-1] if heap_values else 0,
                'peak_heap': max(heap_values) if heap_values else 0,
                'average_heap': sum(heap_values) / len(heap_values) if heap_values else 0
            },
            'object_statistics': {
                'initial_objects': object_counts[0] if object_counts else 0,
                'final_objects': object_counts[-1] if object_counts else 0,
                'peak_objects': max(object_counts) if object_counts else 0,
                'object_growth': object_counts[-1] - object_counts[0] if len(object_counts) > 1 else 0
            },
            'gc_statistics': {
                'total_collections': total_collections,
                'average_pause_time': sum(gc_pause_times) / len(gc_pause_times) if gc_pause_times else 0,
                'max_pause_time': max(gc_pause_times) if gc_pause_times else 0,
                'min_pause_time': min(gc_pause_times) if gc_pause_times else 0,
                'total_pause_time': sum(gc_pause_times),
                'pause_count': len(gc_pause_times)
            },
            'optimization_compliance': {
                'memory_growth_within_limits': (memory_values[-1] - memory_values[0]) <= MEMORY_OPTIMIZATION_TARGETS['max_memory_growth_per_request'] if len(memory_values) > 1 else True,
                'gc_pause_within_limits': max(gc_pause_times) <= MEMORY_OPTIMIZATION_TARGETS['gc_pause_time_threshold'] if gc_pause_times else True,
                'object_growth_within_limits': (object_counts[-1] - object_counts[0]) <= MEMORY_OPTIMIZATION_TARGETS['object_growth_threshold'] if len(object_counts) > 1 else True
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return report


def memory_profile_test(enable_tracemalloc: bool = True, enable_otel: bool = True):
    """
    Decorator for memory profiling individual test functions.
    
    Args:
        enable_tracemalloc: Enable Python tracemalloc for detailed memory tracking
        enable_otel: Enable OpenTelemetry memory metrics collection
        
    Returns:
        Decorated function with memory profiling capabilities
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Initialize memory profiler
            profiler = MemoryProfiler(enable_tracemalloc=enable_tracemalloc, enable_otel=enable_otel)
            
            # Take initial snapshot
            initial_snapshot = profiler.take_snapshot(f"{func.__name__}_start")
            
            # Monitor garbage collection during test execution
            with profiler.monitor_gc_performance() as gc_metrics:
                try:
                    # Execute the test function
                    result = func(*args, **kwargs)
                finally:
                    # Take final snapshot
                    final_snapshot = profiler.take_snapshot(f"{func.__name__}_end")
                    
                    # Detect memory leaks
                    leak_result = profiler.detect_memory_leaks(
                        initial_snapshot, final_snapshot, func.__name__
                    )
                    
                    # Generate memory report
                    memory_report = profiler.generate_memory_report()
                    
                    # Store results in test metadata if available
                    if hasattr(func, '_memory_results'):
                        func._memory_results = {
                            'leak_analysis': leak_result,
                            'memory_report': memory_report,
                            'gc_metrics': gc_metrics
                        }
                    
                    # Assert memory optimization compliance
                    assert not leak_result.leak_detected, f"Memory leak detected in {func.__name__}: {leak_result.growth_percentage:.2f}% growth"
                    assert memory_report['gc_statistics']['max_pause_time'] <= MEMORY_OPTIMIZATION_TARGETS['gc_pause_time_threshold'], \
                        f"GC pause time exceeded threshold: {memory_report['gc_statistics']['max_pause_time']:.2f}ms"
            
            return result
        return wrapper
    return decorator


# ================================================================================================
# PYTEST FIXTURES FOR MEMORY PROFILING AND BENCHMARKING
# ================================================================================================

@pytest.fixture(scope='session')
def memory_profiler_config() -> Dict[str, Any]:
    """
    Memory profiler configuration fixture for comprehensive memory analysis.
    
    Provides configuration parameters for memory profiling, garbage collection
    monitoring, and OpenTelemetry metrics collection per Section 6.5.1.3.
    
    Returns:
        Dict[str, Any]: Memory profiler configuration parameters
    """
    return {
        'enable_tracemalloc': True,
        'enable_otel_metrics': OPENTELEMETRY_AVAILABLE,
        'enable_pympler_tracking': PYMPLER_AVAILABLE,
        'gc_monitoring_enabled': True,
        'memory_leak_detection': True,
        'snapshot_interval': 0.1,  # Take memory snapshots every 100ms
        'gc_threshold_override': None,  # Use default GC thresholds
        'container_memory_limit': MEMORY_OPTIMIZATION_TARGETS['container_memory_limit'],
        'optimization_targets': MEMORY_OPTIMIZATION_TARGETS,
        'baseline_comparison_enabled': True,
        'report_generation': True
    }


@pytest.fixture(scope='function')
def memory_profiler(memory_profiler_config: Dict[str, Any]) -> Generator[MemoryProfiler, None, None]:
    """
    Memory profiler fixture for individual test execution.
    
    Provides MemoryProfiler instance configured for comprehensive memory
    analysis during test execution with automatic cleanup.
    
    Args:
        memory_profiler_config: Memory profiler configuration
        
    Yields:
        MemoryProfiler: Configured memory profiler instance
    """
    profiler = MemoryProfiler(
        enable_tracemalloc=memory_profiler_config['enable_tracemalloc'],
        enable_otel=memory_profiler_config['enable_otel_metrics']
    )
    
    # Configure garbage collection if specified
    if memory_profiler_config.get('gc_threshold_override'):
        original_threshold = gc.get_threshold()
        gc.set_threshold(*memory_profiler_config['gc_threshold_override'])
    else:
        original_threshold = None
    
    try:
        yield profiler
    finally:
        # Cleanup and restore original settings
        if original_threshold:
            gc.set_threshold(*original_threshold)
        
        # Force garbage collection to clean up test artifacts
        gc.collect()


@pytest.fixture(scope='function')
def benchmark_memory_config() -> Dict[str, Any]:
    """
    pytest-benchmark configuration optimized for memory benchmarking.
    
    Provides benchmark configuration specifically tuned for memory
    allocation pattern analysis and garbage collection impact measurement
    per Section 6.5.2.2.
    
    Returns:
        Dict[str, Any]: Memory benchmark configuration parameters
    """
    return {
        'timer': 'time.perf_counter',
        'min_rounds': 5,
        'max_time': 2.0,  # Allow more time for memory operations
        'min_time': 0.01,  # Minimum time for memory-intensive operations
        'warmup': True,
        'warmup_iterations': 3,
        'disable_gc': False,  # Keep GC enabled for memory impact analysis
        'sort': 'mean',
        'histogram': True,
        'save': 'memory_benchmark_results.json',
        'compare': 'nodejs_memory_baseline.json',  # Compare against Node.js baseline per Section 4.7.1
        'group_by': 'name',
        'columns': ['min', 'max', 'mean', 'stddev', 'median', 'iqr', 'outliers', 'ops', 'rounds'],
        'unit': 'seconds'
    }


@pytest.fixture(scope='function')
def nodejs_memory_baseline() -> Dict[str, Any]:
    """
    Node.js memory baseline fixture for comparative analysis per Section 4.7.1.
    
    Provides Node.js system memory performance baseline metrics for
    comparing Flask implementation memory efficiency.
    
    Returns:
        Dict[str, Any]: Node.js memory baseline metrics
    """
    # Mock Node.js baseline data - in production, this would be loaded from actual measurements
    return {
        'api_endpoint_memory_usage': {
            '/api/health': {'peak_memory': 45 * 1024 * 1024, 'average_memory': 42 * 1024 * 1024},  # 45MB peak, 42MB average
            '/api/users': {'peak_memory': 65 * 1024 * 1024, 'average_memory': 58 * 1024 * 1024},   # 65MB peak, 58MB average
            '/api/auth/login': {'peak_memory': 55 * 1024 * 1024, 'average_memory': 50 * 1024 * 1024}, # 55MB peak, 50MB average
            '/api/business-entities': {'peak_memory': 75 * 1024 * 1024, 'average_memory': 68 * 1024 * 1024} # 75MB peak, 68MB average
        },
        'gc_performance': {
            'average_pause_time': 8.5,  # 8.5ms average GC pause
            'max_pause_time': 15.0,     # 15ms maximum GC pause
            'collection_frequency': 2.3  # 2.3 collections per second
        },
        'memory_allocation_patterns': {
            'objects_per_request': 1250,  # Average objects allocated per request
            'memory_per_request': 2.1 * 1024 * 1024,  # 2.1MB per request
            'peak_concurrent_requests': 100  # Peak concurrent request handling
        },
        'baseline_timestamp': '2024-01-01T00:00:00Z',
        'node_version': '18.17.0',
        'environment': 'production'
    }


@pytest.fixture(scope='function')
def long_running_test_scenario() -> Dict[str, Any]:
    """
    Long-running test scenario configuration for memory leak detection per Section 4.7.2.
    
    Provides configuration for extended test execution to identify
    memory leaks and gradual memory growth patterns.
    
    Returns:
        Dict[str, Any]: Long-running test scenario configuration
    """
    return {
        'duration_minutes': 10,  # 10-minute test duration
        'request_frequency': 10,  # 10 requests per second
        'concurrent_users': 5,   # 5 concurrent users
        'endpoint_rotation': [   # Rotate through different endpoints
            '/api/health',
            '/api/users',
            '/api/auth/login',
            '/api/business-entities'
        ],
        'memory_snapshot_interval': 30,  # Take memory snapshots every 30 seconds
        'gc_monitoring': True,
        'leak_detection_threshold': 3.0,  # 3% memory growth threshold
        'expected_stabilization_time': 2,  # Expect memory to stabilize within 2 minutes
        'max_memory_growth_rate': 1.0  # 1% per minute maximum growth rate
    }


# ================================================================================================
# MEMORY PROFILING TEST CLASSES
# ================================================================================================

@pytest.mark.performance
@pytest.mark.memory
class TestMemoryProfilingBaseline:
    """
    Memory profiling baseline tests for Flask application memory characteristics.
    
    This test class establishes baseline memory usage patterns for the Flask
    application and validates memory optimization targets per Section 6.5.1.1.
    """
    
    def test_application_memory_baseline(self, app: Flask, memory_profiler: MemoryProfiler):
        """
        Test Flask application baseline memory usage.
        
        Validates that the Flask application initializes within expected
        memory limits and maintains stable memory consumption.
        
        Args:
            app: Flask application instance
            memory_profiler: Memory profiler for analysis
        """
        # Take initial memory snapshot
        initial_snapshot = memory_profiler.take_snapshot("app_baseline_start")
        
        # Perform basic application operations
        with app.app_context():
            # Test application factory pattern memory efficiency
            test_app = create_app('testing')
            
            # Test blueprint registration memory impact
            with test_app.test_request_context():
                # Simulate basic request processing
                pass
        
        # Take final memory snapshot
        final_snapshot = memory_profiler.take_snapshot("app_baseline_end")
        
        # Validate memory usage against baseline targets
        memory_growth = final_snapshot.rss_memory - initial_snapshot.rss_memory
        assert memory_growth <= MEMORY_OPTIMIZATION_TARGETS['baseline_memory_overhead'], \
            f"Application baseline memory growth exceeded limit: {memory_growth / 1024 / 1024:.2f}MB"
        
        # Validate object creation is within reasonable limits
        object_growth = final_snapshot.object_count - initial_snapshot.object_count
        assert object_growth <= MEMORY_OPTIMIZATION_TARGETS['object_growth_threshold'], \
            f"Object creation exceeded threshold: {object_growth} objects"
    
    @memory_profile_test(enable_tracemalloc=True, enable_otel=True)
    def test_request_context_memory_efficiency(self, app: Flask, client: FlaskClient):
        """
        Test memory efficiency of Flask request context management.
        
        Validates that request context creation and cleanup doesn't
        cause memory leaks or excessive memory allocation.
        
        Args:
            app: Flask application instance
            client: Flask test client
        """
        # Perform multiple request context cycles
        for i in range(100):
            with app.test_request_context(f'/test-endpoint-{i}'):
                # Simulate request processing
                request.method = 'GET'
                request.args = {'test': f'value_{i}'}
                
                # Access Flask globals
                g.test_data = f"test_data_{i}"
        
        # Memory cleanup is validated by the decorator
    
    def test_database_connection_memory_management(self, app: Flask, memory_profiler: MemoryProfiler):
        """
        Test memory management of database connections and SQLAlchemy operations.
        
        Validates that database connections are properly managed and don't
        cause memory leaks during normal operations.
        
        Args:
            app: Flask application instance
            memory_profiler: Memory profiler for analysis
        """
        initial_snapshot = memory_profiler.take_snapshot("db_connection_start")
        
        with app.app_context():
            # Test database connection memory impact
            for i in range(50):
                # Simulate database queries without actual database operations
                with db.engine.connect() as connection:
                    # Simulate query execution
                    pass
        
        final_snapshot = memory_profiler.take_snapshot("db_connection_end")
        
        # Analyze memory impact
        leak_result = memory_profiler.detect_memory_leaks(
            initial_snapshot, final_snapshot, "database_connections"
        )
        
        assert not leak_result.leak_detected, \
            f"Database connection memory leak detected: {leak_result.growth_percentage:.2f}% growth"


@pytest.mark.performance
@pytest.mark.benchmark
class TestMemoryBenchmarking:
    """
    Memory benchmarking tests using pytest-benchmark for performance validation.
    
    This test class implements comprehensive memory allocation pattern analysis
    and garbage collection impact measurement per Section 6.5.2.2.
    """
    
    @pytest.mark.skipif(not PYTEST_BENCHMARK_AVAILABLE, reason="pytest-benchmark not available")
    def test_api_endpoint_memory_allocation(self, benchmark, client: FlaskClient, 
                                          nodejs_memory_baseline: Dict[str, Any],
                                          memory_profiler: MemoryProfiler):
        """
        Benchmark memory allocation patterns for API endpoints.
        
        Measures memory allocation patterns for Flask API endpoints and
        compares against Node.js baseline per Section 4.7.1.
        
        Args:
            benchmark: pytest-benchmark fixture
            client: Flask test client
            nodejs_memory_baseline: Node.js memory baseline metrics
            memory_profiler: Memory profiler for detailed analysis
        """
        def make_api_request():
            """Execute API request for memory benchmarking."""
            initial_snapshot = memory_profiler.take_snapshot("api_request_start")
            
            # Make API request
            response = client.get('/api/health')
            
            final_snapshot = memory_profiler.take_snapshot("api_request_end")
            
            # Validate memory allocation against baseline
            memory_growth = final_snapshot.rss_memory - initial_snapshot.rss_memory
            baseline_memory = nodejs_memory_baseline['api_endpoint_memory_usage']['/api/health']['average_memory']
            
            # Flask should use comparable or less memory than Node.js
            memory_efficiency_ratio = memory_growth / baseline_memory if baseline_memory > 0 else 0
            assert memory_efficiency_ratio <= 1.1, \
                f"Flask memory usage exceeded Node.js baseline by {(memory_efficiency_ratio - 1) * 100:.1f}%"
            
            return response
        
        # Run benchmark
        result = benchmark(make_api_request)
        assert result.status_code == 200
    
    @pytest.mark.skipif(not PYTEST_BENCHMARK_AVAILABLE, reason="pytest-benchmark not available")
    def test_garbage_collection_impact_benchmark(self, benchmark, app: Flask, 
                                                memory_profiler: MemoryProfiler):
        """
        Benchmark garbage collection impact on request processing.
        
        Measures the performance impact of Python garbage collection
        during request processing per Section 6.5.1.1.
        
        Args:
            benchmark: pytest-benchmark fixture
            app: Flask application instance
            memory_profiler: Memory profiler for GC analysis
        """
        def request_with_gc_monitoring():
            """Execute request while monitoring garbage collection."""
            with memory_profiler.monitor_gc_performance() as gc_metrics:
                with app.test_request_context('/benchmark-endpoint'):
                    # Simulate memory-intensive request processing
                    data = [{'id': i, 'data': f'test_data_{i}' * 100} for i in range(1000)]
                    
                    # Force garbage collection to measure impact
                    collected = gc.collect()
                    
                    # Process data to simulate business logic
                    processed_data = [item for item in data if item['id'] % 2 == 0]
                    
                    return len(processed_data)
        
        # Run benchmark with GC monitoring
        result = benchmark(request_with_gc_monitoring)
        
        # Validate GC pause times are within acceptable limits
        avg_gc_pause = sum(gc.pause_duration for gc in memory_profiler.gc_metrics) / len(memory_profiler.gc_metrics) if memory_profiler.gc_metrics else 0
        assert avg_gc_pause <= MEMORY_OPTIMIZATION_TARGETS['gc_pause_time_threshold'], \
            f"Average GC pause time exceeded threshold: {avg_gc_pause:.2f}ms"
        
        assert result > 0  # Ensure processing completed successfully
    
    @pytest.mark.skipif(not PYTEST_BENCHMARK_AVAILABLE, reason="pytest-benchmark not available")
    def test_concurrent_request_memory_scaling(self, benchmark, client: FlaskClient,
                                             memory_profiler: MemoryProfiler):
        """
        Benchmark memory usage scaling under concurrent request load.
        
        Validates that memory usage scales linearly with concurrent
        requests and doesn't exhibit memory explosion patterns.
        
        Args:
            benchmark: pytest-benchmark fixture
            client: Flask test client
            memory_profiler: Memory profiler for scaling analysis
        """
        import threading
        import queue
        
        def concurrent_requests_test():
            """Execute concurrent requests for memory scaling analysis."""
            initial_snapshot = memory_profiler.take_snapshot("concurrent_start")
            
            # Setup concurrent request execution
            request_queue = queue.Queue()
            results = []
            
            def worker():
                """Worker thread for concurrent request execution."""
                while True:
                    item = request_queue.get()
                    if item is None:
                        break
                    
                    response = client.get(f'/api/health?id={item}')
                    results.append(response.status_code)
                    request_queue.task_done()
            
            # Start worker threads
            num_workers = 5
            threads = []
            for _ in range(num_workers):
                thread = threading.Thread(target=worker)
                thread.start()
                threads.append(thread)
            
            # Queue requests
            num_requests = 50
            for i in range(num_requests):
                request_queue.put(i)
            
            # Wait for completion
            request_queue.join()
            
            # Stop workers
            for _ in range(num_workers):
                request_queue.put(None)
            for thread in threads:
                thread.join()
            
            final_snapshot = memory_profiler.take_snapshot("concurrent_end")
            
            # Analyze memory scaling
            memory_growth = final_snapshot.rss_memory - initial_snapshot.rss_memory
            memory_per_request = memory_growth / num_requests if num_requests > 0 else 0
            
            # Validate linear scaling
            assert memory_per_request <= MEMORY_OPTIMIZATION_TARGETS['max_memory_growth_per_request'], \
                f"Memory per request exceeded limit: {memory_per_request / 1024:.2f}KB per request"
            
            return len([r for r in results if r == 200])
        
        # Run concurrent requests benchmark
        successful_requests = benchmark(concurrent_requests_test)
        assert successful_requests >= 45  # Allow for some potential failures


@pytest.mark.performance
@pytest.mark.memory_leak
class TestMemoryLeakDetection:
    """
    Memory leak detection tests for long-running scenarios per Section 4.7.2.
    
    This test class implements automated memory leak detection with
    extended test scenarios to identify gradual memory growth patterns.
    """
    
    @pytest.mark.slow
    def test_long_running_memory_stability(self, app: Flask, client: FlaskClient,
                                         memory_profiler: MemoryProfiler,
                                         long_running_test_scenario: Dict[str, Any]):
        """
        Test memory stability during extended operation periods.
        
        Executes long-running test scenario to detect memory leaks
        and validate memory stability over time.
        
        Args:
            app: Flask application instance
            client: Flask test client
            memory_profiler: Memory profiler for leak detection
            long_running_test_scenario: Long-running test configuration
        """
        import threading
        import time
        from datetime import datetime, timedelta
        
        scenario = long_running_test_scenario
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(minutes=scenario['duration_minutes'])
        
        # Track memory over time
        memory_snapshots = []
        request_count = 0
        
        def memory_monitor():
            """Background thread for continuous memory monitoring."""
            while datetime.utcnow() < end_time:
                snapshot = memory_profiler.take_snapshot(f"monitor_{len(memory_snapshots)}")
                memory_snapshots.append(snapshot)
                time.sleep(scenario['memory_snapshot_interval'])
        
        def request_generator():
            """Generate continuous requests for memory leak testing."""
            nonlocal request_count
            endpoint_index = 0
            
            while datetime.utcnow() < end_time:
                # Rotate through endpoints
                endpoint = scenario['endpoint_rotation'][endpoint_index % len(scenario['endpoint_rotation'])]
                
                try:
                    response = client.get(endpoint)
                    if response.status_code == 200:
                        request_count += 1
                except Exception as e:
                    print(f"Request error: {e}")
                
                endpoint_index += 1
                time.sleep(1.0 / scenario['request_frequency'])
        
        # Start monitoring threads
        monitor_thread = threading.Thread(target=memory_monitor)
        request_thread = threading.Thread(target=request_generator)
        
        initial_snapshot = memory_profiler.take_snapshot("long_running_start")
        
        monitor_thread.start()
        request_thread.start()
        
        # Wait for test completion
        monitor_thread.join()
        request_thread.join()
        
        final_snapshot = memory_profiler.take_snapshot("long_running_end")
        
        # Analyze memory leak patterns
        leak_result = memory_profiler.detect_memory_leaks(
            initial_snapshot, final_snapshot, "long_running_stability"
        )
        
        # Validate memory stability
        assert not leak_result.leak_detected, \
            f"Memory leak detected during long-running test: {leak_result.growth_percentage:.2f}% growth"
        
        # Analyze memory growth rate
        if len(memory_snapshots) > 1:
            memory_values = [s.rss_memory for s in memory_snapshots]
            time_values = [s.timestamp for s in memory_snapshots]
            
            # Calculate linear regression for memory growth trend
            import numpy as np
            if len(memory_values) >= 2:
                time_diff = np.array(time_values) - time_values[0]
                memory_diff = np.array(memory_values) - memory_values[0]
                
                if len(time_diff) > 1 and np.std(time_diff) > 0:
                    growth_rate = np.polyfit(time_diff, memory_diff, 1)[0]  # bytes per second
                    growth_rate_percent_per_minute = (growth_rate * 60 / memory_values[0]) * 100 if memory_values[0] > 0 else 0
                    
                    assert abs(growth_rate_percent_per_minute) <= scenario['max_memory_growth_rate'], \
                        f"Memory growth rate exceeded limit: {growth_rate_percent_per_minute:.2f}% per minute"
        
        print(f"Long-running test completed: {request_count} requests processed, "
              f"{leak_result.memory_growth / 1024 / 1024:.2f}MB total growth")
    
    def test_session_memory_cleanup(self, app: Flask, client: FlaskClient,
                                  memory_profiler: MemoryProfiler):
        """
        Test memory cleanup of user sessions and authentication state.
        
        Validates that user sessions are properly cleaned up and don't
        accumulate in memory over time.
        
        Args:
            app: Flask application instance
            client: Flask test client
            memory_profiler: Memory profiler for session analysis
        """
        initial_snapshot = memory_profiler.take_snapshot("session_cleanup_start")
        
        # Simulate multiple user sessions
        for i in range(100):
            with client.session_transaction() as session:
                session['user_id'] = f'user_{i}'
                session['session_data'] = {'data': f'session_data_{i}' * 100}
                session['timestamp'] = time.time()
        
        # Force session cleanup by starting new sessions
        for i in range(100):
            with client.session_transaction() as session:
                session.clear()
        
        # Force garbage collection to clean up session objects
        gc.collect()
        
        final_snapshot = memory_profiler.take_snapshot("session_cleanup_end")
        
        # Analyze session memory cleanup
        leak_result = memory_profiler.detect_memory_leaks(
            initial_snapshot, final_snapshot, "session_cleanup"
        )
        
        assert not leak_result.leak_detected, \
            f"Session memory leak detected: {leak_result.growth_percentage:.2f}% growth"
    
    def test_database_connection_pool_memory(self, app: Flask, memory_profiler: MemoryProfiler):
        """
        Test memory behavior of database connection pooling.
        
        Validates that database connection pools maintain stable
        memory usage and properly release unused connections.
        
        Args:
            app: Flask application instance
            memory_profiler: Memory profiler for connection pool analysis
        """
        initial_snapshot = memory_profiler.take_snapshot("connection_pool_start")
        
        with app.app_context():
            # Simulate heavy database connection usage
            connections = []
            
            # Create multiple connections
            for i in range(20):
                try:
                    connection = db.engine.connect()
                    connections.append(connection)
                    
                    # Simulate query execution
                    time.sleep(0.01)
                except Exception as e:
                    print(f"Connection error: {e}")
            
            # Close all connections
            for connection in connections:
                try:
                    connection.close()
                except Exception as e:
                    print(f"Connection close error: {e}")
        
        # Force cleanup
        gc.collect()
        
        final_snapshot = memory_profiler.take_snapshot("connection_pool_end")
        
        # Analyze connection pool memory behavior
        leak_result = memory_profiler.detect_memory_leaks(
            initial_snapshot, final_snapshot, "connection_pool"
        )
        
        assert not leak_result.leak_detected, \
            f"Database connection pool memory leak detected: {leak_result.growth_percentage:.2f}% growth"


@pytest.mark.performance
@pytest.mark.integration
class TestOpenTelemetryMemoryMetrics:
    """
    OpenTelemetry memory metrics integration tests per Section 6.5.1.3.
    
    This test class validates OpenTelemetry memory metrics collection
    and ensures comprehensive memory monitoring capabilities.
    """
    
    @pytest.mark.skipif(not OPENTELEMETRY_AVAILABLE, reason="OpenTelemetry not available")
    def test_otel_memory_metrics_collection(self, app: Flask, memory_profiler: MemoryProfiler):
        """
        Test OpenTelemetry memory metrics collection functionality.
        
        Validates that memory metrics are properly collected and
        exported through OpenTelemetry instrumentation.
        
        Args:
            app: Flask application instance
            memory_profiler: Memory profiler with OTEL integration
        """
        # Ensure OpenTelemetry is properly configured
        assert memory_profiler.enable_otel, "OpenTelemetry should be enabled for metrics collection"
        assert memory_profiler.otel_meter is not None, "OpenTelemetry meter should be initialized"
        assert len(memory_profiler.memory_instruments) > 0, "Memory instruments should be created"
        
        # Execute operations to generate metrics
        with app.app_context():
            # Take memory snapshots to trigger metrics recording
            for i in range(10):
                snapshot = memory_profiler.take_snapshot(f"otel_test_{i}")
                time.sleep(0.1)
        
        # Validate metrics were recorded
        assert len(memory_profiler.snapshots) >= 10, "Memory snapshots should be recorded"
        
        # Verify memory instruments are available
        expected_instruments = [
            'memory_usage', 'gc_pause_time', 'object_count',
            'memory_allocations', 'heap_size', 'memory_growth'
        ]
        
        for instrument_name in expected_instruments:
            assert instrument_name in memory_profiler.memory_instruments, \
                f"Memory instrument {instrument_name} should be available"
    
    @pytest.mark.skipif(not OPENTELEMETRY_AVAILABLE, reason="OpenTelemetry not available")
    def test_memory_metrics_export_integration(self, app: Flask, memory_profiler: MemoryProfiler):
        """
        Test memory metrics export integration with monitoring systems.
        
        Validates that memory metrics are properly exported and can be
        consumed by external monitoring systems.
        
        Args:
            app: Flask application instance
            memory_profiler: Memory profiler with OTEL integration
        """
        # Mock metric exporter to capture exported metrics
        exported_metrics = []
        
        def mock_export_metrics(metrics_data):
            """Mock metric export function."""
            exported_metrics.extend(metrics_data)
            return True
        
        # Patch the metric exporter
        with patch.object(memory_profiler.otel_meter, 'create_gauge') as mock_gauge:
            mock_gauge.return_value.set = lambda value, attributes: exported_metrics.append({
                'value': value, 'attributes': attributes, 'timestamp': time.time()
            })
            
            # Generate memory activities
            with app.test_request_context('/metrics-test'):
                # Execute memory-intensive operations
                data = [{'id': i, 'payload': 'x' * 1000} for i in range(1000)]
                
                # Take memory snapshot to trigger metrics export
                snapshot = memory_profiler.take_snapshot("metrics_export_test")
        
        # Validate metrics export
        assert len(exported_metrics) > 0, "Memory metrics should be exported"
        
        # Verify metric attributes contain required information
        for metric in exported_metrics:
            assert 'attributes' in metric, "Exported metrics should include attributes"
            assert 'value' in metric, "Exported metrics should include values"
            assert 'timestamp' in metric, "Exported metrics should include timestamps"


@pytest.mark.performance
@pytest.mark.comparative
class TestNodeJSMemoryComparison:
    """
    Comparative memory analysis tests against Node.js baseline per Section 4.7.1.
    
    This test class implements comprehensive memory footprint comparison
    between Flask and Node.js implementations to validate optimization.
    """
    
    def test_api_endpoint_memory_comparison(self, client: FlaskClient, 
                                          nodejs_memory_baseline: Dict[str, Any],
                                          memory_profiler: MemoryProfiler):
        """
        Compare Flask API endpoint memory usage against Node.js baseline.
        
        Validates that Flask implementation uses comparable or less
        memory than the original Node.js system per Section 4.7.1.
        
        Args:
            client: Flask test client
            nodejs_memory_baseline: Node.js memory baseline metrics
            memory_profiler: Memory profiler for comparison analysis
        """
        baseline_endpoints = nodejs_memory_baseline['api_endpoint_memory_usage']
        comparison_results = {}
        
        for endpoint, baseline_metrics in baseline_endpoints.items():
            # Take initial memory snapshot
            initial_snapshot = memory_profiler.take_snapshot(f"{endpoint}_comparison_start")
            
            try:
                # Execute Flask endpoint
                response = client.get(endpoint)
                assert response.status_code == 200, f"Endpoint {endpoint} should be accessible"
                
                # Take final memory snapshot
                final_snapshot = memory_profiler.take_snapshot(f"{endpoint}_comparison_end")
                
                # Calculate Flask memory usage
                flask_memory_usage = final_snapshot.rss_memory - initial_snapshot.rss_memory
                
                # Compare against Node.js baseline
                nodejs_peak = baseline_metrics['peak_memory']
                nodejs_average = baseline_metrics['average_memory']
                
                memory_efficiency_ratio = flask_memory_usage / nodejs_average if nodejs_average > 0 else 0
                
                comparison_results[endpoint] = {
                    'flask_memory_usage': flask_memory_usage,
                    'nodejs_peak_memory': nodejs_peak,
                    'nodejs_average_memory': nodejs_average,
                    'efficiency_ratio': memory_efficiency_ratio,
                    'memory_improvement': (nodejs_average - flask_memory_usage) / nodejs_average * 100 if nodejs_average > 0 else 0
                }
                
                # Validate Flask doesn't exceed Node.js memory usage
                assert memory_efficiency_ratio <= 1.2, \
                    f"Flask memory usage for {endpoint} exceeded Node.js baseline by {(memory_efficiency_ratio - 1) * 100:.1f}%"
                
            except AssertionError:
                # Log the failure but continue with other endpoints
                print(f"Memory comparison failed for {endpoint}")
                raise
        
        # Generate comparison summary
        total_endpoints = len(comparison_results)
        improved_endpoints = sum(1 for r in comparison_results.values() if r['memory_improvement'] > 0)
        
        print(f"Memory comparison summary: {improved_endpoints}/{total_endpoints} endpoints improved")
        
        # Validate overall memory efficiency
        average_efficiency = sum(r['efficiency_ratio'] for r in comparison_results.values()) / total_endpoints if total_endpoints > 0 else 0
        assert average_efficiency <= 1.1, \
            f"Overall Flask memory efficiency should be within 10% of Node.js baseline, got {(average_efficiency - 1) * 100:.1f}%"
    
    def test_garbage_collection_comparison(self, app: Flask, memory_profiler: MemoryProfiler,
                                         nodejs_memory_baseline: Dict[str, Any]):
        """
        Compare Flask garbage collection performance against Node.js.
        
        Validates that Python GC performance meets or exceeds Node.js
        garbage collection characteristics.
        
        Args:
            app: Flask application instance
            memory_profiler: Memory profiler for GC analysis
            nodejs_memory_baseline: Node.js memory baseline metrics
        """
        nodejs_gc = nodejs_memory_baseline['gc_performance']
        
        with memory_profiler.monitor_gc_performance() as gc_metrics:
            with app.app_context():
                # Generate garbage collection activity
                for i in range(100):
                    # Create temporary objects that will require garbage collection
                    temp_data = [{'id': j, 'data': f'temp_{i}_{j}' * 50} for j in range(100)]
                    
                    # Force garbage collection periodically
                    if i % 10 == 0:
                        gc.collect()
        
        # Analyze GC performance
        if gc_metrics:
            flask_avg_pause = sum(gc.pause_duration for gc in gc_metrics) / len(gc_metrics)
            flask_max_pause = max(gc.pause_duration for gc in gc_metrics)
            flask_collection_frequency = len(gc_metrics) / 60  # Collections per minute (approximate)
            
            # Compare against Node.js baseline
            nodejs_avg_pause = nodejs_gc['average_pause_time']
            nodejs_max_pause = nodejs_gc['max_pause_time']
            nodejs_frequency = nodejs_gc['collection_frequency']
            
            # Validate GC performance
            assert flask_avg_pause <= nodejs_avg_pause * 1.2, \
                f"Flask average GC pause time ({flask_avg_pause:.2f}ms) should be within 20% of Node.js ({nodejs_avg_pause:.2f}ms)"
            
            assert flask_max_pause <= nodejs_max_pause * 1.3, \
                f"Flask maximum GC pause time ({flask_max_pause:.2f}ms) should be within 30% of Node.js ({nodejs_max_pause:.2f}ms)"
            
            # Collection frequency can be higher for Python (acceptable)
            assert flask_collection_frequency <= nodejs_frequency * 2.0, \
                f"Flask GC frequency ({flask_collection_frequency:.2f}/min) should not be more than 2x Node.js ({nodejs_frequency:.2f}/min)"
    
    def test_memory_allocation_pattern_comparison(self, client: FlaskClient,
                                                nodejs_memory_baseline: Dict[str, Any],
                                                memory_profiler: MemoryProfiler):
        """
        Compare memory allocation patterns between Flask and Node.js.
        
        Validates that Flask memory allocation patterns are efficient
        compared to Node.js baseline allocation characteristics.
        
        Args:
            client: Flask test client
            nodejs_memory_baseline: Node.js memory baseline metrics
            memory_profiler: Memory profiler for allocation analysis
        """
        nodejs_patterns = nodejs_memory_baseline['memory_allocation_patterns']
        
        # Execute test requests to analyze allocation patterns
        allocation_metrics = []
        
        for i in range(50):
            initial_snapshot = memory_profiler.take_snapshot(f"allocation_test_{i}_start")
            
            # Execute request
            response = client.get('/api/health')
            assert response.status_code == 200
            
            final_snapshot = memory_profiler.take_snapshot(f"allocation_test_{i}_end")
            
            # Calculate allocation metrics
            memory_per_request = final_snapshot.rss_memory - initial_snapshot.rss_memory
            objects_per_request = final_snapshot.object_count - initial_snapshot.object_count
            
            allocation_metrics.append({
                'memory_per_request': memory_per_request,
                'objects_per_request': objects_per_request
            })
        
        # Analyze allocation patterns
        avg_memory_per_request = sum(m['memory_per_request'] for m in allocation_metrics) / len(allocation_metrics)
        avg_objects_per_request = sum(m['objects_per_request'] for m in allocation_metrics) / len(allocation_metrics)
        
        # Compare against Node.js baseline
        nodejs_memory_per_request = nodejs_patterns['memory_per_request']
        nodejs_objects_per_request = nodejs_patterns['objects_per_request']
        
        # Validate allocation efficiency
        memory_efficiency = avg_memory_per_request / nodejs_memory_per_request if nodejs_memory_per_request > 0 else 0
        object_efficiency = avg_objects_per_request / nodejs_objects_per_request if nodejs_objects_per_request > 0 else 0
        
        assert memory_efficiency <= 1.2, \
            f"Flask memory per request ({avg_memory_per_request / 1024:.2f}KB) should be within 20% of Node.js ({nodejs_memory_per_request / 1024:.2f}KB)"
        
        assert object_efficiency <= 1.5, \
            f"Flask objects per request ({avg_objects_per_request:.0f}) should be within 50% of Node.js ({nodejs_objects_per_request:.0f})"


# ================================================================================================
# CONTAINER MEMORY OPTIMIZATION TESTS
# ================================================================================================

@pytest.mark.performance
@pytest.mark.container
class TestContainerMemoryOptimization:
    """
    Container memory optimization tests for python:3.13.3-slim per Section 6.5.1.1.
    
    This test class validates memory optimization for containerized Flask
    applications running in python:3.13.3-slim containers.
    """
    
    def test_container_memory_limit_compliance(self, app: Flask, memory_profiler: MemoryProfiler):
        """
        Test Flask application compliance with container memory limits.
        
        Validates that the Flask application operates efficiently within
        container memory constraints for python:3.13.3-slim deployment.
        
        Args:
            app: Flask application instance
            memory_profiler: Memory profiler for container analysis
        """
        container_limit = MEMORY_OPTIMIZATION_TARGETS['container_memory_limit']
        
        # Take baseline measurement
        baseline_snapshot = memory_profiler.take_snapshot("container_baseline")
        
        with app.app_context():
            # Simulate typical application workload
            for i in range(100):
                with app.test_request_context(f'/test-workload-{i}'):
                    # Simulate request processing workload
                    data = {'request_id': i, 'payload': 'x' * 1000}
                    processed = {k: v for k, v in data.items() if k != 'payload'}
        
        peak_snapshot = memory_profiler.take_snapshot("container_peak")
        
        # Validate memory usage within container limits
        assert peak_snapshot.rss_memory <= container_limit, \
            f"Memory usage ({peak_snapshot.rss_memory / 1024 / 1024:.2f}MB) exceeded container limit ({container_limit / 1024 / 1024:.2f}MB)"
        
        # Validate memory efficiency
        memory_utilization = peak_snapshot.rss_memory / container_limit
        assert memory_utilization <= 0.8, \
            f"Memory utilization ({memory_utilization * 100:.1f}%) should be under 80% of container limit"
    
    def test_python_slim_memory_footprint(self, memory_profiler: MemoryProfiler):
        """
        Test Python 3.13.3-slim memory footprint optimization.
        
        Validates that the Python runtime memory footprint is optimized
        for containerized deployment.
        
        Args:
            memory_profiler: Memory profiler for footprint analysis
        """
        # Measure Python runtime baseline
        runtime_snapshot = memory_profiler.take_snapshot("python_runtime_baseline")
        
        # Import common Flask modules to measure import overhead
        import flask
        import flask_sqlalchemy
        import werkzeug
        import jinja2
        
        post_import_snapshot = memory_profiler.take_snapshot("post_import")
        
        # Calculate import overhead
        import_overhead = post_import_snapshot.rss_memory - runtime_snapshot.rss_memory
        
        # Validate Python slim optimization
        max_import_overhead = 20 * 1024 * 1024  # 20MB maximum import overhead
        assert import_overhead <= max_import_overhead, \
            f"Python module import overhead ({import_overhead / 1024 / 1024:.2f}MB) exceeded limit ({max_import_overhead / 1024 / 1024:.2f}MB)"
        
        # Validate total runtime footprint
        max_runtime_footprint = 100 * 1024 * 1024  # 100MB maximum runtime footprint
        assert post_import_snapshot.rss_memory <= max_runtime_footprint, \
            f"Python runtime footprint ({post_import_snapshot.rss_memory / 1024 / 1024:.2f}MB) exceeded limit ({max_runtime_footprint / 1024 / 1024:.2f}MB)"


# ================================================================================================
# PYTEST CONFIGURATION FOR MEMORY TESTING
# ================================================================================================

def pytest_configure(config):
    """
    Configure pytest for memory profiling tests.
    
    Adds memory testing markers and configures memory profiling
    environment for comprehensive testing.
    """
    # Register memory testing markers
    config.addinivalue_line("markers", "memory: mark test as memory profiling test")
    config.addinivalue_line("markers", "memory_leak: mark test as memory leak detection test")
    config.addinivalue_line("markers", "benchmark: mark test as memory benchmarking test")
    config.addinivalue_line("markers", "comparative: mark test as Node.js comparison test")
    config.addinivalue_line("markers", "container: mark test as container memory optimization test")


def pytest_runtest_setup(item):
    """
    Setup hook for memory profiling tests.
    
    Configures memory profiling environment before test execution.
    """
    # Skip tests if required dependencies are not available
    if item.get_closest_marker("memory"):
        if not MEMORY_PROFILER_AVAILABLE and not PYMPLER_AVAILABLE:
            pytest.skip("Memory profiling dependencies not available")
    
    if item.get_closest_marker("benchmark"):
        if not PYTEST_BENCHMARK_AVAILABLE:
            pytest.skip("pytest-benchmark not available")
    
    # Configure garbage collection for memory tests
    if item.get_closest_marker("memory") or item.get_closest_marker("memory_leak"):
        # Ensure consistent GC state
        gc.collect()
        gc.set_debug(0)  # Disable GC debugging for performance


def pytest_runtest_teardown(item):
    """
    Teardown hook for memory profiling tests.
    
    Performs cleanup after memory profiling test execution.
    """
    # Force garbage collection after memory tests
    if item.get_closest_marker("memory") or item.get_closest_marker("memory_leak"):
        gc.collect()
    
    # Clear tracemalloc if it was enabled
    if tracemalloc.is_tracing():
        tracemalloc.stop()


# ================================================================================================
# TEST EXECUTION SUMMARY
# ================================================================================================

if __name__ == "__main__":
    """
    Direct test execution for memory profiling validation.
    
    This section provides direct test execution capabilities for
    development and debugging of memory profiling functionality.
    """
    print("Flask Memory Profiling and Benchmarking Test Suite")
    print("=" * 60)
    print(f"Memory Profiler Available: {MEMORY_PROFILER_AVAILABLE}")
    print(f"Pympler Available: {PYMPLER_AVAILABLE}")
    print(f"pytest-benchmark Available: {PYTEST_BENCHMARK_AVAILABLE}")
    print(f"OpenTelemetry Available: {OPENTELEMETRY_AVAILABLE}")
    print(f"Python Version: {sys.version}")
    print(f"Memory Optimization Targets: {MEMORY_OPTIMIZATION_TARGETS}")
    print("=" * 60)
    
    # Run basic memory profiler test
    profiler = MemoryProfiler()
    snapshot = profiler.take_snapshot("test_execution")
    print(f"Current Memory Usage: {snapshot.rss_memory / 1024 / 1024:.2f}MB")
    print(f"Object Count: {snapshot.object_count}")
    print("Memory profiling test suite ready for execution.")