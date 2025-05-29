"""
Memory usage profiling and benchmarking test suite utilizing Python memory profiling tools 
and pytest-benchmark to validate Flask application memory consumption patterns.

This comprehensive test file monitors Python memory allocator statistics, garbage collection 
performance, and ensures memory footprint optimization compared to Node.js baseline while 
identifying potential memory leaks and optimization opportunities. The implementation provides
detailed memory analysis capabilities as specified in Section 6.5.1.1 and Section 6.5.2.2
of the technical specification.

Key Features:
- Python memory profiling using memory_profiler and pympler for comprehensive analysis
- pytest-benchmark fixtures measuring memory allocation patterns and GC impact optimization
- Memory footprint comparison between Flask and Node.js implementations with validation
- Python GC pause time monitoring with performance impact analysis and recommendations
- Automated memory leak detection with long-running test scenarios and resource monitoring
- Flask application factory memory usage analysis with comprehensive lifecycle monitoring
- Container memory optimization validation for python:3.13.3-slim deployment environments
- Statistical memory usage analysis with trend detection and optimization insights

Performance Targets:
- Memory footprint optimization compared to Node.js baseline per Section 4.7.1
- Python GC pause duration monitoring with performance impact analysis per Section 6.5.1.1
- Memory allocation statistics and comprehensive leak detection per Section 6.5.2.2
- Container memory optimization for python:3.13.3-slim per Section 4.11.3
- Resource utilization efficiency with Flask application factory pattern per Section 5.1.1

Dependencies:
- memory_profiler: Line-by-line memory usage analysis with @profile decorator
- pympler: Comprehensive memory tracking and object lifecycle analysis
- tracemalloc: Python built-in memory tracing for allocation pattern analysis
- pytest-benchmark 5.1.0: Statistical benchmarking and performance measurement
- gc: Garbage collection monitoring and optimization analysis
- psutil: System-level memory usage monitoring and process analysis
"""

import gc
import os
import sys
import time
import threading
import tracemalloc
import statistics
import tempfile
import weakref
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Generator, Tuple
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps

import pytest
import psutil
import numpy as np
from memory_profiler import profile, memory_usage, LineProfiler
from pympler import tracker, summary, muppy
from pympler.classtracker import ClassTracker
from pympler.process import ProcessMonitor
from pytest_benchmark import BenchmarkFixture

# Flask and application imports
from flask import Flask, request, g, current_app
from flask.testing import FlaskClient
from werkzeug.test import Client

# Test infrastructure imports from conftest
from tests.performance.conftest import (
    PerformanceTestingConfiguration,
    PerformanceMetricsCollector,
    MemoryProfiler,
    performance_app,
    performance_client,
    performance_metrics_collector,
    benchmark_fixture,
    memory_profiler,
    baseline_comparison_validator,
    performance_threshold_validator
)


@dataclass
class MemorySnapshot:
    """
    Memory snapshot data structure capturing comprehensive memory state
    information including Python allocator statistics, garbage collection
    metrics, and system-level memory usage for detailed analysis.
    """
    timestamp: float
    memory_usage_mb: float
    peak_memory_mb: float
    memory_growth_mb: float
    gc_generation_counts: Dict[int, int]
    gc_collections: Dict[int, int]
    tracemalloc_current: int
    tracemalloc_peak: int
    process_memory_rss: float
    process_memory_vms: float
    heap_size: int
    object_count: int
    thread_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GCMetrics:
    """
    Garbage collection metrics data structure for comprehensive GC
    performance analysis and optimization recommendations.
    """
    collection_time: float
    generation: int
    objects_collected: int
    objects_before: int
    objects_after: int
    uncollectable_objects: int
    pause_duration: float
    efficiency_ratio: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class AdvancedMemoryProfiler:
    """
    Advanced memory profiling utility providing comprehensive memory analysis
    capabilities including garbage collection monitoring, memory leak detection,
    allocation pattern analysis, and baseline comparison for Flask application
    memory optimization validation.
    
    This profiler implements comprehensive Python memory monitoring as specified
    in Section 6.5.1.1 and Section 6.5.2.2 for memory usage analysis, garbage
    collection performance monitoring, and memory footprint optimization.
    """
    
    def __init__(self, enable_tracemalloc: bool = True, gc_monitoring: bool = True):
        self.enable_tracemalloc = enable_tracemalloc
        self.gc_monitoring = gc_monitoring
        self.snapshots: List[MemorySnapshot] = []
        self.gc_metrics: List[GCMetrics] = []
        self.baseline_memory: float = 0
        self.peak_memory: float = 0
        self.memory_threshold_mb = PerformanceTestingConfiguration.MEMORY_USAGE_THRESHOLD_MB
        
        # Initialize memory tracking components
        self.tracker = tracker.SummaryTracker()
        self.class_tracker = ClassTracker()
        self.process_monitor = ProcessMonitor()
        self.line_profiler = LineProfiler()
        
        # Memory leak detection
        self.reference_tracker = weakref.WeakSet()
        self.long_term_objects = []
        
        # GC monitoring setup
        if gc_monitoring:
            self._setup_gc_monitoring()
    
    def _setup_gc_monitoring(self):
        """Setup garbage collection monitoring with callback registration"""
        # Store original GC callback list
        self.original_gc_callbacks = gc.callbacks.copy()
        
        # Add our GC monitoring callback
        gc.callbacks.append(self._gc_callback)
        
        # Configure GC thresholds for optimal monitoring
        self.original_gc_thresholds = gc.get_threshold()
        # Slightly more aggressive GC for better monitoring
        gc.set_threshold(700, 10, 10)
    
    def _gc_callback(self, phase: str, info: Dict[str, Any]):
        """
        Garbage collection callback for comprehensive GC performance monitoring
        
        Args:
            phase: GC phase ('start' or 'stop')
            info: GC information dictionary
        """
        if phase == 'start':
            self._gc_start_time = time.time()
            self._gc_objects_before = sum(gc.get_count())
        elif phase == 'stop':
            gc_duration = time.time() - getattr(self, '_gc_start_time', time.time())
            objects_after = sum(gc.get_count())
            objects_before = getattr(self, '_gc_objects_before', objects_after)
            
            generation = info.get('generation', -1)
            collected = info.get('collected', 0)
            
            # Calculate efficiency metrics
            efficiency_ratio = (collected / objects_before) if objects_before > 0 else 0.0
            
            gc_metric = GCMetrics(
                collection_time=time.time(),
                generation=generation,
                objects_collected=collected,
                objects_before=objects_before,
                objects_after=objects_after,
                uncollectable_objects=len(gc.garbage),
                pause_duration=gc_duration,
                efficiency_ratio=efficiency_ratio,
                metadata=info.copy()
            )
            
            self.gc_metrics.append(gc_metric)
    
    def start_profiling(self, enable_line_profiling: bool = False) -> None:
        """
        Start comprehensive memory profiling with tracemalloc and monitoring
        
        Args:
            enable_line_profiling: Enable line-by-line memory profiling
        """
        if self.enable_tracemalloc:
            tracemalloc.start()
        
        # Get baseline memory measurements
        process = psutil.Process()
        self.baseline_memory = process.memory_info().rss / 1024 / 1024
        
        # Start pympler tracking
        self.tracker.clear()
        
        # Enable line profiling if requested
        if enable_line_profiling:
            self.line_profiler.enable()
        
        # Force initial GC to establish clean baseline
        gc.collect()
        
        # Take initial snapshot
        self._take_snapshot("profiling_start")
    
    def stop_profiling(self) -> Dict[str, Any]:
        """
        Stop memory profiling and return comprehensive analysis results
        
        Returns:
            Dict containing detailed memory profiling analysis and recommendations
        """
        # Take final snapshot
        self._take_snapshot("profiling_end")
        
        # Stop tracemalloc if enabled
        tracemalloc_data = {}
        if self.enable_tracemalloc and tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            tracemalloc_data = {
                'current_memory_bytes': current,
                'peak_memory_bytes': peak,
                'current_memory_mb': current / 1024 / 1024,
                'peak_memory_mb': peak / 1024 / 1024
            }
        
        # Generate comprehensive analysis
        analysis = self._generate_profiling_analysis()
        analysis.update({
            'tracemalloc_data': tracemalloc_data,
            'gc_analysis': self._analyze_gc_performance(),
            'memory_efficiency': self._calculate_memory_efficiency(),
            'optimization_recommendations': self._generate_optimization_recommendations()
        })
        
        return analysis
    
    def profile_function_memory(self, func: Callable, *args, **kwargs) -> Tuple[Any, Dict[str, Any]]:
        """
        Profile memory usage of a specific function with comprehensive analysis
        
        Args:
            func: Function to profile
            *args: Function positional arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Tuple of (function_result, memory_analysis)
        """
        # Take pre-execution snapshot
        self._take_snapshot(f"before_{func.__name__}")
        
        # Profile function execution with memory_profiler
        mem_usage = memory_usage((func, args, kwargs), interval=0.1, timeout=1, max_usage=True)
        
        # Execute function and capture result
        start_time = time.time()
        result = func(*args, **kwargs)
        execution_time = time.time() - start_time
        
        # Take post-execution snapshot
        self._take_snapshot(f"after_{func.__name__}")
        
        # Analyze memory usage patterns
        function_analysis = {
            'function_name': func.__name__,
            'execution_time': execution_time,
            'memory_usage_samples': mem_usage,
            'peak_memory_usage': max(mem_usage) if mem_usage else 0,
            'average_memory_usage': sum(mem_usage) / len(mem_usage) if mem_usage else 0,
            'memory_variance': statistics.variance(mem_usage) if len(mem_usage) > 1 else 0,
            'memory_delta': self._calculate_memory_delta(),
            'gc_activity': self._get_recent_gc_activity()
        }
        
        return result, function_analysis
    
    def detect_memory_leaks(self, test_duration: float = 60.0, 
                           sample_interval: float = 1.0) -> Dict[str, Any]:
        """
        Detect memory leaks through long-running monitoring and analysis
        
        Args:
            test_duration: Duration of leak detection test in seconds
            sample_interval: Interval between memory samples in seconds
            
        Returns:
            Dict containing memory leak analysis and detection results
        """
        print(f"Starting memory leak detection for {test_duration:.1f} seconds...")
        
        leak_snapshots = []
        start_time = time.time()
        sample_count = 0
        
        while (time.time() - start_time) < test_duration:
            # Take memory snapshot
            snapshot = self._take_snapshot(f"leak_detection_{sample_count}")
            leak_snapshots.append(snapshot)
            
            # Force garbage collection periodically
            if sample_count % 10 == 0:
                gc.collect()
            
            # Wait for next sample
            time.sleep(sample_interval)
            sample_count += 1
        
        # Analyze memory leak patterns
        return self._analyze_memory_leak_patterns(leak_snapshots)
    
    def benchmark_memory_allocation(self, allocation_func: Callable, 
                                  iterations: int = 1000) -> Dict[str, Any]:
        """
        Benchmark memory allocation patterns for performance analysis
        
        Args:
            allocation_func: Function that performs memory allocation
            iterations: Number of allocation iterations to benchmark
            
        Returns:
            Dict containing allocation benchmark results and analysis
        """
        allocation_times = []
        memory_deltas = []
        gc_triggers = 0
        
        for i in range(iterations):
            # Record GC count before allocation
            gc_before = sum(gc.get_count())
            
            # Record memory before allocation
            mem_before = psutil.Process().memory_info().rss
            
            # Time the allocation
            start_time = time.time()
            allocation_func()
            allocation_time = time.time() - start_time
            
            # Record memory after allocation
            mem_after = psutil.Process().memory_info().rss
            
            # Record GC count after allocation
            gc_after = sum(gc.get_count())
            
            # Calculate metrics
            allocation_times.append(allocation_time)
            memory_deltas.append((mem_after - mem_before) / 1024 / 1024)  # MB
            
            if gc_after != gc_before:
                gc_triggers += 1
        
        return {
            'total_iterations': iterations,
            'average_allocation_time': statistics.mean(allocation_times),
            'median_allocation_time': statistics.median(allocation_times),
            'allocation_time_stddev': statistics.stdev(allocation_times) if len(allocation_times) > 1 else 0,
            'average_memory_delta': statistics.mean(memory_deltas),
            'total_memory_allocated': sum(memory_deltas),
            'gc_triggers': gc_triggers,
            'gc_trigger_rate': gc_triggers / iterations,
            'allocation_efficiency': iterations / sum(allocation_times)
        }
    
    def _take_snapshot(self, label: str) -> MemorySnapshot:
        """Take comprehensive memory snapshot with detailed metrics"""
        process = psutil.Process()
        memory_info = process.memory_info()
        
        # Get tracemalloc data if enabled
        tracemalloc_current = 0
        tracemalloc_peak = 0
        if self.enable_tracemalloc and tracemalloc.is_tracing():
            tracemalloc_current, tracemalloc_peak = tracemalloc.get_traced_memory()
        
        # Get GC statistics
        gc_counts = gc.get_count()
        gc_stats = gc.get_stats()
        
        # Calculate memory metrics
        current_memory = memory_info.rss / 1024 / 1024
        peak_memory = max(self.peak_memory, current_memory)
        self.peak_memory = peak_memory
        memory_growth = current_memory - self.baseline_memory
        
        # Get object count
        all_objects = muppy.get_objects()
        
        snapshot = MemorySnapshot(
            timestamp=time.time(),
            memory_usage_mb=current_memory,
            peak_memory_mb=peak_memory,
            memory_growth_mb=memory_growth,
            gc_generation_counts={i: gc_counts[i] for i in range(len(gc_counts))},
            gc_collections={i: gc_stats[i]['collections'] for i in range(len(gc_stats))},
            tracemalloc_current=tracemalloc_current,
            tracemalloc_peak=tracemalloc_peak,
            process_memory_rss=memory_info.rss / 1024 / 1024,
            process_memory_vms=memory_info.vms / 1024 / 1024,
            heap_size=sys.getsizeof(all_objects),
            object_count=len(all_objects),
            thread_count=threading.active_count(),
            metadata={'label': label, 'gc_threshold': gc.get_threshold()}
        )
        
        self.snapshots.append(snapshot)
        return snapshot
    
    def _calculate_memory_delta(self) -> float:
        """Calculate memory delta between last two snapshots"""
        if len(self.snapshots) < 2:
            return 0.0
        return self.snapshots[-1].memory_usage_mb - self.snapshots[-2].memory_usage_mb
    
    def _get_recent_gc_activity(self) -> Dict[str, Any]:
        """Get recent garbage collection activity summary"""
        recent_gc = [gc for gc in self.gc_metrics if gc.collection_time > (time.time() - 10)]
        
        if not recent_gc:
            return {'activity': 'none'}
        
        return {
            'activity': 'detected',
            'recent_collections': len(recent_gc),
            'total_pause_time': sum(gc.pause_duration for gc in recent_gc),
            'average_pause_time': statistics.mean([gc.pause_duration for gc in recent_gc]),
            'objects_collected': sum(gc.objects_collected for gc in recent_gc),
            'average_efficiency': statistics.mean([gc.efficiency_ratio for gc in recent_gc])
        }
    
    def _generate_profiling_analysis(self) -> Dict[str, Any]:
        """Generate comprehensive profiling analysis from collected data"""
        if not self.snapshots:
            return {'error': 'No snapshots available for analysis'}
        
        # Memory usage trend analysis
        memory_values = [s.memory_usage_mb for s in self.snapshots]
        memory_growth_values = [s.memory_growth_mb for s in self.snapshots]
        
        # Calculate memory statistics
        memory_stats = {
            'baseline_memory_mb': self.baseline_memory,
            'peak_memory_mb': max(memory_values),
            'final_memory_mb': memory_values[-1],
            'average_memory_mb': statistics.mean(memory_values),
            'memory_variance': statistics.variance(memory_values) if len(memory_values) > 1 else 0,
            'total_memory_growth_mb': memory_values[-1] - memory_values[0],
            'max_memory_growth_mb': max(memory_growth_values),
            'memory_efficiency_score': self._calculate_memory_efficiency()
        }
        
        # Object allocation analysis
        object_counts = [s.object_count for s in self.snapshots]
        object_stats = {
            'initial_objects': object_counts[0] if object_counts else 0,
            'final_objects': object_counts[-1] if object_counts else 0,
            'peak_objects': max(object_counts) if object_counts else 0,
            'object_growth': object_counts[-1] - object_counts[0] if len(object_counts) > 1 else 0,
            'average_objects': statistics.mean(object_counts) if object_counts else 0
        }
        
        return {
            'memory_statistics': memory_stats,
            'object_statistics': object_stats,
            'snapshot_count': len(self.snapshots),
            'profiling_duration': self.snapshots[-1].timestamp - self.snapshots[0].timestamp if len(self.snapshots) > 1 else 0,
            'memory_threshold_compliance': memory_values[-1] <= self.memory_threshold_mb,
            'memory_trend': self._analyze_memory_trend(memory_values)
        }
    
    def _analyze_gc_performance(self) -> Dict[str, Any]:
        """Analyze garbage collection performance and efficiency"""
        if not self.gc_metrics:
            return {'analysis': 'no_gc_activity'}
        
        # GC timing analysis
        pause_times = [gc.pause_duration for gc in self.gc_metrics]
        efficiency_ratios = [gc.efficiency_ratio for gc in self.gc_metrics]
        
        # Generation-specific analysis
        generation_stats = defaultdict(list)
        for gc_metric in self.gc_metrics:
            generation_stats[gc_metric.generation].append(gc_metric)
        
        analysis = {
            'total_collections': len(self.gc_metrics),
            'total_pause_time': sum(pause_times),
            'average_pause_time': statistics.mean(pause_times),
            'max_pause_time': max(pause_times),
            'median_pause_time': statistics.median(pause_times),
            'pause_time_stddev': statistics.stdev(pause_times) if len(pause_times) > 1 else 0,
            'average_efficiency': statistics.mean(efficiency_ratios),
            'total_objects_collected': sum(gc.objects_collected for gc in self.gc_metrics),
            'uncollectable_objects': sum(gc.uncollectable_objects for gc in self.gc_metrics),
            'generation_analysis': {
                gen: {
                    'collections': len(metrics),
                    'average_pause': statistics.mean([m.pause_duration for m in metrics]),
                    'average_efficiency': statistics.mean([m.efficiency_ratio for m in metrics])
                }
                for gen, metrics in generation_stats.items()
            }
        }
        
        # Performance impact assessment
        analysis['performance_impact'] = self._assess_gc_performance_impact(analysis)
        
        return analysis
    
    def _assess_gc_performance_impact(self, gc_analysis: Dict[str, Any]) -> str:
        """Assess GC performance impact and provide recommendations"""
        avg_pause = gc_analysis['average_pause_time']
        max_pause = gc_analysis['max_pause_time']
        total_pause = gc_analysis['total_pause_time']
        
        if max_pause > 0.1:  # 100ms max pause threshold
            return "HIGH - GC pauses exceed 100ms, consider memory optimization"
        elif avg_pause > 0.05:  # 50ms average pause threshold
            return "MEDIUM - Average GC pause time elevated, monitor memory usage"
        elif total_pause > 1.0:  # 1 second total pause threshold
            return "MEDIUM - Total GC time significant, review allocation patterns"
        else:
            return "LOW - GC performance within acceptable bounds"
    
    def _calculate_memory_efficiency(self) -> float:
        """Calculate memory efficiency score (0.0 to 1.0)"""
        if not self.snapshots:
            return 0.0
        
        # Efficiency based on memory growth vs peak usage
        final_memory = self.snapshots[-1].memory_usage_mb
        peak_memory = max(s.memory_usage_mb for s in self.snapshots)
        baseline_memory = self.baseline_memory
        
        if peak_memory <= baseline_memory:
            return 1.0
        
        # Calculate efficiency as ratio of necessary memory to peak memory
        necessary_memory = final_memory - baseline_memory
        peak_overhead = peak_memory - baseline_memory
        
        if peak_overhead == 0:
            return 1.0
        
        efficiency = 1.0 - (peak_overhead - necessary_memory) / peak_overhead
        return max(0.0, min(1.0, efficiency))
    
    def _analyze_memory_trend(self, memory_values: List[float]) -> str:
        """Analyze memory usage trend pattern"""
        if len(memory_values) < 3:
            return "insufficient_data"
        
        # Calculate linear regression slope
        x_values = list(range(len(memory_values)))
        slope = np.polyfit(x_values, memory_values, 1)[0]
        
        # Classify trend based on slope
        if slope > 1.0:  # More than 1MB increase per sample
            return "increasing_rapidly"
        elif slope > 0.1:  # More than 0.1MB increase per sample
            return "increasing_gradually"
        elif slope > -0.1:  # Stable within 0.1MB
            return "stable"
        else:
            return "decreasing"
    
    def _analyze_memory_leak_patterns(self, snapshots: List[MemorySnapshot]) -> Dict[str, Any]:
        """Analyze memory leak patterns from long-running monitoring"""
        if len(snapshots) < 10:
            return {'error': 'Insufficient samples for leak analysis'}
        
        # Extract memory values and timestamps
        timestamps = [s.timestamp for s in snapshots]
        memory_values = [s.memory_usage_mb for s in snapshots]
        object_counts = [s.object_count for s in snapshots]
        
        # Calculate memory growth rate
        time_span = timestamps[-1] - timestamps[0]
        memory_growth_rate = (memory_values[-1] - memory_values[0]) / time_span  # MB per second
        
        # Detect memory leak indicators
        leak_indicators = []
        
        # 1. Consistent memory growth
        if memory_growth_rate > 0.01:  # More than 0.01 MB/s growth
            leak_indicators.append("consistent_memory_growth")
        
        # 2. Object count growth
        object_growth_rate = (object_counts[-1] - object_counts[0]) / time_span
        if object_growth_rate > 100:  # More than 100 objects/s growth
            leak_indicators.append("object_count_growth")
        
        # 3. Memory trend analysis
        correlation = np.corrcoef(timestamps, memory_values)[0, 1]
        if correlation > 0.8:  # Strong positive correlation with time
            leak_indicators.append("strong_positive_correlation")
        
        # Calculate leak severity
        leak_severity = "none"
        if len(leak_indicators) >= 3:
            leak_severity = "high"
        elif len(leak_indicators) >= 2:
            leak_severity = "medium"
        elif len(leak_indicators) >= 1:
            leak_severity = "low"
        
        return {
            'monitoring_duration': time_span,
            'sample_count': len(snapshots),
            'memory_growth_rate_mb_per_sec': memory_growth_rate,
            'object_growth_rate_per_sec': object_growth_rate,
            'memory_time_correlation': correlation,
            'leak_indicators': leak_indicators,
            'leak_severity': leak_severity,
            'initial_memory_mb': memory_values[0],
            'final_memory_mb': memory_values[-1],
            'total_memory_growth_mb': memory_values[-1] - memory_values[0],
            'recommendations': self._generate_leak_recommendations(leak_indicators, leak_severity)
        }
    
    def _generate_leak_recommendations(self, indicators: List[str], severity: str) -> List[str]:
        """Generate memory leak remediation recommendations"""
        recommendations = []
        
        if "consistent_memory_growth" in indicators:
            recommendations.append("Review memory allocation patterns and ensure proper cleanup")
            recommendations.append("Implement reference counting validation for object lifecycle")
        
        if "object_count_growth" in indicators:
            recommendations.append("Audit object creation and destruction patterns")
            recommendations.append("Consider implementing object pooling for frequently created objects")
        
        if "strong_positive_correlation" in indicators:
            recommendations.append("Investigate time-dependent memory accumulation patterns")
            recommendations.append("Review caching mechanisms and implement TTL-based cleanup")
        
        if severity in ["high", "medium"]:
            recommendations.append("Enable detailed memory profiling in development environment")
            recommendations.append("Implement automated memory usage monitoring in production")
            recommendations.append("Consider using memory profiling tools like memory_profiler and pympler")
        
        return recommendations
    
    def _generate_optimization_recommendations(self) -> List[str]:
        """Generate memory optimization recommendations based on analysis"""
        recommendations = []
        
        if not self.snapshots:
            return ["No profiling data available for recommendations"]
        
        # Analyze memory usage patterns
        memory_values = [s.memory_usage_mb for s in self.snapshots]
        peak_memory = max(memory_values)
        final_memory = memory_values[-1]
        memory_efficiency = self._calculate_memory_efficiency()
        
        # Memory threshold compliance
        if peak_memory > self.memory_threshold_mb:
            recommendations.append(f"Memory usage exceeded threshold ({self.memory_threshold_mb}MB)")
            recommendations.append("Consider implementing memory usage monitoring and alerts")
        
        # Memory efficiency
        if memory_efficiency < 0.7:
            recommendations.append("Low memory efficiency detected - review memory allocation patterns")
            recommendations.append("Consider implementing lazy loading for large objects")
        
        # GC performance analysis
        if self.gc_metrics:
            avg_pause = statistics.mean([gc.pause_duration for gc in self.gc_metrics])
            if avg_pause > 0.05:  # 50ms threshold
                recommendations.append("High GC pause times detected - optimize object lifecycle")
                recommendations.append("Consider tuning GC thresholds for better performance")
        
        # Object growth analysis
        if len(self.snapshots) > 1:
            object_growth = self.snapshots[-1].object_count - self.snapshots[0].object_count
            if object_growth > 10000:  # Significant object growth
                recommendations.append("Significant object count growth - review object creation patterns")
                recommendations.append("Implement object pooling for frequently created/destroyed objects")
        
        # Container optimization for python:3.13.3-slim
        recommendations.append("Optimize container memory usage with Python 3.13.3 memory improvements")
        recommendations.append("Consider using __slots__ for frequently instantiated classes")
        recommendations.append("Implement memory-efficient data structures where appropriate")
        
        return recommendations if recommendations else ["Memory usage is within optimal parameters"]
    
    def cleanup(self):
        """Cleanup memory profiler resources and restore original settings"""
        # Restore original GC settings
        if hasattr(self, 'original_gc_thresholds'):
            gc.set_threshold(*self.original_gc_thresholds)
        
        if hasattr(self, 'original_gc_callbacks'):
            gc.callbacks.clear()
            gc.callbacks.extend(self.original_gc_callbacks)
        
        # Stop tracemalloc if running
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        
        # Clear tracking data
        self.snapshots.clear()
        self.gc_metrics.clear()


# ================================
# Memory Profiling Test Fixtures
# ================================

@pytest.fixture
def advanced_memory_profiler() -> Generator[AdvancedMemoryProfiler, None, None]:
    """
    Advanced memory profiler fixture providing comprehensive memory analysis
    capabilities including GC monitoring, leak detection, and optimization
    recommendations for Flask application memory validation.
    """
    profiler = AdvancedMemoryProfiler(enable_tracemalloc=True, gc_monitoring=True)
    yield profiler
    profiler.cleanup()


@pytest.fixture
def memory_baseline_data() -> Dict[str, float]:
    """
    Memory baseline data fixture providing Node.js baseline memory metrics
    for comparison and regression detection in Flask implementation validation.
    """
    # Simulated Node.js baseline data - in real implementation this would be loaded from file
    return {
        'api_endpoint_memory_mb': 45.2,
        'database_query_memory_mb': 52.1,
        'authentication_memory_mb': 38.7,
        'concurrent_load_memory_mb': 156.8,
        'application_startup_memory_mb': 78.3,
        'long_running_memory_mb': 92.5,
        'gc_pause_time_ms': 12.5,
        'memory_efficiency_score': 0.85
    }


@contextmanager
def memory_monitoring_context(profiler: AdvancedMemoryProfiler, test_name: str):
    """
    Context manager for memory monitoring during test execution with
    automatic profiling start/stop and comprehensive analysis collection.
    
    Args:
        profiler: Advanced memory profiler instance
        test_name: Name of the test for metrics tracking
    """
    profiler.start_profiling(enable_line_profiling=True)
    start_memory = psutil.Process().memory_info().rss / 1024 / 1024
    
    try:
        yield profiler
    finally:
        end_memory = psutil.Process().memory_info().rss / 1024 / 1024
        analysis = profiler.stop_profiling()
        
        print(f"\nMemory Analysis for {test_name}:")
        print(f"  Start Memory: {start_memory:.2f} MB")
        print(f"  End Memory: {end_memory:.2f} MB")
        print(f"  Memory Delta: {end_memory - start_memory:+.2f} MB")
        print(f"  Peak Memory: {analysis.get('memory_statistics', {}).get('peak_memory_mb', 0):.2f} MB")
        print(f"  Memory Efficiency: {analysis.get('memory_efficiency', 0):.3f}")
        
        if analysis.get('gc_analysis', {}).get('total_collections', 0) > 0:
            gc_analysis = analysis['gc_analysis']
            print(f"  GC Collections: {gc_analysis['total_collections']}")
            print(f"  Avg GC Pause: {gc_analysis['average_pause_time']*1000:.2f} ms")
            print(f"  GC Efficiency: {gc_analysis['average_efficiency']:.3f}")


# ================================
# Memory Profiling Performance Tests
# ================================

@pytest.mark.memory_test
@pytest.mark.performance
class TestMemoryProfiling:
    """
    Comprehensive memory profiling test suite validating Flask application
    memory performance, garbage collection efficiency, and memory optimization
    compared to Node.js baseline implementation.
    
    This test class implements memory profiling requirements as specified in
    Section 6.5.1.1 and Section 6.5.2.2 for comprehensive memory analysis,
    GC performance monitoring, and memory footprint optimization validation.
    """
    
    def test_basic_memory_profiling(self, advanced_memory_profiler: AdvancedMemoryProfiler,
                                  performance_app: Flask,
                                  performance_metrics_collector: PerformanceMetricsCollector):
        """
        Test basic memory profiling capabilities with memory_profiler and pympler
        integration for comprehensive memory usage analysis and validation.
        
        This test validates basic memory profiling functionality as specified in
        Section 6.5.1.1 for Python memory profiling using memory_profiler and
        pympler for comprehensive memory analysis.
        """
        with memory_monitoring_context(advanced_memory_profiler, "basic_memory_profiling"):
            # Test Flask application memory usage
            with performance_app.app_context():
                # Simulate application operations
                test_data = list(range(10000))  # Allocate test data
                processed_data = [x * 2 for x in test_data]  # Process data
                
                # Force garbage collection
                gc.collect()
                
                # Test memory-intensive operation
                large_dict = {f"key_{i}": f"value_{i}" * 100 for i in range(1000)}
                
                # Cleanup
                del test_data, processed_data, large_dict
                gc.collect()
        
        # Validate memory profiling results
        analysis = advanced_memory_profiler._generate_profiling_analysis()
        
        assert analysis['memory_statistics']['peak_memory_mb'] > 0, "Memory profiling should detect memory usage"
        assert analysis['object_statistics']['peak_objects'] > 0, "Object tracking should detect object allocation"
        assert analysis['memory_threshold_compliance'], f"Memory usage should be within threshold ({advanced_memory_profiler.memory_threshold_mb}MB)"
        
        # Record metrics for baseline comparison
        performance_metrics_collector.record_metric(
            test_name="basic_memory_profiling",
            metric_type="memory_usage",
            value=analysis['memory_statistics']['peak_memory_mb'],
            unit="MB",
            metadata={
                'object_count': analysis['object_statistics']['peak_objects'],
                'memory_efficiency': analysis['memory_statistics']['memory_efficiency_score'],
                'memory_trend': analysis['memory_trend']
            }
        )
    
    @pytest.mark.benchmark
    def test_gc_pause_monitoring(self, benchmark_fixture: BenchmarkFixture,
                                advanced_memory_profiler: AdvancedMemoryProfiler,
                                performance_metrics_collector: PerformanceMetricsCollector):
        """
        Test Python garbage collection pause time monitoring with performance
        impact analysis and optimization recommendations using Python 3.13.3
        garbage collection improvements.
        
        This test implements GC monitoring as specified in Section 6.5.1.1 for
        Python GC pause duration and performance impact monitoring with Python
        3.13.3 optimization analysis.
        """
        def gc_stress_test():
            """Function that triggers garbage collection activity"""
            objects = []
            
            # Create objects that will trigger different GC generations
            for i in range(1000):
                # Create objects with circular references
                obj1 = {'data': list(range(100)), 'ref': None}
                obj2 = {'data': list(range(100)), 'ref': obj1}
                obj1['ref'] = obj2
                objects.append((obj1, obj2))
                
                # Periodically clear some objects to trigger GC
                if i % 100 == 0:
                    objects = objects[50:]  # Keep some objects for next generation
            
            # Force full GC cycle
            gc.collect()
            return len(objects)
        
        with memory_monitoring_context(advanced_memory_profiler, "gc_pause_monitoring"):
            # Benchmark GC performance
            result = benchmark_fixture(gc_stress_test)
        
        # Analyze GC performance
        gc_analysis = advanced_memory_profiler._analyze_gc_performance()
        
        assert gc_analysis['total_collections'] > 0, "GC monitoring should detect garbage collection activity"
        
        # Validate GC pause times are within acceptable bounds
        avg_pause_ms = gc_analysis['average_pause_time'] * 1000
        max_pause_ms = gc_analysis['max_pause_time'] * 1000
        
        assert avg_pause_ms < 100, f"Average GC pause time ({avg_pause_ms:.2f}ms) should be under 100ms"
        assert max_pause_ms < 200, f"Maximum GC pause time ({max_pause_ms:.2f}ms) should be under 200ms"
        
        # Record GC performance metrics
        performance_metrics_collector.record_metric(
            test_name="gc_pause_monitoring",
            metric_type="gc_pause_time",
            value=gc_analysis['average_pause_time'],
            unit="seconds",
            metadata={
                'total_collections': gc_analysis['total_collections'],
                'max_pause_time': gc_analysis['max_pause_time'],
                'efficiency': gc_analysis['average_efficiency'],
                'performance_impact': gc_analysis['performance_impact']
            }
        )
        
        print(f"\nGC Performance Analysis:")
        print(f"  Total Collections: {gc_analysis['total_collections']}")
        print(f"  Average Pause: {avg_pause_ms:.2f} ms")
        print(f"  Maximum Pause: {max_pause_ms:.2f} ms")
        print(f"  GC Efficiency: {gc_analysis['average_efficiency']:.3f}")
        print(f"  Performance Impact: {gc_analysis['performance_impact']}")
    
    @pytest.mark.benchmark
    def test_memory_allocation_patterns(self, benchmark_fixture: BenchmarkFixture,
                                      advanced_memory_profiler: AdvancedMemoryProfiler,
                                      performance_metrics_collector: PerformanceMetricsCollector):
        """
        Test memory allocation patterns and garbage collection impact with
        pytest-benchmark integration measuring allocation efficiency and
        performance optimization for Python 3.13.3 memory improvements.
        
        This test implements allocation pattern analysis as specified in
        Section 6.5.2.2 for memory allocation statistics and comprehensive
        performance analysis with Python 3.13.3 optimization validation.
        """
        def allocation_test_function():
            """Function that performs various allocation patterns"""
            # Test different allocation patterns
            
            # 1. List allocation and growth
            large_list = []
            for i in range(10000):
                large_list.append(i)
            
            # 2. Dictionary allocation with string keys
            large_dict = {}
            for i in range(5000):
                large_dict[f"key_{i}"] = f"value_{i}" * 10
            
            # 3. Object allocation with references
            class TestObject:
                def __init__(self, value):
                    self.value = value
                    self.data = list(range(100))
            
            objects = [TestObject(i) for i in range(1000)]
            
            # 4. Cleanup to test deallocation
            del large_list[:5000]  # Partial cleanup
            del large_dict
            del objects[:500]  # Partial cleanup
            
            return len(objects)
        
        # Benchmark allocation patterns with memory profiling
        with memory_monitoring_context(advanced_memory_profiler, "memory_allocation_patterns"):
            allocation_benchmark = advanced_memory_profiler.benchmark_memory_allocation(
                allocation_test_function, 
                iterations=100
            )
            
            # Also run with pytest-benchmark for comparison
            benchmark_result = benchmark_fixture(allocation_test_function)
        
        # Validate allocation performance
        assert allocation_benchmark['average_allocation_time'] < 0.1, "Allocation should be efficient (<100ms)"
        assert allocation_benchmark['gc_trigger_rate'] < 0.2, "GC trigger rate should be reasonable (<20%)"
        assert allocation_benchmark['allocation_efficiency'] > 10, "Allocation efficiency should be good (>10 ops/sec)"
        
        # Record allocation performance metrics
        performance_metrics_collector.record_metric(
            test_name="memory_allocation_patterns",
            metric_type="allocation_efficiency",
            value=allocation_benchmark['allocation_efficiency'],
            unit="allocations_per_second",
            metadata={
                'average_allocation_time': allocation_benchmark['average_allocation_time'],
                'total_memory_allocated': allocation_benchmark['total_memory_allocated'],
                'gc_trigger_rate': allocation_benchmark['gc_trigger_rate'],
                'allocation_time_stddev': allocation_benchmark['allocation_time_stddev']
            }
        )
        
        print(f"\nMemory Allocation Pattern Analysis:")
        print(f"  Average Allocation Time: {allocation_benchmark['average_allocation_time']*1000:.2f} ms")
        print(f"  Total Memory Allocated: {allocation_benchmark['total_memory_allocated']:.2f} MB")
        print(f"  GC Trigger Rate: {allocation_benchmark['gc_trigger_rate']*100:.1f}%")
        print(f"  Allocation Efficiency: {allocation_benchmark['allocation_efficiency']:.1f} ops/sec")
    
    def test_memory_leak_detection(self, advanced_memory_profiler: AdvancedMemoryProfiler,
                                 performance_metrics_collector: PerformanceMetricsCollector):
        """
        Test automated memory leak detection with long-running test scenarios
        and comprehensive resource monitoring for identifying potential memory
        leaks and optimization opportunities.
        
        This test implements memory leak detection as specified in Section 4.7.2
        for automated memory leak detection with long-running test scenarios
        and resource monitoring validation.
        """
        print("\nStarting memory leak detection test...")
        
        # Simulate potential memory leak scenario
        class PotentialLeaker:
            _instances = []  # Class variable that could cause leaks
            
            def __init__(self, data_size: int = 1000):
                self.data = list(range(data_size))
                self.timestamp = time.time()
                # Intentionally add to class variable to simulate potential leak
                PotentialLeaker._instances.append(self)
        
        # Function that might leak memory
        def potentially_leaking_function():
            # Create objects that might not be properly cleaned up
            leaker = PotentialLeaker(500)
            temp_data = [leaker] * 100  # Create references
            # Simulate some processing
            processed = [item.data[:100] for item in temp_data]
            return len(processed)
        
        # Run leak detection with shorter duration for testing
        with memory_monitoring_context(advanced_memory_profiler, "memory_leak_detection"):
            # Simulate repeated operations that might leak
            for i in range(50):
                potentially_leaking_function()
                if i % 10 == 0:
                    time.sleep(0.1)  # Brief pause to allow GC
            
            # Run dedicated leak detection
            leak_analysis = advanced_memory_profiler.detect_memory_leaks(
                test_duration=10.0,  # 10 seconds for testing
                sample_interval=0.5
            )
        
        # Validate leak detection results
        assert 'leak_severity' in leak_analysis, "Leak detection should provide severity assessment"
        assert 'memory_growth_rate_mb_per_sec' in leak_analysis, "Should measure memory growth rate"
        assert 'recommendations' in leak_analysis, "Should provide optimization recommendations"
        
        # Record leak detection metrics
        performance_metrics_collector.record_metric(
            test_name="memory_leak_detection",
            metric_type="memory_growth_rate",
            value=leak_analysis['memory_growth_rate_mb_per_sec'],
            unit="MB_per_second",
            metadata={
                'leak_severity': leak_analysis['leak_severity'],
                'total_memory_growth': leak_analysis['total_memory_growth_mb'],
                'monitoring_duration': leak_analysis['monitoring_duration'],
                'leak_indicators': leak_analysis['leak_indicators'],
                'recommendations_count': len(leak_analysis['recommendations'])
            }
        )
        
        print(f"\nMemory Leak Detection Results:")
        print(f"  Monitoring Duration: {leak_analysis['monitoring_duration']:.1f} seconds")
        print(f"  Memory Growth Rate: {leak_analysis['memory_growth_rate_mb_per_sec']:.4f} MB/sec")
        print(f"  Total Memory Growth: {leak_analysis['total_memory_growth_mb']:.2f} MB")
        print(f"  Leak Severity: {leak_analysis['leak_severity']}")
        print(f"  Leak Indicators: {leak_analysis['leak_indicators']}")
        
        # Cleanup the intentional "leak" for other tests
        PotentialLeaker._instances.clear()
    
    def test_flask_application_factory_memory(self, performance_app: Flask,
                                            advanced_memory_profiler: AdvancedMemoryProfiler,
                                            performance_client: FlaskClient,
                                            performance_metrics_collector: PerformanceMetricsCollector):
        """
        Test Flask application factory memory usage analysis with comprehensive
        lifecycle monitoring and resource utilization validation for efficient
        Flask application memory management.
        
        This test implements Flask application memory analysis as specified in
        Section 5.1.1 for Flask application factory memory usage analysis with
        comprehensive lifecycle monitoring validation.
        """
        with memory_monitoring_context(advanced_memory_profiler, "flask_application_factory_memory"):
            # Test application initialization memory
            init_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            # Test request handling memory
            with performance_app.app_context():
                # Simulate multiple request contexts
                for i in range(100):
                    with performance_app.test_request_context(f'/test/{i}'):
                        # Simulate request processing
                        g.test_data = list(range(1000))
                        request_result = len(g.test_data)
                
                # Test database operations if available
                try:
                    from src.models import db
                    if db:
                        # Simulate database operations
                        for i in range(50):
                            # Simple query simulation
                            result = db.session.execute('SELECT 1').scalar()
                except ImportError:
                    pass  # Database not available in test environment
                
                # Test Flask blueprint memory usage
                blueprint_memory = psutil.Process().memory_info().rss / 1024 / 1024
                
                # Simulate API endpoint calls
                api_responses = []
                for i in range(50):
                    # Use test client for realistic request simulation
                    try:
                        response = performance_client.get('/')
                        api_responses.append(response.status_code)
                    except Exception:
                        # Handle case where routes don't exist
                        api_responses.append(404)
                
                final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Analyze Flask application memory usage
        analysis = advanced_memory_profiler._generate_profiling_analysis()
        
        # Calculate Flask-specific metrics
        app_memory_usage = final_memory - init_memory
        memory_per_request = app_memory_usage / 100 if app_memory_usage > 0 else 0
        
        # Validate Flask memory efficiency
        assert analysis['memory_threshold_compliance'], "Flask app should stay within memory threshold"
        assert memory_per_request < 1.0, f"Memory per request ({memory_per_request:.3f}MB) should be efficient"
        
        # Record Flask application memory metrics
        performance_metrics_collector.record_metric(
            test_name="flask_application_factory_memory",
            metric_type="app_memory_usage",
            value=analysis['memory_statistics']['peak_memory_mb'],
            unit="MB",
            metadata={
                'memory_per_request': memory_per_request,
                'application_efficiency': analysis['memory_statistics']['memory_efficiency_score'],
                'request_count': 100,
                'successful_requests': len([r for r in api_responses if r == 200]),
                'blueprint_memory_delta': blueprint_memory - init_memory
            }
        )
        
        print(f"\nFlask Application Factory Memory Analysis:")
        print(f"  Initial Memory: {init_memory:.2f} MB")
        print(f"  Final Memory: {final_memory:.2f} MB")
        print(f"  Application Memory Delta: {app_memory_usage:.2f} MB")
        print(f"  Memory per Request: {memory_per_request:.3f} MB")
        print(f"  Memory Efficiency Score: {analysis['memory_statistics']['memory_efficiency_score']:.3f}")
    
    @pytest.mark.baseline_comparison
    def test_memory_footprint_baseline_comparison(self, advanced_memory_profiler: AdvancedMemoryProfiler,
                                                memory_baseline_data: Dict[str, float],
                                                performance_metrics_collector: PerformanceMetricsCollector,
                                                baseline_comparison_validator: Dict[str, Callable]):
        """
        Test memory footprint comparison between Flask and Node.js implementations
        with optimization validation and performance regression detection for
        migration success validation.
        
        This test implements baseline comparison as specified in Section 4.7.1
        for memory footprint comparison between Flask and Node.js implementations
        with optimization validation requirements.
        """
        print("\nStarting Flask vs Node.js memory footprint comparison...")
        
        # Test various memory usage scenarios
        memory_test_results = []
        
        # Test 1: Basic application memory
        with memory_monitoring_context(advanced_memory_profiler, "baseline_app_memory"):
            # Simulate basic application operations
            app_data = [list(range(1000)) for _ in range(100)]
            app_result = sum(len(data) for data in app_data)
            del app_data
            gc.collect()
        
        app_analysis = advanced_memory_profiler._generate_profiling_analysis()
        flask_app_memory = app_analysis['memory_statistics']['peak_memory_mb']
        
        memory_test_results.append({
            'test_name': 'application_memory',
            'metric_type': 'memory_usage',
            'value': flask_app_memory
        })
        
        # Test 2: Database operation memory simulation
        with memory_monitoring_context(advanced_memory_profiler, "baseline_db_memory"):
            # Simulate database query results
            db_results = []
            for i in range(1000):
                record = {
                    'id': i,
                    'data': f"record_data_{i}" * 50,
                    'metadata': {'timestamp': time.time(), 'index': i}
                }
                db_results.append(record)
            
            # Simulate processing
            processed = [r for r in db_results if r['id'] % 2 == 0]
            del db_results, processed
            gc.collect()
        
        db_analysis = advanced_memory_profiler._generate_profiling_analysis()
        flask_db_memory = db_analysis['memory_statistics']['peak_memory_mb']
        
        memory_test_results.append({
            'test_name': 'database_memory',
            'metric_type': 'memory_usage', 
            'value': flask_db_memory
        })
        
        # Test 3: Authentication memory simulation
        with memory_monitoring_context(advanced_memory_profiler, "baseline_auth_memory"):
            # Simulate authentication data structures
            auth_sessions = {}
            for i in range(500):
                session_id = f"session_{i}"
                auth_sessions[session_id] = {
                    'user_id': f"user_{i}",
                    'token': f"token_{i}" * 100,
                    'expires': time.time() + 3600,
                    'permissions': [f"perm_{j}" for j in range(10)]
                }
            
            # Simulate session validation
            valid_sessions = {k: v for k, v in auth_sessions.items() if v['expires'] > time.time()}
            del auth_sessions, valid_sessions
            gc.collect()
        
        auth_analysis = advanced_memory_profiler._generate_profiling_analysis()
        flask_auth_memory = auth_analysis['memory_statistics']['peak_memory_mb']
        
        memory_test_results.append({
            'test_name': 'authentication_memory',
            'metric_type': 'memory_usage',
            'value': flask_auth_memory
        })
        
        # Perform baseline comparison validation
        validation_results = baseline_comparison_validator['validate_regression'](
            memory_test_results,
            regression_threshold=0.15  # Allow 15% memory increase
        )
        
        # Generate comprehensive comparison report
        comparison_report = baseline_comparison_validator['generate_report'](validation_results)
        print(comparison_report)
        
        # Validate baseline comparison results
        assert validation_results['overall_regression_check_passed'], "Memory footprint should not regress significantly"
        
        # Check specific memory improvements
        memory_improvements = validation_results['summary']['tests_with_improvement']
        memory_regressions = validation_results['summary']['tests_with_regression']
        
        print(f"\nBaseline Comparison Summary:")
        print(f"  Tests with Memory Improvement: {memory_improvements}")
        print(f"  Tests with Memory Regression: {memory_regressions}")
        print(f"  Overall Regression Check: {'PASSED' if validation_results['overall_regression_check_passed'] else 'FAILED'}")
        
        # Record baseline comparison metrics
        for result in validation_results['detailed_results']:
            performance_metrics_collector.record_metric(
                test_name=f"baseline_{result['test_name']}",
                metric_type="memory_comparison",
                value=result['performance_ratio'],
                unit="ratio",
                metadata={
                    'flask_memory_mb': result['flask_value'],
                    'nodejs_memory_mb': result['nodejs_value'],
                    'improvement_percentage': result['improvement_percentage'],
                    'passed': result['passed'],
                    'analysis': result['analysis']
                }
            )
    
    @pytest.mark.benchmark 
    def test_container_memory_optimization(self, benchmark_fixture: BenchmarkFixture,
                                         advanced_memory_profiler: AdvancedMemoryProfiler,
                                         performance_metrics_collector: PerformanceMetricsCollector):
        """
        Test python:3.13.3-slim container memory optimization validation with
        performance benchmarking and resource utilization analysis for
        containerized deployment optimization.
        
        This test implements container optimization validation as specified in
        Section 4.11.3 for python:3.13.3-slim container memory optimization
        and resource utilization efficiency validation.
        """
        def container_simulation_test():
            """Simulate containerized application memory usage patterns"""
            # Simulate container initialization
            container_data = {
                'environment': 'production',
                'python_version': '3.13.3',
                'container_type': 'slim',
                'memory_limit': '512MB'
            }
            
            # Simulate application components loading
            components = []
            for i in range(100):
                component = {
                    'name': f'component_{i}',
                    'config': {f'setting_{j}': f'value_{j}' for j in range(50)},
                    'state': 'initialized',
                    'memory_usage': 0
                }
                components.append(component)
            
            # Simulate request processing in container
            request_cache = {}
            for i in range(1000):
                request_id = f'req_{i}'
                request_cache[request_id] = {
                    'timestamp': time.time(),
                    'data': list(range(100)),
                    'processed': True
                }
                
                # Simulate cache cleanup (container memory management)
                if len(request_cache) > 500:
                    oldest_requests = sorted(request_cache.keys())[:100]
                    for req_id in oldest_requests:
                        del request_cache[req_id]
            
            return len(components) + len(request_cache)
        
        # Benchmark container memory usage
        with memory_monitoring_context(advanced_memory_profiler, "container_memory_optimization"):
            benchmark_result = benchmark_fixture(container_simulation_test)
        
        # Analyze container memory efficiency
        analysis = advanced_memory_profiler._generate_profiling_analysis()
        peak_memory = analysis['memory_statistics']['peak_memory_mb']
        memory_efficiency = analysis['memory_statistics']['memory_efficiency_score']
        
        # Container-specific validation
        container_memory_limit = 512  # MB
        memory_utilization = (peak_memory / container_memory_limit) * 100
        
        assert peak_memory < container_memory_limit, f"Memory usage ({peak_memory:.1f}MB) should be under container limit ({container_memory_limit}MB)"
        assert memory_utilization < 80, f"Memory utilization ({memory_utilization:.1f}%) should be under 80% of container limit"
        assert memory_efficiency > 0.7, f"Memory efficiency ({memory_efficiency:.3f}) should be good (>0.7)"
        
        # Validate Python 3.13.3 specific optimizations
        gc_analysis = advanced_memory_profiler._analyze_gc_performance()
        if gc_analysis.get('total_collections', 0) > 0:
            avg_gc_pause = gc_analysis['average_pause_time'] * 1000  # Convert to ms
            assert avg_gc_pause < 50, f"Python 3.13.3 should have optimized GC pauses (<50ms), got {avg_gc_pause:.2f}ms"
        
        # Record container optimization metrics
        performance_metrics_collector.record_metric(
            test_name="container_memory_optimization",
            metric_type="container_memory_usage",
            value=peak_memory,
            unit="MB",
            metadata={
                'memory_utilization_percent': memory_utilization,
                'memory_efficiency': memory_efficiency,
                'container_limit_mb': container_memory_limit,
                'python_version': '3.13.3',
                'container_type': 'slim',
                'gc_pause_time_ms': gc_analysis.get('average_pause_time', 0) * 1000
            }
        )
        
        print(f"\nContainer Memory Optimization Analysis:")
        print(f"  Peak Memory Usage: {peak_memory:.2f} MB")
        print(f"  Container Limit: {container_memory_limit} MB")
        print(f"  Memory Utilization: {memory_utilization:.1f}%")
        print(f"  Memory Efficiency: {memory_efficiency:.3f}")
        print(f"  Python 3.13.3 GC Performance: {gc_analysis.get('average_pause_time', 0)*1000:.2f} ms avg pause")
    
    def test_memory_profiling_comprehensive_report(self, advanced_memory_profiler: AdvancedMemoryProfiler,
                                                 performance_metrics_collector: PerformanceMetricsCollector):
        """
        Generate comprehensive memory profiling report with optimization
        recommendations, performance analysis, and detailed memory usage
        insights for Flask application memory optimization guidance.
        
        This test generates comprehensive reporting as specified in Section 6.5.1.1
        for memory profiling analysis and optimization recommendations with
        detailed performance insights and guidance.
        """
        print("\nGenerating comprehensive memory profiling report...")
        
        # Run comprehensive memory analysis
        with memory_monitoring_context(advanced_memory_profiler, "comprehensive_memory_analysis"):
            # Simulate various memory usage patterns
            
            # 1. Gradual memory allocation
            gradual_data = []
            for i in range(1000):
                gradual_data.append(list(range(100)))
                if i % 100 == 0:
                    time.sleep(0.01)  # Allow GC opportunity
            
            # 2. Burst memory allocation
            burst_data = [list(range(1000)) for _ in range(500)]
            
            # 3. Memory churn (allocation/deallocation)
            for i in range(100):
                temp_data = [f"temp_{j}" * 100 for j in range(1000)]
                del temp_data
                if i % 10 == 0:
                    gc.collect()
            
            # 4. Long-lived objects
            long_lived = {f"persistent_{i}": list(range(500)) for i in range(100)}
            
            # Cleanup
            del gradual_data, burst_data
            gc.collect()
        
        # Generate comprehensive analysis
        memory_analysis = advanced_memory_profiler._generate_profiling_analysis()
        gc_analysis = advanced_memory_profiler._analyze_gc_performance()
        optimization_recommendations = advanced_memory_profiler._generate_optimization_recommendations()
        
        # Create comprehensive report
        report = []
        report.append("=" * 80)
        report.append("COMPREHENSIVE MEMORY PROFILING REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.utcnow().isoformat()}Z")
        report.append(f"Python Version: 3.13.3")
        report.append(f"Flask Version: 3.1.1")
        report.append("")
        
        # Memory Statistics Section
        report.append("MEMORY USAGE STATISTICS:")
        memory_stats = memory_analysis['memory_statistics']
        report.append(f"  Baseline Memory: {memory_stats['baseline_memory_mb']:.2f} MB")
        report.append(f"  Peak Memory: {memory_stats['peak_memory_mb']:.2f} MB")
        report.append(f"  Final Memory: {memory_stats['final_memory_mb']:.2f} MB")
        report.append(f"  Memory Growth: {memory_stats['total_memory_growth_mb']:.2f} MB")
        report.append(f"  Memory Efficiency: {memory_stats['memory_efficiency_score']:.3f}")
        report.append(f"  Memory Trend: {memory_analysis['memory_trend']}")
        report.append("")
        
        # Garbage Collection Analysis Section
        if gc_analysis.get('total_collections', 0) > 0:
            report.append("GARBAGE COLLECTION ANALYSIS:")
            report.append(f"  Total Collections: {gc_analysis['total_collections']}")
            report.append(f"  Average Pause Time: {gc_analysis['average_pause_time']*1000:.2f} ms")
            report.append(f"  Maximum Pause Time: {gc_analysis['max_pause_time']*1000:.2f} ms") 
            report.append(f"  GC Efficiency: {gc_analysis['average_efficiency']:.3f}")
            report.append(f"  Performance Impact: {gc_analysis['performance_impact']}")
            report.append("")
        
        # Object Statistics Section
        object_stats = memory_analysis['object_statistics']
        report.append("OBJECT ALLOCATION STATISTICS:")
        report.append(f"  Initial Objects: {object_stats['initial_objects']:,}")
        report.append(f"  Peak Objects: {object_stats['peak_objects']:,}")
        report.append(f"  Final Objects: {object_stats['final_objects']:,}")
        report.append(f"  Object Growth: {object_stats['object_growth']:,}")
        report.append("")
        
        # Optimization Recommendations Section
        report.append("OPTIMIZATION RECOMMENDATIONS:")
        for i, recommendation in enumerate(optimization_recommendations, 1):
            report.append(f"  {i}. {recommendation}")
        report.append("")
        
        # Performance Summary Section
        report.append("PERFORMANCE SUMMARY:")
        threshold_mb = advanced_memory_profiler.memory_threshold_mb
        compliance = "COMPLIANT" if memory_analysis['memory_threshold_compliance'] else "NON-COMPLIANT"
        report.append(f"  Memory Threshold: {threshold_mb} MB")
        report.append(f"  Compliance Status: {compliance}")
        report.append(f"  Overall Assessment: {'OPTIMIZED' if memory_stats['memory_efficiency_score'] > 0.8 else 'NEEDS_OPTIMIZATION'}")
        report.append("")
        
        report.append("=" * 80)
        
        # Print and validate report
        comprehensive_report = "\n".join(report)
        print(comprehensive_report)
        
        # Validate report generation
        assert memory_analysis['memory_threshold_compliance'], "Memory usage should comply with thresholds"
        assert len(optimization_recommendations) > 0, "Should generate optimization recommendations"
        assert memory_stats['memory_efficiency_score'] > 0.5, "Memory efficiency should be reasonable"
        
        # Record comprehensive metrics
        performance_metrics_collector.record_metric(
            test_name="comprehensive_memory_report",
            metric_type="memory_efficiency_score",
            value=memory_stats['memory_efficiency_score'],
            unit="score",
            metadata={
                'peak_memory_mb': memory_stats['peak_memory_mb'],
                'memory_growth_mb': memory_stats['total_memory_growth_mb'],
                'gc_collections': gc_analysis.get('total_collections', 0),
                'gc_avg_pause_ms': gc_analysis.get('average_pause_time', 0) * 1000,
                'optimization_recommendations': len(optimization_recommendations),
                'threshold_compliance': memory_analysis['memory_threshold_compliance'],
                'report_length': len(comprehensive_report)
            }
        )


# ================================
# Memory Profiling Utility Functions
# ================================

def analyze_memory_distribution(memory_samples: List[float]) -> Dict[str, float]:
    """
    Analyze memory usage distribution and patterns for comprehensive
    memory performance insights and optimization guidance.
    
    Args:
        memory_samples: List of memory usage measurements in MB
        
    Returns:
        Dict containing statistical memory distribution analysis
    """
    if not memory_samples:
        return {'error': 'No memory samples provided'}
    
    return {
        'mean': statistics.mean(memory_samples),
        'median': statistics.median(memory_samples),
        'std_dev': statistics.stdev(memory_samples) if len(memory_samples) > 1 else 0.0,
        'min': min(memory_samples),
        'max': max(memory_samples),
        'range': max(memory_samples) - min(memory_samples),
        'p25': np.percentile(memory_samples, 25),
        'p75': np.percentile(memory_samples, 75),
        'p95': np.percentile(memory_samples, 95),
        'p99': np.percentile(memory_samples, 99),
        'coefficient_of_variation': statistics.stdev(memory_samples) / statistics.mean(memory_samples) if statistics.mean(memory_samples) > 0 else 0,
        'memory_stability': 'stable' if statistics.stdev(memory_samples) < statistics.mean(memory_samples) * 0.1 else 'variable'
    }


def validate_memory_optimization(before_memory: float, after_memory: float, 
                               threshold_improvement: float = 0.05) -> Dict[str, Any]:
    """
    Validate memory optimization effectiveness by comparing before/after
    memory usage measurements with configurable improvement thresholds.
    
    Args:
        before_memory: Memory usage before optimization (MB)
        after_memory: Memory usage after optimization (MB)
        threshold_improvement: Minimum improvement threshold (0.05 = 5%)
        
    Returns:
        Dict containing optimization validation results
    """
    memory_delta = before_memory - after_memory
    improvement_percentage = (memory_delta / before_memory) * 100 if before_memory > 0 else 0
    
    optimization_achieved = improvement_percentage >= (threshold_improvement * 100)
    
    return {
        'before_memory_mb': before_memory,
        'after_memory_mb': after_memory,
        'memory_reduction_mb': memory_delta,
        'improvement_percentage': improvement_percentage,
        'threshold_percentage': threshold_improvement * 100,
        'optimization_achieved': optimization_achieved,
        'assessment': 'significant_improvement' if improvement_percentage > 10 else
                     'moderate_improvement' if improvement_percentage > 5 else
                     'minimal_improvement' if improvement_percentage > 0 else
                     'no_improvement'
    }


# ================================
# Export Memory Profiling Components
# ================================

__all__ = [
    'AdvancedMemoryProfiler',
    'MemorySnapshot',
    'GCMetrics',
    'TestMemoryProfiling',
    'memory_monitoring_context',
    'analyze_memory_distribution',
    'validate_memory_optimization'
]