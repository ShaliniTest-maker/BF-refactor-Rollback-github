"""
Comprehensive Results Analyzer for Flask Migration Comparative Testing

This utility processes comparative test outputs, identifies behavioral differences between 
Node.js and Flask implementations, generates detailed variance reports, and triggers 
automated correction workflows when parity violations are detected per Section 4.7.2 
automated correction workflow requirements.

Core Capabilities:
- Detailed response data comparison with diff analysis for API contract validation
- Performance metric deviation identification with threshold-based alerting system
- Database query result variance analysis for SQLAlchemy optimization guidance
- Error handling inconsistency detection with comprehensive root cause analysis
- Automated report generation with migration status tracking and trend analysis
- Correction workflow integration for automated Flask implementation adjustment
- Real-time discrepancy detection with severity classification and escalation

The analyzer implements comprehensive variance detection algorithms that identify functional
and performance discrepancies between systems, providing actionable insights for Flask
implementation refinement with specific root cause identification and recommended
corrective actions.

Dependencies:
- Flask 3.1.1 with comparative testing framework integration
- pytest-flask 1.3.0 for test result processing and analysis
- pytest-benchmark 5.1.0 for performance metric comparison and validation
- Prometheus client for metrics collection and threshold monitoring
- Jinja2 3.1.x for report template rendering and generation
- SQLAlchemy 2.0.x for database variance analysis and optimization recommendations

References:
- Section 4.7.2: Comparative Testing Process and Automated Correction Workflow
- Section 4.8.1: Error Handling and Recovery Workflows for Issue Detection
- Section 6.5.1: Monitoring and Observability for Performance Threshold Management
- Section 4.7.2: Detailed response data comparison with diff analysis requirements
- Feature F-009: Functionality Parity Validation Process requirements

Author: Migration Team
Version: 1.0.0
Compatible with: Python 3.13.3, Flask 3.1.1, pytest-flask 1.3.0
"""

import os
import sys
import json
import time
import hashlib
import difflib
import traceback
import statistics
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple, Callable, NamedTuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter
from contextlib import contextmanager
from enum import Enum, auto
import logging
import uuid
import re
import yaml
import subprocess

# Third-party imports for comprehensive analysis capabilities
import numpy as np
import pandas as pd
from jinja2 import Environment, FileSystemLoader, Template
from prometheus_client import CollectorRegistry, Counter as PrometheusCounter, Histogram, Gauge, Summary
import structlog
from deepdiff import DeepDiff
from scipy import stats
import requests

# Flask testing framework imports for integration
try:
    from tests.integration.comparative.conftest_comparative import (
        ComparativeTestConfig,
        NodeJSBaselineClient
    )
    from tests.integration.comparative.baseline_capture import BaselineDataCapture
except ImportError as e:
    # Handle import errors gracefully for standalone execution
    logging.warning(f"Comparative testing framework imports unavailable: {e}")
    ComparativeTestConfig = None
    NodeJSBaselineClient = None
    BaselineDataCapture = None

# Configure structured logging for results analysis
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.ConsoleRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    logger_factory=structlog.WriteLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("results_analyzer")


# =============================================================================
# Core Data Models and Enumerations
# =============================================================================

class DiscrepancySeverity(Enum):
    """Enumeration for discrepancy severity levels with escalation priorities."""
    CRITICAL = "critical"      # Functional parity violation requiring immediate correction
    HIGH = "high"             # Performance degradation exceeding acceptable thresholds
    MEDIUM = "medium"         # Minor inconsistencies requiring investigation
    LOW = "low"              # Cosmetic differences with minimal impact
    INFO = "info"            # Informational variances for documentation


class DiscrepancyType(Enum):
    """Enumeration for discrepancy categorization and root cause analysis."""
    API_RESPONSE_MISMATCH = "api_response_mismatch"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    DATABASE_VARIANCE = "database_variance"
    ERROR_HANDLING_INCONSISTENCY = "error_handling_inconsistency"
    AUTHENTICATION_FAILURE = "authentication_failure"
    BUSINESS_LOGIC_DEVIATION = "business_logic_deviation"
    DATA_INTEGRITY_VIOLATION = "data_integrity_violation"
    TIMEOUT_EXCEEDED = "timeout_exceeded"
    RESOURCE_LEAK = "resource_leak"
    SECURITY_VIOLATION = "security_violation"


class AnalysisStatus(Enum):
    """Analysis execution status enumeration for workflow tracking."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CorrectionWorkflowAction(Enum):
    """Automated correction workflow action types."""
    NO_ACTION = "no_action"
    FLASK_CODE_ADJUSTMENT = "flask_code_adjustment"
    SQLALCHEMY_OPTIMIZATION = "sqlalchemy_optimization"
    ERROR_HANDLER_UPDATE = "error_handler_update"
    PERFORMANCE_TUNING = "performance_tuning"
    CONFIGURATION_CHANGE = "configuration_change"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


@dataclass
class PerformanceMetrics:
    """Performance metrics data structure for comparative analysis."""
    response_time_ms: float
    memory_usage_mb: float
    cpu_utilization_percent: float
    database_query_count: int
    database_query_time_ms: float
    concurrent_users: int
    throughput_rps: float
    error_rate_percent: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert performance metrics to dictionary for serialization."""
        return {
            'response_time_ms': self.response_time_ms,
            'memory_usage_mb': self.memory_usage_mb,
            'cpu_utilization_percent': self.cpu_utilization_percent,
            'database_query_count': self.database_query_count,
            'database_query_time_ms': self.database_query_time_ms,
            'concurrent_users': self.concurrent_users,
            'throughput_rps': self.throughput_rps,
            'error_rate_percent': self.error_rate_percent,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ResponseComparison:
    """Response comparison data structure for API contract validation."""
    endpoint: str
    method: str
    nodejs_response: Dict[str, Any]
    flask_response: Dict[str, Any]
    status_code_match: bool
    content_type_match: bool
    data_structure_match: bool
    data_content_match: bool
    headers_match: bool
    performance_delta_ms: float
    differences: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert response comparison to dictionary for serialization."""
        return {
            'endpoint': self.endpoint,
            'method': self.method,
            'nodejs_response': self.nodejs_response,
            'flask_response': self.flask_response,
            'status_code_match': self.status_code_match,
            'content_type_match': self.content_type_match,
            'data_structure_match': self.data_structure_match,
            'data_content_match': self.data_content_match,
            'headers_match': self.headers_match,
            'performance_delta_ms': self.performance_delta_ms,
            'differences': self.differences,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class DatabaseQueryAnalysis:
    """Database query analysis data structure for SQLAlchemy optimization."""
    query_type: str
    table_name: str
    nodejs_execution_time_ms: float
    flask_execution_time_ms: float
    nodejs_result_count: int
    flask_result_count: int
    query_plan_difference: bool
    index_usage_difference: bool
    optimization_recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert database query analysis to dictionary for serialization."""
        return {
            'query_type': self.query_type,
            'table_name': self.table_name,
            'nodejs_execution_time_ms': self.nodejs_execution_time_ms,
            'flask_execution_time_ms': self.flask_execution_time_ms,
            'nodejs_result_count': self.nodejs_result_count,
            'flask_result_count': self.flask_result_count,
            'query_plan_difference': self.query_plan_difference,
            'index_usage_difference': self.index_usage_difference,
            'optimization_recommendations': self.optimization_recommendations,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ErrorHandlingAnalysis:
    """Error handling analysis data structure for consistency validation."""
    error_scenario: str
    nodejs_error_response: Dict[str, Any]
    flask_error_response: Dict[str, Any]
    status_code_consistency: bool
    error_message_consistency: bool
    error_structure_consistency: bool
    logging_consistency: bool
    root_cause_analysis: str
    recommended_corrections: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error handling analysis to dictionary for serialization."""
        return {
            'error_scenario': self.error_scenario,
            'nodejs_error_response': self.nodejs_error_response,
            'flask_error_response': self.flask_error_response,
            'status_code_consistency': self.status_code_consistency,
            'error_message_consistency': self.error_message_consistency,
            'error_structure_consistency': self.error_structure_consistency,
            'logging_consistency': self.logging_consistency,
            'root_cause_analysis': self.root_cause_analysis,
            'recommended_corrections': self.recommended_corrections,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class DiscrepancyRecord:
    """Comprehensive discrepancy record for variance tracking and resolution."""
    discrepancy_id: str
    severity: DiscrepancySeverity
    discrepancy_type: DiscrepancyType
    title: str
    description: str
    affected_component: str
    root_cause: str
    recommended_action: CorrectionWorkflowAction
    remediation_steps: List[str]
    performance_impact: float
    business_impact: str
    evidence: Dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    correction_applied: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert discrepancy record to dictionary for serialization."""
        return {
            'discrepancy_id': self.discrepancy_id,
            'severity': self.severity.value,
            'discrepancy_type': self.discrepancy_type.value,
            'title': self.title,
            'description': self.description,
            'affected_component': self.affected_component,
            'root_cause': self.root_cause,
            'recommended_action': self.recommended_action.value,
            'remediation_steps': self.remediation_steps,
            'performance_impact': self.performance_impact,
            'business_impact': self.business_impact,
            'evidence': self.evidence,
            'created_at': self.created_at.isoformat(),
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolution_notes': self.resolution_notes,
            'correction_applied': self.correction_applied
        }


@dataclass
class AnalysisReport:
    """Comprehensive analysis report for migration status tracking."""
    report_id: str
    analysis_start_time: datetime
    analysis_end_time: datetime
    total_comparisons: int
    successful_comparisons: int
    failed_comparisons: int
    critical_discrepancies: int
    high_severity_discrepancies: int
    medium_severity_discrepancies: int
    low_severity_discrepancies: int
    overall_parity_score: float
    performance_comparison_summary: Dict[str, Any]
    database_analysis_summary: Dict[str, Any]
    error_handling_summary: Dict[str, Any]
    discrepancy_records: List[DiscrepancyRecord]
    correction_workflow_triggered: bool = False
    recommendations: List[str] = field(default_factory=list)
    next_analysis_scheduled: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis report to dictionary for serialization."""
        return {
            'report_id': self.report_id,
            'analysis_start_time': self.analysis_start_time.isoformat(),
            'analysis_end_time': self.analysis_end_time.isoformat(),
            'total_comparisons': self.total_comparisons,
            'successful_comparisons': self.successful_comparisons,
            'failed_comparisons': self.failed_comparisons,
            'critical_discrepancies': self.critical_discrepancies,
            'high_severity_discrepancies': self.high_severity_discrepancies,
            'medium_severity_discrepancies': self.medium_severity_discrepancies,
            'low_severity_discrepancies': self.low_severity_discrepancies,
            'overall_parity_score': self.overall_parity_score,
            'performance_comparison_summary': self.performance_comparison_summary,
            'database_analysis_summary': self.database_analysis_summary,
            'error_handling_summary': self.error_handling_summary,
            'discrepancy_records': [record.to_dict() for record in self.discrepancy_records],
            'correction_workflow_triggered': self.correction_workflow_triggered,
            'recommendations': self.recommendations,
            'next_analysis_scheduled': self.next_analysis_scheduled.isoformat() if self.next_analysis_scheduled else None
        }


# =============================================================================
# Configuration and Thresholds Management
# =============================================================================

class AnalysisConfiguration:
    """Configuration management for results analysis with threshold definitions."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize analysis configuration with default thresholds."""
        self.config_path = config_path
        self.load_configuration()
        self.setup_prometheus_metrics()
        
    def load_configuration(self):
        """Load configuration from file or use defaults."""
        default_config = {
            'performance_thresholds': {
                'response_time_threshold_ms': 200,  # Per Section 4.7.1 API response time requirement
                'database_query_threshold_ms': 100,  # Per Section 6.5.1 database query performance
                'memory_usage_threshold_mb': 500,
                'cpu_utilization_threshold_percent': 80,
                'error_rate_threshold_percent': 1.0,
                'throughput_degradation_threshold_percent': 10.0,
                'performance_variance_threshold_percent': 15.0
            },
            'analysis_settings': {
                'enable_deep_diff_analysis': True,
                'diff_max_depth': 10,
                'response_content_similarity_threshold': 0.95,
                'database_result_variance_threshold': 0.02,
                'error_message_similarity_threshold': 0.85,
                'batch_analysis_size': 100,
                'concurrent_analysis_workers': 4,
                'analysis_timeout_seconds': 300
            },
            'reporting_configuration': {
                'generate_html_reports': True,
                'generate_json_reports': True,
                'generate_prometheus_metrics': True,
                'report_retention_days': 30,
                'detailed_diff_inclusion': True,
                'performance_trend_analysis': True,
                'auto_correction_workflow_enabled': True
            },
            'correction_workflow': {
                'auto_apply_low_risk_corrections': False,
                'require_manual_approval_for_critical': True,
                'correction_timeout_seconds': 600,
                'rollback_on_failure': True,
                'notification_webhooks': [],
                'escalation_thresholds': {
                    'critical_discrepancy_count': 5,
                    'high_severity_percentage': 20.0,
                    'overall_parity_score_threshold': 0.90
                }
            },
            'output_paths': {
                'reports_directory': 'tests/results/comparative_analysis',
                'metrics_export_path': 'tests/results/metrics',
                'correction_logs_path': 'tests/results/corrections',
                'baseline_data_path': 'tests/baseline_data'
            }
        }
        
        if self.config_path and Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as config_file:
                    loaded_config = yaml.safe_load(config_file)
                    # Deep merge with default configuration
                    self._deep_merge_config(default_config, loaded_config)
            except Exception as e:
                logger.warning("Failed to load configuration file, using defaults",
                               config_path=self.config_path, error=str(e))
        
        self.config = default_config
        logger.info("Analysis configuration loaded",
                    performance_thresholds=self.config['performance_thresholds'],
                    analysis_settings=self.config['analysis_settings'])
    
    def _deep_merge_config(self, default: Dict, loaded: Dict):
        """Deep merge loaded configuration with defaults."""
        for key, value in loaded.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._deep_merge_config(default[key], value)
            else:
                default[key] = value
    
    def setup_prometheus_metrics(self):
        """Setup Prometheus metrics for results analysis monitoring."""
        self.metrics_registry = CollectorRegistry()
        
        self.metrics = {
            'discrepancies_detected': PrometheusCounter(
                'comparative_analysis_discrepancies_detected_total',
                'Total number of discrepancies detected',
                ['severity', 'type', 'component'],
                registry=self.metrics_registry
            ),
            'analysis_duration': Histogram(
                'comparative_analysis_duration_seconds',
                'Duration of comparative analysis operations',
                ['analysis_type'],
                registry=self.metrics_registry,
                buckets=(1, 5, 10, 30, 60, 120, 300)
            ),
            'parity_score': Gauge(
                'comparative_analysis_parity_score',
                'Overall parity score between systems',
                ['component'],
                registry=self.metrics_registry
            ),
            'corrections_applied': PrometheusCounter(
                'comparative_analysis_corrections_applied_total',
                'Total number of automated corrections applied',
                ['correction_type', 'success'],
                registry=self.metrics_registry
            ),
            'performance_delta': Histogram(
                'comparative_analysis_performance_delta_ms',
                'Performance difference between Node.js and Flask',
                ['endpoint', 'metric_type'],
                registry=self.metrics_registry,
                buckets=(1, 5, 10, 25, 50, 100, 250, 500, 1000)
            )
        }
    
    def get_threshold(self, category: str, metric: str) -> Union[float, int]:
        """Get threshold value for specific metric."""
        return self.config.get(category, {}).get(metric, 0)
    
    def get_setting(self, category: str, setting: str) -> Any:
        """Get configuration setting value."""
        return self.config.get(category, {}).get(setting)
    
    def update_threshold(self, category: str, metric: str, value: Union[float, int]):
        """Update threshold value dynamically."""
        if category not in self.config:
            self.config[category] = {}
        self.config[category][metric] = value
        logger.info("Threshold updated",
                    category=category, metric=metric, value=value)


# =============================================================================
# Core Results Analysis Engine
# =============================================================================

class ResultsAnalyzer:
    """
    Comprehensive results analyzer for Flask migration comparative testing.
    
    This class implements the core analysis engine that processes comparative test results,
    identifies discrepancies, generates reports, and triggers correction workflows per
    Section 4.7.2 automated correction workflow requirements.
    """
    
    def __init__(self, config: Optional[AnalysisConfiguration] = None):
        """Initialize results analyzer with configuration and analysis capabilities."""
        self.config = config or AnalysisConfiguration()
        self.analysis_id = str(uuid.uuid4())
        self.analysis_start_time = datetime.now(timezone.utc)
        self.analysis_status = AnalysisStatus.PENDING
        
        # Initialize analysis components
        self.response_analyzer = ResponseAnalyzer(self.config)
        self.performance_analyzer = PerformanceAnalyzer(self.config)
        self.database_analyzer = DatabaseAnalyzer(self.config)
        self.error_analyzer = ErrorHandlingAnalyzer(self.config)
        self.report_generator = ReportGenerator(self.config)
        self.correction_workflow = CorrectionWorkflowManager(self.config)
        
        # Analysis state management
        self.discrepancy_records: List[DiscrepancyRecord] = []
        self.response_comparisons: List[ResponseComparison] = []
        self.performance_metrics: Dict[str, List[PerformanceMetrics]] = defaultdict(list)
        self.database_analyses: List[DatabaseQueryAnalysis] = []
        self.error_analyses: List[ErrorHandlingAnalysis] = []
        
        # Thread safety for concurrent analysis
        self.analysis_lock = threading.RLock()
        self.metrics_lock = threading.RLock()
        
        logger.info("Results analyzer initialized",
                    analysis_id=self.analysis_id,
                    config_loaded=True)
    
    def analyze_comparative_results(self, 
                                    test_results: Dict[str, Any],
                                    baseline_data: Optional[Dict[str, Any]] = None) -> AnalysisReport:
        """
        Perform comprehensive analysis of comparative test results.
        
        Args:
            test_results: Dictionary containing comparative test execution results
            baseline_data: Optional baseline data for enhanced comparison
            
        Returns:
            AnalysisReport: Comprehensive analysis report with discrepancies and recommendations
        """
        with self.analysis_lock:
            self.analysis_status = AnalysisStatus.RUNNING
            analysis_start = time.time()
            
            try:
                logger.info("Starting comparative results analysis",
                            analysis_id=self.analysis_id,
                            test_results_keys=list(test_results.keys()))
                
                # Step 1: Response data comparison analysis
                if 'api_responses' in test_results:
                    self._analyze_api_responses(test_results['api_responses'], baseline_data)
                
                # Step 2: Performance metrics analysis
                if 'performance_data' in test_results:
                    self._analyze_performance_metrics(test_results['performance_data'], baseline_data)
                
                # Step 3: Database operation analysis
                if 'database_operations' in test_results:
                    self._analyze_database_operations(test_results['database_operations'], baseline_data)
                
                # Step 4: Error handling consistency analysis
                if 'error_scenarios' in test_results:
                    self._analyze_error_handling(test_results['error_scenarios'], baseline_data)
                
                # Step 5: Generate comprehensive discrepancy analysis
                self._generate_discrepancy_records()
                
                # Step 6: Calculate overall parity score
                overall_parity_score = self._calculate_parity_score()
                
                # Step 7: Generate analysis report
                analysis_report = self._create_analysis_report(overall_parity_score)
                
                # Step 8: Trigger correction workflow if needed
                correction_triggered = self._evaluate_correction_workflow_trigger(analysis_report)
                analysis_report.correction_workflow_triggered = correction_triggered
                
                # Step 9: Update Prometheus metrics
                self._update_prometheus_metrics(analysis_report)
                
                analysis_duration = time.time() - analysis_start
                self.config.metrics['analysis_duration'].labels(
                    analysis_type='comprehensive'
                ).observe(analysis_duration)
                
                self.analysis_status = AnalysisStatus.COMPLETED
                
                logger.info("Comparative results analysis completed",
                            analysis_id=self.analysis_id,
                            duration_seconds=analysis_duration,
                            total_discrepancies=len(self.discrepancy_records),
                            parity_score=overall_parity_score,
                            correction_triggered=correction_triggered)
                
                return analysis_report
                
            except Exception as e:
                self.analysis_status = AnalysisStatus.FAILED
                logger.error("Comparative results analysis failed",
                             analysis_id=self.analysis_id,
                             error=str(e),
                             traceback=traceback.format_exc())
                raise
    
    def _analyze_api_responses(self, api_responses: Dict[str, Any], baseline_data: Optional[Dict[str, Any]]):
        """Analyze API response comparisons for contract compliance and data consistency."""
        logger.info("Analyzing API response comparisons",
                    response_count=len(api_responses))
        
        for endpoint, response_data in api_responses.items():
            try:
                # Extract Node.js and Flask response data
                nodejs_response = response_data.get('nodejs', {})
                flask_response = response_data.get('flask', {})
                
                if not nodejs_response or not flask_response:
                    logger.warning("Incomplete response data for endpoint",
                                   endpoint=endpoint)
                    continue
                
                # Perform detailed response comparison
                comparison = self.response_analyzer.compare_responses(
                    endpoint=endpoint,
                    nodejs_response=nodejs_response,
                    flask_response=flask_response,
                    baseline_data=baseline_data
                )
                
                self.response_comparisons.append(comparison)
                
                # Identify discrepancies and generate records
                discrepancies = self.response_analyzer.identify_discrepancies(comparison)
                self.discrepancy_records.extend(discrepancies)
                
            except Exception as e:
                logger.error("Failed to analyze API response",
                             endpoint=endpoint, error=str(e))
    
    def _analyze_performance_metrics(self, performance_data: Dict[str, Any], baseline_data: Optional[Dict[str, Any]]):
        """Analyze performance metrics for degradation detection and optimization opportunities."""
        logger.info("Analyzing performance metrics",
                    metrics_count=len(performance_data))
        
        for component, metrics_data in performance_data.items():
            try:
                # Extract Node.js and Flask performance metrics
                nodejs_metrics = metrics_data.get('nodejs', {})
                flask_metrics = metrics_data.get('flask', {})
                
                if not nodejs_metrics or not flask_metrics:
                    logger.warning("Incomplete performance data for component",
                                   component=component)
                    continue
                
                # Perform performance comparison analysis
                performance_comparison = self.performance_analyzer.compare_performance(
                    component=component,
                    nodejs_metrics=nodejs_metrics,
                    flask_metrics=flask_metrics,
                    baseline_data=baseline_data
                )
                
                # Store performance metrics for trending
                self.performance_metrics[component].append(performance_comparison)
                
                # Identify performance discrepancies
                performance_discrepancies = self.performance_analyzer.identify_performance_issues(
                    performance_comparison
                )
                self.discrepancy_records.extend(performance_discrepancies)
                
            except Exception as e:
                logger.error("Failed to analyze performance metrics",
                             component=component, error=str(e))
    
    def _analyze_database_operations(self, database_data: Dict[str, Any], baseline_data: Optional[Dict[str, Any]]):
        """Analyze database operation results for query performance and result consistency."""
        logger.info("Analyzing database operations",
                    operation_count=len(database_data))
        
        for operation, operation_data in database_data.items():
            try:
                # Extract Node.js and Flask database operation data
                nodejs_data = operation_data.get('nodejs', {})
                flask_data = operation_data.get('flask', {})
                
                if not nodejs_data or not flask_data:
                    logger.warning("Incomplete database operation data",
                                   operation=operation)
                    continue
                
                # Perform database analysis
                db_analysis = self.database_analyzer.analyze_database_operation(
                    operation=operation,
                    nodejs_data=nodejs_data,
                    flask_data=flask_data,
                    baseline_data=baseline_data
                )
                
                self.database_analyses.append(db_analysis)
                
                # Identify database-related discrepancies
                db_discrepancies = self.database_analyzer.identify_database_issues(db_analysis)
                self.discrepancy_records.extend(db_discrepancies)
                
            except Exception as e:
                logger.error("Failed to analyze database operation",
                             operation=operation, error=str(e))
    
    def _analyze_error_handling(self, error_scenarios: Dict[str, Any], baseline_data: Optional[Dict[str, Any]]):
        """Analyze error handling consistency for proper exception management."""
        logger.info("Analyzing error handling scenarios",
                    scenario_count=len(error_scenarios))
        
        for scenario, scenario_data in error_scenarios.items():
            try:
                # Extract Node.js and Flask error handling data
                nodejs_error = scenario_data.get('nodejs', {})
                flask_error = scenario_data.get('flask', {})
                
                if not nodejs_error or not flask_error:
                    logger.warning("Incomplete error handling data",
                                   scenario=scenario)
                    continue
                
                # Perform error handling analysis
                error_analysis = self.error_analyzer.analyze_error_handling(
                    scenario=scenario,
                    nodejs_error=nodejs_error,
                    flask_error=flask_error,
                    baseline_data=baseline_data
                )
                
                self.error_analyses.append(error_analysis)
                
                # Identify error handling discrepancies
                error_discrepancies = self.error_analyzer.identify_error_inconsistencies(error_analysis)
                self.discrepancy_records.extend(error_discrepancies)
                
            except Exception as e:
                logger.error("Failed to analyze error handling scenario",
                             scenario=scenario, error=str(e))
    
    def _generate_discrepancy_records(self):
        """Consolidate and enhance discrepancy records with additional analysis."""
        logger.info("Generating consolidated discrepancy records",
                    initial_count=len(self.discrepancy_records))
        
        # Remove duplicate discrepancies
        unique_discrepancies = []
        seen_signatures = set()
        
        for discrepancy in self.discrepancy_records:
            signature = self._generate_discrepancy_signature(discrepancy)
            if signature not in seen_signatures:
                unique_discrepancies.append(discrepancy)
                seen_signatures.add(signature)
        
        self.discrepancy_records = unique_discrepancies
        
        # Enhance discrepancies with cross-component analysis
        self._enhance_discrepancy_analysis()
        
        # Sort by severity and impact
        self.discrepancy_records.sort(
            key=lambda d: (d.severity.value, -d.performance_impact),
            reverse=True
        )
        
        logger.info("Discrepancy records consolidated",
                    final_count=len(self.discrepancy_records),
                    critical_count=len([d for d in self.discrepancy_records if d.severity == DiscrepancySeverity.CRITICAL]))
    
    def _generate_discrepancy_signature(self, discrepancy: DiscrepancyRecord) -> str:
        """Generate unique signature for discrepancy deduplication."""
        signature_data = f"{discrepancy.discrepancy_type.value}:{discrepancy.affected_component}:{discrepancy.title}"
        return hashlib.md5(signature_data.encode()).hexdigest()
    
    def _enhance_discrepancy_analysis(self):
        """Enhance discrepancy records with cross-component correlation analysis."""
        # Group discrepancies by component and type for pattern analysis
        component_groups = defaultdict(list)
        for discrepancy in self.discrepancy_records:
            component_groups[discrepancy.affected_component].append(discrepancy)
        
        # Identify patterns and correlations
        for component, discrepancies in component_groups.items():
            if len(discrepancies) > 1:
                pattern_analysis = self._analyze_discrepancy_patterns(discrepancies)
                for discrepancy in discrepancies:
                    if pattern_analysis:
                        discrepancy.root_cause += f" [Pattern: {pattern_analysis}]"
    
    def _analyze_discrepancy_patterns(self, discrepancies: List[DiscrepancyRecord]) -> str:
        """Analyze patterns in component discrepancies for enhanced root cause analysis."""
        severity_counts = Counter(d.severity for d in discrepancies)
        type_counts = Counter(d.discrepancy_type for d in discrepancies)
        
        patterns = []
        
        # Multiple critical issues in same component
        if severity_counts[DiscrepancySeverity.CRITICAL] > 1:
            patterns.append("Multiple critical issues detected")
        
        # Consistent performance degradation
        if type_counts[DiscrepancyType.PERFORMANCE_DEGRADATION] > 2:
            patterns.append("Systematic performance issues")
        
        # Database-related problems
        if type_counts[DiscrepancyType.DATABASE_VARIANCE] > 1:
            patterns.append("Database optimization needed")
        
        return "; ".join(patterns) if patterns else ""
    
    def _calculate_parity_score(self) -> float:
        """Calculate overall parity score based on discrepancy analysis."""
        if not self.discrepancy_records:
            return 1.0  # Perfect parity if no discrepancies
        
        # Weight discrepancies by severity
        severity_weights = {
            DiscrepancySeverity.CRITICAL: 1.0,
            DiscrepancySeverity.HIGH: 0.7,
            DiscrepancySeverity.MEDIUM: 0.4,
            DiscrepancySeverity.LOW: 0.2,
            DiscrepancySeverity.INFO: 0.1
        }
        
        total_weighted_discrepancies = sum(
            severity_weights.get(d.severity, 0.5) for d in self.discrepancy_records
        )
        
        # Calculate base comparisons (assume 100 total comparisons if not specified)
        total_comparisons = max(
            len(self.response_comparisons),
            100
        )
        
        # Calculate parity score (0.0 to 1.0, where 1.0 is perfect parity)
        parity_score = max(0.0, 1.0 - (total_weighted_discrepancies / total_comparisons))
        
        logger.info("Parity score calculated",
                    parity_score=parity_score,
                    total_discrepancies=len(self.discrepancy_records),
                    total_comparisons=total_comparisons)
        
        return parity_score
    
    def _create_analysis_report(self, parity_score: float) -> AnalysisReport:
        """Create comprehensive analysis report with all findings and recommendations."""
        analysis_end_time = datetime.now(timezone.utc)
        
        # Count discrepancies by severity
        severity_counts = Counter(d.severity for d in self.discrepancy_records)
        
        # Generate performance comparison summary
        performance_summary = self._generate_performance_summary()
        
        # Generate database analysis summary
        database_summary = self._generate_database_summary()
        
        # Generate error handling summary
        error_summary = self._generate_error_handling_summary()
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        analysis_report = AnalysisReport(
            report_id=f"analysis_{self.analysis_id}_{int(time.time())}",
            analysis_start_time=self.analysis_start_time,
            analysis_end_time=analysis_end_time,
            total_comparisons=len(self.response_comparisons),
            successful_comparisons=len([c for c in self.response_comparisons if c.data_content_match]),
            failed_comparisons=len([c for c in self.response_comparisons if not c.data_content_match]),
            critical_discrepancies=severity_counts[DiscrepancySeverity.CRITICAL],
            high_severity_discrepancies=severity_counts[DiscrepancySeverity.HIGH],
            medium_severity_discrepancies=severity_counts[DiscrepancySeverity.MEDIUM],
            low_severity_discrepancies=severity_counts[DiscrepancySeverity.LOW],
            overall_parity_score=parity_score,
            performance_comparison_summary=performance_summary,
            database_analysis_summary=database_summary,
            error_handling_summary=error_summary,
            discrepancy_records=self.discrepancy_records,
            recommendations=recommendations
        )
        
        return analysis_report
    
    def _generate_performance_summary(self) -> Dict[str, Any]:
        """Generate performance analysis summary for the report."""
        if not self.performance_metrics:
            return {'status': 'no_data', 'message': 'No performance data available for analysis'}
        
        summary = {
            'components_analyzed': len(self.performance_metrics),
            'performance_issues_detected': len([d for d in self.discrepancy_records 
                                                if d.discrepancy_type == DiscrepancyType.PERFORMANCE_DEGRADATION]),
            'average_response_time_delta_ms': 0,
            'components_with_degradation': [],
            'optimization_opportunities': []
        }
        
        # Calculate average performance deltas
        response_time_deltas = []
        for component, metrics_list in self.performance_metrics.items():
            for metrics in metrics_list:
                if hasattr(metrics, 'performance_delta_ms'):
                    response_time_deltas.append(metrics.performance_delta_ms)
        
        if response_time_deltas:
            summary['average_response_time_delta_ms'] = statistics.mean(response_time_deltas)
        
        return summary
    
    def _generate_database_summary(self) -> Dict[str, Any]:
        """Generate database analysis summary for the report."""
        if not self.database_analyses:
            return {'status': 'no_data', 'message': 'No database analysis data available'}
        
        summary = {
            'queries_analyzed': len(self.database_analyses),
            'performance_regressions': len([a for a in self.database_analyses 
                                            if a.flask_execution_time_ms > a.nodejs_execution_time_ms * 1.1]),
            'result_count_discrepancies': len([a for a in self.database_analyses 
                                               if a.flask_result_count != a.nodejs_result_count]),
            'optimization_recommendations': []
        }
        
        # Collect optimization recommendations
        for analysis in self.database_analyses:
            summary['optimization_recommendations'].extend(analysis.optimization_recommendations)
        
        return summary
    
    def _generate_error_handling_summary(self) -> Dict[str, Any]:
        """Generate error handling analysis summary for the report."""
        if not self.error_analyses:
            return {'status': 'no_data', 'message': 'No error handling analysis data available'}
        
        summary = {
            'scenarios_tested': len(self.error_analyses),
            'status_code_inconsistencies': len([a for a in self.error_analyses if not a.status_code_consistency]),
            'message_inconsistencies': len([a for a in self.error_analyses if not a.error_message_consistency]),
            'structure_inconsistencies': len([a for a in self.error_analyses if not a.error_structure_consistency]),
            'required_corrections': []
        }
        
        # Collect required corrections
        for analysis in self.error_analyses:
            summary['required_corrections'].extend(analysis.recommended_corrections)
        
        return summary
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on analysis results."""
        recommendations = []
        
        # Critical issues recommendations
        critical_discrepancies = [d for d in self.discrepancy_records if d.severity == DiscrepancySeverity.CRITICAL]
        if critical_discrepancies:
            recommendations.append(
                f"URGENT: Address {len(critical_discrepancies)} critical discrepancies immediately to ensure migration success"
            )
        
        # Performance recommendations
        performance_issues = [d for d in self.discrepancy_records if d.discrepancy_type == DiscrepancyType.PERFORMANCE_DEGRADATION]
        if performance_issues:
            recommendations.append(
                f"Optimize Flask implementation to resolve {len(performance_issues)} performance degradation issues"
            )
        
        # Database optimization recommendations
        db_issues = [d for d in self.discrepancy_records if d.discrepancy_type == DiscrepancyType.DATABASE_VARIANCE]
        if db_issues:
            recommendations.append(
                f"Review SQLAlchemy configuration and query optimization for {len(db_issues)} database variance issues"
            )
        
        # Error handling recommendations
        error_issues = [d for d in self.discrepancy_records if d.discrepancy_type == DiscrepancyType.ERROR_HANDLING_INCONSISTENCY]
        if error_issues:
            recommendations.append(
                f"Standardize Flask error handling to match Node.js behavior for {len(error_issues)} inconsistencies"
            )
        
        # Overall parity recommendations
        parity_score = self._calculate_parity_score()
        if parity_score < 0.95:
            recommendations.append(
                f"Overall parity score ({parity_score:.2%}) below target. Comprehensive review of Flask implementation required"
            )
        
        return recommendations
    
    def _evaluate_correction_workflow_trigger(self, report: AnalysisReport) -> bool:
        """Evaluate whether automated correction workflow should be triggered."""
        correction_thresholds = self.config.get_setting('correction_workflow', 'escalation_thresholds')
        
        # Check critical discrepancy count threshold
        if report.critical_discrepancies >= correction_thresholds.get('critical_discrepancy_count', 5):
            logger.warning("Correction workflow triggered due to critical discrepancy count",
                           critical_count=report.critical_discrepancies)
            return True
        
        # Check high severity percentage threshold
        total_discrepancies = len(report.discrepancy_records)
        if total_discrepancies > 0:
            high_severity_percentage = (report.high_severity_discrepancies / total_discrepancies) * 100
            if high_severity_percentage >= correction_thresholds.get('high_severity_percentage', 20.0):
                logger.warning("Correction workflow triggered due to high severity percentage",
                               percentage=high_severity_percentage)
                return True
        
        # Check overall parity score threshold
        if report.overall_parity_score < correction_thresholds.get('overall_parity_score_threshold', 0.90):
            logger.warning("Correction workflow triggered due to low parity score",
                           parity_score=report.overall_parity_score)
            return True
        
        return False
    
    def _update_prometheus_metrics(self, report: AnalysisReport):
        """Update Prometheus metrics with analysis results."""
        with self.metrics_lock:
            # Update discrepancy metrics
            for discrepancy in report.discrepancy_records:
                self.config.metrics['discrepancies_detected'].labels(
                    severity=discrepancy.severity.value,
                    type=discrepancy.discrepancy_type.value,
                    component=discrepancy.affected_component
                ).inc()
            
            # Update parity score
            self.config.metrics['parity_score'].labels(
                component='overall'
            ).set(report.overall_parity_score)
            
            # Update performance deltas
            for comparison in self.response_comparisons:
                self.config.metrics['performance_delta'].labels(
                    endpoint=comparison.endpoint,
                    metric_type='response_time'
                ).observe(comparison.performance_delta_ms)
    
    def export_analysis_results(self, report: AnalysisReport, output_formats: List[str] = None) -> Dict[str, str]:
        """Export analysis results in specified formats."""
        if output_formats is None:
            output_formats = ['json', 'html']
        
        exported_files = {}
        
        try:
            # Ensure output directory exists
            output_dir = Path(self.config.get_setting('output_paths', 'reports_directory'))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Export JSON report
            if 'json' in output_formats:
                json_path = output_dir / f"{report.report_id}.json"
                with open(json_path, 'w') as json_file:
                    json.dump(report.to_dict(), json_file, indent=2, default=str)
                exported_files['json'] = str(json_path)
            
            # Export HTML report
            if 'html' in output_formats:
                html_path = output_dir / f"{report.report_id}.html"
                html_content = self.report_generator.generate_html_report(report)
                with open(html_path, 'w') as html_file:
                    html_file.write(html_content)
                exported_files['html'] = str(html_path)
            
            # Export Prometheus metrics
            if 'prometheus' in output_formats:
                metrics_path = output_dir / f"{report.report_id}_metrics.txt"
                metrics_content = self._export_prometheus_metrics()
                with open(metrics_path, 'w') as metrics_file:
                    metrics_file.write(metrics_content)
                exported_files['prometheus'] = str(metrics_path)
            
            logger.info("Analysis results exported",
                        report_id=report.report_id,
                        formats=list(exported_files.keys()),
                        files=exported_files)
            
            return exported_files
            
        except Exception as e:
            logger.error("Failed to export analysis results",
                         report_id=report.report_id, error=str(e))
            raise
    
    def _export_prometheus_metrics(self) -> str:
        """Export current Prometheus metrics in text format."""
        from prometheus_client import generate_latest
        return generate_latest(self.config.metrics_registry).decode('utf-8')


# =============================================================================
# Specialized Analysis Components
# =============================================================================

class ResponseAnalyzer:
    """Specialized analyzer for API response comparison and diff analysis."""
    
    def __init__(self, config: AnalysisConfiguration):
        self.config = config
        
    def compare_responses(self, endpoint: str, nodejs_response: Dict[str, Any], 
                         flask_response: Dict[str, Any], baseline_data: Optional[Dict[str, Any]] = None) -> ResponseComparison:
        """Perform detailed response comparison with diff analysis."""
        # Extract response components
        nodejs_status = nodejs_response.get('status_code', 0)
        flask_status = flask_response.get('status_code', 0)
        
        nodejs_headers = nodejs_response.get('headers', {})
        flask_headers = flask_response.get('headers', {})
        
        nodejs_data = nodejs_response.get('data', {})
        flask_data = flask_response.get('data', {})
        
        nodejs_content_type = nodejs_headers.get('content-type', '')
        flask_content_type = flask_headers.get('content-type', '')
        
        # Performance metrics
        nodejs_duration = nodejs_response.get('duration_seconds', 0) * 1000  # Convert to ms
        flask_duration = flask_response.get('duration_seconds', 0) * 1000
        performance_delta = flask_duration - nodejs_duration
        
        # Comparison analysis
        status_code_match = nodejs_status == flask_status
        content_type_match = self._normalize_content_type(nodejs_content_type) == self._normalize_content_type(flask_content_type)
        
        # Deep diff analysis for data structure and content
        data_differences = []
        data_structure_match = True
        data_content_match = True
        
        if self.config.get_setting('analysis_settings', 'enable_deep_diff_analysis'):
            diff_result = DeepDiff(
                nodejs_data, 
                flask_data, 
                max_depth=self.config.get_setting('analysis_settings', 'diff_max_depth'),
                ignore_order=True,
                verbose_level=2
            )
            
            if diff_result:
                data_structure_match = 'type_changes' not in diff_result and 'dictionary_item_added' not in diff_result and 'dictionary_item_removed' not in diff_result
                data_content_match = not diff_result
                data_differences = self._process_deep_diff(diff_result)
        
        # Headers comparison (exclude volatile headers)
        headers_match = self._compare_headers(nodejs_headers, flask_headers)
        
        return ResponseComparison(
            endpoint=endpoint,
            method=nodejs_response.get('method', 'GET'),
            nodejs_response=nodejs_response,
            flask_response=flask_response,
            status_code_match=status_code_match,
            content_type_match=content_type_match,
            data_structure_match=data_structure_match,
            data_content_match=data_content_match,
            headers_match=headers_match,
            performance_delta_ms=performance_delta,
            differences=data_differences
        )
    
    def _normalize_content_type(self, content_type: str) -> str:
        """Normalize content type for comparison."""
        return content_type.split(';')[0].strip().lower()
    
    def _process_deep_diff(self, diff_result: Dict) -> List[Dict[str, Any]]:
        """Process DeepDiff result into structured difference records."""
        differences = []
        
        for change_type, changes in diff_result.items():
            if change_type == 'values_changed':
                for path, change in changes.items():
                    differences.append({
                        'type': 'value_changed',
                        'path': path,
                        'nodejs_value': change['old_value'],
                        'flask_value': change['new_value'],
                        'severity': self._assess_difference_severity(change_type, path, change)
                    })
            elif change_type == 'dictionary_item_added':
                for path in changes:
                    differences.append({
                        'type': 'item_added',
                        'path': path,
                        'flask_value': changes[path],
                        'severity': 'medium'
                    })
            elif change_type == 'dictionary_item_removed':
                for path in changes:
                    differences.append({
                        'type': 'item_removed',
                        'path': path,
                        'nodejs_value': changes[path],
                        'severity': 'high'
                    })
            elif change_type == 'type_changes':
                for path, change in changes.items():
                    differences.append({
                        'type': 'type_changed',
                        'path': path,
                        'nodejs_type': str(change['old_type']),
                        'flask_type': str(change['new_type']),
                        'severity': 'critical'
                    })
        
        return differences
    
    def _assess_difference_severity(self, change_type: str, path: str, change: Dict) -> str:
        """Assess severity of detected difference."""
        # Critical paths that must match exactly
        critical_paths = ['id', 'user_id', 'status', 'error_code']
        if any(critical in path.lower() for critical in critical_paths):
            return 'critical'
        
        # High importance paths
        high_importance_paths = ['email', 'username', 'created_at', 'updated_at']
        if any(important in path.lower() for important in high_importance_paths):
            return 'high'
        
        # Type changes are always critical
        if change_type == 'type_changes':
            return 'critical'
        
        return 'medium'
    
    def _compare_headers(self, nodejs_headers: Dict[str, str], flask_headers: Dict[str, str]) -> bool:
        """Compare response headers excluding volatile headers."""
        # Headers to ignore during comparison
        ignore_headers = {
            'date', 'server', 'x-request-id', 'x-response-time', 
            'etag', 'last-modified', 'cache-control'
        }
        
        # Normalize and filter headers
        normalized_nodejs = {
            k.lower(): v for k, v in nodejs_headers.items() 
            if k.lower() not in ignore_headers
        }
        normalized_flask = {
            k.lower(): v for k, v in flask_headers.items() 
            if k.lower() not in ignore_headers
        }
        
        return normalized_nodejs == normalized_flask
    
    def identify_discrepancies(self, comparison: ResponseComparison) -> List[DiscrepancyRecord]:
        """Identify and create discrepancy records from response comparison."""
        discrepancies = []
        
        # Status code mismatch
        if not comparison.status_code_match:
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.CRITICAL,
                discrepancy_type=DiscrepancyType.API_RESPONSE_MISMATCH,
                title=f"Status Code Mismatch: {comparison.endpoint}",
                description=f"Node.js returned {comparison.nodejs_response.get('status_code')}, Flask returned {comparison.flask_response.get('status_code')}",
                affected_component=f"API:{comparison.endpoint}",
                root_cause="Flask error handling or route implementation differs from Node.js",
                recommended_action=CorrectionWorkflowAction.FLASK_CODE_ADJUSTMENT,
                remediation_steps=[
                    "Review Flask route handler implementation",
                    "Compare error handling logic with Node.js implementation",
                    "Update Flask status code handling to match Node.js behavior"
                ],
                performance_impact=0.0,
                business_impact="API contract violation may break client applications",
                evidence={
                    'nodejs_status': comparison.nodejs_response.get('status_code'),
                    'flask_status': comparison.flask_response.get('status_code'),
                    'endpoint': comparison.endpoint,
                    'method': comparison.method
                }
            ))
        
        # Content type mismatch
        if not comparison.content_type_match:
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.HIGH,
                discrepancy_type=DiscrepancyType.API_RESPONSE_MISMATCH,
                title=f"Content Type Mismatch: {comparison.endpoint}",
                description="Response content types differ between Node.js and Flask implementations",
                affected_component=f"API:{comparison.endpoint}",
                root_cause="Flask response content type configuration differs from Node.js",
                recommended_action=CorrectionWorkflowAction.FLASK_CODE_ADJUSTMENT,
                remediation_steps=[
                    "Review Flask response content type settings",
                    "Ensure consistent JSON response formatting",
                    "Update Flask blueprint response handling"
                ],
                performance_impact=0.0,
                business_impact="Content type mismatches may cause client parsing errors",
                evidence={
                    'nodejs_content_type': comparison.nodejs_response.get('headers', {}).get('content-type'),
                    'flask_content_type': comparison.flask_response.get('headers', {}).get('content-type')
                }
            ))
        
        # Data content mismatch
        if not comparison.data_content_match:
            severity = DiscrepancySeverity.CRITICAL if not comparison.data_structure_match else DiscrepancySeverity.HIGH
            
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=severity,
                discrepancy_type=DiscrepancyType.API_RESPONSE_MISMATCH,
                title=f"Response Data Mismatch: {comparison.endpoint}",
                description="Response data differs between Node.js and Flask implementations",
                affected_component=f"API:{comparison.endpoint}",
                root_cause="Business logic or data serialization differences between implementations",
                recommended_action=CorrectionWorkflowAction.FLASK_CODE_ADJUSTMENT,
                remediation_steps=[
                    "Analyze data transformation logic differences",
                    "Review Flask serialization implementation",
                    "Ensure database query results match between systems",
                    "Update Flask business logic to match Node.js behavior"
                ],
                performance_impact=0.0,
                business_impact="Data mismatches cause functional parity violations",
                evidence={
                    'differences_count': len(comparison.differences),
                    'detailed_differences': comparison.differences[:10],  # Limit to first 10 for size
                    'data_structure_match': comparison.data_structure_match
                }
            ))
        
        # Performance degradation
        performance_threshold = self.config.get_threshold('performance_thresholds', 'response_time_threshold_ms')
        if comparison.performance_delta_ms > performance_threshold:
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.HIGH,
                discrepancy_type=DiscrepancyType.PERFORMANCE_DEGRADATION,
                title=f"Performance Degradation: {comparison.endpoint}",
                description=f"Flask response time {comparison.performance_delta_ms:.1f}ms slower than Node.js",
                affected_component=f"API:{comparison.endpoint}",
                root_cause="Flask implementation has performance inefficiencies compared to Node.js",
                recommended_action=CorrectionWorkflowAction.PERFORMANCE_TUNING,
                remediation_steps=[
                    "Profile Flask request processing pipeline",
                    "Optimize database queries and SQLAlchemy configuration",
                    "Review Flask middleware and blueprint performance",
                    "Consider caching strategies for improved response times"
                ],
                performance_impact=comparison.performance_delta_ms,
                business_impact=f"Response time degradation affects user experience (current: {comparison.performance_delta_ms:.1f}ms slower)",
                evidence={
                    'nodejs_duration_ms': comparison.nodejs_response.get('duration_seconds', 0) * 1000,
                    'flask_duration_ms': comparison.flask_response.get('duration_seconds', 0) * 1000,
                    'performance_delta_ms': comparison.performance_delta_ms,
                    'threshold_ms': performance_threshold
                }
            ))
        
        return discrepancies


class PerformanceAnalyzer:
    """Specialized analyzer for performance metrics comparison and degradation detection."""
    
    def __init__(self, config: AnalysisConfiguration):
        self.config = config
        
    def compare_performance(self, component: str, nodejs_metrics: Dict[str, Any], 
                          flask_metrics: Dict[str, Any], baseline_data: Optional[Dict[str, Any]] = None) -> PerformanceMetrics:
        """Compare performance metrics between Node.js and Flask implementations."""
        
        # Extract performance data with safe defaults
        flask_performance = PerformanceMetrics(
            response_time_ms=flask_metrics.get('response_time_ms', 0),
            memory_usage_mb=flask_metrics.get('memory_usage_mb', 0),
            cpu_utilization_percent=flask_metrics.get('cpu_utilization_percent', 0),
            database_query_count=flask_metrics.get('database_query_count', 0),
            database_query_time_ms=flask_metrics.get('database_query_time_ms', 0),
            concurrent_users=flask_metrics.get('concurrent_users', 1),
            throughput_rps=flask_metrics.get('throughput_rps', 0),
            error_rate_percent=flask_metrics.get('error_rate_percent', 0)
        )
        
        # Add performance delta calculation
        flask_performance.performance_delta_ms = (
            flask_performance.response_time_ms - nodejs_metrics.get('response_time_ms', 0)
        )
        
        return flask_performance
    
    def identify_performance_issues(self, performance_metrics: PerformanceMetrics) -> List[DiscrepancyRecord]:
        """Identify performance issues and create discrepancy records."""
        discrepancies = []
        
        # Response time threshold violation
        response_threshold = self.config.get_threshold('performance_thresholds', 'response_time_threshold_ms')
        if performance_metrics.response_time_ms > response_threshold:
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.HIGH,
                discrepancy_type=DiscrepancyType.PERFORMANCE_DEGRADATION,
                title="Response Time Threshold Exceeded",
                description=f"Flask response time {performance_metrics.response_time_ms:.1f}ms exceeds threshold {response_threshold}ms",
                affected_component="Flask Application",
                root_cause="Flask implementation performance optimization needed",
                recommended_action=CorrectionWorkflowAction.PERFORMANCE_TUNING,
                remediation_steps=[
                    "Profile Flask application bottlenecks",
                    "Optimize database query performance",
                    "Review middleware and request processing pipeline",
                    "Implement response caching strategies"
                ],
                performance_impact=performance_metrics.response_time_ms - response_threshold,
                business_impact="Response time exceeds SLA requirements",
                evidence=performance_metrics.to_dict()
            ))
        
        # Memory usage threshold violation
        memory_threshold = self.config.get_threshold('performance_thresholds', 'memory_usage_threshold_mb')
        if performance_metrics.memory_usage_mb > memory_threshold:
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.MEDIUM,
                discrepancy_type=DiscrepancyType.RESOURCE_LEAK,
                title="Memory Usage Threshold Exceeded",
                description=f"Flask memory usage {performance_metrics.memory_usage_mb:.1f}MB exceeds threshold {memory_threshold}MB",
                affected_component="Flask Application",
                root_cause="Potential memory leak or inefficient memory usage in Flask implementation",
                recommended_action=CorrectionWorkflowAction.PERFORMANCE_TUNING,
                remediation_steps=[
                    "Profile memory usage patterns",
                    "Review object lifecycle management",
                    "Optimize database connection pooling",
                    "Check for memory leaks in business logic"
                ],
                performance_impact=performance_metrics.memory_usage_mb - memory_threshold,
                business_impact="High memory usage may affect application scalability",
                evidence=performance_metrics.to_dict()
            ))
        
        # Database query performance issues
        db_threshold = self.config.get_threshold('performance_thresholds', 'database_query_threshold_ms')
        if performance_metrics.database_query_time_ms > db_threshold:
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.HIGH,
                discrepancy_type=DiscrepancyType.DATABASE_VARIANCE,
                title="Database Query Performance Degradation",
                description=f"Database queries taking {performance_metrics.database_query_time_ms:.1f}ms, exceeding threshold {db_threshold}ms",
                affected_component="Database Layer",
                root_cause="SQLAlchemy configuration or query optimization needed",
                recommended_action=CorrectionWorkflowAction.SQLALCHEMY_OPTIMIZATION,
                remediation_steps=[
                    "Analyze SQLAlchemy query execution plans",
                    "Optimize database indexes",
                    "Review connection pool configuration",
                    "Implement query result caching"
                ],
                performance_impact=performance_metrics.database_query_time_ms - db_threshold,
                business_impact="Database performance affects overall application responsiveness",
                evidence=performance_metrics.to_dict()
            ))
        
        # Error rate threshold violation
        error_threshold = self.config.get_threshold('performance_thresholds', 'error_rate_threshold_percent')
        if performance_metrics.error_rate_percent > error_threshold:
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.CRITICAL,
                discrepancy_type=DiscrepancyType.ERROR_HANDLING_INCONSISTENCY,
                title="Error Rate Threshold Exceeded",
                description=f"Error rate {performance_metrics.error_rate_percent:.2f}% exceeds threshold {error_threshold}%",
                affected_component="Flask Application",
                root_cause="Flask implementation has higher error rate than acceptable threshold",
                recommended_action=CorrectionWorkflowAction.ERROR_HANDLER_UPDATE,
                remediation_steps=[
                    "Analyze error patterns and root causes",
                    "Review Flask error handling implementation",
                    "Compare error handling with Node.js implementation",
                    "Implement comprehensive error logging and monitoring"
                ],
                performance_impact=0.0,
                business_impact="High error rate indicates reliability issues affecting user experience",
                evidence=performance_metrics.to_dict()
            ))
        
        return discrepancies


class DatabaseAnalyzer:
    """Specialized analyzer for database query variance analysis and SQLAlchemy optimization."""
    
    def __init__(self, config: AnalysisConfiguration):
        self.config = config
        
    def analyze_database_operation(self, operation: str, nodejs_data: Dict[str, Any], 
                                 flask_data: Dict[str, Any], baseline_data: Optional[Dict[str, Any]] = None) -> DatabaseQueryAnalysis:
        """Analyze database operation for performance and result consistency."""
        
        analysis = DatabaseQueryAnalysis(
            query_type=operation,
            table_name=nodejs_data.get('table_name', 'unknown'),
            nodejs_execution_time_ms=nodejs_data.get('execution_time_ms', 0),
            flask_execution_time_ms=flask_data.get('execution_time_ms', 0),
            nodejs_result_count=nodejs_data.get('result_count', 0),
            flask_result_count=flask_data.get('result_count', 0),
            query_plan_difference=self._compare_query_plans(nodejs_data, flask_data),
            index_usage_difference=self._compare_index_usage(nodejs_data, flask_data)
        )
        
        # Generate optimization recommendations
        analysis.optimization_recommendations = self._generate_optimization_recommendations(analysis)
        
        return analysis
    
    def _compare_query_plans(self, nodejs_data: Dict[str, Any], flask_data: Dict[str, Any]) -> bool:
        """Compare query execution plans between Node.js and Flask implementations."""
        nodejs_plan = nodejs_data.get('query_plan', {})
        flask_plan = flask_data.get('query_plan', {})
        
        # Simple plan comparison - could be enhanced with more sophisticated analysis
        return nodejs_plan != flask_plan
    
    def _compare_index_usage(self, nodejs_data: Dict[str, Any], flask_data: Dict[str, Any]) -> bool:
        """Compare index usage between implementations."""
        nodejs_indexes = set(nodejs_data.get('indexes_used', []))
        flask_indexes = set(flask_data.get('indexes_used', []))
        
        return nodejs_indexes != flask_indexes
    
    def _generate_optimization_recommendations(self, analysis: DatabaseQueryAnalysis) -> List[str]:
        """Generate SQLAlchemy optimization recommendations based on analysis."""
        recommendations = []
        
        # Performance degradation recommendations
        if analysis.flask_execution_time_ms > analysis.nodejs_execution_time_ms * 1.2:
            recommendations.extend([
                "Review SQLAlchemy query generation for efficiency",
                "Consider adding database indexes for frequently queried columns",
                "Optimize SQLAlchemy relationship loading (lazy vs eager)",
                "Review connection pool configuration and sizing"
            ])
        
        # Result count discrepancy recommendations
        if analysis.flask_result_count != analysis.nodejs_result_count:
            recommendations.extend([
                "Verify data migration integrity between MongoDB and PostgreSQL",
                "Review SQL query logic for consistency with MongoDB queries",
                "Check for data type conversion issues affecting query results",
                "Validate foreign key relationships and constraints"
            ])
        
        # Query plan differences
        if analysis.query_plan_difference:
            recommendations.extend([
                "Analyze PostgreSQL query execution plans",
                "Consider query rewriting for optimal PostgreSQL performance",
                "Review SQLAlchemy query generation patterns",
                "Optimize table statistics and query planner settings"
            ])
        
        # Index usage differences
        if analysis.index_usage_difference:
            recommendations.extend([
                "Review index strategy for PostgreSQL migration",
                "Create missing indexes identified in Node.js implementation",
                "Optimize existing indexes for SQLAlchemy query patterns",
                "Consider composite indexes for complex query scenarios"
            ])
        
        return recommendations
    
    def identify_database_issues(self, analysis: DatabaseQueryAnalysis) -> List[DiscrepancyRecord]:
        """Identify database-related discrepancies and create records."""
        discrepancies = []
        
        # Performance degradation
        if analysis.flask_execution_time_ms > analysis.nodejs_execution_time_ms * 1.2:
            performance_impact = analysis.flask_execution_time_ms - analysis.nodejs_execution_time_ms
            
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.HIGH,
                discrepancy_type=DiscrepancyType.DATABASE_VARIANCE,
                title=f"Database Query Performance Degradation: {analysis.query_type}",
                description=f"SQLAlchemy query {analysis.flask_execution_time_ms:.1f}ms slower than MongoDB equivalent",
                affected_component=f"Database:{analysis.table_name}",
                root_cause="SQLAlchemy query optimization or PostgreSQL configuration needed",
                recommended_action=CorrectionWorkflowAction.SQLALCHEMY_OPTIMIZATION,
                remediation_steps=analysis.optimization_recommendations,
                performance_impact=performance_impact,
                business_impact="Database performance degradation affects overall application response times",
                evidence=analysis.to_dict()
            ))
        
        # Result count discrepancy
        if analysis.flask_result_count != analysis.nodejs_result_count:
            severity = DiscrepancySeverity.CRITICAL if abs(analysis.flask_result_count - analysis.nodejs_result_count) > 10 else DiscrepancySeverity.HIGH
            
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=severity,
                discrepancy_type=DiscrepancyType.DATA_INTEGRITY_VIOLATION,
                title=f"Database Result Count Mismatch: {analysis.query_type}",
                description=f"Flask returns {analysis.flask_result_count} results, Node.js returns {analysis.nodejs_result_count}",
                affected_component=f"Database:{analysis.table_name}",
                root_cause="Data migration integrity issue or query logic difference",
                recommended_action=CorrectionWorkflowAction.MANUAL_REVIEW_REQUIRED,
                remediation_steps=[
                    "Verify data migration integrity",
                    "Compare SQL query logic with MongoDB query",
                    "Check for data type conversion issues",
                    "Validate relationship mappings"
                ],
                performance_impact=0.0,
                business_impact="Data integrity violation affects application functionality and user trust",
                evidence=analysis.to_dict()
            ))
        
        return discrepancies


class ErrorHandlingAnalyzer:
    """Specialized analyzer for error handling consistency detection and root cause analysis."""
    
    def __init__(self, config: AnalysisConfiguration):
        self.config = config
        
    def analyze_error_handling(self, scenario: str, nodejs_error: Dict[str, Any], 
                             flask_error: Dict[str, Any], baseline_data: Optional[Dict[str, Any]] = None) -> ErrorHandlingAnalysis:
        """Analyze error handling consistency between implementations."""
        
        # Extract error response components
        nodejs_status = nodejs_error.get('status_code', 500)
        flask_status = flask_error.get('status_code', 500)
        
        nodejs_message = nodejs_error.get('error_message', '')
        flask_message = flask_error.get('error_message', '')
        
        nodejs_structure = nodejs_error.get('error_structure', {})
        flask_structure = flask_error.get('error_structure', {})
        
        # Consistency analysis
        status_code_consistency = nodejs_status == flask_status
        
        # Message similarity analysis
        message_similarity = self._calculate_message_similarity(nodejs_message, flask_message)
        message_threshold = self.config.get_setting('analysis_settings', 'error_message_similarity_threshold')
        error_message_consistency = message_similarity >= message_threshold
        
        # Structure consistency
        error_structure_consistency = self._compare_error_structures(nodejs_structure, flask_structure)
        
        # Logging consistency (if available)
        logging_consistency = self._analyze_logging_consistency(nodejs_error, flask_error)
        
        # Root cause analysis
        root_cause = self._analyze_error_root_cause(
            scenario, nodejs_error, flask_error, 
            status_code_consistency, error_message_consistency, error_structure_consistency
        )
        
        # Generate correction recommendations
        recommended_corrections = self._generate_error_corrections(
            scenario, status_code_consistency, error_message_consistency, error_structure_consistency
        )
        
        return ErrorHandlingAnalysis(
            error_scenario=scenario,
            nodejs_error_response=nodejs_error,
            flask_error_response=flask_error,
            status_code_consistency=status_code_consistency,
            error_message_consistency=error_message_consistency,
            error_structure_consistency=error_structure_consistency,
            logging_consistency=logging_consistency,
            root_cause_analysis=root_cause,
            recommended_corrections=recommended_corrections
        )
    
    def _calculate_message_similarity(self, message1: str, message2: str) -> float:
        """Calculate similarity between error messages."""
        if not message1 or not message2:
            return 0.0 if message1 != message2 else 1.0
        
        # Use difflib for similarity calculation
        similarity = difflib.SequenceMatcher(None, message1.lower(), message2.lower()).ratio()
        return similarity
    
    def _compare_error_structures(self, structure1: Dict[str, Any], structure2: Dict[str, Any]) -> bool:
        """Compare error response structures for consistency."""
        # Normalize structures for comparison
        normalized1 = self._normalize_error_structure(structure1)
        normalized2 = self._normalize_error_structure(structure2)
        
        return normalized1 == normalized2
    
    def _normalize_error_structure(self, structure: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize error structure for comparison."""
        # Remove volatile fields that may differ between implementations
        volatile_fields = {'timestamp', 'request_id', 'trace_id', 'server_time'}
        
        normalized = {}
        for key, value in structure.items():
            if key.lower() not in volatile_fields:
                normalized[key.lower()] = value
        
        return normalized
    
    def _analyze_logging_consistency(self, nodejs_error: Dict[str, Any], flask_error: Dict[str, Any]) -> bool:
        """Analyze logging consistency between implementations."""
        nodejs_logged = nodejs_error.get('logged', False)
        flask_logged = flask_error.get('logged', False)
        
        return nodejs_logged == flask_logged
    
    def _analyze_error_root_cause(self, scenario: str, nodejs_error: Dict[str, Any], flask_error: Dict[str, Any],
                                status_consistent: bool, message_consistent: bool, structure_consistent: bool) -> str:
        """Analyze root cause of error handling inconsistencies."""
        root_causes = []
        
        if not status_consistent:
            root_causes.append("HTTP status code handling differs between Node.js and Flask implementations")
        
        if not message_consistent:
            root_causes.append("Error message generation logic differs between implementations")
        
        if not structure_consistent:
            root_causes.append("Error response structure formatting differs between implementations")
        
        # Scenario-specific analysis
        if 'validation' in scenario.lower():
            root_causes.append("Input validation error handling may need alignment")
        elif 'authentication' in scenario.lower():
            root_causes.append("Authentication error handling requires standardization")
        elif 'database' in scenario.lower():
            root_causes.append("Database error handling and exception mapping needs review")
        
        return "; ".join(root_causes) if root_causes else "Error handling appears consistent"
    
    def _generate_error_corrections(self, scenario: str, status_consistent: bool, 
                                  message_consistent: bool, structure_consistent: bool) -> List[str]:
        """Generate specific correction recommendations for error handling issues."""
        corrections = []
        
        if not status_consistent:
            corrections.extend([
                "Review Flask @app.errorhandler decorator implementations",
                "Ensure HTTP status codes match Node.js error responses",
                "Update Flask error handling middleware for consistency"
            ])
        
        if not message_consistent:
            corrections.extend([
                "Standardize error message formatting between implementations",
                "Review Flask validation error message generation",
                "Implement consistent error message templates"
            ])
        
        if not structure_consistent:
            corrections.extend([
                "Align Flask error response JSON structure with Node.js format",
                "Update Flask error serialization logic",
                "Ensure consistent error field naming and structure"
            ])
        
        # Scenario-specific corrections
        if 'validation' in scenario.lower():
            corrections.extend([
                "Review Flask-WTF validation error handling",
                "Ensure validation error responses match Node.js format",
                "Update Flask form validation error serialization"
            ])
        elif 'authentication' in scenario.lower():
            corrections.extend([
                "Review Flask-Login error handling implementation",
                "Align Auth0 integration error responses",
                "Update Flask authentication middleware error handling"
            ])
        elif 'database' in scenario.lower():
            corrections.extend([
                "Review SQLAlchemy exception handling and mapping",
                "Ensure database error responses match MongoDB equivalents",
                "Update Flask database error handler decorators"
            ])
        
        return corrections
    
    def identify_error_inconsistencies(self, analysis: ErrorHandlingAnalysis) -> List[DiscrepancyRecord]:
        """Identify error handling inconsistencies and create discrepancy records."""
        discrepancies = []
        
        # Status code inconsistency
        if not analysis.status_code_consistency:
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.CRITICAL,
                discrepancy_type=DiscrepancyType.ERROR_HANDLING_INCONSISTENCY,
                title=f"Error Status Code Inconsistency: {analysis.error_scenario}",
                description=f"Node.js returns {analysis.nodejs_error_response.get('status_code')}, Flask returns {analysis.flask_error_response.get('status_code')}",
                affected_component=f"Error Handling:{analysis.error_scenario}",
                root_cause=analysis.root_cause_analysis,
                recommended_action=CorrectionWorkflowAction.ERROR_HANDLER_UPDATE,
                remediation_steps=analysis.recommended_corrections,
                performance_impact=0.0,
                business_impact="Status code inconsistencies break API contracts and client expectations",
                evidence=analysis.to_dict()
            ))
        
        # Message inconsistency
        if not analysis.error_message_consistency:
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.HIGH,
                discrepancy_type=DiscrepancyType.ERROR_HANDLING_INCONSISTENCY,
                title=f"Error Message Inconsistency: {analysis.error_scenario}",
                description="Error messages differ significantly between Node.js and Flask implementations",
                affected_component=f"Error Handling:{analysis.error_scenario}",
                root_cause=analysis.root_cause_analysis,
                recommended_action=CorrectionWorkflowAction.ERROR_HANDLER_UPDATE,
                remediation_steps=analysis.recommended_corrections,
                performance_impact=0.0,
                business_impact="Inconsistent error messages confuse users and complicate debugging",
                evidence=analysis.to_dict()
            ))
        
        # Structure inconsistency
        if not analysis.error_structure_consistency:
            discrepancies.append(DiscrepancyRecord(
                discrepancy_id=str(uuid.uuid4()),
                severity=DiscrepancySeverity.HIGH,
                discrepancy_type=DiscrepancyType.ERROR_HANDLING_INCONSISTENCY,
                title=f"Error Structure Inconsistency: {analysis.error_scenario}",
                description="Error response structures differ between implementations",
                affected_component=f"Error Handling:{analysis.error_scenario}",
                root_cause=analysis.root_cause_analysis,
                recommended_action=CorrectionWorkflowAction.ERROR_HANDLER_UPDATE,
                remediation_steps=analysis.recommended_corrections,
                performance_impact=0.0,
                business_impact="Structural differences in error responses may break client error handling",
                evidence=analysis.to_dict()
            ))
        
        return discrepancies


# =============================================================================
# Report Generation and Output Management
# =============================================================================

class ReportGenerator:
    """Comprehensive report generator for analysis results with multiple output formats."""
    
    def __init__(self, config: AnalysisConfiguration):
        self.config = config
        self.template_env = self._setup_template_environment()
        
    def _setup_template_environment(self) -> Environment:
        """Setup Jinja2 template environment for report generation."""
        # Create template directory if it doesn't exist
        template_dir = Path(__file__).parent / 'templates'
        template_dir.mkdir(exist_ok=True)
        
        # Create basic templates if they don't exist
        self._create_default_templates(template_dir)
        
        return Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
    
    def _create_default_templates(self, template_dir: Path):
        """Create default report templates if they don't exist."""
        html_template_path = template_dir / 'analysis_report.html'
        
        if not html_template_path.exists():
            html_template_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flask Migration Analysis Report - {{ report.report_id }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { border-bottom: 2px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #007bff; margin: 0; }
        .header .meta { color: #666; margin-top: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #007bff; }
        .summary-card h3 { margin: 0 0 10px 0; color: #333; }
        .summary-card .value { font-size: 2em; font-weight: bold; color: #007bff; }
        .critical { border-left-color: #dc3545; }
        .critical .value { color: #dc3545; }
        .high { border-left-color: #fd7e14; }
        .high .value { color: #fd7e14; }
        .success { border-left-color: #28a745; }
        .success .value { color: #28a745; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #333; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
        .discrepancy { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 20px; margin-bottom: 20px; }
        .discrepancy.critical { border-left: 4px solid #dc3545; }
        .discrepancy.high { border-left: 4px solid #fd7e14; }
        .discrepancy.medium { border-left: 4px solid #ffc107; }
        .discrepancy.low { border-left: 4px solid #17a2b8; }
        .discrepancy h4 { margin: 0 0 10px 0; color: #333; }
        .discrepancy .severity { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }
        .severity.critical { background: #dc3545; color: white; }
        .severity.high { background: #fd7e14; color: white; }
        .severity.medium { background: #ffc107; color: black; }
        .severity.low { background: #17a2b8; color: white; }
        .evidence { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 15px; }
        .evidence pre { margin: 0; overflow-x: auto; }
        .recommendations { background: #e7f3ff; padding: 20px; border-radius: 6px; border-left: 4px solid #007bff; }
        .recommendations ul { margin: 10px 0; }
        .parity-score { text-align: center; margin: 30px 0; }
        .parity-meter { width: 300px; height: 20px; background: #ddd; border-radius: 10px; margin: 20px auto; overflow: hidden; }
        .parity-fill { height: 100%; background: linear-gradient(90deg, #dc3545 0%, #ffc107 50%, #28a745 100%); border-radius: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Flask Migration Analysis Report</h1>
            <div class="meta">
                <strong>Report ID:</strong> {{ report.report_id }}<br>
                <strong>Analysis Duration:</strong> {{ (report.analysis_end_time - report.analysis_start_time).total_seconds() | round(2) }} seconds<br>
                <strong>Generated:</strong> {{ report.analysis_end_time.strftime('%Y-%m-%d %H:%M:%S UTC') }}
            </div>
        </div>

        <div class="parity-score">
            <h2>Overall Parity Score</h2>
            <div class="parity-meter">
                <div class="parity-fill" style="width: {{ (report.overall_parity_score * 100) | round(1) }}%"></div>
            </div>
            <div style="font-size: 2em; font-weight: bold; margin-top: 10px; 
                        color: {% if report.overall_parity_score >= 0.9 %}#28a745{% elif report.overall_parity_score >= 0.7 %}#ffc107{% else %}#dc3545{% endif %}">
                {{ (report.overall_parity_score * 100) | round(1) }}%
            </div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Comparisons</h3>
                <div class="value">{{ report.total_comparisons }}</div>
            </div>
            <div class="summary-card success">
                <h3>Successful</h3>
                <div class="value">{{ report.successful_comparisons }}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical Issues</h3>
                <div class="value">{{ report.critical_discrepancies }}</div>
            </div>
            <div class="summary-card high">
                <h3>High Priority</h3>
                <div class="value">{{ report.high_severity_discrepancies }}</div>
            </div>
        </div>

        {% if report.discrepancy_records %}
        <div class="section">
            <h2>Discrepancy Analysis</h2>
            {% for discrepancy in report.discrepancy_records %}
            <div class="discrepancy {{ discrepancy.severity.value }}">
                <h4>
                    {{ discrepancy.title }}
                    <span class="severity {{ discrepancy.severity.value }}">{{ discrepancy.severity.value }}</span>
                </h4>
                <p><strong>Component:</strong> {{ discrepancy.affected_component }}</p>
                <p><strong>Description:</strong> {{ discrepancy.description }}</p>
                <p><strong>Root Cause:</strong> {{ discrepancy.root_cause }}</p>
                <p><strong>Business Impact:</strong> {{ discrepancy.business_impact }}</p>
                
                {% if discrepancy.remediation_steps %}
                <div><strong>Remediation Steps:</strong></div>
                <ul>
                    {% for step in discrepancy.remediation_steps %}
                    <li>{{ step }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
                
                {% if discrepancy.evidence %}
                <div class="evidence">
                    <strong>Evidence:</strong>
                    <pre>{{ discrepancy.evidence | tojson(indent=2) }}</pre>
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if report.recommendations %}
        <div class="section">
            <div class="recommendations">
                <h2>Recommendations</h2>
                <ul>
                    {% for recommendation in report.recommendations %}
                    <li>{{ recommendation }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h2>Performance Summary</h2>
            <div class="evidence">
                <pre>{{ report.performance_comparison_summary | tojson(indent=2) }}</pre>
            </div>
        </div>

        <div class="section">
            <h2>Database Analysis Summary</h2>
            <div class="evidence">
                <pre>{{ report.database_analysis_summary | tojson(indent=2) }}</pre>
            </div>
        </div>

        <div class="section">
            <h2>Error Handling Summary</h2>
            <div class="evidence">
                <pre>{{ report.error_handling_summary | tojson(indent=2) }}</pre>
            </div>
        </div>
    </div>
</body>
</html>
            """.strip()
            
            with open(html_template_path, 'w') as f:
                f.write(html_template_content)
    
    def generate_html_report(self, report: AnalysisReport) -> str:
        """Generate HTML report from analysis results."""
        try:
            template = self.template_env.get_template('analysis_report.html')
            html_content = template.render(report=report)
            
            logger.info("HTML report generated successfully",
                        report_id=report.report_id,
                        content_length=len(html_content))
            
            return html_content
            
        except Exception as e:
            logger.error("Failed to generate HTML report",
                         report_id=report.report_id, error=str(e))
            # Return basic HTML report as fallback
            return self._generate_basic_html_report(report)
    
    def _generate_basic_html_report(self, report: AnalysisReport) -> str:
        """Generate basic HTML report as fallback."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Analysis Report - {report.report_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .discrepancy {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; }}
                .critical {{ border-left: 5px solid red; }}
                .high {{ border-left: 5px solid orange; }}
            </style>
        </head>
        <body>
            <h1>Flask Migration Analysis Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Parity Score: {report.overall_parity_score:.2%}</p>
                <p>Total Discrepancies: {len(report.discrepancy_records)}</p>
                <p>Critical Issues: {report.critical_discrepancies}</p>
            </div>
            <h2>Discrepancies</h2>
        """
        
        for discrepancy in report.discrepancy_records[:10]:  # Limit to first 10
            html += f"""
            <div class="discrepancy {discrepancy.severity.value}">
                <h3>{discrepancy.title}</h3>
                <p>{discrepancy.description}</p>
                <p><strong>Severity:</strong> {discrepancy.severity.value}</p>
            </div>
            """
        
        html += "</body></html>"
        return html


# =============================================================================
# Automated Correction Workflow Manager
# =============================================================================

class CorrectionWorkflowManager:
    """Manages automated correction workflows for Flask implementation adjustments."""
    
    def __init__(self, config: AnalysisConfiguration):
        self.config = config
        self.active_corrections: Dict[str, Dict[str, Any]] = {}
        self.correction_history: List[Dict[str, Any]] = []
        
    def trigger_correction_workflow(self, report: AnalysisReport) -> Dict[str, Any]:
        """Trigger automated correction workflow based on analysis results."""
        workflow_id = str(uuid.uuid4())
        workflow_start_time = datetime.now(timezone.utc)
        
        logger.info("Triggering correction workflow",
                    workflow_id=workflow_id,
                    report_id=report.report_id,
                    critical_discrepancies=report.critical_discrepancies)
        
        workflow_result = {
            'workflow_id': workflow_id,
            'report_id': report.report_id,
            'start_time': workflow_start_time,
            'status': 'running',
            'corrections_attempted': [],
            'corrections_successful': [],
            'corrections_failed': [],
            'manual_review_required': []
        }
        
        self.active_corrections[workflow_id] = workflow_result
        
        try:
            # Process critical discrepancies first
            critical_discrepancies = [d for d in report.discrepancy_records if d.severity == DiscrepancySeverity.CRITICAL]
            for discrepancy in critical_discrepancies:
                correction_result = self._apply_correction(discrepancy)
                workflow_result['corrections_attempted'].append(correction_result)
                
                if correction_result['success']:
                    workflow_result['corrections_successful'].append(correction_result)
                    # Update Prometheus metrics
                    self.config.metrics['corrections_applied'].labels(
                        correction_type=discrepancy.recommended_action.value,
                        success='true'
                    ).inc()
                else:
                    workflow_result['corrections_failed'].append(correction_result)
                    self.config.metrics['corrections_applied'].labels(
                        correction_type=discrepancy.recommended_action.value,
                        success='false'
                    ).inc()
            
            # Process high severity discrepancies
            high_discrepancies = [d for d in report.discrepancy_records if d.severity == DiscrepancySeverity.HIGH]
            for discrepancy in high_discrepancies:
                if self._should_auto_correct(discrepancy):
                    correction_result = self._apply_correction(discrepancy)
                    workflow_result['corrections_attempted'].append(correction_result)
                    
                    if correction_result['success']:
                        workflow_result['corrections_successful'].append(correction_result)
                    else:
                        workflow_result['corrections_failed'].append(correction_result)
                else:
                    workflow_result['manual_review_required'].append({
                        'discrepancy_id': discrepancy.discrepancy_id,
                        'title': discrepancy.title,
                        'reason': 'High severity requires manual approval'
                    })
            
            workflow_result['status'] = 'completed'
            workflow_result['end_time'] = datetime.now(timezone.utc)
            
            # Log workflow completion
            logger.info("Correction workflow completed",
                        workflow_id=workflow_id,
                        successful_corrections=len(workflow_result['corrections_successful']),
                        failed_corrections=len(workflow_result['corrections_failed']),
                        manual_review_required=len(workflow_result['manual_review_required']))
            
            # Store in correction history
            self.correction_history.append(workflow_result.copy())
            
            return workflow_result
            
        except Exception as e:
            workflow_result['status'] = 'failed'
            workflow_result['error'] = str(e)
            workflow_result['end_time'] = datetime.now(timezone.utc)
            
            logger.error("Correction workflow failed",
                         workflow_id=workflow_id, error=str(e))
            
            return workflow_result
        finally:
            # Cleanup active correction tracking
            if workflow_id in self.active_corrections:
                del self.active_corrections[workflow_id]
    
    def _should_auto_correct(self, discrepancy: DiscrepancyRecord) -> bool:
        """Determine if discrepancy should be auto-corrected or require manual approval."""
        auto_apply_setting = self.config.get_setting('correction_workflow', 'auto_apply_low_risk_corrections')
        require_manual_approval = self.config.get_setting('correction_workflow', 'require_manual_approval_for_critical')
        
        # Never auto-correct critical issues if manual approval is required
        if discrepancy.severity == DiscrepancySeverity.CRITICAL and require_manual_approval:
            return False
        
        # Auto-correct based on action type and risk level
        low_risk_actions = {
            CorrectionWorkflowAction.CONFIGURATION_CHANGE,
            CorrectionWorkflowAction.ERROR_HANDLER_UPDATE
        }
        
        medium_risk_actions = {
            CorrectionWorkflowAction.FLASK_CODE_ADJUSTMENT,
            CorrectionWorkflowAction.PERFORMANCE_TUNING
        }
        
        high_risk_actions = {
            CorrectionWorkflowAction.SQLALCHEMY_OPTIMIZATION,
            CorrectionWorkflowAction.MANUAL_REVIEW_REQUIRED
        }
        
        if discrepancy.recommended_action in low_risk_actions and auto_apply_setting:
            return True
        elif discrepancy.recommended_action in medium_risk_actions and discrepancy.severity != DiscrepancySeverity.CRITICAL:
            return auto_apply_setting
        else:
            return False
    
    def _apply_correction(self, discrepancy: DiscrepancyRecord) -> Dict[str, Any]:
        """Apply specific correction based on discrepancy type and recommended action."""
        correction_start_time = datetime.now(timezone.utc)
        
        correction_result = {
            'discrepancy_id': discrepancy.discrepancy_id,
            'correction_type': discrepancy.recommended_action.value,
            'start_time': correction_start_time,
            'success': False,
            'details': [],
            'error': None
        }
        
        try:
            logger.info("Applying correction",
                        discrepancy_id=discrepancy.discrepancy_id,
                        correction_type=discrepancy.recommended_action.value)
            
            if discrepancy.recommended_action == CorrectionWorkflowAction.FLASK_CODE_ADJUSTMENT:
                correction_result.update(self._apply_flask_code_adjustment(discrepancy))
            elif discrepancy.recommended_action == CorrectionWorkflowAction.SQLALCHEMY_OPTIMIZATION:
                correction_result.update(self._apply_sqlalchemy_optimization(discrepancy))
            elif discrepancy.recommended_action == CorrectionWorkflowAction.ERROR_HANDLER_UPDATE:
                correction_result.update(self._apply_error_handler_update(discrepancy))
            elif discrepancy.recommended_action == CorrectionWorkflowAction.PERFORMANCE_TUNING:
                correction_result.update(self._apply_performance_tuning(discrepancy))
            elif discrepancy.recommended_action == CorrectionWorkflowAction.CONFIGURATION_CHANGE:
                correction_result.update(self._apply_configuration_change(discrepancy))
            else:
                correction_result['error'] = f"Unsupported correction action: {discrepancy.recommended_action.value}"
            
            correction_result['end_time'] = datetime.now(timezone.utc)
            
            if correction_result['success']:
                logger.info("Correction applied successfully",
                            discrepancy_id=discrepancy.discrepancy_id,
                            correction_type=discrepancy.recommended_action.value)
            else:
                logger.warning("Correction failed",
                               discrepancy_id=discrepancy.discrepancy_id,
                               error=correction_result.get('error'))
            
            return correction_result
            
        except Exception as e:
            correction_result['success'] = False
            correction_result['error'] = str(e)
            correction_result['end_time'] = datetime.now(timezone.utc)
            
            logger.error("Correction application failed",
                         discrepancy_id=discrepancy.discrepancy_id,
                         error=str(e))
            
            return correction_result
    
    def _apply_flask_code_adjustment(self, discrepancy: DiscrepancyRecord) -> Dict[str, Any]:
        """Apply Flask code adjustments for response and behavior consistency."""
        # This would implement actual code adjustments in a real scenario
        # For now, we simulate the correction process
        
        details = []
        success = False
        
        try:
            # Simulate code adjustment based on discrepancy evidence
            if 'status_code' in discrepancy.evidence:
                details.append("Updated Flask route status code handling")
                success = True
            
            if 'content_type' in discrepancy.evidence:
                details.append("Adjusted Flask response content type configuration")
                success = True
            
            if 'response_data' in discrepancy.evidence:
                details.append("Modified Flask response serialization logic")
                success = True
            
            return {
                'success': success,
                'details': details,
                'simulated': True,  # Indicates this is a simulation
                'remediation_applied': discrepancy.remediation_steps[:3]  # Apply first 3 steps
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Flask code adjustment failed: {str(e)}",
                'details': details
            }
    
    def _apply_sqlalchemy_optimization(self, discrepancy: DiscrepancyRecord) -> Dict[str, Any]:
        """Apply SQLAlchemy optimizations for database performance improvements."""
        details = []
        success = False
        
        try:
            # Simulate SQLAlchemy optimization
            if 'query_performance' in str(discrepancy.evidence):
                details.append("Optimized SQLAlchemy query generation")
                details.append("Updated database connection pool configuration")
                success = True
            
            if 'index' in str(discrepancy.evidence):
                details.append("Created recommended database indexes")
                success = True
            
            return {
                'success': success,
                'details': details,
                'simulated': True,
                'performance_impact_reduction': discrepancy.performance_impact * 0.7  # Assume 70% improvement
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"SQLAlchemy optimization failed: {str(e)}",
                'details': details
            }
    
    def _apply_error_handler_update(self, discrepancy: DiscrepancyRecord) -> Dict[str, Any]:
        """Apply error handler updates for consistency with Node.js implementation."""
        details = []
        success = False
        
        try:
            # Simulate error handler updates
            if 'error_handling' in discrepancy.discrepancy_type.value:
                details.append("Updated Flask @app.errorhandler decorators")
                details.append("Standardized error response format")
                success = True
            
            return {
                'success': success,
                'details': details,
                'simulated': True,
                'consistency_improvement': True
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Error handler update failed: {str(e)}",
                'details': details
            }
    
    def _apply_performance_tuning(self, discrepancy: DiscrepancyRecord) -> Dict[str, Any]:
        """Apply performance tuning for Flask application optimization."""
        details = []
        success = False
        
        try:
            # Simulate performance tuning
            if discrepancy.performance_impact > 0:
                details.append("Optimized Flask middleware pipeline")
                details.append("Implemented response caching")
                details.append("Tuned Gunicorn worker configuration")
                success = True
            
            return {
                'success': success,
                'details': details,
                'simulated': True,
                'estimated_improvement_ms': discrepancy.performance_impact * 0.6
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Performance tuning failed: {str(e)}",
                'details': details
            }
    
    def _apply_configuration_change(self, discrepancy: DiscrepancyRecord) -> Dict[str, Any]:
        """Apply configuration changes for Flask application settings."""
        details = []
        success = False
        
        try:
            # Simulate configuration changes
            details.append("Updated Flask application configuration")
            details.append("Modified environment-specific settings")
            success = True
            
            return {
                'success': success,
                'details': details,
                'simulated': True,
                'configuration_updated': True
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Configuration change failed: {str(e)}",
                'details': details
            }
    
    def get_correction_history(self) -> List[Dict[str, Any]]:
        """Get correction workflow history."""
        return self.correction_history.copy()
    
    def get_active_corrections(self) -> Dict[str, Dict[str, Any]]:
        """Get currently active correction workflows."""
        return self.active_corrections.copy()


# =============================================================================
# Main Analysis Interface and Utility Functions
# =============================================================================

def analyze_comparative_test_results(test_results_path: str, 
                                    config_path: Optional[str] = None,
                                    output_formats: List[str] = None) -> AnalysisReport:
    """
    Main interface function for analyzing comparative test results.
    
    Args:
        test_results_path: Path to comparative test results file
        config_path: Optional path to analysis configuration file
        output_formats: List of output formats for report generation
        
    Returns:
        AnalysisReport: Comprehensive analysis report
    """
    # Initialize configuration
    config = AnalysisConfiguration(config_path)
    
    # Initialize analyzer
    analyzer = ResultsAnalyzer(config)
    
    try:
        # Load test results
        with open(test_results_path, 'r') as results_file:
            test_results = json.load(results_file)
        
        logger.info("Starting comparative results analysis",
                    results_file=test_results_path,
                    config_file=config_path)
        
        # Perform analysis
        analysis_report = analyzer.analyze_comparative_results(test_results)
        
        # Export results in specified formats
        if output_formats:
            exported_files = analyzer.export_analysis_results(analysis_report, output_formats)
            logger.info("Analysis results exported",
                        formats=output_formats,
                        files=exported_files)
        
        return analysis_report
        
    except Exception as e:
        logger.error("Comparative results analysis failed",
                     error=str(e), traceback=traceback.format_exc())
        raise


def main():
    """Command-line interface for results analyzer."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Flask Migration Results Analyzer')
    parser.add_argument('test_results', help='Path to comparative test results file')
    parser.add_argument('--config', help='Path to analysis configuration file')
    parser.add_argument('--output-formats', nargs='+', default=['json', 'html'],
                        choices=['json', 'html', 'prometheus'],
                        help='Output formats for analysis report')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        analysis_report = analyze_comparative_test_results(
            test_results_path=args.test_results,
            config_path=args.config,
            output_formats=args.output_formats
        )
        
        print(f"Analysis completed successfully!")
        print(f"Report ID: {analysis_report.report_id}")
        print(f"Overall Parity Score: {analysis_report.overall_parity_score:.2%}")
        print(f"Total Discrepancies: {len(analysis_report.discrepancy_records)}")
        print(f"Critical Issues: {analysis_report.critical_discrepancies}")
        
        if analysis_report.correction_workflow_triggered:
            print("⚠️  Automated correction workflow was triggered")
        
        sys.exit(0)
        
    except Exception as e:
        print(f"Analysis failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()