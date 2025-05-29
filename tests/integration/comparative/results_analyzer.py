"""
Comprehensive discrepancy analysis and reporting utility for comparative testing results.

This tool processes comparative test outputs, identifies behavioral differences between Node.js 
and Flask implementations, generates detailed variance reports, and triggers automated correction 
workflows when parity violations are detected.

Features:
- Detailed response data comparison with diff analysis per Section 4.7.2
- Performance metric deviation identification with threshold-based alerting
- Database query result variance analysis for SQLAlchemy optimization guidance  
- Error handling inconsistency detection with root cause analysis
- Automated report generation with comprehensive migration status tracking
- Correction workflow integration for automated Flask implementation adjustment
"""

import json
import logging
import statistics
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from difflib import unified_diff
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pytest
from deepdiff import DeepDiff


logger = logging.getLogger(__name__)


@dataclass
class DiscrepancyDetails:
    """Detailed information about a discrepancy between Node.js and Flask implementations."""
    
    discrepancy_id: str
    category: str  # 'api_response', 'performance', 'database', 'error_handling'
    severity: str  # 'critical', 'major', 'minor', 'informational'
    description: str
    node_js_value: Any
    flask_value: Any
    difference_details: Dict[str, Any]
    root_cause_analysis: Optional[str] = None
    recommended_action: Optional[str] = None
    correction_workflow_triggered: bool = False
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class PerformanceMetrics:
    """Performance metrics captured during comparative testing."""
    
    response_time_ms: float
    memory_usage_mb: float
    cpu_utilization_percent: float
    database_query_time_ms: float
    concurrent_user_capacity: int
    throughput_requests_per_second: float


@dataclass
class AnalysisReport:
    """Comprehensive analysis report for comparative testing results."""
    
    report_id: str
    test_session_id: str
    timestamp: datetime
    total_discrepancies: int
    critical_discrepancies: int
    major_discrepancies: int
    minor_discrepancies: int
    parity_percentage: float
    discrepancies: List[DiscrepancyDetails]
    performance_comparison: Dict[str, Any]
    migration_status: str  # 'passing', 'failing', 'warning'
    correction_workflows_triggered: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary for serialization."""
        return {
            'report_id': self.report_id,
            'test_session_id': self.test_session_id,
            'timestamp': self.timestamp.isoformat(),
            'summary': {
                'total_discrepancies': self.total_discrepancies,
                'critical_discrepancies': self.critical_discrepancies,
                'major_discrepancies': self.major_discrepancies,
                'minor_discrepancies': self.minor_discrepancies,
                'parity_percentage': self.parity_percentage,
                'migration_status': self.migration_status
            },
            'discrepancies': [
                {
                    'discrepancy_id': d.discrepancy_id,
                    'category': d.category,
                    'severity': d.severity,
                    'description': d.description,
                    'root_cause_analysis': d.root_cause_analysis,
                    'recommended_action': d.recommended_action,
                    'correction_workflow_triggered': d.correction_workflow_triggered,
                    'timestamp': d.timestamp.isoformat()
                }
                for d in self.discrepancies
            ],
            'performance_comparison': self.performance_comparison,
            'correction_workflows_triggered': self.correction_workflows_triggered
        }


class ComparativeResultsAnalyzer:
    """
    Comprehensive discrepancy analysis and reporting utility for comparative testing results.
    
    This analyzer processes test outputs from parallel Node.js and Flask system execution,
    identifies behavioral differences, generates detailed variance reports, and triggers
    automated correction workflows when parity violations are detected.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the results analyzer with configuration settings.
        
        Args:
            config: Configuration dictionary containing thresholds and settings
        """
        self.config = config or self._get_default_config()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.report_storage_path = Path(self.config.get('report_storage_path', 'test_reports'))
        self.report_storage_path.mkdir(exist_ok=True)
        
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for the analyzer."""
        return {
            'performance_thresholds': {
                'response_time_tolerance_ms': 100,
                'memory_usage_tolerance_mb': 50,
                'cpu_utilization_tolerance_percent': 10,
                'database_query_tolerance_ms': 25,
                'throughput_tolerance_percent': 5
            },
            'api_comparison': {
                'ignore_timestamp_fields': True,
                'ignore_generated_ids': True,
                'decimal_precision': 2
            },
            'correction_workflow': {
                'auto_trigger_enabled': True,
                'critical_severity_threshold': 1,
                'major_severity_threshold': 3
            },
            'report_storage_path': 'test_reports',
            'detailed_diff_enabled': True
        }
    
    def analyze_comparative_results(
        self, 
        test_session_id: str,
        node_js_results: Dict[str, Any], 
        flask_results: Dict[str, Any]
    ) -> AnalysisReport:
        """
        Analyze comparative testing results between Node.js and Flask implementations.
        
        Args:
            test_session_id: Unique identifier for the test session
            node_js_results: Test results from Node.js baseline system
            flask_results: Test results from Flask implementation
            
        Returns:
            Comprehensive analysis report with discrepancies and recommendations
        """
        self.logger.info(f"Starting comparative analysis for session {test_session_id}")
        
        discrepancies = []
        
        # Analyze API response differences
        api_discrepancies = self._analyze_api_responses(
            node_js_results.get('api_responses', {}),
            flask_results.get('api_responses', {})
        )
        discrepancies.extend(api_discrepancies)
        
        # Analyze performance metric differences  
        performance_discrepancies = self._analyze_performance_metrics(
            node_js_results.get('performance_metrics', {}),
            flask_results.get('performance_metrics', {})
        )
        discrepancies.extend(performance_discrepancies)
        
        # Analyze database query result differences
        database_discrepancies = self._analyze_database_results(
            node_js_results.get('database_results', {}),
            flask_results.get('database_results', {})
        )
        discrepancies.extend(database_discrepancies)
        
        # Analyze error handling differences
        error_handling_discrepancies = self._analyze_error_handling(
            node_js_results.get('error_responses', {}),
            flask_results.get('error_responses', {})
        )
        discrepancies.extend(error_handling_discrepancies)
        
        # Generate comprehensive report
        report = self._generate_analysis_report(test_session_id, discrepancies, node_js_results, flask_results)
        
        # Trigger correction workflows if needed
        self._trigger_correction_workflows(report)
        
        # Store report for future reference
        self._store_report(report)
        
        self.logger.info(f"Analysis completed. Found {len(discrepancies)} discrepancies")
        return report
    
    def _analyze_api_responses(
        self, 
        node_js_responses: Dict[str, Any], 
        flask_responses: Dict[str, Any]
    ) -> List[DiscrepancyDetails]:
        """
        Analyze API response differences with detailed diff analysis.
        
        Args:
            node_js_responses: API responses from Node.js system
            flask_responses: API responses from Flask system
            
        Returns:
            List of discrepancies found in API responses
        """
        discrepancies = []
        
        # Compare responses for each endpoint
        all_endpoints = set(node_js_responses.keys()) | set(flask_responses.keys())
        
        for endpoint in all_endpoints:
            node_response = node_js_responses.get(endpoint)
            flask_response = flask_responses.get(endpoint)
            
            # Check for missing endpoints
            if node_response is None:
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id=f"api_missing_nodejs_{endpoint}",
                    category="api_response",
                    severity="critical",
                    description=f"Endpoint {endpoint} missing in Node.js baseline",
                    node_js_value=None,
                    flask_value=flask_response,
                    difference_details={'type': 'missing_endpoint', 'endpoint': endpoint},
                    root_cause_analysis="Node.js baseline incomplete or endpoint not tested",
                    recommended_action="Verify Node.js baseline capture completeness"
                ))
                continue
                
            if flask_response is None:
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id=f"api_missing_flask_{endpoint}",
                    category="api_response", 
                    severity="critical",
                    description=f"Endpoint {endpoint} missing in Flask implementation",
                    node_js_value=node_response,
                    flask_value=None,
                    difference_details={'type': 'missing_endpoint', 'endpoint': endpoint},
                    root_cause_analysis="Flask endpoint not implemented or blueprint not registered",
                    recommended_action="Implement missing Flask endpoint or register blueprint"
                ))
                continue
            
            # Detailed response comparison
            endpoint_discrepancies = self._compare_response_details(endpoint, node_response, flask_response)
            discrepancies.extend(endpoint_discrepancies)
        
        return discrepancies
    
    def _compare_response_details(
        self, 
        endpoint: str, 
        node_response: Dict[str, Any], 
        flask_response: Dict[str, Any]
    ) -> List[DiscrepancyDetails]:
        """
        Perform detailed comparison of individual API responses.
        
        Args:
            endpoint: API endpoint being compared
            node_response: Response from Node.js system
            flask_response: Response from Flask system
            
        Returns:
            List of discrepancies found in the responses
        """
        discrepancies = []
        
        # Compare status codes
        node_status = node_response.get('status_code')
        flask_status = flask_response.get('status_code')
        
        if node_status != flask_status:
            discrepancies.append(DiscrepancyDetails(
                discrepancy_id=f"api_status_{endpoint}",
                category="api_response",
                severity="major",
                description=f"Status code mismatch for {endpoint}",
                node_js_value=node_status,
                flask_value=flask_status,
                difference_details={'type': 'status_code', 'endpoint': endpoint},
                root_cause_analysis="Different error handling or business logic implementation",
                recommended_action="Review Flask error handling and status code mapping"
            ))
        
        # Compare response headers
        node_headers = node_response.get('headers', {})
        flask_headers = flask_response.get('headers', {})
        
        header_diff = DeepDiff(node_headers, flask_headers, ignore_order=True)
        if header_diff:
            discrepancies.append(DiscrepancyDetails(
                discrepancy_id=f"api_headers_{endpoint}",
                category="api_response",
                severity="minor",
                description=f"Header differences for {endpoint}",
                node_js_value=node_headers,
                flask_value=flask_headers,
                difference_details={'type': 'headers', 'diff': header_diff, 'endpoint': endpoint},
                root_cause_analysis="Different middleware or framework default headers",
                recommended_action="Review Flask response header configuration"
            ))
        
        # Compare response body with deep diff analysis
        node_body = node_response.get('body')
        flask_body = flask_response.get('body')
        
        if self.config['api_comparison']['ignore_timestamp_fields']:
            node_body = self._remove_timestamp_fields(node_body)
            flask_body = self._remove_timestamp_fields(flask_body)
        
        if self.config['api_comparison']['ignore_generated_ids']:
            node_body = self._normalize_generated_ids(node_body)
            flask_body = self._normalize_generated_ids(flask_body)
        
        body_diff = DeepDiff(
            node_body, 
            flask_body, 
            ignore_order=True,
            significant_digits=self.config['api_comparison']['decimal_precision']
        )
        
        if body_diff:
            severity = self._determine_body_diff_severity(body_diff)
            
            discrepancies.append(DiscrepancyDetails(
                discrepancy_id=f"api_body_{endpoint}",
                category="api_response",
                severity=severity,
                description=f"Response body differences for {endpoint}",
                node_js_value=node_body,
                flask_value=flask_body,
                difference_details={
                    'type': 'response_body',
                    'diff': body_diff,
                    'endpoint': endpoint,
                    'detailed_diff': self._generate_detailed_diff(node_body, flask_body)
                },
                root_cause_analysis=self._analyze_body_diff_root_cause(body_diff),
                recommended_action=self._recommend_body_diff_action(body_diff)
            ))
        
        return discrepancies
    
    def _analyze_performance_metrics(
        self, 
        node_js_metrics: Dict[str, Any], 
        flask_metrics: Dict[str, Any]
    ) -> List[DiscrepancyDetails]:
        """
        Analyze performance metric differences with threshold-based alerting.
        
        Args:
            node_js_metrics: Performance metrics from Node.js system
            flask_metrics: Performance metrics from Flask system
            
        Returns:
            List of performance-related discrepancies
        """
        discrepancies = []
        thresholds = self.config['performance_thresholds']
        
        # Compare response times
        node_response_times = node_js_metrics.get('response_times', [])
        flask_response_times = flask_metrics.get('response_times', [])
        
        if node_response_times and flask_response_times:
            node_avg = statistics.mean(node_response_times)
            flask_avg = statistics.mean(flask_response_times)
            diff_ms = abs(flask_avg - node_avg)
            
            if diff_ms > thresholds['response_time_tolerance_ms']:
                severity = "critical" if diff_ms > thresholds['response_time_tolerance_ms'] * 2 else "major"
                
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id="performance_response_time",
                    category="performance",
                    severity=severity,
                    description=f"Response time deviation: {diff_ms:.2f}ms",
                    node_js_value=node_avg,
                    flask_value=flask_avg,
                    difference_details={
                        'type': 'response_time',
                        'deviation_ms': diff_ms,
                        'threshold_ms': thresholds['response_time_tolerance_ms'],
                        'node_min': min(node_response_times),
                        'node_max': max(node_response_times),
                        'flask_min': min(flask_response_times),
                        'flask_max': max(flask_response_times)
                    },
                    root_cause_analysis="Potential SQLAlchemy query optimization needed or Flask routing inefficiency",
                    recommended_action="Profile Flask application and optimize database queries"
                ))
        
        # Compare memory usage
        node_memory = node_js_metrics.get('memory_usage_mb')
        flask_memory = flask_metrics.get('memory_usage_mb')
        
        if node_memory is not None and flask_memory is not None:
            memory_diff = abs(flask_memory - node_memory)
            
            if memory_diff > thresholds['memory_usage_tolerance_mb']:
                severity = "major" if memory_diff > thresholds['memory_usage_tolerance_mb'] * 2 else "minor"
                
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id="performance_memory_usage",
                    category="performance",
                    severity=severity,
                    description=f"Memory usage deviation: {memory_diff:.2f}MB",
                    node_js_value=node_memory,
                    flask_value=flask_memory,
                    difference_details={
                        'type': 'memory_usage',
                        'deviation_mb': memory_diff,
                        'threshold_mb': thresholds['memory_usage_tolerance_mb']
                    },
                    root_cause_analysis="Different memory allocation patterns or SQLAlchemy object caching",
                    recommended_action="Review Flask memory usage patterns and SQLAlchemy session management"
                ))
        
        # Compare database query performance
        node_query_times = node_js_metrics.get('database_query_times', [])
        flask_query_times = flask_metrics.get('database_query_times', [])
        
        if node_query_times and flask_query_times:
            node_db_avg = statistics.mean(node_query_times)
            flask_db_avg = statistics.mean(flask_query_times)
            db_diff_ms = abs(flask_db_avg - node_db_avg)
            
            if db_diff_ms > thresholds['database_query_tolerance_ms']:
                severity = "major" if db_diff_ms > thresholds['database_query_tolerance_ms'] * 3 else "minor"
                
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id="performance_database_query",
                    category="performance",
                    severity=severity,
                    description=f"Database query time deviation: {db_diff_ms:.2f}ms",
                    node_js_value=node_db_avg,
                    flask_value=flask_db_avg,
                    difference_details={
                        'type': 'database_query_time',
                        'deviation_ms': db_diff_ms,
                        'threshold_ms': thresholds['database_query_tolerance_ms'],
                        'node_queries_count': len(node_query_times),
                        'flask_queries_count': len(flask_query_times)
                    },
                    root_cause_analysis="SQLAlchemy query patterns differ from original MongoDB queries",
                    recommended_action="Optimize SQLAlchemy queries and consider eager loading strategies"
                ))
        
        return discrepancies
    
    def _analyze_database_results(
        self, 
        node_js_results: Dict[str, Any], 
        flask_results: Dict[str, Any]
    ) -> List[DiscrepancyDetails]:
        """
        Analyze database query result differences for SQLAlchemy optimization guidance.
        
        Args:
            node_js_results: Database query results from Node.js system
            flask_results: Database query results from Flask system
            
        Returns:
            List of database-related discrepancies
        """
        discrepancies = []
        
        # Compare query result sets
        for query_id in set(node_js_results.keys()) | set(flask_results.keys()):
            node_result = node_js_results.get(query_id)
            flask_result = flask_results.get(query_id)
            
            if node_result is None or flask_result is None:
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id=f"database_missing_query_{query_id}",
                    category="database",
                    severity="major",
                    description=f"Query {query_id} missing in one system",
                    node_js_value=node_result,
                    flask_value=flask_result,
                    difference_details={'type': 'missing_query', 'query_id': query_id},
                    root_cause_analysis="Different database query execution or missing SQL translation",
                    recommended_action="Verify SQLAlchemy query implementation for missing operations"
                ))
                continue
            
            # Compare result data
            result_diff = DeepDiff(
                node_result.get('data', []), 
                flask_result.get('data', []), 
                ignore_order=True
            )
            
            if result_diff:
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id=f"database_result_diff_{query_id}",
                    category="database",
                    severity="major",
                    description=f"Database result differences for query {query_id}",
                    node_js_value=node_result.get('data'),
                    flask_value=flask_result.get('data'),
                    difference_details={
                        'type': 'result_data',
                        'query_id': query_id,
                        'diff': result_diff
                    },
                    root_cause_analysis="SQLAlchemy model relationships or query logic differs from MongoDB",
                    recommended_action="Review SQLAlchemy model definitions and query implementation"
                ))
            
            # Compare query execution metadata
            node_meta = node_result.get('metadata', {})
            flask_meta = flask_result.get('metadata', {})
            
            if node_meta.get('row_count') != flask_meta.get('row_count'):
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id=f"database_row_count_{query_id}",
                    category="database",
                    severity="critical",
                    description=f"Row count mismatch for query {query_id}",
                    node_js_value=node_meta.get('row_count'),
                    flask_value=flask_meta.get('row_count'),
                    difference_details={
                        'type': 'row_count',
                        'query_id': query_id
                    },
                    root_cause_analysis="Data migration issue or SQLAlchemy query filtering differences",
                    recommended_action="Verify data migration completeness and query filters"
                ))
        
        return discrepancies
    
    def _analyze_error_handling(
        self, 
        node_js_errors: Dict[str, Any], 
        flask_errors: Dict[str, Any]
    ) -> List[DiscrepancyDetails]:
        """
        Analyze error handling inconsistencies with root cause analysis.
        
        Args:
            node_js_errors: Error responses from Node.js system
            flask_errors: Error responses from Flask system
            
        Returns:
            List of error handling discrepancies
        """
        discrepancies = []
        
        # Compare error response patterns
        for error_scenario in set(node_js_errors.keys()) | set(flask_errors.keys()):
            node_error = node_js_errors.get(error_scenario)
            flask_error = flask_errors.get(error_scenario)
            
            if node_error is None or flask_error is None:
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id=f"error_missing_{error_scenario}",
                    category="error_handling",
                    severity="major",
                    description=f"Error scenario {error_scenario} missing in one system",
                    node_js_value=node_error,
                    flask_value=flask_error,
                    difference_details={'type': 'missing_error_scenario', 'scenario': error_scenario},
                    root_cause_analysis="Error handler not implemented in Flask or different error conditions",
                    recommended_action="Implement missing Flask error handlers with @app.errorhandler"
                ))
                continue
            
            # Compare error status codes
            if node_error.get('status_code') != flask_error.get('status_code'):
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id=f"error_status_{error_scenario}",
                    category="error_handling",
                    severity="major",
                    description=f"Error status code mismatch for {error_scenario}",
                    node_js_value=node_error.get('status_code'),
                    flask_value=flask_error.get('status_code'),
                    difference_details={
                        'type': 'error_status_code',
                        'scenario': error_scenario
                    },
                    root_cause_analysis="Different error handling middleware or Flask error handler mapping",
                    recommended_action="Review Flask error handler status code assignments"
                ))
            
            # Compare error message format
            node_message = node_error.get('message')
            flask_message = flask_error.get('message')
            
            if node_message != flask_message:
                severity = "minor" if self._are_error_messages_equivalent(node_message, flask_message) else "major"
                
                discrepancies.append(DiscrepancyDetails(
                    discrepancy_id=f"error_message_{error_scenario}",
                    category="error_handling",
                    severity=severity,
                    description=f"Error message format difference for {error_scenario}",
                    node_js_value=node_message,
                    flask_value=flask_message,
                    difference_details={
                        'type': 'error_message',
                        'scenario': error_scenario
                    },
                    root_cause_analysis="Different error message templates or validation message formats",
                    recommended_action="Standardize Flask error message formats to match Node.js baseline"
                ))
        
        return discrepancies
    
    def _generate_analysis_report(
        self, 
        test_session_id: str, 
        discrepancies: List[DiscrepancyDetails],
        node_js_results: Dict[str, Any],
        flask_results: Dict[str, Any]
    ) -> AnalysisReport:
        """
        Generate comprehensive analysis report with migration status tracking.
        
        Args:
            test_session_id: Unique identifier for the test session
            discrepancies: List of all identified discrepancies
            node_js_results: Complete Node.js test results
            flask_results: Complete Flask test results
            
        Returns:
            Comprehensive analysis report
        """
        # Count discrepancies by severity
        critical_count = sum(1 for d in discrepancies if d.severity == "critical")
        major_count = sum(1 for d in discrepancies if d.severity == "major")
        minor_count = sum(1 for d in discrepancies if d.severity == "minor")
        
        # Calculate parity percentage
        total_comparisons = self._count_total_comparisons(node_js_results, flask_results)
        parity_percentage = max(0, (total_comparisons - len(discrepancies)) / total_comparisons * 100) if total_comparisons > 0 else 0
        
        # Determine migration status
        migration_status = self._determine_migration_status(critical_count, major_count, parity_percentage)
        
        # Generate performance comparison summary
        performance_comparison = self._generate_performance_comparison(node_js_results, flask_results)
        
        return AnalysisReport(
            report_id=f"analysis_{test_session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            test_session_id=test_session_id,
            timestamp=datetime.now(),
            total_discrepancies=len(discrepancies),
            critical_discrepancies=critical_count,
            major_discrepancies=major_count,
            minor_discrepancies=minor_count,
            parity_percentage=parity_percentage,
            discrepancies=discrepancies,
            performance_comparison=performance_comparison,
            migration_status=migration_status,
            correction_workflows_triggered=[]
        )
    
    def _trigger_correction_workflows(self, report: AnalysisReport) -> None:
        """
        Trigger automated correction workflows when parity failures are detected.
        
        Args:
            report: Analysis report containing discrepancies
        """
        if not self.config['correction_workflow']['auto_trigger_enabled']:
            return
        
        workflows_triggered = []
        
        # Trigger workflow for critical discrepancies
        if report.critical_discrepancies >= self.config['correction_workflow']['critical_severity_threshold']:
            workflow_id = self._trigger_critical_correction_workflow(report)
            workflows_triggered.append(workflow_id)
            self.logger.warning(f"Critical correction workflow triggered: {workflow_id}")
        
        # Trigger workflow for major discrepancies
        if report.major_discrepancies >= self.config['correction_workflow']['major_severity_threshold']:
            workflow_id = self._trigger_major_correction_workflow(report)
            workflows_triggered.append(workflow_id)
            self.logger.info(f"Major correction workflow triggered: {workflow_id}")
        
        # Update report with triggered workflows
        report.correction_workflows_triggered = workflows_triggered
        
        # Mark discrepancies that triggered workflows
        for discrepancy in report.discrepancies:
            if discrepancy.severity in ["critical", "major"]:
                discrepancy.correction_workflow_triggered = True
    
    def _trigger_critical_correction_workflow(self, report: AnalysisReport) -> str:
        """
        Trigger critical priority correction workflow.
        
        Args:
            report: Analysis report with critical discrepancies
            
        Returns:
            Workflow identifier
        """
        workflow_id = f"critical_correction_{report.test_session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Generate correction instructions for critical issues
        critical_discrepancies = [d for d in report.discrepancies if d.severity == "critical"]
        
        correction_plan = {
            'workflow_id': workflow_id,
            'priority': 'critical',
            'discrepancies': [
                {
                    'id': d.discrepancy_id,
                    'category': d.category,
                    'description': d.description,
                    'recommended_action': d.recommended_action,
                    'root_cause': d.root_cause_analysis
                }
                for d in critical_discrepancies
            ],
            'automated_fixes': self._generate_automated_fixes(critical_discrepancies),
            'manual_review_required': self._identify_manual_review_items(critical_discrepancies)
        }
        
        # Store correction plan for workflow execution
        self._store_correction_plan(workflow_id, correction_plan)
        
        return workflow_id
    
    def _trigger_major_correction_workflow(self, report: AnalysisReport) -> str:
        """
        Trigger major priority correction workflow.
        
        Args:
            report: Analysis report with major discrepancies
            
        Returns:
            Workflow identifier
        """
        workflow_id = f"major_correction_{report.test_session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Generate correction instructions for major issues
        major_discrepancies = [d for d in report.discrepancies if d.severity == "major"]
        
        correction_plan = {
            'workflow_id': workflow_id,
            'priority': 'major',
            'discrepancies': [
                {
                    'id': d.discrepancy_id,
                    'category': d.category,
                    'description': d.description,
                    'recommended_action': d.recommended_action,
                    'root_cause': d.root_cause_analysis
                }
                for d in major_discrepancies
            ],
            'optimization_recommendations': self._generate_optimization_recommendations(major_discrepancies),
            'implementation_adjustments': self._generate_implementation_adjustments(major_discrepancies)
        }
        
        # Store correction plan for workflow execution
        self._store_correction_plan(workflow_id, correction_plan)
        
        return workflow_id
    
    def _store_report(self, report: AnalysisReport) -> None:
        """
        Store analysis report for future reference and trending.
        
        Args:
            report: Analysis report to store
        """
        report_file = self.report_storage_path / f"{report.report_id}.json"
        
        try:
            with open(report_file, 'w') as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            
            self.logger.info(f"Analysis report stored: {report_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to store analysis report: {e}")
    
    def _store_correction_plan(self, workflow_id: str, correction_plan: Dict[str, Any]) -> None:
        """
        Store correction plan for workflow execution.
        
        Args:
            workflow_id: Unique workflow identifier
            correction_plan: Detailed correction plan
        """
        correction_file = self.report_storage_path / f"correction_{workflow_id}.json"
        
        try:
            with open(correction_file, 'w') as f:
                json.dump(correction_plan, f, indent=2, default=str)
            
            self.logger.info(f"Correction plan stored: {correction_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to store correction plan: {e}")
    
    # Helper methods for analysis
    
    def _remove_timestamp_fields(self, data: Any) -> Any:
        """Remove timestamp fields from response data for comparison."""
        if isinstance(data, dict):
            return {
                k: self._remove_timestamp_fields(v) 
                for k, v in data.items() 
                if k not in ['timestamp', 'created_at', 'updated_at', 'last_modified']
            }
        elif isinstance(data, list):
            return [self._remove_timestamp_fields(item) for item in data]
        return data
    
    def _normalize_generated_ids(self, data: Any) -> Any:
        """Normalize generated IDs for comparison."""
        if isinstance(data, dict):
            normalized = {}
            for k, v in data.items():
                if k in ['id', '_id', 'uuid'] and isinstance(v, (str, int)):
                    normalized[k] = 'NORMALIZED_ID'
                else:
                    normalized[k] = self._normalize_generated_ids(v)
            return normalized
        elif isinstance(data, list):
            return [self._normalize_generated_ids(item) for item in data]
        return data
    
    def _determine_body_diff_severity(self, body_diff: Dict[str, Any]) -> str:
        """Determine severity level for response body differences."""
        if 'values_changed' in body_diff and len(body_diff.get('values_changed', {})) > 5:
            return "major"
        elif 'dictionary_item_added' in body_diff or 'dictionary_item_removed' in body_diff:
            return "major"
        elif 'type_changes' in body_diff:
            return "critical"
        else:
            return "minor"
    
    def _analyze_body_diff_root_cause(self, body_diff: Dict[str, Any]) -> str:
        """Analyze root cause of response body differences."""
        if 'type_changes' in body_diff:
            return "Data type conversion issues between JavaScript and Python"
        elif 'dictionary_item_added' in body_diff:
            return "Additional fields returned by Flask implementation"
        elif 'dictionary_item_removed' in body_diff:
            return "Missing fields in Flask response - potential serialization issue"
        elif 'values_changed' in body_diff:
            return "Different business logic execution or data processing"
        else:
            return "Minor formatting or precision differences"
    
    def _recommend_body_diff_action(self, body_diff: Dict[str, Any]) -> str:
        """Recommend action based on response body differences."""
        if 'type_changes' in body_diff:
            return "Review data type handling in Flask serialization"
        elif 'dictionary_item_added' in body_diff or 'dictionary_item_removed' in body_diff:
            return "Verify Flask model serialization matches Node.js response format"
        elif 'values_changed' in body_diff:
            return "Compare business logic implementation between Node.js and Flask"
        else:
            return "Review response formatting and precision handling"
    
    def _are_error_messages_equivalent(self, node_message: str, flask_message: str) -> bool:
        """Check if error messages are semantically equivalent."""
        if not node_message or not flask_message:
            return False
        
        # Simple semantic equivalence check
        node_lower = node_message.lower()
        flask_lower = flask_message.lower()
        
        # Check for common variations
        variations = [
            ('validation error', 'validation failed'),
            ('not found', 'does not exist'),
            ('unauthorized', 'access denied'),
            ('bad request', 'invalid request')
        ]
        
        for var1, var2 in variations:
            if (var1 in node_lower and var2 in flask_lower) or (var2 in node_lower and var1 in flask_lower):
                return True
        
        return False
    
    def _count_total_comparisons(self, node_js_results: Dict[str, Any], flask_results: Dict[str, Any]) -> int:
        """Count total number of comparisons made."""
        comparisons = 0
        
        # API endpoints
        comparisons += len(set(node_js_results.get('api_responses', {}).keys()) | 
                         set(flask_results.get('api_responses', {}).keys()))
        
        # Database queries
        comparisons += len(set(node_js_results.get('database_results', {}).keys()) | 
                         set(flask_results.get('database_results', {}).keys()))
        
        # Error scenarios
        comparisons += len(set(node_js_results.get('error_responses', {}).keys()) | 
                         set(flask_results.get('error_responses', {}).keys()))
        
        # Performance metrics
        if node_js_results.get('performance_metrics') and flask_results.get('performance_metrics'):
            comparisons += 5  # Response time, memory, CPU, DB queries, throughput
        
        return comparisons
    
    def _determine_migration_status(self, critical_count: int, major_count: int, parity_percentage: float) -> str:
        """Determine overall migration status."""
        if critical_count > 0:
            return "failing"
        elif major_count > 5 or parity_percentage < 85:
            return "warning"
        else:
            return "passing"
    
    def _generate_performance_comparison(self, node_js_results: Dict[str, Any], flask_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate performance comparison summary."""
        node_perf = node_js_results.get('performance_metrics', {})
        flask_perf = flask_results.get('performance_metrics', {})
        
        comparison = {
            'response_time': self._compare_metric_lists(
                node_perf.get('response_times', []),
                flask_perf.get('response_times', [])
            ),
            'memory_usage': self._compare_metrics(
                node_perf.get('memory_usage_mb'),
                flask_perf.get('memory_usage_mb')
            ),
            'database_queries': self._compare_metric_lists(
                node_perf.get('database_query_times', []),
                flask_perf.get('database_query_times', [])
            )
        }
        
        return comparison
    
    def _compare_metric_lists(self, node_values: List[float], flask_values: List[float]) -> Dict[str, Any]:
        """Compare lists of metric values."""
        if not node_values or not flask_values:
            return {'status': 'incomplete_data'}
        
        node_avg = statistics.mean(node_values)
        flask_avg = statistics.mean(flask_values)
        
        return {
            'node_js_average': node_avg,
            'flask_average': flask_avg,
            'difference': flask_avg - node_avg,
            'percentage_change': ((flask_avg - node_avg) / node_avg * 100) if node_avg > 0 else 0,
            'status': 'improved' if flask_avg < node_avg else 'degraded' if flask_avg > node_avg * 1.1 else 'equivalent'
        }
    
    def _compare_metrics(self, node_value: Optional[float], flask_value: Optional[float]) -> Dict[str, Any]:
        """Compare individual metric values."""
        if node_value is None or flask_value is None:
            return {'status': 'incomplete_data'}
        
        return {
            'node_js_value': node_value,
            'flask_value': flask_value,
            'difference': flask_value - node_value,
            'percentage_change': ((flask_value - node_value) / node_value * 100) if node_value > 0 else 0,
            'status': 'improved' if flask_value < node_value else 'degraded' if flask_value > node_value * 1.1 else 'equivalent'
        }
    
    def _generate_detailed_diff(self, node_data: Any, flask_data: Any) -> str:
        """Generate detailed textual diff for response comparison."""
        if not self.config['detailed_diff_enabled']:
            return ""
        
        try:
            node_json = json.dumps(node_data, indent=2, sort_keys=True, default=str)
            flask_json = json.dumps(flask_data, indent=2, sort_keys=True, default=str)
            
            diff_lines = list(unified_diff(
                node_json.splitlines(keepends=True),
                flask_json.splitlines(keepends=True),
                fromfile='node_js_response',
                tofile='flask_response',
                lineterm=''
            ))
            
            return ''.join(diff_lines)
            
        except Exception as e:
            return f"Failed to generate detailed diff: {e}"
    
    def _generate_automated_fixes(self, discrepancies: List[DiscrepancyDetails]) -> List[Dict[str, Any]]:
        """Generate automated fix suggestions for critical discrepancies."""
        fixes = []
        
        for discrepancy in discrepancies:
            if discrepancy.category == "api_response" and "missing_flask" in discrepancy.discrepancy_id:
                fixes.append({
                    'type': 'missing_endpoint',
                    'action': 'create_flask_route',
                    'details': {
                        'endpoint': discrepancy.difference_details.get('endpoint'),
                        'node_js_response': discrepancy.node_js_value
                    }
                })
            elif discrepancy.category == "database" and discrepancy.severity == "critical":
                fixes.append({
                    'type': 'database_query',
                    'action': 'fix_sqlalchemy_query',
                    'details': {
                        'query_id': discrepancy.difference_details.get('query_id'),
                        'expected_result': discrepancy.node_js_value
                    }
                })
        
        return fixes
    
    def _identify_manual_review_items(self, discrepancies: List[DiscrepancyDetails]) -> List[Dict[str, Any]]:
        """Identify items requiring manual review."""
        manual_items = []
        
        for discrepancy in discrepancies:
            if discrepancy.category == "error_handling":
                manual_items.append({
                    'type': 'error_handling_review',
                    'description': discrepancy.description,
                    'recommended_action': discrepancy.recommended_action
                })
            elif "type_changes" in str(discrepancy.difference_details):
                manual_items.append({
                    'type': 'data_type_review',
                    'description': discrepancy.description,
                    'node_js_value': discrepancy.node_js_value,
                    'flask_value': discrepancy.flask_value
                })
        
        return manual_items
    
    def _generate_optimization_recommendations(self, discrepancies: List[DiscrepancyDetails]) -> List[Dict[str, Any]]:
        """Generate optimization recommendations for major discrepancies."""
        recommendations = []
        
        performance_discrepancies = [d for d in discrepancies if d.category == "performance"]
        
        for discrepancy in performance_discrepancies:
            if "response_time" in discrepancy.discrepancy_id:
                recommendations.append({
                    'type': 'performance_optimization',
                    'target': 'response_time',
                    'recommendation': 'Implement query optimization and connection pooling',
                    'expected_improvement': 'Reduce response time by targeting sub-100ms variance'
                })
            elif "database_query" in discrepancy.discrepancy_id:
                recommendations.append({
                    'type': 'database_optimization',
                    'target': 'query_performance',
                    'recommendation': 'Review SQLAlchemy eager loading and query patterns',
                    'expected_improvement': 'Optimize database query execution time'
                })
        
        return recommendations
    
    def _generate_implementation_adjustments(self, discrepancies: List[DiscrepancyDetails]) -> List[Dict[str, Any]]:
        """Generate implementation adjustment recommendations."""
        adjustments = []
        
        api_discrepancies = [d for d in discrepancies if d.category == "api_response"]
        
        for discrepancy in api_discrepancies:
            if "status_code" in discrepancy.discrepancy_id:
                adjustments.append({
                    'type': 'status_code_adjustment',
                    'endpoint': discrepancy.difference_details.get('endpoint'),
                    'current_status': discrepancy.flask_value,
                    'expected_status': discrepancy.node_js_value,
                    'adjustment': 'Update Flask error handler status code mapping'
                })
            elif "headers" in discrepancy.discrepancy_id:
                adjustments.append({
                    'type': 'header_adjustment',
                    'endpoint': discrepancy.difference_details.get('endpoint'),
                    'adjustment': 'Configure Flask response headers to match Node.js baseline'
                })
        
        return adjustments


# Utility functions for pytest integration

def pytest_configure(config):
    """Configure pytest for comparative results analysis."""
    config.addinivalue_line("markers", "comparative: mark test as comparative analysis test")


@pytest.fixture
def results_analyzer():
    """Provide results analyzer fixture for testing."""
    return ComparativeResultsAnalyzer()


@pytest.fixture
def sample_test_results():
    """Provide sample test results for analyzer testing."""
    return {
        'node_js_results': {
            'api_responses': {
                '/api/users': {
                    'status_code': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': {'users': [{'id': 1, 'name': 'John Doe'}]}
                }
            },
            'performance_metrics': {
                'response_times': [45.2, 52.1, 48.9],
                'memory_usage_mb': 128.5,
                'database_query_times': [12.3, 15.6, 11.8]
            },
            'database_results': {
                'user_list_query': {
                    'data': [{'id': 1, 'name': 'John Doe', 'email': 'john@example.com'}],
                    'metadata': {'row_count': 1}
                }
            },
            'error_responses': {
                'invalid_user_id': {
                    'status_code': 404,
                    'message': 'User not found'
                }
            }
        },
        'flask_results': {
            'api_responses': {
                '/api/users': {
                    'status_code': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': {'users': [{'id': 1, 'name': 'John Doe'}]}
                }
            },
            'performance_metrics': {
                'response_times': [48.7, 55.3, 51.2],
                'memory_usage_mb': 135.2,
                'database_query_times': [14.1, 16.8, 13.5]
            },
            'database_results': {
                'user_list_query': {
                    'data': [{'id': 1, 'name': 'John Doe', 'email': 'john@example.com'}],
                    'metadata': {'row_count': 1}
                }
            },
            'error_responses': {
                'invalid_user_id': {
                    'status_code': 404,
                    'message': 'User not found'
                }
            }
        }
    }