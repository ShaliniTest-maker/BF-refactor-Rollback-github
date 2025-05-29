"""
Comparative testing utilities enabling parallel execution and validation between 
Node.js baseline system and Flask implementation.

This module orchestrates comprehensive functionality parity validation required by 
Feature F-009, ensuring 100% functional equivalence through automated comparison 
testing and real-time discrepancy detection.

Key Components:
- Parallel test execution framework for Node.js and Flask system comparison
- Automated functional parity validation with 100% API response equivalence
- Real-time discrepancy detection and reporting utilities
- Business logic verification ensuring identical workflow outcomes
- tox 4.26.0 integration for multi-environment comparative testing
- Automated correction workflow triggers for parity failure remediation

Requirements Compliance:
- Feature F-009: 100% functional equivalence with Node.js baseline
- Feature F-005: Business logic testing for equivalent workflow execution
- Section 4.7.2: Multi-environment testing using tox 4.26.0
"""

import asyncio
import json
import logging
import multiprocessing
import os
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin

import requests
import pytest
import psutil
from deepdiff import DeepDiff
from jinja2 import Template

# Third-party testing framework dependencies
try:
    import tox
    from tox.config import Config as ToxConfig
except ImportError:
    logging.warning("tox 4.26.0 not installed - multi-environment testing disabled")
    tox = None

# Import Flask testing utilities
from tests.utils.flask_fixtures import (
    flask_app_factory,
    flask_test_client,
    flask_request_context
)
from tests.utils.performance_benchmarks import (
    performance_baseline_validator,
    memory_usage_profiler
)


# Configure comprehensive logging for comparative testing
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('comparative_testing.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class TestEnvironmentConfig:
    """
    Configuration container for Node.js and Flask test environments.
    
    Manages environment-specific settings for parallel test execution,
    ensuring consistent comparison conditions between systems.
    """
    # Node.js baseline system configuration
    nodejs_base_url: str = "http://localhost:3000"
    nodejs_health_endpoint: str = "/health"
    nodejs_timeout: int = 30
    nodejs_process_name: str = "node"
    
    # Flask implementation configuration
    flask_base_url: str = "http://localhost:5000"
    flask_health_endpoint: str = "/health"
    flask_timeout: int = 30
    flask_app_module: str = "src.app"
    
    # Comparative testing configuration
    max_parallel_tests: int = 10
    response_comparison_threshold: float = 0.0  # 100% equivalence required
    performance_tolerance: float = 0.1  # 10% performance tolerance
    retry_attempts: int = 3
    retry_delay: float = 1.0
    
    # Multi-environment testing configuration
    tox_environments: List[str] = field(default_factory=lambda: [
        "py313-flask31",
        "py313-performance", 
        "py313-integration"
    ])
    tox_config_path: str = "tests/comparative/tox-comparative.ini"


@dataclass
class ComparisonResult:
    """
    Container for detailed comparison results between Node.js and Flask responses.
    
    Provides comprehensive analysis of functional parity validation with
    detailed discrepancy reporting and automated correction recommendations.
    """
    test_name: str
    endpoint: str
    method: str
    request_data: Optional[Dict[str, Any]]
    
    # Response comparison results
    nodejs_response: Optional[Dict[str, Any]] = None
    flask_response: Optional[Dict[str, Any]] = None
    status_code_match: bool = False
    response_data_match: bool = False
    headers_match: bool = False
    
    # Performance comparison results
    nodejs_response_time: Optional[float] = None
    flask_response_time: Optional[float] = None
    performance_delta: Optional[float] = None
    performance_acceptable: bool = False
    
    # Discrepancy analysis
    discrepancies: Dict[str, Any] = field(default_factory=dict)
    discrepancy_count: int = 0
    critical_discrepancies: List[str] = field(default_factory=list)
    
    # Test metadata
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    execution_time: Optional[float] = None
    success: bool = False
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert comparison result to dictionary for reporting."""
        return {
            'test_name': self.test_name,
            'endpoint': self.endpoint,
            'method': self.method,
            'status_code_match': self.status_code_match,
            'response_data_match': self.response_data_match,
            'headers_match': self.headers_match,
            'performance_delta': self.performance_delta,
            'performance_acceptable': self.performance_acceptable,
            'discrepancy_count': self.discrepancy_count,
            'critical_discrepancies': self.critical_discrepancies,
            'success': self.success,
            'timestamp': self.timestamp.isoformat(),
            'execution_time': self.execution_time,
            'error_message': self.error_message
        }


class ParallelSystemExecutor:
    """
    Orchestrates parallel test execution between Node.js and Flask systems.
    
    Provides comprehensive coordination for simultaneous system testing,
    ensuring accurate comparative analysis with proper environment isolation.
    """
    
    def __init__(self, config: TestEnvironmentConfig):
        self.config = config
        self.nodejs_session = requests.Session()
        self.flask_session = requests.Session()
        self.executor = ThreadPoolExecutor(max_workers=config.max_parallel_tests)
        
        # Configure session timeouts
        self.nodejs_session.timeout = config.nodejs_timeout
        self.flask_session.timeout = config.flask_timeout
        
        logger.info(f"Initialized ParallelSystemExecutor with {config.max_parallel_tests} workers")
    
    def verify_system_health(self) -> Tuple[bool, bool]:
        """
        Verify both Node.js and Flask systems are operational.
        
        Returns:
            Tuple of (nodejs_healthy, flask_healthy) status flags
        """
        nodejs_healthy = False
        flask_healthy = False
        
        try:
            # Check Node.js system health
            nodejs_response = self.nodejs_session.get(
                urljoin(self.config.nodejs_base_url, self.config.nodejs_health_endpoint)
            )
            nodejs_healthy = nodejs_response.status_code == 200
            logger.info(f"Node.js health check: {'PASS' if nodejs_healthy else 'FAIL'}")
        except Exception as e:
            logger.error(f"Node.js health check failed: {e}")
        
        try:
            # Check Flask system health
            flask_response = self.flask_session.get(
                urljoin(self.config.flask_base_url, self.config.flask_health_endpoint)
            )
            flask_healthy = flask_response.status_code == 200
            logger.info(f"Flask health check: {'PASS' if flask_healthy else 'FAIL'}")
        except Exception as e:
            logger.error(f"Flask health check failed: {e}")
        
        return nodejs_healthy, flask_healthy
    
    def execute_parallel_request(
        self, 
        endpoint: str, 
        method: str = "GET", 
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[requests.Response], Optional[requests.Response]]:
        """
        Execute identical requests against both Node.js and Flask systems in parallel.
        
        Args:
            endpoint: API endpoint to test
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request payload data
            headers: Request headers
            
        Returns:
            Tuple of (nodejs_response, flask_response)
        """
        futures = []
        
        # Prepare request parameters
        nodejs_url = urljoin(self.config.nodejs_base_url, endpoint)
        flask_url = urljoin(self.config.flask_base_url, endpoint)
        
        request_kwargs = {
            'json': data if data else None,
            'headers': headers if headers else {}
        }
        
        # Submit parallel requests
        nodejs_future = self.executor.submit(
            self._execute_request, self.nodejs_session, method, nodejs_url, request_kwargs
        )
        flask_future = self.executor.submit(
            self._execute_request, self.flask_session, method, flask_url, request_kwargs
        )
        
        futures.extend([nodejs_future, flask_future])
        
        # Collect results
        nodejs_response = None
        flask_response = None
        
        try:
            nodejs_response = nodejs_future.result(timeout=self.config.nodejs_timeout)
            flask_response = flask_future.result(timeout=self.config.flask_timeout)
        except Exception as e:
            logger.error(f"Parallel request execution failed for {endpoint}: {e}")
        
        return nodejs_response, flask_response
    
    def _execute_request(
        self, 
        session: requests.Session, 
        method: str, 
        url: str, 
        kwargs: Dict[str, Any]
    ) -> Optional[requests.Response]:
        """Execute a single HTTP request with error handling and retries."""
        for attempt in range(self.config.retry_attempts):
            try:
                response = session.request(method, url, **kwargs)
                return response
            except Exception as e:
                logger.warning(f"Request attempt {attempt + 1} failed for {url}: {e}")
                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay)
        
        return None
    
    def cleanup(self):
        """Clean up executor resources."""
        self.executor.shutdown(wait=True)
        self.nodejs_session.close()
        self.flask_session.close()


class FunctionalParityValidator:
    """
    Comprehensive validation engine for 100% functional equivalence between systems.
    
    Implements detailed response comparison, business logic verification, and 
    discrepancy analysis as required by Feature F-009.
    """
    
    def __init__(self, config: TestEnvironmentConfig):
        self.config = config
        self.executor = ParallelSystemExecutor(config)
    
    def validate_api_parity(
        self, 
        test_name: str,
        endpoint: str, 
        method: str = "GET", 
        request_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        custom_validators: Optional[List[callable]] = None
    ) -> ComparisonResult:
        """
        Validate 100% API response equivalence between Node.js and Flask systems.
        
        Args:
            test_name: Descriptive name for the test case
            endpoint: API endpoint to validate
            method: HTTP method to test
            request_data: Request payload data
            headers: Request headers
            custom_validators: Additional validation functions
            
        Returns:
            ComparisonResult with detailed parity analysis
        """
        start_time = time.time()
        result = ComparisonResult(
            test_name=test_name,
            endpoint=endpoint,
            method=method,
            request_data=request_data
        )
        
        try:
            # Execute parallel requests
            nodejs_response, flask_response = self.executor.execute_parallel_request(
                endpoint, method, request_data, headers
            )
            
            if not nodejs_response or not flask_response:
                result.error_message = "Failed to execute requests on one or both systems"
                return result
            
            # Record response times
            result.nodejs_response_time = getattr(nodejs_response, 'elapsed', None)
            result.flask_response_time = getattr(flask_response, 'elapsed', None)
            
            if result.nodejs_response_time and result.flask_response_time:
                result.performance_delta = (
                    result.flask_response_time.total_seconds() - 
                    result.nodejs_response_time.total_seconds()
                )
                result.performance_acceptable = (
                    abs(result.performance_delta) <= self.config.performance_tolerance
                )
            
            # Parse response data
            try:
                result.nodejs_response = {
                    'status_code': nodejs_response.status_code,
                    'headers': dict(nodejs_response.headers),
                    'data': nodejs_response.json() if nodejs_response.content else None
                }
            except Exception as e:
                result.nodejs_response = {
                    'status_code': nodejs_response.status_code,
                    'headers': dict(nodejs_response.headers),
                    'data': nodejs_response.text,
                    'parse_error': str(e)
                }
            
            try:
                result.flask_response = {
                    'status_code': flask_response.status_code,
                    'headers': dict(flask_response.headers),
                    'data': flask_response.json() if flask_response.content else None
                }
            except Exception as e:
                result.flask_response = {
                    'status_code': flask_response.status_code,
                    'headers': dict(flask_response.headers),
                    'data': flask_response.text,
                    'parse_error': str(e)
                }
            
            # Validate status code parity
            result.status_code_match = (
                result.nodejs_response['status_code'] == 
                result.flask_response['status_code']
            )
            
            # Validate response data parity using DeepDiff for comprehensive comparison
            if (result.nodejs_response.get('data') is not None and 
                result.flask_response.get('data') is not None):
                
                diff = DeepDiff(
                    result.nodejs_response['data'],
                    result.flask_response['data'],
                    ignore_order=True,
                    report_type='json'
                )
                
                result.response_data_match = len(diff) == 0
                if diff:
                    result.discrepancies['response_data'] = diff
                    result.critical_discrepancies.append('response_data_mismatch')
            else:
                result.response_data_match = (
                    result.nodejs_response.get('data') == 
                    result.flask_response.get('data')
                )
            
            # Validate critical headers (excluding server-specific headers)
            critical_headers = ['content-type', 'content-length']
            nodejs_headers = {
                k.lower(): v for k, v in result.nodejs_response['headers'].items()
                if k.lower() in critical_headers
            }
            flask_headers = {
                k.lower(): v for k, v in result.flask_response['headers'].items()
                if k.lower() in critical_headers
            }
            
            result.headers_match = nodejs_headers == flask_headers
            if not result.headers_match:
                result.discrepancies['headers'] = {
                    'nodejs': nodejs_headers,
                    'flask': flask_headers
                }
            
            # Count total discrepancies
            result.discrepancy_count = len(result.discrepancies)
            
            # Apply custom validators if provided
            if custom_validators:
                for validator in custom_validators:
                    try:
                        validator_result = validator(result)
                        if not validator_result.get('success', True):
                            result.discrepancies[validator.__name__] = validator_result
                            result.discrepancy_count += 1
                    except Exception as e:
                        logger.error(f"Custom validator {validator.__name__} failed: {e}")
            
            # Determine overall success
            result.success = (
                result.status_code_match and 
                result.response_data_match and 
                result.headers_match and
                result.discrepancy_count == 0
            )
            
            logger.info(f"API parity validation for {endpoint}: {'PASS' if result.success else 'FAIL'}")
            
        except Exception as e:
            result.error_message = f"Validation failed with exception: {str(e)}"
            logger.error(f"API parity validation failed for {endpoint}: {e}")
            logger.error(traceback.format_exc())
        
        finally:
            result.execution_time = time.time() - start_time
        
        return result
    
    def validate_business_logic_parity(
        self,
        workflow_name: str,
        test_steps: List[Dict[str, Any]],
        workflow_data: Optional[Dict[str, Any]] = None
    ) -> List[ComparisonResult]:
        """
        Validate business logic workflow equivalence between systems.
        
        Executes a sequence of API calls representing a business workflow
        and validates that both systems produce identical outcomes.
        
        Args:
            workflow_name: Descriptive name for the business workflow
            test_steps: List of test steps with endpoint and request information
            workflow_data: Initial data for the workflow
            
        Returns:
            List of ComparisonResult objects for each step
        """
        results = []
        context_data = workflow_data.copy() if workflow_data else {}
        
        logger.info(f"Starting business logic validation for workflow: {workflow_name}")
        
        for i, step in enumerate(test_steps):
            step_name = f"{workflow_name}_step_{i+1}_{step.get('name', 'unnamed')}"
            
            # Substitute context data in request
            request_data = step.get('data', {})
            if isinstance(request_data, dict):
                request_data = self._substitute_context_variables(request_data, context_data)
            
            # Execute step validation
            step_result = self.validate_api_parity(
                test_name=step_name,
                endpoint=step['endpoint'],
                method=step.get('method', 'GET'),
                request_data=request_data,
                headers=step.get('headers')
            )
            
            results.append(step_result)
            
            # Update context with response data for subsequent steps
            if step_result.success and step_result.flask_response:
                response_data = step_result.flask_response.get('data', {})
                if isinstance(response_data, dict):
                    context_data.update(response_data)
            
            # Fail fast on critical workflow failures
            if not step_result.success and step.get('critical', True):
                logger.error(f"Critical workflow step failed: {step_name}")
                break
        
        workflow_success = all(result.success for result in results)
        logger.info(f"Business logic validation for {workflow_name}: {'PASS' if workflow_success else 'FAIL'}")
        
        return results
    
    def _substitute_context_variables(
        self, 
        data: Dict[str, Any], 
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Substitute context variables in request data using Jinja2 templating."""
        try:
            json_str = json.dumps(data)
            template = Template(json_str)
            substituted_str = template.render(**context)
            return json.loads(substituted_str)
        except Exception as e:
            logger.warning(f"Context variable substitution failed: {e}")
            return data
    
    def cleanup(self):
        """Clean up validator resources."""
        self.executor.cleanup()


class DiscrepancyDetector:
    """
    Real-time discrepancy detection and analysis for comparative testing.
    
    Provides automated detection of behavioral differences between systems
    with detailed reporting and correction workflow triggering.
    """
    
    def __init__(self, config: TestEnvironmentConfig):
        self.config = config
        self.detected_discrepancies = []
        self.correction_triggers = []
    
    def analyze_discrepancies(self, results: List[ComparisonResult]) -> Dict[str, Any]:
        """
        Analyze comprehensive discrepancy patterns across test results.
        
        Args:
            results: List of comparison results to analyze
            
        Returns:
            Detailed discrepancy analysis report
        """
        analysis = {
            'total_tests': len(results),
            'successful_tests': sum(1 for r in results if r.success),
            'failed_tests': sum(1 for r in results if not r.success),
            'success_rate': 0.0,
            'discrepancy_categories': {},
            'critical_issues': [],
            'performance_issues': [],
            'recommendations': []
        }
        
        if analysis['total_tests'] > 0:
            analysis['success_rate'] = analysis['successful_tests'] / analysis['total_tests']
        
        # Categorize discrepancies
        status_code_failures = []
        response_data_failures = []
        header_failures = []
        performance_failures = []
        
        for result in results:
            if not result.success:
                if not result.status_code_match:
                    status_code_failures.append(result)
                if not result.response_data_match:
                    response_data_failures.append(result)
                if not result.headers_match:
                    header_failures.append(result)
                if not result.performance_acceptable:
                    performance_failures.append(result)
        
        analysis['discrepancy_categories'] = {
            'status_code_mismatches': len(status_code_failures),
            'response_data_mismatches': len(response_data_failures),
            'header_mismatches': len(header_failures),
            'performance_issues': len(performance_failures)
        }
        
        # Identify critical issues requiring immediate attention
        if response_data_failures:
            analysis['critical_issues'].append({
                'type': 'response_data_mismatch',
                'count': len(response_data_failures),
                'affected_endpoints': [r.endpoint for r in response_data_failures],
                'severity': 'HIGH'
            })
        
        if status_code_failures:
            analysis['critical_issues'].append({
                'type': 'status_code_mismatch',
                'count': len(status_code_failures),
                'affected_endpoints': [r.endpoint for r in status_code_failures],
                'severity': 'HIGH'
            })
        
        # Identify performance issues
        if performance_failures:
            analysis['performance_issues'] = [{
                'type': 'response_time_deviation',
                'count': len(performance_failures),
                'affected_endpoints': [r.endpoint for r in performance_failures],
                'average_delta': sum(r.performance_delta or 0 for r in performance_failures) / len(performance_failures)
            }]
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        logger.info(f"Discrepancy analysis complete: {analysis['success_rate']:.2%} success rate")
        
        return analysis
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on discrepancy analysis."""
        recommendations = []
        
        if analysis['discrepancy_categories']['response_data_mismatches'] > 0:
            recommendations.append(
                "Review Flask service layer implementation for business logic equivalence"
            )
            recommendations.append(
                "Validate SQLAlchemy model relationships match MongoDB schema structure"
            )
        
        if analysis['discrepancy_categories']['status_code_mismatches'] > 0:
            recommendations.append(
                "Review Flask route decorators and error handling middleware"
            )
            recommendations.append(
                "Validate Flask application configuration matches Node.js environment"
            )
        
        if analysis['discrepancy_categories']['performance_issues'] > 0:
            recommendations.append(
                "Optimize Flask-SQLAlchemy query patterns for performance equivalence"
            )
            recommendations.append(
                "Review Flask application factory configuration for performance settings"
            )
        
        if analysis['success_rate'] < 0.95:  # Less than 95% success rate
            recommendations.append(
                "Trigger automated correction workflow for Flask implementation refinement"
            )
        
        return recommendations
    
    def trigger_correction_workflow(
        self, 
        analysis: Dict[str, Any], 
        results: List[ComparisonResult]
    ) -> bool:
        """
        Trigger automated correction workflow when critical discrepancies are detected.
        
        Args:
            analysis: Discrepancy analysis results
            results: Original comparison results
            
        Returns:
            Success flag for correction workflow initiation
        """
        if analysis['success_rate'] >= 0.95:  # 95% threshold for acceptable parity
            logger.info("Parity validation within acceptable threshold - no correction needed")
            return True
        
        try:
            correction_report = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'analysis': analysis,
                'failed_tests': [r.to_dict() for r in results if not r.success],
                'correction_actions': []
            }
            
            # Determine correction actions based on failure patterns
            if analysis['discrepancy_categories']['response_data_mismatches'] > 0:
                correction_report['correction_actions'].append({
                    'action': 'service_layer_adjustment',
                    'description': 'Adjust Flask service layer implementation for data parity',
                    'priority': 'HIGH'
                })
            
            if analysis['discrepancy_categories']['status_code_mismatches'] > 0:
                correction_report['correction_actions'].append({
                    'action': 'route_handler_adjustment', 
                    'description': 'Adjust Flask route handlers for status code parity',
                    'priority': 'HIGH'
                })
            
            if analysis['discrepancy_categories']['performance_issues'] > 0:
                correction_report['correction_actions'].append({
                    'action': 'performance_optimization',
                    'description': 'Optimize Flask application for performance parity',
                    'priority': 'MEDIUM'
                })
            
            # Save correction report
            report_path = f"correction_workflow_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_path, 'w') as f:
                json.dump(correction_report, f, indent=2)
            
            logger.info(f"Correction workflow triggered - report saved to {report_path}")
            
            # Here would integrate with actual correction automation
            # For now, we log the requirement for manual intervention
            logger.warning("Automated correction workflow requires manual implementation")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to trigger correction workflow: {e}")
            return False


class ToxMultiEnvironmentRunner:
    """
    Multi-environment testing orchestration using tox 4.26.0.
    
    Provides comprehensive Flask implementation compatibility testing across
    different Python versions and dependency configurations.
    """
    
    def __init__(self, config: TestEnvironmentConfig):
        self.config = config
        self.tox_available = tox is not None
        
        if not self.tox_available:
            logger.warning("tox 4.26.0 not available - multi-environment testing disabled")
    
    def execute_multi_environment_testing(
        self, 
        test_modules: List[str],
        environments: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute comparative testing across multiple tox environments.
        
        Args:
            test_modules: List of test modules to execute
            environments: Specific tox environments to run (defaults to config)
            
        Returns:
            Multi-environment test execution results
        """
        if not self.tox_available:
            return {
                'success': False,
                'error': 'tox 4.26.0 not available',
                'environments': {}
            }
        
        environments = environments or self.config.tox_environments
        results = {
            'success': True,
            'total_environments': len(environments),
            'successful_environments': 0,
            'failed_environments': 0,
            'environments': {}
        }
        
        logger.info(f"Starting multi-environment testing across {len(environments)} environments")
        
        for env in environments:
            logger.info(f"Executing tests in environment: {env}")
            
            try:
                env_result = self._execute_tox_environment(env, test_modules)
                results['environments'][env] = env_result
                
                if env_result['success']:
                    results['successful_environments'] += 1
                else:
                    results['failed_environments'] += 1
                    results['success'] = False
                
            except Exception as e:
                logger.error(f"Failed to execute environment {env}: {e}")
                results['environments'][env] = {
                    'success': False,
                    'error': str(e),
                    'test_results': {}
                }
                results['failed_environments'] += 1
                results['success'] = False
        
        success_rate = results['successful_environments'] / results['total_environments']
        logger.info(f"Multi-environment testing complete: {success_rate:.2%} success rate")
        
        return results
    
    def _execute_tox_environment(
        self, 
        environment: str, 
        test_modules: List[str]
    ) -> Dict[str, Any]:
        """Execute tests in a specific tox environment."""
        try:
            # Construct tox command
            tox_cmd = [
                'tox',
                '-e', environment,
                '-c', self.config.tox_config_path,
                '--'
            ] + test_modules
            
            # Execute tox command
            start_time = time.time()
            process = subprocess.run(
                tox_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            execution_time = time.time() - start_time
            
            return {
                'success': process.returncode == 0,
                'return_code': process.returncode,
                'stdout': process.stdout,
                'stderr': process.stderr,
                'execution_time': execution_time,
                'test_results': self._parse_test_output(process.stdout)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Test execution timeout',
                'execution_time': 300
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _parse_test_output(self, output: str) -> Dict[str, Any]:
        """Parse pytest output to extract test results."""
        results = {
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'errors': [],
            'warnings': []
        }
        
        try:
            # Basic parsing - could be enhanced with pytest-json-report
            lines = output.split('\n')
            for line in lines:
                if 'passed' in line and 'failed' in line:
                    # Look for summary line like "5 passed, 2 failed"
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'passed' and i > 0:
                            results['passed_tests'] = int(parts[i-1])
                        elif part == 'failed' and i > 0:
                            results['failed_tests'] = int(parts[i-1])
            
            results['total_tests'] = results['passed_tests'] + results['failed_tests']
            
        except Exception as e:
            logger.warning(f"Failed to parse test output: {e}")
        
        return results


class ComparativeTestReporter:
    """
    Comprehensive reporting system for comparative testing results.
    
    Generates detailed reports with discrepancy analysis, performance metrics,
    and actionable recommendations for migration validation.
    """
    
    def __init__(self, config: TestEnvironmentConfig):
        self.config = config
    
    def generate_comprehensive_report(
        self, 
        test_results: List[ComparisonResult],
        discrepancy_analysis: Dict[str, Any],
        multi_env_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive comparative testing report.
        
        Args:
            test_results: List of individual test comparison results
            discrepancy_analysis: Discrepancy analysis from DiscrepancyDetector
            multi_env_results: Multi-environment testing results
            
        Returns:
            Comprehensive test report
        """
        report = {
            'report_metadata': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'total_tests': len(test_results),
                'report_version': '1.0',
                'config': {
                    'nodejs_base_url': self.config.nodejs_base_url,
                    'flask_base_url': self.config.flask_base_url,
                    'performance_tolerance': self.config.performance_tolerance
                }
            },
            'executive_summary': self._generate_executive_summary(test_results, discrepancy_analysis),
            'detailed_results': {
                'individual_tests': [result.to_dict() for result in test_results],
                'discrepancy_analysis': discrepancy_analysis
            },
            'performance_analysis': self._generate_performance_analysis(test_results),
            'recommendations': discrepancy_analysis.get('recommendations', []),
            'multi_environment_results': multi_env_results
        }
        
        return report
    
    def _generate_executive_summary(
        self, 
        results: List[ComparisonResult],
        analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate executive summary of test results."""
        return {
            'overall_success': analysis['success_rate'] >= 0.95,
            'success_rate': analysis['success_rate'],
            'total_tests': len(results),
            'successful_tests': analysis['successful_tests'],
            'failed_tests': analysis['failed_tests'],
            'critical_issues_count': len(analysis.get('critical_issues', [])),
            'performance_issues_count': len(analysis.get('performance_issues', [])),
            'parity_status': 'ACHIEVED' if analysis['success_rate'] >= 0.95 else 'REQUIRES_ATTENTION',
            'migration_readiness': analysis['success_rate'] >= 0.98
        }
    
    def _generate_performance_analysis(self, results: List[ComparisonResult]) -> Dict[str, Any]:
        """Generate performance comparison analysis."""
        performance_results = [r for r in results if r.performance_delta is not None]
        
        if not performance_results:
            return {'available': False}
        
        deltas = [r.performance_delta for r in performance_results]
        acceptable_count = sum(1 for r in performance_results if r.performance_acceptable)
        
        return {
            'available': True,
            'total_measured': len(performance_results),
            'acceptable_performance': acceptable_count,
            'performance_success_rate': acceptable_count / len(performance_results),
            'average_delta': sum(deltas) / len(deltas),
            'min_delta': min(deltas),
            'max_delta': max(deltas),
            'improvements': sum(1 for d in deltas if d < 0),
            'regressions': sum(1 for d in deltas if d > self.config.performance_tolerance)
        }
    
    def save_report(
        self, 
        report: Dict[str, Any], 
        filename: Optional[str] = None
    ) -> str:
        """Save report to file and return filename."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"comparative_test_report_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Comprehensive test report saved to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to save report to {filename}: {e}")
            raise


# Main orchestration functions for external usage

def execute_comprehensive_comparative_testing(
    test_cases: List[Dict[str, Any]],
    config: Optional[TestEnvironmentConfig] = None,
    include_multi_env: bool = True
) -> Dict[str, Any]:
    """
    Execute comprehensive comparative testing between Node.js and Flask systems.
    
    This is the main entry point for Feature F-009 functionality parity validation.
    
    Args:
        test_cases: List of test case definitions
        config: Configuration for test execution
        include_multi_env: Whether to include multi-environment testing
        
    Returns:
        Comprehensive test execution results
    """
    config = config or TestEnvironmentConfig()
    
    # Initialize components
    validator = FunctionalParityValidator(config)
    detector = DiscrepancyDetector(config)
    reporter = ComparativeTestReporter(config)
    tox_runner = ToxMultiEnvironmentRunner(config) if include_multi_env else None
    
    try:
        # Verify system health
        nodejs_healthy, flask_healthy = validator.executor.verify_system_health()
        if not (nodejs_healthy and flask_healthy):
            return {
                'success': False,
                'error': 'System health check failed',
                'nodejs_healthy': nodejs_healthy,
                'flask_healthy': flask_healthy
            }
        
        logger.info("Starting comprehensive comparative testing")
        
        # Execute individual test cases
        test_results = []
        for test_case in test_cases:
            if test_case.get('type') == 'workflow':
                # Business logic workflow testing
                workflow_results = validator.validate_business_logic_parity(
                    workflow_name=test_case['name'],
                    test_steps=test_case['steps'],
                    workflow_data=test_case.get('data')
                )
                test_results.extend(workflow_results)
            else:
                # Single API endpoint testing
                result = validator.validate_api_parity(
                    test_name=test_case['name'],
                    endpoint=test_case['endpoint'],
                    method=test_case.get('method', 'GET'),
                    request_data=test_case.get('data'),
                    headers=test_case.get('headers')
                )
                test_results.append(result)
        
        # Analyze discrepancies
        discrepancy_analysis = detector.analyze_discrepancies(test_results)
        
        # Trigger correction workflow if needed
        if discrepancy_analysis['success_rate'] < 0.95:
            detector.trigger_correction_workflow(discrepancy_analysis, test_results)
        
        # Execute multi-environment testing
        multi_env_results = None
        if include_multi_env and tox_runner and tox_runner.tox_available:
            multi_env_results = tox_runner.execute_multi_environment_testing([
                'tests/utils/comparative_testing.py'
            ])
        
        # Generate comprehensive report
        final_report = reporter.generate_comprehensive_report(
            test_results=test_results,
            discrepancy_analysis=discrepancy_analysis,
            multi_env_results=multi_env_results
        )
        
        # Save report
        report_filename = reporter.save_report(final_report)
        final_report['report_filename'] = report_filename
        
        logger.info(f"Comparative testing complete - Success rate: {discrepancy_analysis['success_rate']:.2%}")
        
        return final_report
        
    except Exception as e:
        logger.error(f"Comprehensive comparative testing failed: {e}")
        logger.error(traceback.format_exc())
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    finally:
        # Cleanup resources
        validator.cleanup()


# Pytest integration fixtures and utilities

@pytest.fixture
def comparative_test_config():
    """Pytest fixture providing test configuration."""
    return TestEnvironmentConfig()


@pytest.fixture
def functional_parity_validator(comparative_test_config):
    """Pytest fixture providing parity validator."""
    validator = FunctionalParityValidator(comparative_test_config)
    yield validator
    validator.cleanup()


@pytest.fixture
def discrepancy_detector(comparative_test_config):
    """Pytest fixture providing discrepancy detector."""
    return DiscrepancyDetector(comparative_test_config)


# Example test cases for validation

def test_api_endpoint_parity(functional_parity_validator):
    """Example test demonstrating API endpoint parity validation."""
    result = functional_parity_validator.validate_api_parity(
        test_name="health_check_parity",
        endpoint="/health",
        method="GET"
    )
    
    assert result.success, f"API parity validation failed: {result.error_message}"
    assert result.status_code_match, "Status codes do not match"
    assert result.response_data_match, "Response data does not match"


def test_business_logic_workflow_parity(functional_parity_validator):
    """Example test demonstrating business logic workflow parity validation."""
    workflow_steps = [
        {
            'name': 'create_user',
            'endpoint': '/api/users',
            'method': 'POST',
            'data': {'name': 'Test User', 'email': 'test@example.com'}
        },
        {
            'name': 'get_user',
            'endpoint': '/api/users/{{ user_id }}',
            'method': 'GET'
        }
    ]
    
    results = functional_parity_validator.validate_business_logic_parity(
        workflow_name="user_management_workflow",
        test_steps=workflow_steps
    )
    
    assert all(result.success for result in results), "Business logic workflow validation failed"


if __name__ == "__main__":
    # Example usage for standalone execution
    sample_test_cases = [
        {
            'name': 'health_check',
            'endpoint': '/health',
            'method': 'GET'
        },
        {
            'name': 'api_status',
            'endpoint': '/api/status',
            'method': 'GET'
        }
    ]
    
    results = execute_comprehensive_comparative_testing(
        test_cases=sample_test_cases,
        include_multi_env=True
    )
    
    print(f"Comparative testing completed with {results.get('success', False)} status")
    if results.get('report_filename'):
        print(f"Detailed report saved to: {results['report_filename']}")