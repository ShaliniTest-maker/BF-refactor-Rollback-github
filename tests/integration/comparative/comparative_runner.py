#!/usr/bin/env python3
"""
Comparative Testing Orchestration Runner

This module provides comprehensive orchestration for comparative testing between Node.js and Flask 
implementations, ensuring 100% functional parity validation during the migration process. 

The runner coordinates parallel system testing, manages environment setup/teardown, executes 
automated test sequencing, and generates consolidated comparison reports for migration validation.

Technical Specification Compliance:
- Section 4.7.2: Multi-environment testing orchestration using tox 4.26.0
- Section 8.4: CI/CD pipeline integration for automated comparative testing
- Feature F-009: Functionality parity validation with comprehensive testing
- Section 2.2.9: API endpoint testing and business logic validation

Dependencies:
- tox 4.26.0: Multi-environment testing orchestration
- pytest-flask 1.3.0: Flask application testing fixtures
- pytest-benchmark 5.1.0: Performance benchmarking capabilities
- Flask 3.1.1: Flask ecosystem integration testing
"""

import os
import sys
import json
import time
import logging
import argparse
import subprocess
import threading
import concurrent.futures
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# Import testing framework dependencies
import pytest
import tox
from tox.config import parseconfig
from tox.session import Session

# Import specialized testing utilities
from deepdiff import DeepDiff
import jsoncompare
import psutil
import memory_profiler

# Import Flask testing dependencies
try:
    from tests.integration.comparative.conftest_comparative import (
        ComparativeTestFixtures,
        NodeJSSystemConnector,
        FlaskTestEnvironment
    )
    from tests.integration.comparative.baseline_capture import BaselineCapture
    from tests.integration.comparative.results_analyzer import ResultsAnalyzer
except ImportError as e:
    logging.warning(f"Comparative testing modules not yet available: {e}")


class TestCategory(Enum):
    """Test categories for systematic execution sequencing."""
    API = "api"
    PERFORMANCE = "performance" 
    WORKFLOWS = "workflows"
    DATABASE = "database"
    AUTHENTICATION = "auth"
    ALL = "all"


class TestResult(Enum):
    """Test execution results for validation tracking."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class TestExecutionReport:
    """Comprehensive test execution report structure."""
    test_category: str
    execution_time: float
    result: TestResult
    node_js_baseline: Optional[Dict[str, Any]]
    flask_results: Optional[Dict[str, Any]]
    discrepancies: Optional[List[Dict[str, Any]]]
    performance_metrics: Optional[Dict[str, Any]]
    error_details: Optional[str]
    timestamp: str


@dataclass
class ComparativeTestSession:
    """Comparative testing session configuration and state."""
    session_id: str
    test_categories: List[TestCategory]
    tox_environments: List[str]
    parallel_execution: bool
    baseline_refresh: bool
    correction_workflow_enabled: bool
    ci_cd_mode: bool
    reports_directory: Path
    start_time: datetime
    end_time: Optional[datetime] = None
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    execution_reports: List[TestExecutionReport] = None
    
    def __post_init__(self):
        if self.execution_reports is None:
            self.execution_reports = []


class ComparativeTestRunner:
    """
    Orchestration controller for comprehensive comparative testing between Node.js and Flask 
    implementations using tox 4.26.0 multi-environment testing coordination.
    
    This class manages the complete testing lifecycle including:
    - Environment setup and teardown for both Node.js and Flask systems
    - Parallel test execution coordination across multiple environments
    - Automated test sequencing for systematic validation coverage
    - Real-time discrepancy detection and automated correction workflows
    - Consolidated reporting with migration status tracking
    - CI/CD pipeline integration for automated testing
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the comparative testing orchestration runner.
        
        Args:
            config_path: Optional path to comparative testing configuration file
        """
        self.logger = self._setup_logging()
        self.config_path = config_path or Path("tests/integration/comparative/tox-comparative.ini")
        self.base_directory = Path(__file__).parent.parent.parent.parent
        self.reports_directory = self.base_directory / "reports" / "comparative"
        self.reports_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize testing infrastructure components
        self.tox_config = None
        self.baseline_capture = None
        self.results_analyzer = None
        self.test_fixtures = None
        
        # Session state management
        self.current_session: Optional[ComparativeTestSession] = None
        self.nodejs_system_ready = False
        self.flask_system_ready = False
        
        # Performance monitoring
        self.resource_monitor = psutil.Process()
        self.memory_profiler_enabled = True
        
        # Initialize core components
        self._initialize_testing_infrastructure()
        
    def _setup_logging(self) -> logging.Logger:
        """Configure comprehensive logging for test orchestration tracking."""
        logger = logging.getLogger("comparative_runner")
        logger.setLevel(logging.INFO)
        
        # Create formatters for different log levels
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        
        # Console handler for real-time output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(detailed_formatter)
        logger.addHandler(console_handler)
        
        # File handler for detailed logging
        log_file = self.base_directory / "logs" / "comparative_testing.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
        
        return logger
        
    def _initialize_testing_infrastructure(self) -> None:
        """Initialize tox configuration and testing infrastructure components."""
        try:
            # Load tox configuration for multi-environment testing
            if self.config_path.exists():
                self.logger.info(f"Loading tox configuration from {self.config_path}")
                self.tox_config = parseconfig(["-c", str(self.config_path)])
            else:
                self.logger.warning(f"Tox configuration not found at {self.config_path}, using default")
                self.tox_config = parseconfig([])
                
            # Initialize specialized testing components
            try:
                self.baseline_capture = BaselineCapture()
                self.results_analyzer = ResultsAnalyzer()
                self.test_fixtures = ComparativeTestFixtures()
                self.logger.info("Testing infrastructure components initialized successfully")
            except ImportError:
                self.logger.warning("Some testing components not available, will create mock implementations")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize testing infrastructure: {e}")
            raise
            
    def create_test_session(
        self,
        test_categories: List[TestCategory] = None,
        tox_environments: List[str] = None,
        parallel_execution: bool = True,
        baseline_refresh: bool = False,
        correction_workflow_enabled: bool = True,
        ci_cd_mode: bool = False
    ) -> ComparativeTestSession:
        """
        Create a new comparative testing session with specified configuration.
        
        Args:
            test_categories: List of test categories to execute (default: all)
            tox_environments: List of tox environments for multi-environment testing
            parallel_execution: Enable parallel execution of Node.js and Flask tests
            baseline_refresh: Refresh Node.js baseline data before testing
            correction_workflow_enabled: Enable automated correction workflows
            ci_cd_mode: Enable CI/CD pipeline integration mode
            
        Returns:
            Configured comparative testing session
        """
        if test_categories is None:
            test_categories = [TestCategory.ALL]
            
        if tox_environments is None:
            tox_environments = ["py313-flask311", "py313-comparative"]
            
        session_id = f"comparative_test_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        
        session = ComparativeTestSession(
            session_id=session_id,
            test_categories=test_categories,
            tox_environments=tox_environments,
            parallel_execution=parallel_execution,
            baseline_refresh=baseline_refresh,
            correction_workflow_enabled=correction_workflow_enabled,
            ci_cd_mode=ci_cd_mode,
            reports_directory=self.reports_directory / session_id,
            start_time=datetime.now(timezone.utc)
        )
        
        # Create session reports directory
        session.reports_directory.mkdir(parents=True, exist_ok=True)
        
        self.current_session = session
        self.logger.info(f"Created comparative testing session: {session_id}")
        
        return session
        
    def setup_test_environments(self) -> bool:
        """
        Setup and validate both Node.js and Flask testing environments.
        
        Returns:
            True if both environments are ready for testing
        """
        self.logger.info("Setting up comparative testing environments...")
        
        setup_success = True
        
        # Setup Node.js baseline environment
        try:
            self._setup_nodejs_environment()
            self.nodejs_system_ready = True
            self.logger.info("Node.js baseline environment ready")
        except Exception as e:
            self.logger.error(f"Failed to setup Node.js environment: {e}")
            setup_success = False
            
        # Setup Flask testing environment using tox
        try:
            self._setup_flask_environment()
            self.flask_system_ready = True
            self.logger.info("Flask testing environment ready")
        except Exception as e:
            self.logger.error(f"Failed to setup Flask environment: {e}")
            setup_success = False
            
        if setup_success:
            self.logger.info("Both testing environments ready for comparative testing")
        else:
            self.logger.error("Environment setup failed - comparative testing cannot proceed")
            
        return setup_success
        
    def _setup_nodejs_environment(self) -> None:
        """Setup Node.js baseline system for comparative testing."""
        try:
            # Validate Node.js system availability
            result = subprocess.run(
                ["node", "--version"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise RuntimeError("Node.js runtime not available")
                
            self.logger.info(f"Node.js version: {result.stdout.strip()}")
            
            # Setup Node.js application if baseline capture is enabled
            if self.baseline_capture:
                self.baseline_capture.setup_nodejs_connection()
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("Node.js environment setup timed out")
        except Exception as e:
            raise RuntimeError(f"Node.js environment setup failed: {e}")
            
    def _setup_flask_environment(self) -> None:
        """Setup Flask testing environment using tox multi-environment orchestration."""
        try:
            # Validate tox configuration
            if not self.tox_config:
                raise RuntimeError("Tox configuration not available")
                
            # Create tox session for environment management
            tox_session = Session(self.tox_config)
            
            # Validate required environments are available
            available_envs = list(tox_session.config.envconfigs.keys())
            required_envs = self.current_session.tox_environments if self.current_session else ["py313-flask311"]
            
            missing_envs = [env for env in required_envs if env not in available_envs]
            if missing_envs:
                self.logger.warning(f"Missing tox environments: {missing_envs}")
                
            self.logger.info(f"Available tox environments: {available_envs}")
            
        except Exception as e:
            raise RuntimeError(f"Flask environment setup failed: {e}")
            
    def execute_comparative_testing(self, session: ComparativeTestSession) -> Dict[str, Any]:
        """
        Execute comprehensive comparative testing with automated sequencing and reporting.
        
        Args:
            session: Configured comparative testing session
            
        Returns:
            Comprehensive testing results with discrepancy analysis
        """
        self.logger.info(f"Starting comparative testing session: {session.session_id}")
        
        # Refresh baseline data if requested
        if session.baseline_refresh and self.baseline_capture:
            self.logger.info("Refreshing Node.js baseline data...")
            try:
                self.baseline_capture.refresh_baseline_data()
            except Exception as e:
                self.logger.error(f"Baseline refresh failed: {e}")
                
        # Execute test categories in systematic sequence
        test_results = {}
        
        for category in session.test_categories:
            if category == TestCategory.ALL:
                # Execute all test categories systematically
                all_categories = [
                    TestCategory.API,
                    TestCategory.DATABASE, 
                    TestCategory.WORKFLOWS,
                    TestCategory.AUTHENTICATION,
                    TestCategory.PERFORMANCE
                ]
                
                for test_category in all_categories:
                    result = self._execute_test_category(test_category, session)
                    test_results[test_category.value] = result
            else:
                result = self._execute_test_category(category, session)
                test_results[category.value] = result
                
        # Generate consolidated test report
        session.end_time = datetime.now(timezone.utc)
        consolidated_report = self._generate_consolidated_report(session, test_results)
        
        # Trigger correction workflows if discrepancies detected
        if session.correction_workflow_enabled:
            self._trigger_correction_workflows(consolidated_report)
            
        self.logger.info(f"Comparative testing session completed: {session.session_id}")
        
        return consolidated_report
        
    def _execute_test_category(
        self, 
        category: TestCategory, 
        session: ComparativeTestSession
    ) -> TestExecutionReport:
        """
        Execute comparative testing for a specific test category.
        
        Args:
            category: Test category to execute
            session: Current testing session
            
        Returns:
            Test execution report with comparative results
        """
        self.logger.info(f"Executing {category.value} comparative testing...")
        
        start_time = time.time()
        test_file_mapping = {
            TestCategory.API: "tests/integration/comparative/test_comparative_api.py",
            TestCategory.PERFORMANCE: "tests/integration/comparative/test_comparative_performance.py",
            TestCategory.WORKFLOWS: "tests/integration/comparative/test_comparative_workflows.py",
            TestCategory.DATABASE: "tests/integration/comparative/test_comparative_database.py",
            TestCategory.AUTHENTICATION: "tests/integration/comparative/test_comparative_auth.py"
        }
        
        test_file = test_file_mapping.get(category)
        if not test_file:
            return self._create_error_report(category, "Test file not mapped", start_time)
            
        try:
            # Execute tests using tox for multi-environment validation
            if session.parallel_execution:
                results = self._execute_parallel_testing(test_file, session)
            else:
                results = self._execute_sequential_testing(test_file, session)
                
            # Analyze results for discrepancies
            discrepancies = self._analyze_test_discrepancies(results)
            
            # Create execution report
            execution_time = time.time() - start_time
            report = TestExecutionReport(
                test_category=category.value,
                execution_time=execution_time,
                result=TestResult.PASSED if not discrepancies else TestResult.FAILED,
                node_js_baseline=results.get("nodejs_baseline"),
                flask_results=results.get("flask_results"),
                discrepancies=discrepancies,
                performance_metrics=results.get("performance_metrics"),
                error_details=None,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
            session.execution_reports.append(report)
            session.total_tests += 1
            
            if report.result == TestResult.PASSED:
                session.passed_tests += 1
                self.logger.info(f"{category.value} testing PASSED")
            else:
                session.failed_tests += 1
                self.logger.warning(f"{category.value} testing FAILED with {len(discrepancies)} discrepancies")
                
            return report
            
        except Exception as e:
            self.logger.error(f"{category.value} testing failed with error: {e}")
            return self._create_error_report(category, str(e), start_time)
            
    def _execute_parallel_testing(
        self, 
        test_file: str, 
        session: ComparativeTestSession
    ) -> Dict[str, Any]:
        """
        Execute parallel testing across Node.js and Flask systems using concurrent execution.
        
        Args:
            test_file: Path to test file for execution
            session: Current testing session
            
        Returns:
            Combined test results from both systems
        """
        self.logger.info(f"Executing parallel testing: {test_file}")
        
        results = {
            "nodejs_baseline": None,
            "flask_results": None,
            "performance_metrics": {}
        }
        
        # Use ThreadPoolExecutor for parallel execution coordination
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            
            # Submit Node.js baseline execution
            nodejs_future = executor.submit(self._execute_nodejs_baseline_tests, test_file)
            
            # Submit Flask testing execution  
            flask_future = executor.submit(self._execute_flask_tests, test_file, session)
            
            # Collect results from parallel execution
            try:
                results["nodejs_baseline"] = nodejs_future.result(timeout=300)  # 5 minute timeout
                self.logger.info("Node.js baseline testing completed")
            except concurrent.futures.TimeoutError:
                self.logger.error("Node.js baseline testing timed out")
            except Exception as e:
                self.logger.error(f"Node.js baseline testing failed: {e}")
                
            try:
                flask_result = flask_future.result(timeout=300)  # 5 minute timeout
                results["flask_results"] = flask_result["test_results"]
                results["performance_metrics"] = flask_result["performance_metrics"]
                self.logger.info("Flask testing completed")
            except concurrent.futures.TimeoutError:
                self.logger.error("Flask testing timed out")
            except Exception as e:
                self.logger.error(f"Flask testing failed: {e}")
                
        return results
        
    def _execute_sequential_testing(
        self, 
        test_file: str, 
        session: ComparativeTestSession
    ) -> Dict[str, Any]:
        """
        Execute sequential testing for systematic validation coverage.
        
        Args:
            test_file: Path to test file for execution
            session: Current testing session
            
        Returns:
            Sequential test results with baseline comparison
        """
        self.logger.info(f"Executing sequential testing: {test_file}")
        
        results = {
            "nodejs_baseline": None,
            "flask_results": None,
            "performance_metrics": {}
        }
        
        # Execute Node.js baseline tests first
        try:
            results["nodejs_baseline"] = self._execute_nodejs_baseline_tests(test_file)
            self.logger.info("Node.js baseline testing completed")
        except Exception as e:
            self.logger.error(f"Node.js baseline testing failed: {e}")
            
        # Execute Flask tests with baseline comparison
        try:
            flask_result = self._execute_flask_tests(test_file, session)
            results["flask_results"] = flask_result["test_results"]
            results["performance_metrics"] = flask_result["performance_metrics"]
            self.logger.info("Flask testing completed")
        except Exception as e:
            self.logger.error(f"Flask testing failed: {e}")
            
        return results
        
    def _execute_nodejs_baseline_tests(self, test_file: str) -> Dict[str, Any]:
        """
        Execute Node.js baseline tests for comparative reference data.
        
        Args:
            test_file: Test file path for execution
            
        Returns:
            Node.js baseline test results
        """
        if self.baseline_capture:
            return self.baseline_capture.capture_baseline_for_test(test_file)
        else:
            # Mock baseline data for development
            return {
                "test_file": test_file,
                "results": {"mock": "nodejs_baseline_data"},
                "performance": {"response_time": 100, "memory_usage": 50}
            }
            
    def _execute_flask_tests(
        self, 
        test_file: str, 
        session: ComparativeTestSession
    ) -> Dict[str, Any]:
        """
        Execute Flask tests using tox multi-environment orchestration.
        
        Args:
            test_file: Test file path for execution
            session: Current testing session
            
        Returns:
            Flask test results with performance metrics
        """
        results = {
            "test_results": None,
            "performance_metrics": {}
        }
        
        # Monitor resource usage during testing
        start_memory = self.resource_monitor.memory_info().rss
        start_time = time.time()
        
        try:
            # Execute tests using tox for each configured environment
            for tox_env in session.tox_environments:
                self.logger.info(f"Executing Flask tests in environment: {tox_env}")
                
                # Build tox command for test execution
                tox_cmd = [
                    "tox",
                    "-e", tox_env,
                    "--",
                    test_file,
                    "-v",
                    "--tb=short"
                ]
                
                if session.ci_cd_mode:
                    tox_cmd.extend(["--junit-xml", f"{session.reports_directory}/{tox_env}_results.xml"])
                    
                # Execute tox command
                result = subprocess.run(
                    tox_cmd,
                    cwd=self.base_directory,
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 minute timeout
                )
                
                if result.returncode == 0:
                    self.logger.info(f"Flask tests passed in environment: {tox_env}")
                    results["test_results"] = {
                        "environment": tox_env,
                        "status": "passed",
                        "output": result.stdout
                    }
                else:
                    self.logger.warning(f"Flask tests failed in environment: {tox_env}")
                    results["test_results"] = {
                        "environment": tox_env,
                        "status": "failed",
                        "output": result.stdout,
                        "error": result.stderr
                    }
                    
        except subprocess.TimeoutExpired:
            self.logger.error("Flask test execution timed out")
            results["test_results"] = {"status": "timeout"}
        except Exception as e:
            self.logger.error(f"Flask test execution failed: {e}")
            results["test_results"] = {"status": "error", "error": str(e)}
            
        # Calculate performance metrics
        end_time = time.time()
        end_memory = self.resource_monitor.memory_info().rss
        
        results["performance_metrics"] = {
            "execution_time": end_time - start_time,
            "memory_usage_delta": end_memory - start_memory,
            "peak_memory": max(start_memory, end_memory)
        }
        
        return results
        
    def _analyze_test_discrepancies(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze test results for discrepancies between Node.js and Flask implementations.
        
        Args:
            results: Combined test results from both systems
            
        Returns:
            List of detected discrepancies with analysis details
        """
        discrepancies = []
        
        if not results.get("nodejs_baseline") or not results.get("flask_results"):
            return [{"type": "missing_results", "description": "Incomplete test results for comparison"}]
            
        try:
            # Use results analyzer if available
            if self.results_analyzer:
                discrepancies = self.results_analyzer.analyze_discrepancies(
                    results["nodejs_baseline"],
                    results["flask_results"]
                )
            else:
                # Basic discrepancy detection
                nodejs_data = results["nodejs_baseline"]
                flask_data = results["flask_results"]
                
                # Compare basic result status
                if nodejs_data.get("status") != flask_data.get("status"):
                    discrepancies.append({
                        "type": "status_mismatch",
                        "description": f"Status mismatch: NodeJS={nodejs_data.get('status')}, Flask={flask_data.get('status')}"
                    })
                    
                # Compare performance metrics if available
                if "performance" in nodejs_data and "performance_metrics" in results:
                    nodejs_perf = nodejs_data["performance"]
                    flask_perf = results["performance_metrics"]
                    
                    # Check response time difference (allow 20% variance)
                    if "response_time" in nodejs_perf and "execution_time" in flask_perf:
                        time_diff = abs(flask_perf["execution_time"] - nodejs_perf["response_time"])
                        if time_diff > nodejs_perf["response_time"] * 0.2:
                            discrepancies.append({
                                "type": "performance_regression",
                                "description": f"Response time variance: {time_diff:.2f}s"
                            })
                            
        except Exception as e:
            self.logger.error(f"Discrepancy analysis failed: {e}")
            discrepancies.append({
                "type": "analysis_error",
                "description": f"Failed to analyze discrepancies: {e}"
            })
            
        return discrepancies
        
    def _create_error_report(
        self, 
        category: TestCategory, 
        error_message: str, 
        start_time: float
    ) -> TestExecutionReport:
        """Create error report for failed test execution."""
        return TestExecutionReport(
            test_category=category.value,
            execution_time=time.time() - start_time,
            result=TestResult.ERROR,
            node_js_baseline=None,
            flask_results=None,
            discrepancies=None,
            performance_metrics=None,
            error_details=error_message,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
    def _generate_consolidated_report(
        self, 
        session: ComparativeTestSession,
        test_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate comprehensive consolidated report with migration status tracking.
        
        Args:
            session: Completed testing session
            test_results: All test execution results
            
        Returns:
            Consolidated comparative testing report
        """
        total_execution_time = (session.end_time - session.start_time).total_seconds()
        
        # Calculate parity percentage
        parity_percentage = (session.passed_tests / session.total_tests * 100) if session.total_tests > 0 else 0
        
        # Aggregate all discrepancies
        all_discrepancies = []
        for report in session.execution_reports:
            if report.discrepancies:
                all_discrepancies.extend(report.discrepancies)
                
        # Create consolidated report
        consolidated_report = {
            "session_id": session.session_id,
            "execution_summary": {
                "start_time": session.start_time.isoformat(),
                "end_time": session.end_time.isoformat(),
                "total_execution_time": total_execution_time,
                "total_tests": session.total_tests,
                "passed_tests": session.passed_tests,
                "failed_tests": session.failed_tests,
                "parity_percentage": parity_percentage
            },
            "migration_status": {
                "functional_parity": parity_percentage >= 100.0,
                "ready_for_deployment": parity_percentage >= 100.0 and len(all_discrepancies) == 0,
                "critical_issues": len([d for d in all_discrepancies if d.get("type") in ["api_contract_violation", "data_integrity_issue"]]),
                "performance_regressions": len([d for d in all_discrepancies if d.get("type") == "performance_regression"])
            },
            "test_category_results": {
                report.test_category: {
                    "result": report.result.value,
                    "execution_time": report.execution_time,
                    "discrepancy_count": len(report.discrepancies) if report.discrepancies else 0
                }
                for report in session.execution_reports
            },
            "discrepancy_analysis": {
                "total_discrepancies": len(all_discrepancies),
                "discrepancy_types": self._categorize_discrepancies(all_discrepancies),
                "detailed_discrepancies": all_discrepancies
            },
            "performance_analysis": self._aggregate_performance_metrics(session.execution_reports),
            "recommendations": self._generate_recommendations(session, all_discrepancies)
        }
        
        # Save consolidated report
        report_file = session.reports_directory / "consolidated_report.json"
        with open(report_file, 'w') as f:
            json.dump(consolidated_report, f, indent=2, default=str)
            
        self.logger.info(f"Consolidated report saved: {report_file}")
        
        return consolidated_report
        
    def _categorize_discrepancies(self, discrepancies: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize discrepancies by type for analysis."""
        categories = {}
        for discrepancy in discrepancies:
            disc_type = discrepancy.get("type", "unknown")
            categories[disc_type] = categories.get(disc_type, 0) + 1
        return categories
        
    def _aggregate_performance_metrics(self, reports: List[TestExecutionReport]) -> Dict[str, Any]:
        """Aggregate performance metrics across all test reports."""
        total_execution_time = sum(report.execution_time for report in reports)
        
        # Extract performance data where available
        performance_data = []
        for report in reports:
            if report.performance_metrics:
                performance_data.append(report.performance_metrics)
                
        return {
            "total_test_execution_time": total_execution_time,
            "average_test_execution_time": total_execution_time / len(reports) if reports else 0,
            "performance_data_points": len(performance_data),
            "aggregated_metrics": performance_data
        }
        
    def _generate_recommendations(
        self, 
        session: ComparativeTestSession,
        discrepancies: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate actionable recommendations based on testing results."""
        recommendations = []
        
        if session.failed_tests > 0:
            recommendations.append(
                f"Review and resolve {session.failed_tests} failed test categories before deployment"
            )
            
        critical_discrepancies = [d for d in discrepancies if d.get("type") in ["api_contract_violation", "data_integrity_issue"]]
        if critical_discrepancies:
            recommendations.append(
                f"Address {len(critical_discrepancies)} critical discrepancies that could impact production"
            )
            
        performance_issues = [d for d in discrepancies if d.get("type") == "performance_regression"]
        if performance_issues:
            recommendations.append(
                f"Optimize Flask implementation to resolve {len(performance_issues)} performance regressions"
            )
            
        if session.passed_tests == session.total_tests and not discrepancies:
            recommendations.append("All tests passed with no discrepancies - Flask implementation ready for deployment")
            
        return recommendations
        
    def _trigger_correction_workflows(self, consolidated_report: Dict[str, Any]) -> None:
        """
        Trigger automated correction workflows when parity failures are detected.
        
        Args:
            consolidated_report: Consolidated test report with discrepancy analysis
        """
        critical_issues = consolidated_report["migration_status"]["critical_issues"]
        
        if critical_issues > 0:
            self.logger.warning(f"Triggering correction workflow for {critical_issues} critical issues")
            
            # Log correction workflow details
            correction_log = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "trigger": "critical_discrepancies_detected",
                "critical_issues": critical_issues,
                "total_discrepancies": consolidated_report["discrepancy_analysis"]["total_discrepancies"],
                "session_id": consolidated_report["session_id"]
            }
            
            correction_file = self.reports_directory / "correction_workflows.log"
            with open(correction_file, 'a') as f:
                f.write(json.dumps(correction_log) + "\n")
                
            # In a full implementation, this would trigger automated correction scripts
            self.logger.info("Correction workflow triggered - review discrepancy analysis for required fixes")
        else:
            self.logger.info("No critical issues detected - correction workflow not required")
            
    def cleanup_test_environments(self) -> None:
        """Cleanup and teardown testing environments after execution."""
        self.logger.info("Cleaning up testing environments...")
        
        try:
            # Cleanup tox environments
            if self.current_session:
                for tox_env in self.current_session.tox_environments:
                    cleanup_cmd = ["tox", "-e", tox_env, "--recreate"]
                    subprocess.run(cleanup_cmd, capture_output=True, timeout=60)
                    
            self.logger.info("Environment cleanup completed")
            
        except Exception as e:
            self.logger.warning(f"Environment cleanup failed: {e}")
            
    def generate_ci_cd_artifacts(self, session: ComparativeTestSession) -> Dict[str, Path]:
        """
        Generate CI/CD pipeline artifacts for automated testing integration.
        
        Args:
            session: Completed testing session
            
        Returns:
            Dictionary of generated artifact file paths
        """
        artifacts = {}
        
        # Generate JUnit XML for CI/CD integration
        junit_file = session.reports_directory / "junit_results.xml"
        self._generate_junit_xml(session, junit_file)
        artifacts["junit_xml"] = junit_file
        
        # Generate pipeline status file
        pipeline_status = {
            "status": "passed" if session.failed_tests == 0 else "failed",
            "total_tests": session.total_tests,
            "passed_tests": session.passed_tests,
            "failed_tests": session.failed_tests,
            "session_id": session.session_id
        }
        
        status_file = session.reports_directory / "pipeline_status.json"
        with open(status_file, 'w') as f:
            json.dump(pipeline_status, f, indent=2)
        artifacts["pipeline_status"] = status_file
        
        self.logger.info(f"CI/CD artifacts generated: {list(artifacts.keys())}")
        
        return artifacts
        
    def _generate_junit_xml(self, session: ComparativeTestSession, output_file: Path) -> None:
        """Generate JUnit XML format test results for CI/CD integration."""
        # Simplified JUnit XML generation
        # In a full implementation, this would create proper XML structure
        junit_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="ComparativeTesting" tests="{session.total_tests}" failures="{session.failed_tests}" time="{(session.end_time - session.start_time).total_seconds()}">
"""
        
        for report in session.execution_reports:
            test_status = "failure" if report.result == TestResult.FAILED else ""
            junit_content += f'  <testcase name="{report.test_category}" time="{report.execution_time}" {test_status}>\n'
            if report.result == TestResult.FAILED and report.discrepancies:
                junit_content += f'    <failure message="Discrepancies detected">{len(report.discrepancies)} discrepancies found</failure>\n'
            junit_content += "  </testcase>\n"
            
        junit_content += "</testsuite>"
        
        with open(output_file, 'w') as f:
            f.write(junit_content)


def main():
    """
    Main entry point for comparative testing orchestration.
    
    Supports command-line execution with configurable parameters for different testing scenarios.
    """
    parser = argparse.ArgumentParser(description="Comparative Testing Orchestration Runner")
    
    parser.add_argument(
        "--test-categories",
        nargs="+",
        choices=[cat.value for cat in TestCategory],
        default=["all"],
        help="Test categories to execute"
    )
    
    parser.add_argument(
        "--tox-environments",
        nargs="+",
        default=["py313-flask311", "py313-comparative"],
        help="Tox environments for multi-environment testing"
    )
    
    parser.add_argument(
        "--parallel",
        action="store_true",
        default=True,
        help="Enable parallel execution of Node.js and Flask tests"
    )
    
    parser.add_argument(
        "--baseline-refresh",
        action="store_true",
        help="Refresh Node.js baseline data before testing"
    )
    
    parser.add_argument(
        "--no-correction-workflow",
        action="store_true",
        help="Disable automated correction workflows"
    )
    
    parser.add_argument(
        "--ci-cd-mode",
        action="store_true",
        help="Enable CI/CD pipeline integration mode"
    )
    
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to comparative testing configuration file"
    )
    
    args = parser.parse_args()
    
    # Convert string test categories to enums
    test_categories = [TestCategory(cat) for cat in args.test_categories]
    
    try:
        # Initialize comparative testing runner
        runner = ComparativeTestRunner(config_path=args.config)
        
        # Setup testing environments
        if not runner.setup_test_environments():
            sys.exit(1)
            
        # Create testing session
        session = runner.create_test_session(
            test_categories=test_categories,
            tox_environments=args.tox_environments,
            parallel_execution=args.parallel,
            baseline_refresh=args.baseline_refresh,
            correction_workflow_enabled=not args.no_correction_workflow,
            ci_cd_mode=args.ci_cd_mode
        )
        
        # Execute comparative testing
        results = runner.execute_comparative_testing(session)
        
        # Generate CI/CD artifacts if in CI/CD mode
        if args.ci_cd_mode:
            artifacts = runner.generate_ci_cd_artifacts(session)
            print(f"CI/CD artifacts generated: {artifacts}")
            
        # Cleanup environments
        runner.cleanup_test_environments()
        
        # Print summary
        print(f"\nComparative Testing Summary:")
        print(f"Session ID: {session.session_id}")
        print(f"Total Tests: {session.total_tests}")
        print(f"Passed: {session.passed_tests}")
        print(f"Failed: {session.failed_tests}")
        print(f"Parity Percentage: {results['execution_summary']['parity_percentage']:.1f}%")
        
        # Exit with appropriate code
        sys.exit(0 if session.failed_tests == 0 else 1)
        
    except KeyboardInterrupt:
        print("\nComparative testing interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Comparative testing failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()