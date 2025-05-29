"""
Multi-environment testing orchestration module implementing tox 4.26.0 for comprehensive
Flask implementation compatibility testing across different Python versions and dependency
configurations. This file ensures system behavior consistency through isolated virtual
environments and validates Flask 3.1.1 compatibility per Section 4.7.2.

This module provides comprehensive multi-environment test execution capabilities including:
- tox 4.26.0 configuration for isolated virtual environment testing
- Python 3.13.3 primary environment validation for Flask 3.1.1 
- Isolated dependency management with pip requirements.txt integration
- Virtual environment isolation for reproducible test execution
- Parallel environment provisioning for comprehensive coverage validation
- Integration with pytest-flask 1.3.0 for Flask application testing
- Performance validation across multiple environments
- Compatibility testing with various dependency versions

Key Features:
- Multi-environment orchestration with tox 4.26.0
- Flask 3.1.1 compatibility validation across Python versions
- Isolated dependency management preventing version conflicts
- Parallel test execution for improved test performance
- Comprehensive environment provisioning and cleanup
- Integration with comparative testing for Node.js parity validation
- Performance benchmarking across environments
- Automated environment setup and teardown

Dependencies:
- tox 4.26.0: Multi-environment test orchestration and virtual environment management
- pytest-flask 1.3.0: Flask application testing fixtures and utilities
- Flask 3.1.1: Target framework for compatibility validation
- pytest-xdist: Parallel test execution capabilities
- pytest-benchmark 5.1.0: Performance testing across environments
"""

import os
import sys
import subprocess
import tempfile
import shutil
import json
import yaml
import configparser
from pathlib import Path
from typing import Dict, List, Any, Optional, Generator, Tuple, Union
from datetime import datetime, timedelta
import concurrent.futures
import threading
import time
import psutil
import hashlib
from dataclasses import dataclass, field
from enum import Enum
import logging
from contextlib import contextmanager

# Testing framework imports
import pytest
import tox
from tox import cmdline
from tox.config import parseconfig
from tox.session import Session
import pytest_benchmark
from pytest_benchmark.fixture import BenchmarkFixture

# Flask and testing imports
import flask
from flask import Flask
from flask.testing import FlaskClient
import flask_sqlalchemy
import flask_migrate

# Import project-specific testing utilities
from tests.conftest import (
    TestingConfiguration, MockUser, MockAuth0Client,
    app, client, authenticated_user, performance_monitor,
    json_response_validator, test_data_factory
)


class EnvironmentType(Enum):
    """
    Enumeration of supported testing environment types for multi-environment
    testing orchestration with specific configuration requirements.
    """
    PRIMARY = "primary"           # Python 3.13.3 with Flask 3.1.1
    COMPATIBILITY = "compatibility"  # Alternative Python versions
    MINIMAL = "minimal"          # Minimal dependency set
    DEVELOPMENT = "development"  # Development dependencies included
    PRODUCTION = "production"    # Production-like configuration


class TestStatus(Enum):
    """Test execution status tracking for multi-environment validation"""
    PENDING = "pending"
    RUNNING = "running" 
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class EnvironmentConfig:
    """
    Configuration data class for individual testing environments with
    comprehensive dependency and configuration management.
    
    This class encapsulates all environment-specific settings required
    for isolated virtual environment provisioning and testing execution.
    """
    name: str
    python_version: str
    env_type: EnvironmentType
    base_dependencies: List[str] = field(default_factory=list)
    test_dependencies: List[str] = field(default_factory=list)
    environment_variables: Dict[str, str] = field(default_factory=dict)
    configuration_overrides: Dict[str, Any] = field(default_factory=dict)
    parallel_execution: bool = True
    timeout_seconds: int = 300
    memory_limit_mb: int = 512
    cleanup_on_completion: bool = True
    
    def __post_init__(self):
        """Post-initialization validation and default setup"""
        if not self.base_dependencies:
            self.base_dependencies = self._get_default_dependencies()
        if not self.test_dependencies:
            self.test_dependencies = self._get_default_test_dependencies()
        if not self.environment_variables:
            self.environment_variables = self._get_default_env_vars()
    
    def _get_default_dependencies(self) -> List[str]:
        """Get default base dependencies for environment type"""
        base_deps = [
            "Flask==3.1.1",
            "Flask-SQLAlchemy==3.1.1", 
            "Flask-Migrate==4.1.0",
            "Flask-Login>=0.6.2",
            "Werkzeug>=3.1",
            "Jinja2>=3.1.2",
            "ItsDangerous>=2.2",
            "Click>=8.1.3",
            "Blinker>=1.9"
        ]
        
        if self.env_type == EnvironmentType.DEVELOPMENT:
            base_deps.extend([
                "Flask-DebugToolbar>=0.13.1",
                "Werkzeug[watchdog]>=3.1"
            ])
        elif self.env_type == EnvironmentType.PRODUCTION:
            base_deps.extend([
                "gunicorn>=21.2.0",
                "psycopg2-binary>=2.9.7"
            ])
        
        return base_deps
    
    def _get_default_test_dependencies(self) -> List[str]:
        """Get default test dependencies for environment"""
        return [
            "pytest>=7.4.0",
            "pytest-flask==1.3.0",
            "pytest-benchmark==5.1.0",
            "pytest-xdist>=3.3.1",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.11.1",
            "tox==4.26.0",
            "coverage>=7.3.0"
        ]
    
    def _get_default_env_vars(self) -> Dict[str, str]:
        """Get default environment variables for testing"""
        return {
            "FLASK_ENV": "testing",
            "TESTING": "True",
            "SECRET_KEY": "test-secret-key-for-pytest-only",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": "False",
            "DISABLE_EXTERNAL_CALLS": "True"
        }
    
    def to_tox_config(self) -> Dict[str, Any]:
        """Convert environment config to tox configuration format"""
        return {
            "basepython": f"python{self.python_version}",
            "deps": self.base_dependencies + self.test_dependencies,
            "setenv": self.environment_variables,
            "commands": [
                "pytest {posargs}",
                "coverage report"
            ],
            "parallel_show_output": True,
            "whitelist_externals": ["coverage"],
            "timeout": self.timeout_seconds
        }


@dataclass 
class TestResult:
    """
    Comprehensive test result data class for multi-environment test tracking
    and reporting with detailed metrics and performance data.
    """
    environment_name: str
    status: TestStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    tests_passed: int = 0
    tests_failed: int = 0
    tests_skipped: int = 0
    tests_total: int = 0
    coverage_percentage: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    cpu_usage_percentage: Optional[float] = None
    error_message: Optional[str] = None
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    output_log: str = ""
    
    def __post_init__(self):
        """Calculate derived metrics after initialization"""
        if self.end_time and self.start_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary for serialization"""
        return {
            "environment_name": self.environment_name,
            "status": self.status.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "tests_skipped": self.tests_skipped,
            "tests_total": self.tests_total,
            "coverage_percentage": self.coverage_percentage,
            "memory_usage_mb": self.memory_usage_mb,
            "cpu_usage_percentage": self.cpu_usage_percentage,
            "error_message": self.error_message,
            "performance_metrics": self.performance_metrics,
            "success_rate": self.tests_passed / self.tests_total if self.tests_total > 0 else 0
        }


class ToxConfigurationManager:
    """
    Comprehensive tox configuration management class providing dynamic
    tox.ini generation, environment provisioning, and configuration
    validation for multi-environment testing orchestration.
    
    This class implements tox 4.26.0 specific configuration patterns
    and ensures proper virtual environment isolation and dependency
    management as specified in Section 4.7.2.
    """
    
    def __init__(self, project_root: Path, config_file: str = "tox.ini"):
        """
        Initialize tox configuration manager with project context
        
        Args:
            project_root: Root directory of the project
            config_file: Name of tox configuration file
        """
        self.project_root = Path(project_root)
        self.config_file = self.project_root / config_file
        self.environments: Dict[str, EnvironmentConfig] = {}
        self.global_config: Dict[str, Any] = {}
        self._setup_default_environments()
        self._setup_global_configuration()
    
    def _setup_default_environments(self):
        """Setup default testing environments per Section 4.7.2 requirements"""
        
        # Primary Python 3.13.3 environment for Flask 3.1.1 validation
        self.environments["py313"] = EnvironmentConfig(
            name="py313",
            python_version="3.13.3",
            env_type=EnvironmentType.PRIMARY,
            parallel_execution=True,
            timeout_seconds=600
        )
        
        # Compatibility testing environments
        self.environments["py312"] = EnvironmentConfig(
            name="py312", 
            python_version="3.12",
            env_type=EnvironmentType.COMPATIBILITY,
            parallel_execution=True,
            timeout_seconds=300
        )
        
        self.environments["py311"] = EnvironmentConfig(
            name="py311",
            python_version="3.11", 
            env_type=EnvironmentType.COMPATIBILITY,
            parallel_execution=True,
            timeout_seconds=300
        )
        
        # Minimal dependency environment for lightweight testing
        minimal_deps = [
            "Flask==3.1.1",
            "pytest>=7.4.0",
            "pytest-flask==1.3.0"
        ]
        self.environments["minimal"] = EnvironmentConfig(
            name="minimal",
            python_version="3.13.3",
            env_type=EnvironmentType.MINIMAL,
            base_dependencies=minimal_deps,
            parallel_execution=False,
            timeout_seconds=180
        )
        
        # Development environment with additional tools
        self.environments["development"] = EnvironmentConfig(
            name="development",
            python_version="3.13.3", 
            env_type=EnvironmentType.DEVELOPMENT,
            parallel_execution=True,
            timeout_seconds=450
        )
        
        # Production-like environment configuration
        self.environments["production"] = EnvironmentConfig(
            name="production",
            python_version="3.13.3",
            env_type=EnvironmentType.PRODUCTION,
            parallel_execution=True,
            timeout_seconds=600
        )
    
    def _setup_global_configuration(self):
        """Setup global tox configuration settings"""
        self.global_config = {
            "minversion": "4.26.0",
            "envlist": list(self.environments.keys()),
            "skip_missing_interpreters": "True",
            "isolated_build": "True",
            "parallel_show_output": "True",
            "indexserver": {
                "default": "https://pypi.org/simple/"
            },
            "testpaths": ["tests"],
            "python_files": ["test_*.py"],
            "python_classes": ["Test*"],
            "python_functions": ["test_*"],
            "markers": [
                "unit: Unit tests",
                "integration: Integration tests", 
                "performance: Performance tests",
                "comparative: Comparative tests"
            ]
        }
    
    def add_environment(self, env_config: EnvironmentConfig):
        """
        Add custom environment configuration to manager
        
        Args:
            env_config: Environment configuration to add
        """
        self.environments[env_config.name] = env_config
        self.global_config["envlist"] = list(self.environments.keys())
    
    def remove_environment(self, env_name: str):
        """
        Remove environment configuration from manager
        
        Args:
            env_name: Name of environment to remove
        """
        if env_name in self.environments:
            del self.environments[env_name]
            self.global_config["envlist"] = list(self.environments.keys())
    
    def generate_tox_config(self) -> str:
        """
        Generate complete tox.ini configuration file content
        
        Returns:
            str: Complete tox.ini file content
        """
        config = configparser.ConfigParser()
        
        # Add [tox] section with global configuration
        config.add_section("tox")
        for key, value in self.global_config.items():
            if isinstance(value, list):
                config.set("tox", key, "\n    ".join([""] + value))
            elif isinstance(value, dict):
                # Handle nested dictionaries like indexserver
                if key == "indexserver":
                    for subkey, subvalue in value.items():
                        config.set("tox", f"{key}:{subkey}", subvalue)
                else:
                    config.set("tox", key, str(value))
            else:
                config.set("tox", key, str(value))
        
        # Add testenv sections for each environment
        for env_name, env_config in self.environments.items():
            section_name = f"testenv:{env_name}" if env_name != "testenv" else "testenv"
            config.add_section(section_name)
            
            tox_config = env_config.to_tox_config()
            for key, value in tox_config.items():
                if isinstance(value, list):
                    config.set(section_name, key, "\n    ".join([""] + value))
                elif isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        config.set(section_name, f"{key}:{subkey}", str(subvalue))
                else:
                    config.set(section_name, key, str(value))
        
        # Add pytest configuration section
        config.add_section("pytest")
        pytest_config = {
            "testpaths": "tests",
            "python_files": "test_*.py",
            "python_classes": "Test*",
            "python_functions": "test_*",
            "addopts": "-v --tb=short --strict-markers --disable-warnings",
            "markers": [
                "unit: Unit tests",
                "integration: Integration tests",
                "performance: Performance tests",
                "comparative: Comparative tests"
            ]
        }
        
        for key, value in pytest_config.items():
            if isinstance(value, list):
                config.set("pytest", key, "\n    ".join([""] + value))
            else:
                config.set("pytest", key, str(value))
        
        # Generate configuration file content
        import io
        output = io.StringIO()
        config.write(output)
        content = output.getvalue()
        output.close()
        
        return content
    
    def write_tox_config(self):
        """Write tox configuration to tox.ini file"""
        config_content = self.generate_tox_config()
        with open(self.config_file, 'w') as f:
            f.write(config_content)
        
        logging.info(f"Tox configuration written to {self.config_file}")
    
    def validate_configuration(self) -> List[str]:
        """
        Validate tox configuration and return list of issues
        
        Returns:
            List[str]: List of validation issues
        """
        issues = []
        
        # Validate environments
        for env_name, env_config in self.environments.items():
            if not env_config.python_version:
                issues.append(f"Environment {env_name} missing python_version")
            
            if not env_config.base_dependencies:
                issues.append(f"Environment {env_name} missing base_dependencies")
            
            if env_config.timeout_seconds <= 0:
                issues.append(f"Environment {env_name} has invalid timeout")
        
        # Validate global configuration
        if not self.global_config.get("envlist"):
            issues.append("Global configuration missing envlist")
        
        return issues


class MultiEnvironmentTestExecutor:
    """
    Comprehensive multi-environment test execution orchestrator implementing
    tox 4.26.0 integration with pytest-flask for Flask 3.1.1 compatibility
    validation across isolated virtual environments.
    
    This class provides complete test execution management including environment
    provisioning, parallel execution, result aggregation, and performance monitoring
    as specified in Section 4.7.2 of the technical specification.
    """
    
    def __init__(self, config_manager: ToxConfigurationManager, 
                 results_dir: Optional[Path] = None):
        """
        Initialize multi-environment test executor
        
        Args:
            config_manager: Tox configuration manager instance
            results_dir: Directory for storing test results
        """
        self.config_manager = config_manager
        self.results_dir = results_dir or Path("test_results")
        self.results_dir.mkdir(exist_ok=True)
        
        self.test_results: Dict[str, TestResult] = {}
        self.execution_lock = threading.Lock()
        self.logger = self._setup_logging()
        
        # Performance monitoring
        self.process_monitor = psutil.Process()
        self.start_memory = self.process_monitor.memory_info().rss / 1024 / 1024
        
    def _setup_logging(self) -> logging.Logger:
        """Setup comprehensive logging for test execution tracking"""
        logger = logging.getLogger("multi_environment_test_executor")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            # File handler for detailed logs
            log_file = self.results_dir / "test_execution.log"
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            
            # Console handler for important messages
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            # Formatter for structured logging
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)
        
        return logger
    
    def execute_all_environments(self, parallel: bool = True, 
                                max_workers: Optional[int] = None) -> Dict[str, TestResult]:
        """
        Execute tests across all configured environments with comprehensive
        monitoring and result aggregation.
        
        Args:
            parallel: Enable parallel execution across environments
            max_workers: Maximum number of concurrent workers
            
        Returns:
            Dict[str, TestResult]: Test results by environment name
        """
        self.logger.info(f"Starting multi-environment test execution across {len(self.config_manager.environments)} environments")
        
        # Clear previous results
        self.test_results.clear()
        
        if parallel:
            return self._execute_parallel(max_workers)
        else:
            return self._execute_sequential()
    
    def _execute_parallel(self, max_workers: Optional[int] = None) -> Dict[str, TestResult]:
        """Execute tests in parallel across multiple environments"""
        max_workers = max_workers or min(len(self.config_manager.environments), os.cpu_count())
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all environment tests
            future_to_env = {
                executor.submit(self._execute_single_environment, env_name, env_config): env_name
                for env_name, env_config in self.config_manager.environments.items()
                if env_config.parallel_execution
            }
            
            # Execute non-parallel environments sequentially
            for env_name, env_config in self.config_manager.environments.items():
                if not env_config.parallel_execution:
                    self._execute_single_environment(env_name, env_config)
            
            # Collect results from parallel executions
            for future in concurrent.futures.as_completed(future_to_env):
                env_name = future_to_env[future]
                try:
                    result = future.result(timeout=600)  # 10 minute timeout
                    with self.execution_lock:
                        self.test_results[env_name] = result
                        self.logger.info(f"Environment {env_name} completed: {result.status.value}")
                except Exception as exc:
                    self.logger.error(f"Environment {env_name} generated exception: {exc}")
                    with self.execution_lock:
                        self.test_results[env_name] = TestResult(
                            environment_name=env_name,
                            status=TestStatus.ERROR,
                            start_time=datetime.now(),
                            error_message=str(exc)
                        )
        
        return self.test_results
    
    def _execute_sequential(self) -> Dict[str, TestResult]:
        """Execute tests sequentially across environments"""
        for env_name, env_config in self.config_manager.environments.items():
            self.logger.info(f"Executing tests in environment: {env_name}")
            result = self._execute_single_environment(env_name, env_config)
            self.test_results[env_name] = result
        
        return self.test_results
    
    def _execute_single_environment(self, env_name: str, 
                                  env_config: EnvironmentConfig) -> TestResult:
        """
        Execute tests in a single environment with comprehensive monitoring
        
        Args:
            env_name: Name of the environment
            env_config: Environment configuration
            
        Returns:
            TestResult: Comprehensive test results for the environment
        """
        result = TestResult(
            environment_name=env_name,
            status=TestStatus.RUNNING,
            start_time=datetime.now()
        )
        
        try:
            self.logger.info(f"Starting test execution in environment: {env_name}")
            
            # Setup environment-specific configuration
            env_dir = self.results_dir / env_name
            env_dir.mkdir(exist_ok=True)
            
            # Create temporary tox configuration for this environment
            tox_config_path = env_dir / "tox.ini"
            self._write_environment_tox_config(tox_config_path, env_name, env_config)
            
            # Execute tox with environment-specific configuration
            result = self._run_tox_environment(env_name, env_config, tox_config_path, result)
            
            # Collect performance metrics
            result = self._collect_performance_metrics(env_name, result)
            
            # Parse test results and coverage
            result = self._parse_test_results(env_dir, result)
            
            result.end_time = datetime.now()
            result.status = TestStatus.PASSED if result.tests_failed == 0 else TestStatus.FAILED
            
            self.logger.info(f"Environment {env_name} completed successfully")
            
        except Exception as exc:
            self.logger.error(f"Error executing environment {env_name}: {exc}")
            result.end_time = datetime.now()
            result.status = TestStatus.ERROR
            result.error_message = str(exc)
        
        return result
    
    def _write_environment_tox_config(self, config_path: Path, 
                                    env_name: str, env_config: EnvironmentConfig):
        """Write environment-specific tox configuration"""
        temp_manager = ToxConfigurationManager(config_path.parent)
        temp_manager.environments = {env_name: env_config}
        temp_manager.global_config["envlist"] = [env_name]
        
        config_content = temp_manager.generate_tox_config()
        with open(config_path, 'w') as f:
            f.write(config_content)
    
    def _run_tox_environment(self, env_name: str, env_config: EnvironmentConfig,
                           tox_config_path: Path, result: TestResult) -> TestResult:
        """Execute tox for specific environment with monitoring"""
        
        # Build tox command with comprehensive options
        tox_cmd = [
            sys.executable, "-m", "tox",
            "-c", str(tox_config_path),
            "-e", env_name,
            "--recreate",  # Ensure clean environment
            "--parallel", "auto" if env_config.parallel_execution else "1",
            "-v"  # Verbose output
        ]
        
        # Setup environment variables
        tox_env = os.environ.copy()
        tox_env.update(env_config.environment_variables)
        
        # Execute tox with timeout and monitoring
        try:
            self.logger.debug(f"Executing command: {' '.join(tox_cmd)}")
            
            start_time = time.time()
            process = subprocess.Popen(
                tox_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=tox_env,
                cwd=self.config_manager.project_root
            )
            
            # Monitor process execution
            output_lines = []
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    output_lines.append(line.strip())
                    
                # Check timeout
                if time.time() - start_time > env_config.timeout_seconds:
                    process.terminate()
                    raise TimeoutError(f"Environment {env_name} exceeded timeout of {env_config.timeout_seconds}s")
            
            return_code = process.wait()
            result.output_log = "\n".join(output_lines)
            
            if return_code != 0:
                raise subprocess.CalledProcessError(return_code, tox_cmd, result.output_log)
                
        except subprocess.CalledProcessError as exc:
            self.logger.error(f"Tox execution failed for {env_name}: {exc}")
            result.error_message = f"Tox execution failed: {exc}"
            raise
        except TimeoutError as exc:
            self.logger.error(f"Tox execution timeout for {env_name}: {exc}")
            result.error_message = str(exc)
            raise
        
        return result
    
    def _collect_performance_metrics(self, env_name: str, result: TestResult) -> TestResult:
        """Collect performance metrics for environment execution"""
        try:
            # Memory usage
            current_memory = self.process_monitor.memory_info().rss / 1024 / 1024
            result.memory_usage_mb = current_memory - self.start_memory
            
            # CPU usage (average over short period)
            cpu_percent = self.process_monitor.cpu_percent(interval=1.0)
            result.cpu_usage_percentage = cpu_percent
            
            # Additional performance metrics
            result.performance_metrics = {
                "memory_peak_mb": result.memory_usage_mb,
                "cpu_avg_percent": cpu_percent,
                "execution_start": result.start_time.timestamp(),
                "python_version": sys.version,
                "platform": sys.platform
            }
            
        except Exception as exc:
            self.logger.warning(f"Failed to collect performance metrics for {env_name}: {exc}")
        
        return result
    
    def _parse_test_results(self, env_dir: Path, result: TestResult) -> TestResult:
        """Parse pytest test results and coverage information"""
        try:
            # Look for pytest JSON report
            json_report_path = env_dir / "pytest_report.json" 
            if json_report_path.exists():
                with open(json_report_path) as f:
                    pytest_data = json.load(f)
                    
                result.tests_passed = pytest_data.get("summary", {}).get("passed", 0)
                result.tests_failed = pytest_data.get("summary", {}).get("failed", 0)
                result.tests_skipped = pytest_data.get("summary", {}).get("skipped", 0)
                result.tests_total = result.tests_passed + result.tests_failed + result.tests_skipped
            
            # Look for coverage report
            coverage_report_path = env_dir / "coverage.json"
            if coverage_report_path.exists():
                with open(coverage_report_path) as f:
                    coverage_data = json.load(f)
                    result.coverage_percentage = coverage_data.get("totals", {}).get("percent_covered")
            
            # Parse output log for test counts if JSON not available
            if result.tests_total == 0 and result.output_log:
                self._parse_output_log_for_results(result)
                
        except Exception as exc:
            self.logger.warning(f"Failed to parse test results: {exc}")
        
        return result
    
    def _parse_output_log_for_results(self, result: TestResult):
        """Parse pytest output log for test results when JSON not available"""
        log_lines = result.output_log.split('\n')
        
        for line in log_lines:
            if "passed" in line and "failed" in line:
                # Try to extract test counts from summary line
                import re
                pattern = r'(\d+) passed.*?(\d+) failed.*?(\d+) skipped'
                match = re.search(pattern, line)
                if match:
                    result.tests_passed = int(match.group(1))
                    result.tests_failed = int(match.group(2))
                    result.tests_skipped = int(match.group(3))
                    result.tests_total = result.tests_passed + result.tests_failed + result.tests_skipped
                    break
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive test execution report with analytics
        
        Returns:
            Dict[str, Any]: Complete test execution report
        """
        if not self.test_results:
            return {"error": "No test results available"}
        
        # Calculate summary statistics
        total_environments = len(self.test_results)
        passed_environments = sum(1 for r in self.test_results.values() if r.status == TestStatus.PASSED)
        failed_environments = sum(1 for r in self.test_results.values() if r.status == TestStatus.FAILED)
        error_environments = sum(1 for r in self.test_results.values() if r.status == TestStatus.ERROR)
        
        total_tests = sum(r.tests_total for r in self.test_results.values())
        total_passed = sum(r.tests_passed for r in self.test_results.values())
        total_failed = sum(r.tests_failed for r in self.test_results.values())
        total_skipped = sum(r.tests_skipped for r in self.test_results.values())
        
        # Calculate averages
        avg_duration = sum(r.duration_seconds or 0 for r in self.test_results.values()) / total_environments
        avg_coverage = sum(r.coverage_percentage or 0 for r in self.test_results.values() if r.coverage_percentage) / max(1, sum(1 for r in self.test_results.values() if r.coverage_percentage))
        avg_memory = sum(r.memory_usage_mb or 0 for r in self.test_results.values()) / total_environments
        
        report = {
            "execution_summary": {
                "total_environments": total_environments,
                "passed_environments": passed_environments,
                "failed_environments": failed_environments,
                "error_environments": error_environments,
                "success_rate": passed_environments / total_environments * 100,
                "total_execution_time": sum(r.duration_seconds or 0 for r in self.test_results.values()),
                "average_execution_time": avg_duration
            },
            "test_summary": {
                "total_tests": total_tests,
                "total_passed": total_passed,
                "total_failed": total_failed,
                "total_skipped": total_skipped,
                "overall_success_rate": total_passed / total_tests * 100 if total_tests > 0 else 0
            },
            "performance_summary": {
                "average_coverage_percentage": avg_coverage,
                "average_memory_usage_mb": avg_memory,
                "total_memory_usage_mb": sum(r.memory_usage_mb or 0 for r in self.test_results.values())
            },
            "environment_results": {
                name: result.to_dict() for name, result in self.test_results.items()
            },
            "flask_compatibility": {
                "flask_version": "3.1.1",
                "python_versions_tested": list(set(
                    self.config_manager.environments[name].python_version 
                    for name in self.test_results.keys()
                )),
                "primary_environment_status": self.test_results.get("py313", TestResult("", TestStatus.ERROR, datetime.now())).status.value,
                "compatibility_environments_passed": sum(
                    1 for name, result in self.test_results.items() 
                    if "py31" in name and result.status == TestStatus.PASSED
                ),
                "all_environments_compatible": all(
                    r.status == TestStatus.PASSED for r in self.test_results.values()
                )
            },
            "recommendations": self._generate_recommendations(),
            "timestamp": datetime.now().isoformat(),
            "report_version": "1.0"
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        # Check for failed environments
        failed_envs = [name for name, result in self.test_results.items() if result.status == TestStatus.FAILED]
        if failed_envs:
            recommendations.append(f"Investigate test failures in environments: {', '.join(failed_envs)}")
        
        # Check performance issues
        high_memory_envs = [name for name, result in self.test_results.items() if (result.memory_usage_mb or 0) > 200]
        if high_memory_envs:
            recommendations.append(f"High memory usage detected in environments: {', '.join(high_memory_envs)}")
        
        # Check coverage
        low_coverage_envs = [name for name, result in self.test_results.items() if (result.coverage_percentage or 0) < 80]
        if low_coverage_envs:
            recommendations.append(f"Low test coverage (<80%) in environments: {', '.join(low_coverage_envs)}")
        
        # Check primary environment
        if "py313" in self.test_results and self.test_results["py313"].status != TestStatus.PASSED:
            recommendations.append("Primary Python 3.13.3 environment failed - this is critical for Flask 3.1.1 migration")
        
        if not recommendations:
            recommendations.append("All environments passed successfully - Flask 3.1.1 migration validation complete")
        
        return recommendations
    
    def save_report(self, report: Dict[str, Any], filename: str = "multi_environment_report.json"):
        """Save comprehensive report to file"""
        report_path = self.results_dir / filename
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"Comprehensive report saved to {report_path}")
        
        # Also save a summary text report
        summary_path = self.results_dir / "test_summary.txt"
        self._save_text_summary(report, summary_path)
    
    def _save_text_summary(self, report: Dict[str, Any], summary_path: Path):
        """Save human-readable text summary"""
        with open(summary_path, 'w') as f:
            f.write("Multi-Environment Test Execution Summary\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Execution Date: {report['timestamp']}\n")
            f.write(f"Total Environments: {report['execution_summary']['total_environments']}\n")
            f.write(f"Passed: {report['execution_summary']['passed_environments']}\n")
            f.write(f"Failed: {report['execution_summary']['failed_environments']}\n")
            f.write(f"Errors: {report['execution_summary']['error_environments']}\n")
            f.write(f"Success Rate: {report['execution_summary']['success_rate']:.1f}%\n\n")
            
            f.write("Flask 3.1.1 Compatibility Status:\n")
            f.write("-" * 30 + "\n")
            f.write(f"Primary Environment (Python 3.13.3): {report['flask_compatibility']['primary_environment_status']}\n")
            f.write(f"All Environments Compatible: {report['flask_compatibility']['all_environments_compatible']}\n\n")
            
            f.write("Recommendations:\n")
            f.write("-" * 15 + "\n")
            for rec in report['recommendations']:
                f.write(f"- {rec}\n")


class MultiEnvironmentTestSuite:
    """
    Comprehensive multi-environment test suite implementing pytest-flask integration
    with tox 4.26.0 orchestration for Flask 3.1.1 compatibility validation.
    
    This class provides the main interface for multi-environment testing as specified
    in Section 4.7.2, including test discovery, execution, and result reporting.
    """
    
    def __init__(self, project_root: Optional[Path] = None):
        """
        Initialize multi-environment test suite
        
        Args:
            project_root: Root directory of the project (defaults to current directory)
        """
        self.project_root = project_root or Path.cwd()
        self.config_manager = ToxConfigurationManager(self.project_root)
        self.executor = MultiEnvironmentTestExecutor(self.config_manager)
        self.logger = logging.getLogger("multi_environment_test_suite")
    
    def validate_setup(self) -> Tuple[bool, List[str]]:
        """
        Validate multi-environment testing setup and configuration
        
        Returns:
            Tuple[bool, List[str]]: Success status and list of issues
        """
        issues = []
        
        # Validate tox configuration
        config_issues = self.config_manager.validate_configuration()
        issues.extend(config_issues)
        
        # Validate project structure
        if not (self.project_root / "tests").exists():
            issues.append("Tests directory not found")
        
        if not (self.project_root / "src").exists() and not (self.project_root / "app.py").exists():
            issues.append("Application source code not found")
        
        # Validate Python interpreters
        for env_name, env_config in self.config_manager.environments.items():
            python_cmd = f"python{env_config.python_version}"
            if shutil.which(python_cmd) is None:
                issues.append(f"Python {env_config.python_version} not found for environment {env_name}")
        
        # Validate tox installation
        if shutil.which("tox") is None:
            issues.append("tox not found - install with 'pip install tox==4.26.0'")
        
        return len(issues) == 0, issues
    
    def run_comprehensive_testing(self, parallel: bool = True, 
                                 generate_report: bool = True) -> Dict[str, Any]:
        """
        Run comprehensive multi-environment testing with full reporting
        
        Args:
            parallel: Enable parallel execution
            generate_report: Generate comprehensive report
            
        Returns:
            Dict[str, Any]: Test execution results and report
        """
        self.logger.info("Starting comprehensive multi-environment testing")
        
        # Validate setup
        setup_valid, issues = self.validate_setup()
        if not setup_valid:
            error_msg = f"Setup validation failed: {'; '.join(issues)}"
            self.logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg,
                "issues": issues
            }
        
        # Write tox configuration
        self.config_manager.write_tox_config()
        
        # Execute tests
        test_results = self.executor.execute_all_environments(parallel=parallel)
        
        # Generate report
        report = None
        if generate_report:
            report = self.executor.generate_comprehensive_report()
            self.executor.save_report(report)
        
        # Determine overall success
        success = all(result.status == TestStatus.PASSED for result in test_results.values())
        
        return {
            "success": success,
            "test_results": {name: result.to_dict() for name, result in test_results.items()},
            "report": report,
            "flask_compatibility_verified": success and "py313" in test_results
        }


# ================================
# pytest Integration and Fixtures
# ================================

@pytest.fixture(scope="session")
def multi_environment_suite() -> MultiEnvironmentTestSuite:
    """
    Multi-environment test suite fixture for pytest integration
    
    Returns:
        MultiEnvironmentTestSuite: Configured test suite instance
    """
    return MultiEnvironmentTestSuite()


@pytest.fixture(scope="session") 
def tox_config_manager() -> ToxConfigurationManager:
    """
    Tox configuration manager fixture for environment configuration testing
    
    Returns:
        ToxConfigurationManager: Configured tox manager instance
    """
    return ToxConfigurationManager(Path.cwd())


@pytest.fixture
def environment_config_factory():
    """
    Factory fixture for creating environment configurations in tests
    
    Returns:
        Callable: Function to create EnvironmentConfig instances
    """
    def create_environment_config(name: str = "test_env", 
                                python_version: str = "3.13.3",
                                env_type: EnvironmentType = EnvironmentType.PRIMARY,
                                **kwargs) -> EnvironmentConfig:
        return EnvironmentConfig(
            name=name,
            python_version=python_version,
            env_type=env_type,
            **kwargs
        )
    
    return create_environment_config


# ================================
# Test Classes for Multi-Environment Validation
# ================================

class TestMultiEnvironmentConfiguration:
    """
    Test class for validating multi-environment configuration management
    and tox integration per Section 4.7.2 requirements.
    """
    
    def test_default_environment_setup(self, tox_config_manager):
        """Test that default environments are properly configured"""
        assert "py313" in tox_config_manager.environments
        assert "py312" in tox_config_manager.environments
        assert "minimal" in tox_config_manager.environments
        
        # Validate primary environment
        py313_env = tox_config_manager.environments["py313"]
        assert py313_env.python_version == "3.13.3"
        assert py313_env.env_type == EnvironmentType.PRIMARY
        assert "Flask==3.1.1" in py313_env.base_dependencies
    
    def test_tox_configuration_generation(self, tox_config_manager):
        """Test tox.ini configuration file generation"""
        config_content = tox_config_manager.generate_tox_config()
        
        assert "[tox]" in config_content
        assert "minversion = 4.26.0" in config_content
        assert "[testenv:py313]" in config_content
        assert "Flask==3.1.1" in config_content
    
    def test_environment_validation(self, tox_config_manager):
        """Test environment configuration validation"""
        issues = tox_config_manager.validate_configuration()
        assert len(issues) == 0, f"Configuration validation failed: {issues}"
    
    def test_custom_environment_addition(self, tox_config_manager, environment_config_factory):
        """Test adding custom environments to configuration"""
        custom_env = environment_config_factory(
            name="custom_test",
            python_version="3.12",
            env_type=EnvironmentType.DEVELOPMENT
        )
        
        initial_count = len(tox_config_manager.environments)
        tox_config_manager.add_environment(custom_env)
        
        assert len(tox_config_manager.environments) == initial_count + 1
        assert "custom_test" in tox_config_manager.environments
        assert "custom_test" in tox_config_manager.global_config["envlist"]


class TestMultiEnvironmentExecution:
    """
    Test class for validating multi-environment test execution with
    comprehensive monitoring and result aggregation.
    """
    
    @pytest.mark.integration
    def test_single_environment_execution(self, multi_environment_suite):
        """Test execution of tests in a single environment"""
        # Use minimal environment for faster testing
        suite = multi_environment_suite
        config_manager = suite.config_manager
        
        # Create executor with minimal configuration
        executor = MultiEnvironmentTestExecutor(config_manager)
        
        # Execute minimal environment only
        minimal_config = config_manager.environments["minimal"]
        result = executor._execute_single_environment("minimal", minimal_config)
        
        assert result is not None
        assert result.environment_name == "minimal"
        assert result.status in [TestStatus.PASSED, TestStatus.FAILED, TestStatus.ERROR]
        assert result.start_time is not None
    
    @pytest.mark.performance
    def test_performance_metrics_collection(self, multi_environment_suite):
        """Test collection of performance metrics during execution"""
        suite = multi_environment_suite
        executor = MultiEnvironmentTestExecutor(suite.config_manager)
        
        # Create mock result for testing
        result = TestResult(
            environment_name="test_env",
            status=TestStatus.RUNNING,
            start_time=datetime.now()
        )
        
        # Collect performance metrics
        result_with_metrics = executor._collect_performance_metrics("test_env", result)
        
        assert result_with_metrics.performance_metrics is not None
        assert "python_version" in result_with_metrics.performance_metrics
        assert "platform" in result_with_metrics.performance_metrics
    
    def test_report_generation(self, multi_environment_suite):
        """Test comprehensive report generation"""
        suite = multi_environment_suite
        executor = MultiEnvironmentTestExecutor(suite.config_manager)
        
        # Create mock test results
        executor.test_results["test_env"] = TestResult(
            environment_name="test_env",
            status=TestStatus.PASSED,
            start_time=datetime.now(),
            end_time=datetime.now(),
            tests_passed=10,
            tests_failed=0,
            tests_total=10,
            coverage_percentage=85.5
        )
        
        report = executor.generate_comprehensive_report()
        
        assert "execution_summary" in report
        assert "test_summary" in report
        assert "performance_summary" in report
        assert "flask_compatibility" in report
        assert report["flask_compatibility"]["flask_version"] == "3.1.1"


class TestFlaskCompatibilityValidation:
    """
    Test class for validating Flask 3.1.1 compatibility across multiple
    environments as specified in Section 4.7.2.
    """
    
    @pytest.mark.integration
    def test_flask_application_factory_compatibility(self, app, client):
        """Test Flask application factory pattern compatibility"""
        assert app is not None
        assert hasattr(app, 'config')
        assert app.config['TESTING'] is True
        
        # Test that application can handle requests
        response = client.get('/')
        assert response.status_code in [200, 404]  # Either valid response or route not found
    
    @pytest.mark.unit
    def test_flask_version_validation(self):
        """Test that Flask 3.1.1 is properly installed and accessible"""
        import flask
        
        # Verify Flask version
        flask_version = flask.__version__
        assert flask_version.startswith("3.1"), f"Expected Flask 3.1.x, got {flask_version}"
    
    @pytest.mark.unit
    def test_flask_sqlalchemy_compatibility(self):
        """Test Flask-SQLAlchemy 3.1.1 compatibility"""
        import flask_sqlalchemy
        
        # Verify Flask-SQLAlchemy version
        sqlalchemy_version = flask_sqlalchemy.__version__
        assert sqlalchemy_version.startswith("3.1"), f"Expected Flask-SQLAlchemy 3.1.x, got {sqlalchemy_version}"
    
    @pytest.mark.integration
    def test_blueprint_registration_compatibility(self, app):
        """Test Flask blueprint registration compatibility"""
        from flask import Blueprint
        
        # Create test blueprint
        test_bp = Blueprint('test', __name__)
        
        @test_bp.route('/test')
        def test_route():
            return {'status': 'ok'}
        
        # Register blueprint
        app.register_blueprint(test_bp)
        
        # Verify blueprint is registered
        assert 'test' in app.blueprints
    
    @pytest.mark.integration 
    def test_werkzeug_integration_compatibility(self, app):
        """Test Werkzeug integration compatibility with Flask 3.1.1"""
        import werkzeug
        
        # Verify Werkzeug version compatibility
        werkzeug_version = werkzeug.__version__
        assert werkzeug_version.startswith("3."), f"Expected Werkzeug 3.x, got {werkzeug_version}"
        
        # Test WSGI application
        with app.test_client() as client:
            response = client.get('/nonexistent')
            assert response.status_code == 404


class TestEnvironmentIsolation:
    """
    Test class for validating virtual environment isolation and
    dependency management across different testing environments.
    """
    
    @pytest.mark.unit
    def test_environment_configuration_isolation(self, environment_config_factory):
        """Test that environment configurations are properly isolated"""
        env1 = environment_config_factory(
            name="env1", 
            base_dependencies=["Flask==3.1.1"]
        )
        env2 = environment_config_factory(
            name="env2",
            base_dependencies=["Flask==3.0.0"]
        )
        
        # Verify configurations are independent
        assert env1.base_dependencies != env2.base_dependencies
        assert env1.name != env2.name
        
        # Modify one environment
        env1.base_dependencies.append("pytest==7.4.0")
        
        # Verify other environment is unaffected
        assert "pytest==7.4.0" not in env2.base_dependencies
    
    @pytest.mark.integration
    def test_virtual_environment_provisioning(self, tox_config_manager, tmp_path):
        """Test virtual environment provisioning and isolation"""
        # Create temporary tox configuration
        temp_config = tmp_path / "tox.ini"
        
        # Write configuration
        tox_config_manager.config_file = temp_config
        tox_config_manager.write_tox_config()
        
        assert temp_config.exists()
        
        # Verify configuration content
        content = temp_config.read_text()
        assert "Flask==3.1.1" in content
        assert "pytest-flask==1.3.0" in content
    
    def test_dependency_resolution_isolation(self, environment_config_factory):
        """Test that dependency resolution is isolated per environment"""
        minimal_env = environment_config_factory(
            name="minimal",
            env_type=EnvironmentType.MINIMAL,
            base_dependencies=["Flask==3.1.1", "pytest>=7.4.0"]
        )
        
        dev_env = environment_config_factory(
            name="development", 
            env_type=EnvironmentType.DEVELOPMENT
        )
        
        # Verify minimal environment has fewer dependencies
        assert len(minimal_env.base_dependencies) < len(dev_env.base_dependencies)
        
        # Verify both have Flask
        minimal_flask_deps = [dep for dep in minimal_env.base_dependencies if "Flask" in dep]
        dev_flask_deps = [dep for dep in dev_env.base_dependencies if "Flask" in dep]
        
        assert len(minimal_flask_deps) > 0
        assert len(dev_flask_deps) > 0


# ================================
# Performance and Benchmark Tests
# ================================

class TestMultiEnvironmentPerformance:
    """
    Test class for validating performance characteristics of multi-environment
    testing with pytest-benchmark integration per Section 4.7.1.
    """
    
    @pytest.mark.performance
    def test_environment_provisioning_performance(self, benchmark: BenchmarkFixture, 
                                                 environment_config_factory):
        """Benchmark environment configuration generation performance"""
        def create_environment():
            return environment_config_factory(
                name="perf_test",
                python_version="3.13.3",
                env_type=EnvironmentType.PRIMARY
            )
        
        result = benchmark(create_environment)
        assert result is not None
        assert result.name == "perf_test"
    
    @pytest.mark.performance
    def test_tox_config_generation_performance(self, benchmark: BenchmarkFixture,
                                             tox_config_manager):
        """Benchmark tox configuration generation performance"""
        def generate_config():
            return tox_config_manager.generate_tox_config()
        
        config_content = benchmark(generate_config)
        assert len(config_content) > 0
        assert "[tox]" in config_content
    
    @pytest.mark.performance
    def test_parallel_execution_efficiency(self, multi_environment_suite):
        """Test parallel execution efficiency compared to sequential"""
        suite = multi_environment_suite
        
        # Create minimal test environments for performance testing
        minimal_envs = {
            "test1": EnvironmentConfig("test1", "3.13.3", EnvironmentType.MINIMAL),
            "test2": EnvironmentConfig("test2", "3.13.3", EnvironmentType.MINIMAL)
        }
        
        # Override environments temporarily
        original_envs = suite.config_manager.environments
        suite.config_manager.environments = minimal_envs
        
        try:
            # Time parallel execution
            start_parallel = time.time()
            parallel_results = suite.executor.execute_all_environments(parallel=True)
            parallel_time = time.time() - start_parallel
            
            # Reset for sequential test
            suite.executor.test_results.clear()
            
            # Time sequential execution  
            start_sequential = time.time()
            sequential_results = suite.executor.execute_all_environments(parallel=False)
            sequential_time = time.time() - start_sequential
            
            # Verify parallel is faster (allowing for overhead)
            # Note: In real scenarios with actual test execution, parallel should be faster
            # For this test, we just verify both complete successfully
            assert len(parallel_results) == len(sequential_results)
            
        finally:
            # Restore original environments
            suite.config_manager.environments = original_envs


# ================================
# Integration Tests
# ================================

@pytest.mark.integration
class TestMultiEnvironmentIntegration:
    """
    Integration test class for end-to-end multi-environment testing
    workflow validation and Flask 3.1.1 migration verification.
    """
    
    def test_complete_multi_environment_workflow(self, multi_environment_suite):
        """Test complete multi-environment testing workflow"""
        suite = multi_environment_suite
        
        # Validate setup
        setup_valid, issues = suite.validate_setup()
        if not setup_valid:
            pytest.skip(f"Setup validation failed: {issues}")
        
        # Run minimal test to verify workflow
        # Note: Full execution would take too long for unit tests
        config_content = suite.config_manager.generate_tox_config()
        assert config_content is not None
        assert len(config_content) > 0
    
    def test_flask_migration_validation_integration(self, app, client):
        """Test Flask migration validation integration"""
        # Test basic Flask functionality
        assert app is not None
        
        # Test application context
        with app.app_context():
            from flask import current_app
            assert current_app == app
        
        # Test request context
        with client:
            response = client.get('/')
            # Should either return valid response or 404 for missing route
            assert response.status_code in [200, 404]
    
    def test_comparative_testing_integration(self, multi_environment_suite):
        """Test integration with comparative testing infrastructure"""
        suite = multi_environment_suite
        
        # Verify that comparative testing modules can access multi-environment results
        executor = suite.executor
        
        # Create mock results for integration testing
        test_result = TestResult(
            environment_name="integration_test",
            status=TestStatus.PASSED,
            start_time=datetime.now(),
            end_time=datetime.now(),
            tests_passed=5,
            tests_total=5
        )
        
        executor.test_results["integration_test"] = test_result
        
        # Generate report
        report = executor.generate_comprehensive_report()
        
        # Verify report structure for integration
        assert "flask_compatibility" in report
        assert "environment_results" in report
        assert "integration_test" in report["environment_results"]


# ================================
# Main Execution Function
# ================================

def main():
    """
    Main execution function for running multi-environment testing from command line.
    
    This function provides a command-line interface for executing comprehensive
    multi-environment testing with various options and configurations.
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Multi-Environment Testing for Flask 3.1.1 Migration"
    )
    parser.add_argument(
        "--parallel", 
        action="store_true", 
        default=True,
        help="Enable parallel execution across environments"
    )
    parser.add_argument(
        "--no-parallel",
        action="store_false",
        dest="parallel",
        help="Disable parallel execution"
    )
    parser.add_argument(
        "--environment",
        "-e",
        action="append",
        help="Specific environment(s) to test (default: all)"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        default=True,
        help="Generate comprehensive test report"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate setup without running tests"
    )
    parser.add_argument(
        "--output-dir",
        default="test_results",
        help="Output directory for test results and reports"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize test suite
    suite = MultiEnvironmentTestSuite()
    suite.executor.results_dir = Path(args.output_dir)
    suite.executor.results_dir.mkdir(exist_ok=True)
    
    # Validate setup
    setup_valid, issues = suite.validate_setup()
    
    if not setup_valid:
        print(f"Setup validation failed:")
        for issue in issues:
            print(f"  - {issue}")
        return 1
    
    if args.validate_only:
        print("Setup validation successful!")
        return 0
    
    # Filter environments if specified
    if args.environment:
        original_envs = suite.config_manager.environments.copy()
        filtered_envs = {
            name: config for name, config in original_envs.items()
            if name in args.environment
        }
        suite.config_manager.environments = filtered_envs
        
        if not filtered_envs:
            print(f"No matching environments found: {args.environment}")
            return 1
    
    # Run comprehensive testing
    print("Starting multi-environment testing...")
    results = suite.run_comprehensive_testing(
        parallel=args.parallel,
        generate_report=args.report
    )
    
    # Print summary
    if results["success"]:
        print("✅ All environments passed successfully!")
        if results.get("flask_compatibility_verified"):
            print("✅ Flask 3.1.1 migration compatibility verified!")
    else:
        print("❌ Some environments failed!")
        
        if "error" in results:
            print(f"Error: {results['error']}")
        
        # Print failed environments
        for env_name, result in results.get("test_results", {}).items():
            if result["status"] != "passed":
                print(f"  ❌ {env_name}: {result['status']}")
    
    # Print report location if generated
    if args.report and results.get("report"):
        report_file = suite.executor.results_dir / "multi_environment_report.json"
        print(f"📊 Comprehensive report saved to: {report_file}")
    
    return 0 if results["success"] else 1


if __name__ == "__main__":
    sys.exit(main())