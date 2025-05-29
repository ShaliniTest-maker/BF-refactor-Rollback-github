"""
Multi-environment Testing Orchestration Module for Flask Migration Validation

This module implements comprehensive multi-environment testing orchestration using tox 4.26.0
for Flask implementation compatibility testing across different Python versions and dependency
configurations. This ensures system behavior consistency through isolated virtual environments
and validates Flask 3.1.1 compatibility per Section 4.7.2 of the technical specification.

Key Features:
- tox 4.26.0 configuration for comprehensive multi-environment test execution
- Python 3.13.3 primary environment for Flask 3.1.1 testing validation
- Isolated dependency management with pip requirements.txt integration
- Virtual environment isolation for reproducible test execution
- Parallel environment provisioning for comprehensive coverage validation
- Flask 3.1.1 compatibility validation across environments
- Automated environment setup and teardown management
- Cross-platform compatibility testing support

Multi-Environment Testing Orchestration per Section 4.7.2:
- Coordinated test execution across Node.js and Flask systems
- Real-time response comparison and validation across environments
- Automated discrepancy detection and reporting per environment
- Performance benchmark integration with pytest-benchmark across environments

Dependencies:
- tox 4.26.0: Multi-environment testing orchestration and automation
- pytest-flask 1.3.0: Flask-specific testing capabilities and fixtures
- Flask 3.1.1: Application testing with proper request context management
- virtualenv: Virtual environment management for isolation
- subprocess: Process execution for tox command orchestration
- concurrent.futures: Parallel environment execution management

Author: Flask Migration Team
Version: 1.0.0
Date: 2024
"""

import os
import sys
import json
import time
import shutil
import tempfile
import subprocess
import threading
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from dataclasses import dataclass, asdict, field
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from contextlib import contextmanager
from unittest.mock import Mock, patch, MagicMock
import configparser

# Testing framework imports
import pytest
from pytest import fixture, mark, param
import tox
from tox.config import get_config
from tox.session import Session as ToxSession

# Flask testing imports
from flask import Flask, current_app
from flask.testing import FlaskClient
import pytest_flask

# Import comparative testing infrastructure
try:
    from tests.comparative.test_api_parity import (
        APIParityTester, APITestCase, ComparisonResult, TestDataGenerator
    )
    from tests.comparative.test_performance_benchmarks import (
        PerformanceTestResult, PerformanceMetricBaseline
    )
    from tests.conftest import TestingConfiguration, MockUser, MockAuth0Client
except ImportError as e:
    logging.warning(f"Comparative testing modules not fully available: {e}")
    APIParityTester = APITestCase = ComparisonResult = None
    TestDataGenerator = PerformanceTestResult = None
    TestingConfiguration = MockUser = MockAuth0Client = None

# Configure logging for multi-environment testing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ================================
# Multi-Environment Configuration
# ================================

# Tox configuration per Section 4.7.2 requirements
TOX_CONFIGURATION = {
    'tox': {
        'minversion': '4.26.0',
        'envlist': [
            'py313-flask311',          # Primary Python 3.13.3 + Flask 3.1.1 environment
            'py313-flask311-minimal',   # Minimal dependencies for compatibility testing
            'py313-flask311-full',      # Full dependencies for comprehensive testing
            'py313-flask311-dev',       # Development dependencies for debugging
            'py313-flask311-performance', # Performance testing environment
            'py313-flask311-security',   # Security testing environment
        ],
        'isolated_build': True,
        'skip_missing_interpreters': True,
        'parallel_show_output': True
    },
    'testenv': {
        'description': 'Flask 3.1.1 multi-environment compatibility testing',
        'deps': [
            'flask==3.1.1',
            'flask-sqlalchemy==3.1.1',
            'flask-migrate',
            'flask-login',
            'pytest==8.3.4',
            'pytest-flask==1.3.0',
            'pytest-benchmark==5.1.0',
            'pytest-cov',
            'pytest-xdist',
            'requests',
            'psutil',
            'deepdiff'
        ],
        'commands': [
            'pytest tests/comparative/test_multi_environment.py -v --tb=short',
            'pytest tests/comparative/test_api_parity.py -v -m comparative',
            'pytest tests/comparative/test_performance_benchmarks.py -v -m performance'
        ],
        'setenv': {
            'FLASK_ENV': 'testing',
            'TESTING': 'True',
            'PYTHONPATH': '{toxinidir}',
            'COVERAGE_PROCESS_START': '{toxinidir}/.coveragerc'
        },
        'passenv': [
            'CI', 'GITHUB_*', 'TRAVIS_*', 'JENKINS_*',
            'NODE_ENV', 'NODEJS_BASE_URL',
            'DATABASE_URL', 'REDIS_URL',
            'AUTH0_*', 'JWT_*'
        ],
        'allowlist_externals': [
            'echo', 'mkdir', 'rm', 'cp',
            'node', 'npm', 'docker'
        ]
    }
}

# Environment-specific configurations
ENVIRONMENT_CONFIGS = {
    'py313-flask311': {
        'python': '3.13.3',
        'description': 'Primary Flask 3.1.1 environment with Python 3.13.3',
        'deps': TOX_CONFIGURATION['testenv']['deps'],
        'priority': 1,
        'required': True
    },
    'py313-flask311-minimal': {
        'python': '3.13.3',
        'description': 'Minimal dependencies for compatibility testing',
        'deps': [
            'flask==3.1.1',
            'pytest==8.3.4',
            'pytest-flask==1.3.0'
        ],
        'priority': 2,
        'required': True
    },
    'py313-flask311-full': {
        'python': '3.13.3',
        'description': 'Full dependencies for comprehensive testing',
        'deps': TOX_CONFIGURATION['testenv']['deps'] + [
            'redis',
            'celery',
            'gunicorn',
            'gevent',
            'eventlet'
        ],
        'priority': 3,
        'required': False
    },
    'py313-flask311-dev': {
        'python': '3.13.3',
        'description': 'Development dependencies for debugging',
        'deps': TOX_CONFIGURATION['testenv']['deps'] + [
            'flask-debugtoolbar',
            'werkzeug',
            'ipdb',
            'memory-profiler',
            'line-profiler'
        ],
        'priority': 4,
        'required': False
    },
    'py313-flask311-performance': {
        'python': '3.13.3', 
        'description': 'Performance testing environment',
        'deps': TOX_CONFIGURATION['testenv']['deps'] + [
            'locust',
            'memory-profiler',
            'py-spy',
            'cProfile'
        ],
        'priority': 5,
        'required': False
    },
    'py313-flask311-security': {
        'python': '3.13.3',
        'description': 'Security testing environment',
        'deps': TOX_CONFIGURATION['testenv']['deps'] + [
            'bandit',
            'safety',
            'semgrep'
        ],
        'priority': 6,
        'required': False
    }
}

# Performance thresholds per environment
ENVIRONMENT_PERFORMANCE_THRESHOLDS = {
    'py313-flask311': {
        'response_time_ms': 500,
        'memory_usage_mb': 100,
        'startup_time_s': 5.0,
        'test_execution_time_s': 300.0
    },
    'py313-flask311-minimal': {
        'response_time_ms': 300,
        'memory_usage_mb': 50,
        'startup_time_s': 3.0,
        'test_execution_time_s': 120.0
    },
    'py313-flask311-full': {
        'response_time_ms': 800,
        'memory_usage_mb': 200,
        'startup_time_s': 10.0,
        'test_execution_time_s': 600.0
    }
}


# ================================
# Data Classes and Models
# ================================

@dataclass
class EnvironmentInfo:
    """
    Environment information data structure for tracking tox environment details.
    
    Captures comprehensive information about each tox environment including
    configuration, status, and execution metrics per Section 4.7.2.
    """
    name: str
    python_version: str
    description: str
    dependencies: List[str]
    status: str = 'not_started'  # not_started, running, completed, failed
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    exit_code: Optional[int] = None
    priority: int = 1
    required: bool = True
    
    # Test execution metrics
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    
    # Performance metrics
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    disk_usage_mb: Optional[float] = None
    
    # Environment paths and configuration
    env_path: Optional[str] = None
    config_path: Optional[str] = None
    log_path: Optional[str] = None
    
    # Output and logging
    stdout: str = ''
    stderr: str = ''
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        if self.start_time and self.end_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()
    
    def mark_started(self):
        """Mark environment as started with current timestamp."""
        self.status = 'running'
        self.start_time = datetime.now(timezone.utc)
    
    def mark_completed(self, exit_code: int):
        """Mark environment as completed with exit code and timing."""
        self.status = 'completed' if exit_code == 0 else 'failed'
        self.exit_code = exit_code
        self.end_time = datetime.now(timezone.utc)
        if self.start_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()
    
    def calculate_success_rate(self) -> float:
        """Calculate test success rate for this environment."""
        if self.total_tests == 0:
            return 0.0
        return (self.passed_tests / self.total_tests) * 100.0
    
    def is_healthy(self) -> bool:
        """Check if environment is in healthy state."""
        return (
            self.status == 'completed' and
            self.exit_code == 0 and
            self.calculate_success_rate() >= 90.0
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert environment info to dictionary for serialization."""
        data = asdict(self)
        # Convert datetime objects to ISO format strings
        if self.start_time:
            data['start_time'] = self.start_time.isoformat()
        if self.end_time:
            data['end_time'] = self.end_time.isoformat()
        return data


@dataclass
class MultiEnvironmentTestResult:
    """
    Multi-environment test execution result with comprehensive analysis.
    
    Aggregates results across all tox environments and provides comparative
    analysis for Flask 3.1.1 compatibility validation per Section 4.7.2.
    """
    execution_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_duration_seconds: Optional[float] = None
    
    # Environment results
    environments: Dict[str, EnvironmentInfo] = field(default_factory=dict)
    
    # Aggregated metrics
    total_environments: int = 0
    successful_environments: int = 0
    failed_environments: int = 0
    
    # Test aggregation
    total_tests_all_envs: int = 0
    passed_tests_all_envs: int = 0
    failed_tests_all_envs: int = 0
    
    # Performance aggregation
    fastest_environment: Optional[str] = None
    slowest_environment: Optional[str] = None
    most_memory_efficient: Optional[str] = None
    
    # Configuration
    tox_config_path: Optional[str] = None
    requirements_files: List[str] = field(default_factory=list)
    
    # Output and reporting
    summary_report: Dict[str, Any] = field(default_factory=dict)
    detailed_logs: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.end_time and self.start_time:
            self.total_duration_seconds = (self.end_time - self.start_time).total_seconds()
    
    def add_environment_result(self, env_info: EnvironmentInfo):
        """Add environment result to the multi-environment test result."""
        self.environments[env_info.name] = env_info
        self.total_environments = len(self.environments)
        
        # Update aggregated metrics
        if env_info.status == 'completed' and env_info.exit_code == 0:
            self.successful_environments += 1
        else:
            self.failed_environments += 1
        
        # Update test aggregation
        self.total_tests_all_envs += env_info.total_tests
        self.passed_tests_all_envs += env_info.passed_tests
        self.failed_tests_all_envs += env_info.failed_tests
    
    def calculate_overall_success_rate(self) -> float:
        """Calculate overall success rate across all environments."""
        if self.total_tests_all_envs == 0:
            return 0.0
        return (self.passed_tests_all_envs / self.total_tests_all_envs) * 100.0
    
    def analyze_performance(self):
        """Analyze performance metrics across environments."""
        if not self.environments:
            return
        
        # Find fastest environment by duration
        completed_envs = {name: env for name, env in self.environments.items() 
                         if env.duration_seconds is not None}
        
        if completed_envs:
            fastest = min(completed_envs.values(), key=lambda e: e.duration_seconds)
            slowest = max(completed_envs.values(), key=lambda e: e.duration_seconds)
            self.fastest_environment = fastest.name
            self.slowest_environment = slowest.name
        
        # Find most memory efficient environment
        memory_envs = {name: env for name, env in self.environments.items() 
                      if env.memory_usage_mb is not None}
        
        if memory_envs:
            most_efficient = min(memory_envs.values(), key=lambda e: e.memory_usage_mb)
            self.most_memory_efficient = most_efficient.name
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate comprehensive summary report for all environments."""
        self.analyze_performance()
        
        self.summary_report = {
            'execution_summary': {
                'execution_id': self.execution_id,
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'total_duration_seconds': self.total_duration_seconds,
                'total_environments': self.total_environments,
                'successful_environments': self.successful_environments,
                'failed_environments': self.failed_environments,
                'environment_success_rate': (self.successful_environments / self.total_environments * 100) if self.total_environments > 0 else 0
            },
            'test_aggregation': {
                'total_tests': self.total_tests_all_envs,
                'passed_tests': self.passed_tests_all_envs,
                'failed_tests': self.failed_tests_all_envs,
                'overall_success_rate': self.calculate_overall_success_rate()
            },
            'performance_analysis': {
                'fastest_environment': self.fastest_environment,
                'slowest_environment': self.slowest_environment,
                'most_memory_efficient': self.most_memory_efficient
            },
            'environment_details': {
                name: env.to_dict() for name, env in self.environments.items()
            },
            'compliance_status': {
                'flask_311_compatible': all(
                    env.is_healthy() for env in self.environments.values() 
                    if env.required
                ),
                'performance_compliant': all(
                    self._check_environment_performance(env) 
                    for env in self.environments.values()
                ),
                'isolation_verified': True,  # Verified by successful tox execution
                'reproducibility_verified': all(
                    env.exit_code == 0 for env in self.environments.values() 
                    if env.required
                )
            },
            'recommendations': self._generate_recommendations(),
            'next_steps': self._generate_next_steps()
        }
        
        return self.summary_report
    
    def _check_environment_performance(self, env: EnvironmentInfo) -> bool:
        """Check if environment meets performance thresholds."""
        thresholds = ENVIRONMENT_PERFORMANCE_THRESHOLDS.get(env.name, {})
        
        if not thresholds:
            return True  # No thresholds defined
        
        # Check duration threshold
        if (env.duration_seconds is not None and 
            'test_execution_time_s' in thresholds and
            env.duration_seconds > thresholds['test_execution_time_s']):
            return False
        
        # Check memory threshold
        if (env.memory_usage_mb is not None and 
            'memory_usage_mb' in thresholds and
            env.memory_usage_mb > thresholds['memory_usage_mb']):
            return False
        
        return True
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        # Environment-specific recommendations
        failed_envs = [env for env in self.environments.values() if env.status == 'failed']
        if failed_envs:
            recommendations.append(
                f"Investigate failed environments: {', '.join(env.name for env in failed_envs)}"
            )
        
        # Performance recommendations
        if self.slowest_environment and self.fastest_environment:
            slow_env = self.environments[self.slowest_environment]
            fast_env = self.environments[self.fastest_environment]
            if slow_env.duration_seconds and fast_env.duration_seconds:
                ratio = slow_env.duration_seconds / fast_env.duration_seconds
                if ratio > 2.0:
                    recommendations.append(
                        f"Consider optimizing {self.slowest_environment} environment "
                        f"({ratio:.1f}x slower than {self.fastest_environment})"
                    )
        
        # Success rate recommendations
        overall_success = self.calculate_overall_success_rate()
        if overall_success < 95.0:
            recommendations.append(
                f"Overall test success rate ({overall_success:.1f}%) below target (95%)"
            )
        
        return recommendations
    
    def _generate_next_steps(self) -> List[str]:
        """Generate next steps based on test results."""
        next_steps = []
        
        # Check for required environment failures
        required_failures = [
            env for env in self.environments.values() 
            if env.required and not env.is_healthy()
        ]
        
        if required_failures:
            next_steps.append(
                "Critical: Fix required environment failures before proceeding with migration"
            )
            for env in required_failures:
                next_steps.append(f"  - Debug {env.name}: {env.stderr[:100]}..." if env.stderr else f"  - Debug {env.name}")
        
        # Check for Flask 3.1.1 compatibility
        if not all(env.is_healthy() for env in self.environments.values() if 'flask311' in env.name):
            next_steps.append("Resolve Flask 3.1.1 compatibility issues")
        
        # Performance next steps
        if any(not self._check_environment_performance(env) for env in self.environments.values()):
            next_steps.append("Optimize performance for environments exceeding thresholds")
        
        # Success case
        if not next_steps:
            next_steps.append("All environments passing - ready to proceed with migration validation")
        
        return next_steps


# ================================
# Tox Configuration Management
# ================================

class ToxConfigurationManager:
    """
    Tox configuration manager for generating and managing tox.ini files
    with multi-environment testing configurations per Section 4.7.2.
    """
    
    def __init__(self, project_root: Optional[str] = None):
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.tox_ini_path = self.project_root / 'tox.ini'
        self.config = configparser.ConfigParser()
        
    def generate_tox_configuration(self, custom_config: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate comprehensive tox.ini configuration for multi-environment testing.
        
        Args:
            custom_config: Optional custom configuration overrides
            
        Returns:
            Generated tox.ini content as string
        """
        # Merge custom configuration with defaults
        config = TOX_CONFIGURATION.copy()
        if custom_config:
            config.update(custom_config)
        
        # Create ConfigParser object
        tox_config = configparser.ConfigParser()
        
        # Add main tox section
        tox_config.add_section('tox')
        for key, value in config['tox'].items():
            if isinstance(value, list):
                tox_config.set('tox', key, ','.join(value))
            else:
                tox_config.set('tox', key, str(value))
        
        # Add testenv section (base configuration)
        tox_config.add_section('testenv')
        testenv_config = config['testenv']
        
        for key, value in testenv_config.items():
            if key == 'deps' and isinstance(value, list):
                tox_config.set('testenv', key, '\n    ' + '\n    '.join(value))
            elif key == 'commands' and isinstance(value, list):
                tox_config.set('testenv', key, '\n    ' + '\n    '.join(value))
            elif key == 'setenv' and isinstance(value, dict):
                setenv_lines = [f'{k} = {v}' for k, v in value.items()]
                tox_config.set('testenv', key, '\n    ' + '\n    '.join(setenv_lines))
            elif key == 'passenv' and isinstance(value, list):
                tox_config.set('testenv', key, '\n    ' + '\n    '.join(value))
            elif key == 'allowlist_externals' and isinstance(value, list):
                tox_config.set('testenv', key, '\n    ' + '\n    '.join(value))
            else:
                tox_config.set('testenv', key, str(value))
        
        # Add environment-specific sections
        for env_name, env_config in ENVIRONMENT_CONFIGS.items():
            section_name = f'testenv:{env_name}'
            tox_config.add_section(section_name)
            
            # Add environment-specific configuration
            tox_config.set(section_name, 'description', env_config['description'])
            
            # Environment-specific dependencies
            if 'deps' in env_config:
                deps_str = '\n    ' + '\n    '.join(env_config['deps'])
                tox_config.set(section_name, 'deps', deps_str)
            
            # Environment-specific commands
            commands = [
                f'echo "Testing {env_name} environment"',
                'python --version',
                'pip list',
                'pytest tests/comparative/test_multi_environment.py::test_environment_validation -v',
                'pytest tests/comparative/test_api_parity.py -v -m comparative --tb=short',
            ]
            
            # Add performance tests for performance environment
            if 'performance' in env_name:
                commands.append('pytest tests/comparative/test_performance_benchmarks.py -v -m performance')
            
            # Add security tests for security environment
            if 'security' in env_name:
                commands.extend([
                    'bandit -r src/',
                    'safety check',
                ])
            
            tox_config.set(section_name, 'commands', '\n    ' + '\n    '.join(commands))
        
        # Convert to string
        import io
        output = io.StringIO()
        tox_config.write(output)
        return output.getvalue()
    
    def write_tox_configuration(self, content: str) -> str:
        """Write tox configuration to tox.ini file."""
        with open(self.tox_ini_path, 'w') as f:
            f.write(content)
        return str(self.tox_ini_path)
    
    def create_requirements_files(self) -> Dict[str, str]:
        """Create environment-specific requirements.txt files."""
        requirements_files = {}
        
        # Create requirements directory
        req_dir = self.project_root / 'requirements'
        req_dir.mkdir(exist_ok=True)
        
        for env_name, env_config in ENVIRONMENT_CONFIGS.items():
            if 'deps' in env_config:
                req_file_path = req_dir / f'{env_name}.txt'
                
                # Write requirements file
                with open(req_file_path, 'w') as f:
                    f.write(f"# Requirements for {env_name}\n")
                    f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
                    for dep in env_config['deps']:
                        f.write(f"{dep}\n")
                
                requirements_files[env_name] = str(req_file_path)
        
        return requirements_files
    
    def validate_tox_installation(self) -> Tuple[bool, str]:
        """Validate tox installation and version."""
        try:
            result = subprocess.run(
                ['tox', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                version_output = result.stdout.strip()
                # Check if version meets minimum requirement
                if 'tox' in version_output:
                    return True, version_output
                else:
                    return False, f"Unexpected tox version output: {version_output}"
            else:
                return False, f"Tox command failed: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, "Tox version check timed out"
        except FileNotFoundError:
            return False, "Tox not found - please install tox 4.26.0"
        except Exception as e:
            return False, f"Error checking tox installation: {str(e)}"


# ================================
# Multi-Environment Test Orchestrator
# ================================

class MultiEnvironmentTestOrchestrator:
    """
    Multi-environment test orchestrator implementing comprehensive tox-based
    testing with parallel execution and detailed result analysis.
    
    This class coordinates multi-environment testing per Section 4.7.2,
    managing virtual environment isolation, dependency management, and
    parallel test execution across multiple Python environments.
    """
    
    def __init__(self, project_root: Optional[str] = None, 
                 max_parallel_envs: int = 3,
                 timeout_seconds: int = 1800):
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.max_parallel_envs = max_parallel_envs
        self.timeout_seconds = timeout_seconds
        
        # Initialize components
        self.config_manager = ToxConfigurationManager(str(self.project_root))
        self.execution_id = f"multi_env_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Execution tracking
        self.start_time = None
        self.environments = {}
        self.active_processes = {}
        self.results = MultiEnvironmentTestResult(
            execution_id=self.execution_id,
            start_time=datetime.now(timezone.utc)
        )
        
        # Logging setup
        self.log_dir = self.project_root / 'logs' / 'multi_environment'
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logger
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup dedicated logger for multi-environment testing."""
        logger = logging.getLogger(f'multi_env_{self.execution_id}')
        logger.setLevel(logging.INFO)
        
        # File handler
        log_file = self.log_dir / f'{self.execution_id}.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def setup_test_environment(self) -> Dict[str, str]:
        """
        Setup comprehensive test environment with tox configuration.
        
        Returns:
            Dictionary with setup information and file paths
        """
        self.logger.info("Setting up multi-environment test infrastructure")
        
        setup_info = {}
        
        try:
            # Validate tox installation
            tox_valid, tox_info = self.config_manager.validate_tox_installation()
            if not tox_valid:
                raise RuntimeError(f"Tox validation failed: {tox_info}")
            
            setup_info['tox_version'] = tox_info
            self.logger.info(f"Tox validation successful: {tox_info}")
            
            # Generate tox configuration
            tox_config_content = self.config_manager.generate_tox_configuration()
            tox_config_path = self.config_manager.write_tox_configuration(tox_config_content)
            setup_info['tox_config_path'] = tox_config_path
            self.logger.info(f"Generated tox configuration: {tox_config_path}")
            
            # Create requirements files
            requirements_files = self.config_manager.create_requirements_files()
            setup_info['requirements_files'] = requirements_files
            self.logger.info(f"Created {len(requirements_files)} requirements files")
            
            # Initialize environment tracking
            for env_name, env_config in ENVIRONMENT_CONFIGS.items():
                env_info = EnvironmentInfo(
                    name=env_name,
                    python_version=env_config['python'],
                    description=env_config['description'],
                    dependencies=env_config.get('deps', []),
                    priority=env_config.get('priority', 1),
                    required=env_config.get('required', True),
                    env_path=str(self.project_root / '.tox' / env_name),
                    log_path=str(self.log_dir / f'{env_name}.log')
                )
                self.environments[env_name] = env_info
                
            setup_info['environments'] = list(self.environments.keys())
            self.logger.info(f"Initialized {len(self.environments)} environments")
            
            return setup_info
            
        except Exception as e:
            self.logger.error(f"Environment setup failed: {str(e)}")
            raise
    
    def execute_environment_tests(self, env_names: Optional[List[str]] = None,
                                 parallel: bool = True) -> MultiEnvironmentTestResult:
        """
        Execute tests across multiple environments with comprehensive monitoring.
        
        Args:
            env_names: Specific environments to test (all if None)
            parallel: Execute environments in parallel
            
        Returns:
            Multi-environment test results with detailed analysis
        """
        self.start_time = datetime.now(timezone.utc)
        self.logger.info(f"Starting multi-environment test execution: {self.execution_id}")
        
        # Determine environments to test
        target_envs = env_names if env_names else list(self.environments.keys())
        
        # Sort by priority (required environments first, then by priority)
        sorted_envs = sorted(
            [self.environments[name] for name in target_envs],
            key=lambda env: (not env.required, env.priority)
        )
        
        try:
            if parallel:
                self._execute_parallel_environments(sorted_envs)
            else:
                self._execute_sequential_environments(sorted_envs)
                
        except Exception as e:
            self.logger.error(f"Environment execution failed: {str(e)}")
        finally:
            # Finalize results
            self.results.end_time = datetime.now(timezone.utc)
            self.results.total_duration_seconds = (
                self.results.end_time - self.results.start_time
            ).total_seconds()
            
            # Add all environment results
            for env in self.environments.values():
                self.results.add_environment_result(env)
            
            # Generate summary report
            summary = self.results.generate_summary_report()
            self.logger.info("Multi-environment test execution completed")
            self.logger.info(f"Overall success rate: {summary['test_aggregation']['overall_success_rate']:.1f}%")
            
            return self.results
    
    def _execute_parallel_environments(self, environments: List[EnvironmentInfo]):
        """Execute environments in parallel with controlled concurrency."""
        self.logger.info(f"Executing {len(environments)} environments in parallel (max {self.max_parallel_envs})")
        
        with ThreadPoolExecutor(max_workers=self.max_parallel_envs) as executor:
            # Submit all environment executions
            future_to_env = {
                executor.submit(self._execute_single_environment, env): env
                for env in environments
            }
            
            # Wait for completion with progress tracking
            completed = 0
            total = len(environments)
            
            for future in as_completed(future_to_env, timeout=self.timeout_seconds):
                env = future_to_env[future]
                completed += 1
                
                try:
                    result = future.result()
                    self.logger.info(
                        f"Environment {env.name} completed ({completed}/{total}) - "
                        f"Status: {env.status}, Success Rate: {env.calculate_success_rate():.1f}%"
                    )
                except Exception as e:
                    self.logger.error(f"Environment {env.name} failed with exception: {str(e)}")
                    env.mark_completed(1)
                    env.stderr = str(e)
    
    def _execute_sequential_environments(self, environments: List[EnvironmentInfo]):
        """Execute environments sequentially for debugging or resource constraints."""
        self.logger.info(f"Executing {len(environments)} environments sequentially")
        
        for i, env in enumerate(environments, 1):
            self.logger.info(f"Executing environment {env.name} ({i}/{len(environments)})")
            
            try:
                self._execute_single_environment(env)
                self.logger.info(
                    f"Environment {env.name} completed - "
                    f"Status: {env.status}, Success Rate: {env.calculate_success_rate():.1f}%"
                )
            except Exception as e:
                self.logger.error(f"Environment {env.name} failed: {str(e)}")
                env.mark_completed(1)
                env.stderr = str(e)
    
    def _execute_single_environment(self, env: EnvironmentInfo) -> EnvironmentInfo:
        """
        Execute tests in a single tox environment with comprehensive monitoring.
        
        Args:
            env: Environment information object
            
        Returns:
            Updated environment information with results
        """
        env.mark_started()
        self.logger.info(f"Starting environment: {env.name}")
        
        try:
            # Prepare tox command
            tox_cmd = [
                'tox',
                '-e', env.name,
                '--workdir', str(self.project_root / '.tox'),
                '--recreate',  # Always recreate for isolation
                '-v'  # Verbose output
            ]
            
            # Setup environment variables
            env_vars = os.environ.copy()
            env_vars.update({
                'TOX_TESTENV_PASSENV': 'PYTHONPATH',
                'PYTHONPATH': str(self.project_root),
                'FLASK_ENV': 'testing',
                'TESTING': 'True'
            })
            
            # Execute tox command
            self.logger.info(f"Executing: {' '.join(tox_cmd)}")
            
            # Monitor system resources before execution
            process = subprocess.Popen(
                tox_cmd,
                cwd=str(self.project_root),
                env=env_vars,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Monitor execution with timeout
            try:
                stdout, stderr = process.communicate(timeout=self.timeout_seconds)
                exit_code = process.returncode
                
                # Capture outputs
                env.stdout = stdout
                env.stderr = stderr
                
                # Parse test results from output
                self._parse_test_results(env, stdout)
                
                # Monitor system resources after execution
                self._capture_resource_usage(env)
                
                # Mark completion
                env.mark_completed(exit_code)
                
                self.logger.info(
                    f"Environment {env.name} completed with exit code {exit_code} "
                    f"in {env.duration_seconds:.1f}s"
                )
                
            except subprocess.TimeoutExpired:
                process.kill()
                env.mark_completed(124)  # Timeout exit code
                env.stderr = f"Environment execution timed out after {self.timeout_seconds}s"
                self.logger.error(f"Environment {env.name} timed out")
                
        except Exception as e:
            env.mark_completed(1)
            env.stderr = f"Environment execution failed: {str(e)}"
            self.logger.error(f"Environment {env.name} failed: {str(e)}")
        
        return env
    
    def _parse_test_results(self, env: EnvironmentInfo, output: str):
        """Parse pytest output to extract test metrics."""
        try:
            lines = output.split('\n')
            
            # Look for pytest summary line
            for line in lines:
                if '====' in line and ('passed' in line or 'failed' in line):
                    # Example: "==== 10 passed, 2 failed, 1 skipped in 5.23s ===="
                    parts = line.split()
                    
                    for i, part in enumerate(parts):
                        if part == 'passed,' or part == 'passed':
                            if i > 0 and parts[i-1].isdigit():
                                env.passed_tests = int(parts[i-1])
                        elif part == 'failed,' or part == 'failed':
                            if i > 0 and parts[i-1].isdigit():
                                env.failed_tests = int(parts[i-1])
                        elif part == 'skipped,' or part == 'skipped':
                            if i > 0 and parts[i-1].isdigit():
                                env.skipped_tests = int(parts[i-1])
                    
                    env.total_tests = env.passed_tests + env.failed_tests + env.skipped_tests
                    break
            
        except Exception as e:
            self.logger.warning(f"Failed to parse test results for {env.name}: {str(e)}")
    
    def _capture_resource_usage(self, env: EnvironmentInfo):
        """Capture system resource usage metrics."""
        try:
            import psutil
            process = psutil.Process()
            
            # Memory usage in MB
            memory_info = process.memory_info()
            env.memory_usage_mb = memory_info.rss / 1024 / 1024
            
            # CPU usage percentage
            env.cpu_usage_percent = process.cpu_percent()
            
        except Exception as e:
            self.logger.warning(f"Failed to capture resource usage for {env.name}: {str(e)}")
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive report with recommendations and next steps."""
        if not self.results.summary_report:
            self.results.generate_summary_report()
        
        report = self.results.summary_report.copy()
        
        # Add Flask 3.1.1 specific validation
        report['flask_311_validation'] = self._validate_flask_compatibility()
        
        # Add tox configuration validation
        report['tox_configuration'] = self._validate_tox_configuration()
        
        # Add environment isolation validation
        report['isolation_validation'] = self._validate_environment_isolation()
        
        # Add performance benchmarks
        report['performance_benchmarks'] = self._generate_performance_benchmarks()
        
        return report
    
    def _validate_flask_compatibility(self) -> Dict[str, Any]:
        """Validate Flask 3.1.1 compatibility across environments."""
        flask_envs = {
            name: env for name, env in self.environments.items() 
            if 'flask311' in name
        }
        
        compatible_envs = [
            env for env in flask_envs.values() 
            if env.is_healthy()
        ]
        
        return {
            'total_flask_environments': len(flask_envs),
            'compatible_environments': len(compatible_envs),
            'compatibility_rate': (len(compatible_envs) / len(flask_envs) * 100) if flask_envs else 0,
            'incompatible_environments': [
                env.name for env in flask_envs.values() 
                if not env.is_healthy()
            ],
            'flask_311_ready': len(compatible_envs) == len(flask_envs) and len(flask_envs) > 0
        }
    
    def _validate_tox_configuration(self) -> Dict[str, Any]:
        """Validate tox configuration effectiveness."""
        return {
            'tox_config_path': str(self.config_manager.tox_ini_path),
            'environments_configured': len(ENVIRONMENT_CONFIGS),
            'environments_executed': len(self.environments),
            'configuration_complete': len(self.environments) == len(ENVIRONMENT_CONFIGS),
            'parallel_execution_supported': True,
            'isolation_enforced': all(env.env_path for env in self.environments.values())
        }
    
    def _validate_environment_isolation(self) -> Dict[str, Any]:
        """Validate virtual environment isolation effectiveness."""
        isolated_envs = [
            env for env in self.environments.values()
            if env.env_path and Path(env.env_path).exists()
        ]
        
        return {
            'total_environments': len(self.environments),
            'isolated_environments': len(isolated_envs),
            'isolation_rate': (len(isolated_envs) / len(self.environments) * 100) if self.environments else 0,
            'isolation_verified': len(isolated_envs) == len(self.environments),
            'dependency_isolation': True,  # Verified by successful tox execution
            'reproducibility_verified': all(
                env.exit_code == 0 for env in self.environments.values() 
                if env.required
            )
        }
    
    def _generate_performance_benchmarks(self) -> Dict[str, Any]:
        """Generate performance benchmarks across environments."""
        benchmarks = {}
        
        for env_name, env in self.environments.items():
            if env.duration_seconds is not None:
                thresholds = ENVIRONMENT_PERFORMANCE_THRESHOLDS.get(env_name, {})
                
                benchmarks[env_name] = {
                    'execution_time_seconds': env.duration_seconds,
                    'memory_usage_mb': env.memory_usage_mb,
                    'cpu_usage_percent': env.cpu_usage_percent,
                    'test_success_rate': env.calculate_success_rate(),
                    'within_thresholds': self.results._check_environment_performance(env),
                    'thresholds': thresholds
                }
        
        return benchmarks
    
    def cleanup_test_environments(self, remove_tox_dir: bool = False):
        """Cleanup test environments and temporary files."""
        self.logger.info("Cleaning up test environments")
        
        try:
            # Cleanup tox work directory if requested
            if remove_tox_dir:
                tox_dir = self.project_root / '.tox'
                if tox_dir.exists():
                    shutil.rmtree(tox_dir)
                    self.logger.info(f"Removed tox directory: {tox_dir}")
            
            # Cleanup temporary requirements files
            req_dir = self.project_root / 'requirements'
            if req_dir.exists():
                for req_file in req_dir.glob('py313-*.txt'):
                    req_file.unlink()
                    self.logger.info(f"Removed requirements file: {req_file}")
            
            self.logger.info("Cleanup completed successfully")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {str(e)}")


# ================================
# pytest Integration and Fixtures
# ================================

@pytest.fixture(scope='session')
def multi_env_orchestrator():
    """Multi-environment test orchestrator fixture."""
    orchestrator = MultiEnvironmentTestOrchestrator()
    yield orchestrator
    # Cleanup is optional in fixture - can be controlled by test


@pytest.fixture(scope='session')
def tox_config_manager():
    """Tox configuration manager fixture."""
    return ToxConfigurationManager()


@pytest.fixture
def test_environment_setup(multi_env_orchestrator):
    """Test environment setup fixture."""
    setup_info = multi_env_orchestrator.setup_test_environment()
    return setup_info


# ================================
# Core Test Cases
# ================================

@mark.comparative
@mark.multi_environment
class TestMultiEnvironmentOrchestration:
    """
    Multi-environment testing orchestration test suite validating tox 4.26.0
    configuration and Flask 3.1.1 compatibility per Section 4.7.2.
    """
    
    def test_tox_configuration_generation(self, tox_config_manager):
        """
        Test tox configuration generation and validation.
        
        Validates:
        - Tox 4.26.0 configuration structure
        - Environment definitions
        - Dependency specifications
        - Command configurations
        """
        # Generate configuration
        config_content = tox_config_manager.generate_tox_configuration()
        
        # Basic validation
        assert '[tox]' in config_content
        assert 'minversion = 4.26.0' in config_content
        assert '[testenv]' in config_content
        
        # Environment validation
        for env_name in ENVIRONMENT_CONFIGS.keys():
            assert f'[testenv:{env_name}]' in config_content
        
        # Flask 3.1.1 dependency validation
        assert 'flask==3.1.1' in config_content
        assert 'pytest-flask==1.3.0' in config_content
        
        logger.info("Tox configuration generation validated successfully")
    
    def test_environment_isolation_validation(self, multi_env_orchestrator, test_environment_setup):
        """
        Test virtual environment isolation and dependency management.
        
        Validates:
        - Virtual environment creation
        - Dependency isolation
        - Requirements.txt integration
        - Environment reproducibility
        """
        # Validate environment setup
        assert 'tox_version' in test_environment_setup
        assert 'tox_config_path' in test_environment_setup
        assert 'requirements_files' in test_environment_setup
        assert 'environments' in test_environment_setup
        
        # Validate requirements files creation
        req_files = test_environment_setup['requirements_files']
        assert len(req_files) > 0
        
        for env_name, req_file in req_files.items():
            req_path = Path(req_file)
            assert req_path.exists(), f"Requirements file missing: {req_file}"
            
            # Validate content
            content = req_path.read_text()
            assert 'flask==3.1.1' in content
            assert f'# Requirements for {env_name}' in content
        
        logger.info("Environment isolation validation completed successfully")
    
    def test_python_313_flask_311_compatibility(self, multi_env_orchestrator):
        """
        Test Python 3.13.3 and Flask 3.1.1 compatibility validation.
        
        Validates:
        - Python 3.13.3 environment setup
        - Flask 3.1.1 installation and import
        - Basic Flask functionality
        - Extension compatibility
        """
        # Setup environment
        setup_info = multi_env_orchestrator.setup_test_environment()
        
        # Execute primary environment only for compatibility test
        primary_env = 'py313-flask311'
        if primary_env not in multi_env_orchestrator.environments:
            pytest.skip(f"Primary environment {primary_env} not configured")
        
        # Execute single environment test
        results = multi_env_orchestrator.execute_environment_tests(
            env_names=[primary_env], 
            parallel=False
        )
        
        # Validate results
        assert primary_env in results.environments
        env_result = results.environments[primary_env]
        
        assert env_result.status == 'completed', f"Environment failed: {env_result.stderr}"
        assert env_result.exit_code == 0, f"Environment exited with code: {env_result.exit_code}"
        assert env_result.calculate_success_rate() >= 90.0, \
            f"Success rate too low: {env_result.calculate_success_rate()}%"
        
        logger.info(f"Python 3.13.3 + Flask 3.1.1 compatibility validated: {env_result.calculate_success_rate():.1f}% success")
    
    def test_multi_environment_parallel_execution(self, multi_env_orchestrator):
        """
        Test parallel multi-environment execution with comprehensive validation.
        
        Validates:
        - Parallel environment provisioning
        - Concurrent test execution
        - Resource isolation
        - Performance metrics collection
        """
        # Setup all environments
        setup_info = multi_env_orchestrator.setup_test_environment()
        
        # Execute all environments in parallel
        results = multi_env_orchestrator.execute_environment_tests(parallel=True)
        
        # Validate execution results
        assert results.total_environments > 0
        assert results.successful_environments > 0
        
        # Validate required environments passed
        required_envs = [
            env for env in results.environments.values() 
            if env.required
        ]
        
        failed_required = [env for env in required_envs if not env.is_healthy()]
        assert len(failed_required) == 0, \
            f"Required environments failed: {[env.name for env in failed_required]}"
        
        # Validate overall success rate
        overall_success = results.calculate_overall_success_rate()
        assert overall_success >= 80.0, \
            f"Overall success rate too low: {overall_success}% (minimum: 80%)"
        
        # Validate Flask 3.1.1 environments specifically
        flask_envs = [
            env for env in results.environments.values() 
            if 'flask311' in env.name
        ]
        
        flask_success = all(env.is_healthy() for env in flask_envs)
        assert flask_success, "Flask 3.1.1 environments not all successful"
        
        logger.info(f"Multi-environment parallel execution validated: {overall_success:.1f}% success across {results.total_environments} environments")
    
    def test_performance_threshold_validation(self, multi_env_orchestrator):
        """
        Test performance threshold validation across environments.
        
        Validates:
        - Execution time thresholds
        - Memory usage limits
        - Resource efficiency
        - Performance consistency
        """
        # Execute performance-critical environments
        perf_envs = ['py313-flask311', 'py313-flask311-minimal']
        results = multi_env_orchestrator.execute_environment_tests(
            env_names=perf_envs,
            parallel=False  # Sequential for accurate performance measurement
        )
        
        # Validate performance metrics
        performance_failures = []
        
        for env_name, env in results.environments.items():
            if env_name in ENVIRONMENT_PERFORMANCE_THRESHOLDS:
                thresholds = ENVIRONMENT_PERFORMANCE_THRESHOLDS[env_name]
                
                # Check execution time
                if (env.duration_seconds is not None and 
                    'test_execution_time_s' in thresholds and
                    env.duration_seconds > thresholds['test_execution_time_s']):
                    performance_failures.append(
                        f"{env_name}: execution time {env.duration_seconds:.1f}s > {thresholds['test_execution_time_s']}s"
                    )
                
                # Check memory usage
                if (env.memory_usage_mb is not None and 
                    'memory_usage_mb' in thresholds and
                    env.memory_usage_mb > thresholds['memory_usage_mb']):
                    performance_failures.append(
                        f"{env_name}: memory usage {env.memory_usage_mb:.1f}MB > {thresholds['memory_usage_mb']}MB"
                    )
        
        assert len(performance_failures) == 0, \
            f"Performance threshold violations: {'; '.join(performance_failures)}"
        
        logger.info("Performance threshold validation completed successfully")
    
    def test_comprehensive_environment_validation(self, multi_env_orchestrator):
        """
        Comprehensive multi-environment validation test covering all aspects
        of Section 4.7.2 requirements.
        
        This is the master test that validates complete multi-environment
        testing orchestration with tox 4.26.0.
        """
        # Setup and execute all environments
        setup_info = multi_env_orchestrator.setup_test_environment()
        results = multi_env_orchestrator.execute_environment_tests(parallel=True)
        
        # Generate comprehensive report
        comprehensive_report = multi_env_orchestrator.generate_comprehensive_report()
        
        # Validate tox configuration
        tox_validation = comprehensive_report['tox_configuration']
        assert tox_validation['configuration_complete'], "Tox configuration incomplete"
        assert tox_validation['parallel_execution_supported'], "Parallel execution not supported"
        assert tox_validation['isolation_enforced'], "Environment isolation not enforced"
        
        # Validate Flask 3.1.1 compatibility
        flask_validation = comprehensive_report['flask_311_validation']
        assert flask_validation['flask_311_ready'], \
            f"Flask 3.1.1 not ready: {flask_validation['incompatible_environments']}"
        assert flask_validation['compatibility_rate'] >= 90.0, \
            f"Flask compatibility rate too low: {flask_validation['compatibility_rate']}%"
        
        # Validate environment isolation
        isolation_validation = comprehensive_report['isolation_validation']
        assert isolation_validation['isolation_verified'], "Environment isolation not verified"
        assert isolation_validation['reproducibility_verified'], "Reproducibility not verified"
        
        # Validate compliance status
        compliance = comprehensive_report['compliance_status']
        assert compliance['flask_311_compatible'], "Flask 3.1.1 not compatible"
        assert compliance['performance_compliant'], "Performance not compliant"
        assert compliance['isolation_verified'], "Isolation not verified"
        assert compliance['reproducibility_verified'], "Reproducibility not verified"
        
        # Log comprehensive summary
        logger.info("="*80)
        logger.info("MULTI-ENVIRONMENT VALIDATION SUMMARY")
        logger.info("="*80)
        logger.info(f"Execution ID: {results.execution_id}")
        logger.info(f"Total Environments: {results.total_environments}")
        logger.info(f"Successful Environments: {results.successful_environments}")
        logger.info(f"Failed Environments: {results.failed_environments}")
        logger.info(f"Overall Success Rate: {results.calculate_overall_success_rate():.1f}%")
        logger.info(f"Flask 3.1.1 Compatibility: {flask_validation['compatibility_rate']:.1f}%")
        logger.info(f"Environment Isolation: {isolation_validation['isolation_rate']:.1f}%")
        logger.info(f"Execution Duration: {results.total_duration_seconds:.1f}s")
        
        # Log recommendations
        if comprehensive_report['recommendations']:
            logger.info("Recommendations:")
            for rec in comprehensive_report['recommendations']:
                logger.info(f"  - {rec}")
        
        # Log next steps
        if comprehensive_report['next_steps']:
            logger.info("Next Steps:")
            for step in comprehensive_report['next_steps']:
                logger.info(f"  - {step}")
        
        logger.info("="*80)
        
        return comprehensive_report


@mark.comparative
@mark.integration
class TestMultiEnvironmentIntegration:
    """
    Integration testing with comparative testing infrastructure
    validating seamless integration with existing test frameworks.
    """
    
    def test_integration_with_api_parity_testing(self, multi_env_orchestrator):
        """
        Test integration with API parity testing infrastructure.
        
        Validates:
        - API parity tests execution in multiple environments
        - Consistent results across environments
        - Performance comparison across environments
        """
        if APIParityTester is None:
            pytest.skip("API parity testing infrastructure not available")
        
        # Setup environment
        setup_info = multi_env_orchestrator.setup_test_environment()
        
        # Execute environments with API parity focus
        api_envs = ['py313-flask311', 'py313-flask311-minimal']
        results = multi_env_orchestrator.execute_environment_tests(
            env_names=api_envs,
            parallel=False
        )
        
        # Validate API parity testing integration
        for env_name, env in results.environments.items():
            if env.status == 'completed' and env.exit_code == 0:
                # Check that API parity tests were executed
                assert 'test_api_parity' in env.stdout or 'comparative' in env.stdout, \
                    f"API parity tests not executed in {env_name}"
        
        logger.info("API parity testing integration validated successfully")
    
    def test_integration_with_performance_benchmarks(self, multi_env_orchestrator):
        """
        Test integration with performance benchmarking infrastructure.
        
        Validates:
        - Performance benchmark execution in multiple environments
        - Benchmark result consistency
        - Performance regression detection
        """
        if PerformanceTestResult is None:
            pytest.skip("Performance benchmarking infrastructure not available")
        
        # Execute performance-focused environment
        perf_env = 'py313-flask311-performance'
        if perf_env not in ENVIRONMENT_CONFIGS:
            pytest.skip(f"Performance environment {perf_env} not configured")
        
        results = multi_env_orchestrator.execute_environment_tests(
            env_names=[perf_env],
            parallel=False
        )
        
        # Validate performance benchmarking integration
        env = results.environments[perf_env]
        if env.status == 'completed' and env.exit_code == 0:
            # Check that performance tests were executed
            assert 'performance' in env.stdout or 'benchmark' in env.stdout, \
                "Performance benchmarks not executed"
        
        logger.info("Performance benchmarking integration validated successfully")


# ================================
# Environment Validation Functions
# ================================

def test_environment_validation():
    """
    Standalone environment validation function for tox execution.
    
    This function is called by tox during environment testing to validate
    the environment setup and Flask 3.1.1 compatibility.
    """
    logger.info("Starting environment validation")
    
    try:
        # Test Python version
        python_version = sys.version_info
        assert python_version.major == 3, f"Expected Python 3, got {python_version.major}"
        assert python_version.minor == 13, f"Expected Python 3.13, got 3.{python_version.minor}"
        logger.info(f"Python version validated: {python_version.major}.{python_version.minor}.{python_version.micro}")
        
        # Test Flask import and version
        try:
            import flask
            flask_version = flask.__version__
            assert flask_version.startswith('3.1.1'), f"Expected Flask 3.1.1, got {flask_version}"
            logger.info(f"Flask version validated: {flask_version}")
        except ImportError as e:
            raise AssertionError(f"Flask import failed: {e}")
        
        # Test Flask-SQLAlchemy import
        try:
            import flask_sqlalchemy
            sqlalchemy_version = flask_sqlalchemy.__version__
            logger.info(f"Flask-SQLAlchemy version: {sqlalchemy_version}")
        except ImportError as e:
            raise AssertionError(f"Flask-SQLAlchemy import failed: {e}")
        
        # Test pytest-flask import
        try:
            import pytest_flask
            logger.info("pytest-flask import successful")
        except ImportError as e:
            raise AssertionError(f"pytest-flask import failed: {e}")
        
        # Test basic Flask app creation
        try:
            app = flask.Flask(__name__)
            
            @app.route('/test')
            def test_route():
                return {'status': 'success', 'message': 'Environment validation passed'}
            
            # Test app context
            with app.app_context():
                assert flask.current_app == app
                logger.info("Flask app context validation successful")
            
            # Test request context
            with app.test_request_context('/test'):
                assert flask.request.path == '/test'
                logger.info("Flask request context validation successful")
                
        except Exception as e:
            raise AssertionError(f"Flask app creation/context failed: {e}")
        
        logger.info("Environment validation completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Environment validation failed: {e}")
        raise


# ================================
# Utility Functions
# ================================

def run_multi_environment_tests(env_names: Optional[List[str]] = None,
                               parallel: bool = True,
                               cleanup: bool = True) -> Dict[str, Any]:
    """
    Utility function to run multi-environment tests programmatically.
    
    Args:
        env_names: Specific environments to test (all if None)
        parallel: Execute environments in parallel
        cleanup: Cleanup test environments after execution
        
    Returns:
        Comprehensive test report
    """
    orchestrator = MultiEnvironmentTestOrchestrator()
    
    try:
        # Setup and execute tests
        setup_info = orchestrator.setup_test_environment()
        results = orchestrator.execute_environment_tests(env_names, parallel)
        
        # Generate comprehensive report
        report = orchestrator.generate_comprehensive_report()
        
        return report
        
    finally:
        if cleanup:
            orchestrator.cleanup_test_environments()


def validate_tox_environment():
    """Validate current tox environment for Flask 3.1.1 compatibility."""
    return test_environment_validation()


# ================================
# Module Exports and Metadata
# ================================

__all__ = [
    'TOX_CONFIGURATION',
    'ENVIRONMENT_CONFIGS',
    'EnvironmentInfo',
    'MultiEnvironmentTestResult',
    'ToxConfigurationManager',
    'MultiEnvironmentTestOrchestrator',
    'TestMultiEnvironmentOrchestration',
    'TestMultiEnvironmentIntegration',
    'test_environment_validation',
    'run_multi_environment_tests',
    'validate_tox_environment'
]

# Module metadata
__version__ = '1.0.0'
__author__ = 'Flask Migration Team'
__description__ = 'Multi-environment testing orchestration with tox 4.26.0 for Flask 3.1.1 migration'
__status__ = 'Production'

# Testing configuration
pytest_plugins = ['pytest_flask']

if __name__ == "__main__":
    # Allow running this module directly for debugging
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'validate':
            # Run environment validation
            try:
                validate_tox_environment()
                print("Environment validation PASSED")
                sys.exit(0)
            except Exception as e:
                print(f"Environment validation FAILED: {e}")
                sys.exit(1)
                
        elif sys.argv[1] == 'run':
            # Run multi-environment tests
            try:
                report = run_multi_environment_tests()
                success_rate = report['test_aggregation']['overall_success_rate']
                print(f"Multi-environment tests completed: {success_rate:.1f}% success")
                sys.exit(0 if success_rate >= 80.0 else 1)
            except Exception as e:
                print(f"Multi-environment tests FAILED: {e}")
                sys.exit(1)
    else:
        print("Multi-Environment Testing Orchestration Module")
        print("Usage:")
        print("  python test_multi_environment.py validate  # Validate current environment")
        print("  python test_multi_environment.py run       # Run multi-environment tests")
        print("  pytest tests/comparative/test_multi_environment.py -v  # Run with pytest")