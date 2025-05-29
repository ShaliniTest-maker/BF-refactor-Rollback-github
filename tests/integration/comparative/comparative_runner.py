#!/usr/bin/env python3
"""
Orchestration script for coordinating comprehensive comparative testing between 
Node.js and Flask implementations.

This utility manages test execution sequencing, handles environment setup and teardown,
coordinates parallel system testing, and generates consolidated comparison reports 
for migration validation.

Key Features:
- tox 4.26.0 orchestration for multi-environment comparative testing per Section 4.7.2
- Parallel system testing coordination with automated Node.js and Flask environment management
- Automated test sequencing for API, performance, and workflow comparative validation
- Consolidated reporting with discrepancy analysis and migration status tracking
- Automated correction workflow triggering when parity failures are detected
- CI/CD pipeline integration for automated comparative testing during continuous integration

Requirements Compliance:
- Section 4.7.2: Comparative Testing Process with tox 4.26.0 multi-environment execution
- Section 8.4: CI/CD Pipeline integration for automated comparative validation
- Feature F-009: 100% functional equivalence validation through comprehensive testing
- Section 4.7.1: pytest-flask 1.3.0 and pytest-benchmark 5.1.0 integration
"""

import asyncio
import argparse
import json
import logging
import multiprocessing
import os
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import psutil
import yaml
from jinja2 import Template

# Import comparative testing utilities
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from tests.utils.comparative_testing import (
    TestEnvironmentConfig,
    ComparisonResult,
    FunctionalParityValidator,
    DiscrepancyDetector,
    ToxMultiEnvironmentRunner,
    ComparativeTestReporter,
    execute_comprehensive_comparative_testing
)

# Configure comprehensive logging for orchestration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(processName)s:%(threadName)s] - %(message)s',
    handlers=[
        logging.FileHandler('comparative_runner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class OrchestrationConfig:
    """
    Configuration container for comprehensive comparative testing orchestration.
    
    Manages all aspects of multi-environment testing, parallel execution,
    and reporting configuration per Section 4.7.2 requirements.
    """
    # System environment configuration
    nodejs_base_url: str = "http://localhost:3000"
    flask_base_url: str = "http://localhost:5000"
    environment_startup_timeout: int = 120  # 2 minutes
    environment_health_check_interval: int = 5  # 5 seconds
    
    # tox 4.26.0 multi-environment orchestration configuration
    tox_config_path: str = "tests/integration/comparative/tox-comparative.ini"
    tox_general_config_path: str = "tests/integration/tox.ini"
    tox_parallel_execution: bool = True
    tox_max_workers: int = 4
    tox_timeout: int = 1800  # 30 minutes
    
    # Test execution sequencing configuration
    test_sequence_stages: List[str] = field(default_factory=lambda: [
        "baseline_capture",
        "flask_validation", 
        "api_parity",
        "performance_comparison",
        "workflow_validation",
        "database_parity",
        "auth_validation",
        "parallel_systems",
        "discrepancy_analysis"
    ])
    
    # Parallel system testing coordination
    max_parallel_environments: int = 3
    system_coordination_timeout: int = 300  # 5 minutes
    real_time_monitoring: bool = True
    automated_environment_management: bool = True
    
    # Reporting and analysis configuration
    consolidated_report_formats: List[str] = field(default_factory=lambda: [
        "json", "html", "xml", "pdf"
    ])
    report_output_directory: str = "test-results/comparative-orchestration"
    discrepancy_threshold: float = 0.05  # 5% failure threshold
    critical_failure_threshold: float = 0.10  # 10% critical failure threshold
    
    # Automated correction workflow configuration
    correction_workflow_enabled: bool = True
    correction_trigger_threshold: float = 0.05  # 5% failure rate triggers correction
    correction_timeout: int = 600  # 10 minutes
    
    # CI/CD pipeline integration configuration
    ci_mode: bool = False
    ci_timeout: int = 3600  # 1 hour for CI execution
    ci_parallel_jobs: int = 2
    ci_report_format: str = "junit"
    github_actions_integration: bool = True
    
    # Environment management configuration
    node_process_management: bool = True
    flask_process_management: bool = True
    database_isolation: bool = True
    port_management: bool = True
    
    # Advanced orchestration features
    failure_fast_mode: bool = False
    retry_failed_tests: bool = True
    retry_attempts: int = 2
    detailed_logging: bool = True


@dataclass
class EnvironmentStatus:
    """Container for tracking environment health and operational status."""
    name: str
    process_id: Optional[int] = None
    port: Optional[int] = None
    base_url: Optional[str] = None
    healthy: bool = False
    startup_time: Optional[float] = None
    last_health_check: Optional[datetime] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert environment status to dictionary for reporting."""
        return {
            'name': self.name,
            'process_id': self.process_id,
            'port': self.port,
            'base_url': self.base_url,
            'healthy': self.healthy,
            'startup_time': self.startup_time,
            'last_health_check': self.last_health_check.isoformat() if self.last_health_check else None,
            'error_message': self.error_message
        }


@dataclass
class OrchestrationResult:
    """
    Container for comprehensive orchestration execution results.
    
    Captures all aspects of multi-environment testing, analysis results,
    and orchestration metadata for consolidated reporting.
    """
    orchestration_id: str
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    execution_time: Optional[float] = None
    
    # Environment management results
    environments: Dict[str, EnvironmentStatus] = field(default_factory=dict)
    environment_startup_success: bool = False
    
    # Test execution results
    test_stages: Dict[str, Any] = field(default_factory=dict)
    total_test_count: int = 0
    successful_test_count: int = 0
    failed_test_count: int = 0
    
    # Multi-environment tox results
    tox_execution_results: Dict[str, Any] = field(default_factory=dict)
    tox_environments_success_count: int = 0
    tox_environments_total_count: int = 0
    
    # Analysis and reporting results
    discrepancy_analysis: Dict[str, Any] = field(default_factory=dict)
    correction_workflow_triggered: bool = False
    correction_workflow_results: Dict[str, Any] = field(default_factory=dict)
    
    # Report generation results
    generated_reports: List[str] = field(default_factory=list)
    report_generation_success: bool = False
    
    # Overall orchestration status
    overall_success: bool = False
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert orchestration result to dictionary for comprehensive reporting."""
        return {
            'orchestration_id': self.orchestration_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'execution_time': self.execution_time,
            'environments': {name: env.to_dict() for name, env in self.environments.items()},
            'environment_startup_success': self.environment_startup_success,
            'test_stages': self.test_stages,
            'total_test_count': self.total_test_count,
            'successful_test_count': self.successful_test_count,
            'failed_test_count': self.failed_test_count,
            'tox_execution_results': self.tox_execution_results,
            'tox_environments_success_count': self.tox_environments_success_count,
            'tox_environments_total_count': self.tox_environments_total_count,
            'discrepancy_analysis': self.discrepancy_analysis,
            'correction_workflow_triggered': self.correction_workflow_triggered,
            'correction_workflow_results': self.correction_workflow_results,
            'generated_reports': self.generated_reports,
            'report_generation_success': self.report_generation_success,
            'overall_success': self.overall_success,
            'error_message': self.error_message
        }


class SystemEnvironmentManager:
    """
    Automated environment management for Node.js and Flask systems.
    
    Provides comprehensive lifecycle management including startup, health monitoring,
    coordination, and cleanup for both baseline and target systems.
    """
    
    def __init__(self, config: OrchestrationConfig):
        self.config = config
        self.environments: Dict[str, EnvironmentStatus] = {}
        self.processes: Dict[str, subprocess.Popen] = {}
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        
        # Create output directory for environment logs
        self.log_directory = Path(config.report_output_directory) / "environment-logs"
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        logger.info("Initialized SystemEnvironmentManager")
    
    async def startup_environments(self) -> bool:
        """
        Start Node.js and Flask environments with health monitoring.
        
        Returns:
            Success flag for environment startup coordination
        """
        logger.info("Starting comprehensive environment startup sequence")
        
        try:
            # Initialize environment status tracking
            self.environments['nodejs'] = EnvironmentStatus(
                name='nodejs',
                port=3000,
                base_url=self.config.nodejs_base_url
            )
            self.environments['flask'] = EnvironmentStatus(
                name='flask',
                port=5000,
                base_url=self.config.flask_base_url
            )
            
            # Start environments in parallel
            startup_tasks = [
                self._startup_nodejs_environment(),
                self._startup_flask_environment()
            ]
            
            startup_results = await asyncio.gather(*startup_tasks, return_exceptions=True)
            
            # Evaluate startup success
            nodejs_success = not isinstance(startup_results[0], Exception) and startup_results[0]
            flask_success = not isinstance(startup_results[1], Exception) and startup_results[1]
            
            if isinstance(startup_results[0], Exception):
                logger.error(f"Node.js startup failed: {startup_results[0]}")
                self.environments['nodejs'].error_message = str(startup_results[0])
            
            if isinstance(startup_results[1], Exception):
                logger.error(f"Flask startup failed: {startup_results[1]}")
                self.environments['flask'].error_message = str(startup_results[1])
            
            overall_success = nodejs_success and flask_success
            
            if overall_success:
                logger.info("Environment startup sequence completed successfully")
                # Start health monitoring
                await self._start_health_monitoring()
            else:
                logger.error("Environment startup sequence failed")
            
            return overall_success
            
        except Exception as e:
            logger.error(f"Environment startup sequence failed with exception: {e}")
            logger.error(traceback.format_exc())
            return False
    
    async def _startup_nodejs_environment(self) -> bool:
        """Start Node.js baseline environment with health validation."""
        logger.info("Starting Node.js baseline environment")
        
        try:
            # Check if Node.js is already running on the target port
            if self._is_port_in_use(3000):
                logger.info("Node.js appears to be already running on port 3000")
                # Verify it's actually responding
                if await self._check_environment_health('nodejs'):
                    self.environments['nodejs'].healthy = True
                    return True
                else:
                    logger.warning("Process on port 3000 is not responding correctly")
                    return False
            
            # Start Node.js development server (assuming package.json scripts)
            start_time = time.time()
            
            # Look for Node.js application entry point
            nodejs_entry_points = ['app.js', 'server.js', 'index.js']
            nodejs_entry = None
            
            for entry in nodejs_entry_points:
                if Path(entry).exists():
                    nodejs_entry = entry
                    break
            
            if not nodejs_entry:
                # Try npm start command
                node_cmd = ['npm', 'start']
                logger.info("Using npm start for Node.js environment")
            else:
                node_cmd = ['node', nodejs_entry]
                logger.info(f"Starting Node.js with entry point: {nodejs_entry}")
            
            # Start Node.js process
            node_log_file = self.log_directory / "nodejs_startup.log"
            with open(node_log_file, 'w') as log_file:
                process = subprocess.Popen(
                    node_cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    env={**os.environ, 'NODE_ENV': 'test', 'PORT': '3000'}
                )
            
            self.processes['nodejs'] = process
            self.environments['nodejs'].process_id = process.pid
            
            logger.info(f"Node.js process started with PID: {process.pid}")
            
            # Wait for startup and health validation
            startup_success = await self._wait_for_environment_health(
                'nodejs', 
                timeout=self.config.environment_startup_timeout
            )
            
            if startup_success:
                self.environments['nodejs'].startup_time = time.time() - start_time
                self.environments['nodejs'].healthy = True
                logger.info(f"Node.js environment ready in {self.environments['nodejs'].startup_time:.2f}s")
                return True
            else:
                logger.error("Node.js environment failed to become healthy")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start Node.js environment: {e}")
            self.environments['nodejs'].error_message = str(e)
            return False
    
    async def _startup_flask_environment(self) -> bool:
        """Start Flask target environment with health validation."""
        logger.info("Starting Flask target environment")
        
        try:
            # Check if Flask is already running on the target port
            if self._is_port_in_use(5000):
                logger.info("Flask appears to be already running on port 5000")
                # Verify it's actually responding
                if await self._check_environment_health('flask'):
                    self.environments['flask'].healthy = True
                    return True
                else:
                    logger.warning("Process on port 5000 is not responding correctly")
                    return False
            
            # Start Flask development server
            start_time = time.time()
            
            # Flask startup command using application factory
            flask_cmd = [
                'python', '-m', 'flask', 'run',
                '--host', '0.0.0.0',
                '--port', '5000',
                '--debug'
            ]
            
            # Flask environment configuration
            flask_env = {
                **os.environ,
                'FLASK_APP': 'src.app:create_app',
                'FLASK_ENV': 'testing',
                'FLASK_DEBUG': '1',
                'DATABASE_URL': 'sqlite:///test_comparative.db',
                'SECRET_KEY': 'test-secret-key-for-comparative-testing'
            }
            
            # Start Flask process
            flask_log_file = self.log_directory / "flask_startup.log"
            with open(flask_log_file, 'w') as log_file:
                process = subprocess.Popen(
                    flask_cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    env=flask_env,
                    cwd=str(Path.cwd())
                )
            
            self.processes['flask'] = process
            self.environments['flask'].process_id = process.pid
            
            logger.info(f"Flask process started with PID: {process.pid}")
            
            # Wait for startup and health validation
            startup_success = await self._wait_for_environment_health(
                'flask',
                timeout=self.config.environment_startup_timeout
            )
            
            if startup_success:
                self.environments['flask'].startup_time = time.time() - start_time
                self.environments['flask'].healthy = True
                logger.info(f"Flask environment ready in {self.environments['flask'].startup_time:.2f}s")
                return True
            else:
                logger.error("Flask environment failed to become healthy")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start Flask environment: {e}")
            self.environments['flask'].error_message = str(e)
            return False
    
    def _is_port_in_use(self, port: int) -> bool:
        """Check if a port is currently in use."""
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                    return True
            return False
        except Exception:
            return False
    
    async def _wait_for_environment_health(self, env_name: str, timeout: int) -> bool:
        """Wait for environment to become healthy with timeout."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if await self._check_environment_health(env_name):
                return True
            
            await asyncio.sleep(self.config.environment_health_check_interval)
        
        logger.error(f"Environment {env_name} failed to become healthy within {timeout}s")
        return False
    
    async def _check_environment_health(self, env_name: str) -> bool:
        """Check if environment is responding to health checks."""
        env = self.environments.get(env_name)
        if not env or not env.base_url:
            return False
        
        try:
            import aiohttp
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                health_url = f"{env.base_url}/health"
                async with session.get(health_url) as response:
                    if response.status == 200:
                        env.last_health_check = datetime.now(timezone.utc)
                        return True
                    else:
                        logger.warning(f"{env_name} health check returned status {response.status}")
                        return False
                        
        except Exception as e:
            logger.debug(f"{env_name} health check failed: {e}")
            return False
    
    async def _start_health_monitoring(self):
        """Start continuous health monitoring for all environments."""
        logger.info("Starting continuous health monitoring")
        
        for env_name in self.environments.keys():
            task = asyncio.create_task(self._monitor_environment_health(env_name))
            self.monitoring_tasks[env_name] = task
    
    async def _monitor_environment_health(self, env_name: str):
        """Continuously monitor environment health."""
        while True:
            try:
                healthy = await self._check_environment_health(env_name)
                self.environments[env_name].healthy = healthy
                
                if not healthy:
                    logger.warning(f"Environment {env_name} health check failed")
                
                await asyncio.sleep(self.config.environment_health_check_interval)
                
            except asyncio.CancelledError:
                logger.info(f"Health monitoring stopped for {env_name}")
                break
            except Exception as e:
                logger.error(f"Health monitoring error for {env_name}: {e}")
                await asyncio.sleep(self.config.environment_health_check_interval)
    
    def get_environment_status(self) -> Dict[str, Dict[str, Any]]:
        """Get current status of all managed environments."""
        return {name: env.to_dict() for name, env in self.environments.items()}
    
    async def cleanup_environments(self):
        """Clean up all managed environments and processes."""
        logger.info("Starting environment cleanup")
        
        # Stop health monitoring
        for task in self.monitoring_tasks.values():
            task.cancel()
        
        # Wait for monitoring tasks to complete
        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks.values(), return_exceptions=True)
        
        # Terminate processes
        for name, process in self.processes.items():
            try:
                if process.poll() is None:  # Process is still running
                    logger.info(f"Terminating {name} process (PID: {process.pid})")
                    process.terminate()
                    
                    # Wait for graceful termination
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Force killing {name} process")
                        process.kill()
                        process.wait()
            except Exception as e:
                logger.error(f"Error cleaning up {name} process: {e}")
        
        self.processes.clear()
        logger.info("Environment cleanup completed")


class TestSequenceOrchestrator:
    """
    Orchestrates automated test sequencing for comprehensive comparative validation.
    
    Manages the execution of API, performance, workflow, and integration tests
    in a systematic sequence ensuring complete migration validation coverage.
    """
    
    def __init__(self, config: OrchestrationConfig, env_manager: SystemEnvironmentManager):
        self.config = config
        self.env_manager = env_manager
        self.sequence_results: Dict[str, Any] = {}
        
        # Initialize test stage configurations
        self.test_stage_configs = {
            'baseline_capture': {
                'tox_env': 'nodejs-baseline-capture',
                'test_modules': ['tests/integration/comparative/baseline_capture.py'],
                'timeout': 300,
                'critical': True
            },
            'flask_validation': {
                'tox_env': 'flask-target-validation',
                'test_modules': ['tests/integration/comparative/test_flask_readiness.py'],
                'timeout': 300,
                'critical': True
            },
            'api_parity': {
                'tox_env': 'comparative-api-parity',
                'test_modules': ['tests/integration/comparative/test_comparative_api.py'],
                'timeout': 600,
                'critical': True
            },
            'performance_comparison': {
                'tox_env': 'comparative-performance',
                'test_modules': ['tests/integration/comparative/test_comparative_performance.py'],
                'timeout': 900,
                'critical': False
            },
            'workflow_validation': {
                'tox_env': 'comparative-workflows',
                'test_modules': ['tests/integration/comparative/test_comparative_workflows.py'],
                'timeout': 600,
                'critical': True
            },
            'database_parity': {
                'tox_env': 'comparative-database',
                'test_modules': ['tests/integration/comparative/test_database_parity.py'],
                'timeout': 450,
                'critical': True
            },
            'auth_validation': {
                'tox_env': 'comparative-auth',
                'test_modules': ['tests/integration/comparative/test_auth_parity.py'],
                'timeout': 300,
                'critical': True
            },
            'parallel_systems': {
                'tox_env': 'parallel-systems-validation',
                'test_modules': ['tests/integration/comparative/test_parallel_systems.py'],
                'timeout': 600,
                'critical': False
            },
            'discrepancy_analysis': {
                'tox_env': 'discrepancy-analysis',
                'test_modules': ['tests/integration/comparative/results_analyzer.py'],
                'timeout': 300,
                'critical': True
            }
        }
        
        logger.info("Initialized TestSequenceOrchestrator")
    
    async def execute_test_sequence(self) -> Dict[str, Any]:
        """
        Execute the complete test sequence with systematic staging.
        
        Returns:
            Comprehensive test sequence execution results
        """
        logger.info(f"Starting test sequence execution with {len(self.config.test_sequence_stages)} stages")
        
        sequence_start_time = time.time()
        sequence_results = {
            'total_stages': len(self.config.test_sequence_stages),
            'completed_stages': 0,
            'successful_stages': 0,
            'failed_stages': 0,
            'stage_results': {},
            'overall_success': False,
            'execution_time': 0,
            'critical_failures': []
        }
        
        try:
            # Execute each stage in sequence
            for stage_name in self.config.test_sequence_stages:
                logger.info(f"Executing test stage: {stage_name}")
                
                stage_config = self.test_stage_configs.get(stage_name)
                if not stage_config:
                    logger.error(f"Unknown test stage: {stage_name}")
                    continue
                
                # Verify environment health before stage execution
                if not await self._verify_environment_health():
                    logger.error(f"Environment health check failed before stage {stage_name}")
                    if stage_config.get('critical', False):
                        sequence_results['critical_failures'].append(stage_name)
                        if self.config.failure_fast_mode:
                            break
                    continue
                
                stage_result = await self._execute_test_stage(stage_name, stage_config)
                sequence_results['stage_results'][stage_name] = stage_result
                sequence_results['completed_stages'] += 1
                
                if stage_result.get('success', False):
                    sequence_results['successful_stages'] += 1
                    logger.info(f"Test stage {stage_name} completed successfully")
                else:
                    sequence_results['failed_stages'] += 1
                    logger.error(f"Test stage {stage_name} failed")
                    
                    if stage_config.get('critical', False):
                        sequence_results['critical_failures'].append(stage_name)
                        if self.config.failure_fast_mode:
                            logger.error("Critical stage failed - stopping test sequence")
                            break
                
                # Brief pause between stages for system stability
                await asyncio.sleep(2)
            
            # Calculate overall success
            critical_stage_count = sum(
                1 for stage in self.config.test_sequence_stages 
                if self.test_stage_configs.get(stage, {}).get('critical', False)
            )
            critical_failures = len(sequence_results['critical_failures'])
            
            sequence_results['overall_success'] = (
                critical_failures == 0 and 
                sequence_results['failed_stages'] <= self.config.discrepancy_threshold * sequence_results['total_stages']
            )
            
            sequence_results['execution_time'] = time.time() - sequence_start_time
            
            logger.info(f"Test sequence execution completed - Success: {sequence_results['overall_success']}")
            logger.info(f"Stage results: {sequence_results['successful_stages']}/{sequence_results['total_stages']} successful")
            
        except Exception as e:
            logger.error(f"Test sequence execution failed with exception: {e}")
            logger.error(traceback.format_exc())
            sequence_results['error'] = str(e)
        
        return sequence_results
    
    async def _execute_test_stage(self, stage_name: str, stage_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an individual test stage with tox environment."""
        stage_start_time = time.time()
        stage_result = {
            'stage_name': stage_name,
            'tox_environment': stage_config['tox_env'],
            'test_modules': stage_config['test_modules'],
            'success': False,
            'execution_time': 0,
            'tox_results': {},
            'retry_attempts': 0
        }
        
        max_attempts = self.config.retry_attempts + 1 if self.config.retry_failed_tests else 1
        
        for attempt in range(max_attempts):
            try:
                if attempt > 0:
                    logger.info(f"Retrying stage {stage_name} (attempt {attempt + 1}/{max_attempts})")
                    stage_result['retry_attempts'] = attempt
                
                # Execute tox environment
                tox_cmd = [
                    'tox', 
                    '-e', stage_config['tox_env'],
                    '-c', self.config.tox_config_path,
                    '--'
                ] + stage_config['test_modules']
                
                logger.info(f"Executing tox command: {' '.join(tox_cmd)}")
                
                # Execute with timeout
                process = await asyncio.create_subprocess_exec(
                    *tox_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(Path.cwd())
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=stage_config.get('timeout', 600)
                    )
                    
                    stage_result['tox_results'] = {
                        'return_code': process.returncode,
                        'stdout': stdout.decode('utf-8', errors='ignore'),
                        'stderr': stderr.decode('utf-8', errors='ignore')
                    }
                    
                    if process.returncode == 0:
                        stage_result['success'] = True
                        logger.info(f"Stage {stage_name} completed successfully on attempt {attempt + 1}")
                        break
                    else:
                        logger.warning(f"Stage {stage_name} failed with return code {process.returncode}")
                        
                except asyncio.TimeoutError:
                    logger.error(f"Stage {stage_name} timed out after {stage_config.get('timeout', 600)}s")
                    process.kill()
                    await process.wait()
                    stage_result['tox_results'] = {'error': 'Execution timeout'}
                
            except Exception as e:
                logger.error(f"Stage {stage_name} execution failed on attempt {attempt + 1}: {e}")
                stage_result['tox_results'] = {'error': str(e)}
        
        stage_result['execution_time'] = time.time() - stage_start_time
        return stage_result
    
    async def _verify_environment_health(self) -> bool:
        """Verify that both environments are healthy before test execution."""
        env_status = self.env_manager.get_environment_status()
        
        nodejs_healthy = env_status.get('nodejs', {}).get('healthy', False)
        flask_healthy = env_status.get('flask', {}).get('healthy', False)
        
        if not nodejs_healthy:
            logger.warning("Node.js environment is not healthy")
        if not flask_healthy:
            logger.warning("Flask environment is not healthy")
        
        return nodejs_healthy and flask_healthy


class ToxMultiEnvironmentOrchestrator:
    """
    Advanced tox 4.26.0 multi-environment orchestration for comprehensive testing.
    
    Manages parallel tox environment execution, dependency coordination,
    and comprehensive results aggregation per Section 4.7.2 requirements.
    """
    
    def __init__(self, config: OrchestrationConfig):
        self.config = config
        self.executor = ProcessPoolExecutor(max_workers=config.tox_max_workers)
        self.tox_environments = [
            'py313-integration',
            'py313-performance', 
            'py313-comparative',
            'py313-coverage',
            'py313-flask311',
            'py313-sqlalchemy',
            'py313-parallel'
        ]
        
        logger.info(f"Initialized ToxMultiEnvironmentOrchestrator with {config.tox_max_workers} workers")
    
    async def execute_multi_environment_testing(self) -> Dict[str, Any]:
        """
        Execute comprehensive multi-environment testing using tox 4.26.0.
        
        Returns:
            Comprehensive multi-environment execution results
        """
        logger.info(f"Starting multi-environment testing across {len(self.tox_environments)} environments")
        
        execution_start_time = time.time()
        results = {
            'total_environments': len(self.tox_environments),
            'successful_environments': 0,
            'failed_environments': 0,
            'environment_results': {},
            'overall_success': False,
            'execution_time': 0,
            'parallel_execution': self.config.tox_parallel_execution
        }
        
        try:
            if self.config.tox_parallel_execution:
                # Execute environments in parallel
                results['environment_results'] = await self._execute_parallel_environments()
            else:
                # Execute environments sequentially
                results['environment_results'] = await self._execute_sequential_environments()
            
            # Analyze results
            for env_name, env_result in results['environment_results'].items():
                if env_result.get('success', False):
                    results['successful_environments'] += 1
                else:
                    results['failed_environments'] += 1
            
            # Determine overall success
            success_rate = results['successful_environments'] / results['total_environments']
            results['overall_success'] = success_rate >= (1.0 - self.config.discrepancy_threshold)
            results['execution_time'] = time.time() - execution_start_time
            
            logger.info(f"Multi-environment testing completed - Success rate: {success_rate:.2%}")
            
        except Exception as e:
            logger.error(f"Multi-environment testing failed: {e}")
            logger.error(traceback.format_exc())
            results['error'] = str(e)
        
        return results
    
    async def _execute_parallel_environments(self) -> Dict[str, Any]:
        """Execute tox environments in parallel using ProcessPoolExecutor."""
        loop = asyncio.get_event_loop()
        futures = []
        
        # Submit all environment executions
        for env_name in self.tox_environments:
            future = loop.run_in_executor(
                self.executor,
                self._execute_single_tox_environment,
                env_name
            )
            futures.append((env_name, future))
        
        # Collect results as they complete
        environment_results = {}
        
        for env_name, future in futures:
            try:
                result = await asyncio.wait_for(future, timeout=self.config.tox_timeout)
                environment_results[env_name] = result
                logger.info(f"Environment {env_name} completed")
            except asyncio.TimeoutError:
                logger.error(f"Environment {env_name} timed out")
                environment_results[env_name] = {
                    'success': False,
                    'error': 'Execution timeout',
                    'timeout': True
                }
            except Exception as e:
                logger.error(f"Environment {env_name} failed: {e}")
                environment_results[env_name] = {
                    'success': False,
                    'error': str(e)
                }
        
        return environment_results
    
    async def _execute_sequential_environments(self) -> Dict[str, Any]:
        """Execute tox environments sequentially."""
        environment_results = {}
        
        for env_name in self.tox_environments:
            logger.info(f"Executing environment: {env_name}")
            
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    self.executor,
                    self._execute_single_tox_environment,
                    env_name
                )
                environment_results[env_name] = result
                
                if result.get('success', False):
                    logger.info(f"Environment {env_name} completed successfully")
                else:
                    logger.error(f"Environment {env_name} failed")
                    
                    # Check for critical failure threshold
                    if len([r for r in environment_results.values() if not r.get('success', False)]) > \
                       self.config.critical_failure_threshold * len(self.tox_environments):
                        logger.error("Critical failure threshold exceeded - stopping sequential execution")
                        break
                        
            except Exception as e:
                logger.error(f"Environment {env_name} execution failed: {e}")
                environment_results[env_name] = {
                    'success': False,
                    'error': str(e)
                }
        
        return environment_results
    
    def _execute_single_tox_environment(self, env_name: str) -> Dict[str, Any]:
        """Execute a single tox environment synchronously."""
        start_time = time.time()
        
        try:
            # Construct tox command
            tox_cmd = [
                'tox',
                '-e', env_name,
                '-c', self.config.tox_general_config_path
            ]
            
            # Execute tox command
            process = subprocess.run(
                tox_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.tox_timeout,
                cwd=str(Path.cwd())
            )
            
            execution_time = time.time() - start_time
            
            # Parse test results from output
            test_results = self._parse_tox_output(process.stdout)
            
            return {
                'success': process.returncode == 0,
                'return_code': process.returncode,
                'execution_time': execution_time,
                'stdout': process.stdout,
                'stderr': process.stderr,
                'test_results': test_results,
                'environment': env_name
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Tox environment {env_name} timed out',
                'execution_time': self.config.tox_timeout,
                'environment': env_name
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to execute tox environment {env_name}: {str(e)}',
                'execution_time': time.time() - start_time,
                'environment': env_name
            }
    
    def _parse_tox_output(self, output: str) -> Dict[str, Any]:
        """Parse tox output to extract test statistics."""
        test_results = {
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'skipped_tests': 0,
            'error_tests': 0
        }
        
        try:
            lines = output.split('\n')
            for line in lines:
                # Look for pytest summary lines
                if 'passed' in line or 'failed' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        try:
                            if part == 'passed' and i > 0:
                                test_results['passed_tests'] += int(parts[i-1])
                            elif part == 'failed' and i > 0:
                                test_results['failed_tests'] += int(parts[i-1])
                            elif part == 'skipped' and i > 0:
                                test_results['skipped_tests'] += int(parts[i-1])
                            elif part == 'error' and i > 0:
                                test_results['error_tests'] += int(parts[i-1])
                        except (ValueError, IndexError):
                            continue
            
            test_results['total_tests'] = (
                test_results['passed_tests'] + 
                test_results['failed_tests'] + 
                test_results['skipped_tests'] + 
                test_results['error_tests']
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse tox output: {e}")
        
        return test_results
    
    def cleanup(self):
        """Clean up executor resources."""
        self.executor.shutdown(wait=True)


class ConsolidatedReportGenerator:
    """
    Comprehensive report generation for consolidated comparative testing results.
    
    Generates multiple report formats with detailed analysis, discrepancy tracking,
    and actionable recommendations for migration validation.
    """
    
    def __init__(self, config: OrchestrationConfig):
        self.config = config
        
        # Ensure output directory exists
        self.output_dir = Path(config.report_output_directory)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initialized ConsolidatedReportGenerator - Output: {self.output_dir}")
    
    def generate_comprehensive_report(
        self,
        orchestration_result: OrchestrationResult,
        test_sequence_results: Dict[str, Any],
        multi_env_results: Dict[str, Any],
        discrepancy_analysis: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Generate comprehensive consolidated reports in multiple formats.
        
        Args:
            orchestration_result: Overall orchestration execution results
            test_sequence_results: Test sequence stage results
            multi_env_results: Multi-environment tox execution results
            discrepancy_analysis: Optional discrepancy analysis results
            
        Returns:
            List of generated report file paths
        """
        logger.info("Generating comprehensive consolidated reports")
        
        generated_reports = []
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Prepare consolidated report data
        report_data = {
            'report_metadata': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'orchestration_id': orchestration_result.orchestration_id,
                'report_version': '2.0',
                'generator': 'ComparativeTestingOrchestrator'
            },
            'executive_summary': self._generate_executive_summary(
                orchestration_result, test_sequence_results, multi_env_results
            ),
            'orchestration_results': orchestration_result.to_dict(),
            'test_sequence_results': test_sequence_results,
            'multi_environment_results': multi_env_results,
            'discrepancy_analysis': discrepancy_analysis or {},
            'recommendations': self._generate_actionable_recommendations(
                orchestration_result, test_sequence_results, multi_env_results
            )
        }
        
        try:
            # Generate reports in requested formats
            for report_format in self.config.consolidated_report_formats:
                report_path = self._generate_format_specific_report(
                    report_data, report_format, timestamp
                )
                if report_path:
                    generated_reports.append(str(report_path))
            
            logger.info(f"Generated {len(generated_reports)} consolidated reports")
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            logger.error(traceback.format_exc())
        
        return generated_reports
    
    def _generate_executive_summary(
        self,
        orchestration_result: OrchestrationResult,
        test_sequence_results: Dict[str, Any],
        multi_env_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate executive summary of all testing results."""
        
        # Calculate overall success metrics
        total_tests = (
            orchestration_result.total_test_count + 
            sum(
                env_result.get('test_results', {}).get('total_tests', 0)
                for env_result in multi_env_results.get('environment_results', {}).values()
            )
        )
        
        successful_tests = (
            orchestration_result.successful_test_count +
            sum(
                env_result.get('test_results', {}).get('passed_tests', 0)
                for env_result in multi_env_results.get('environment_results', {}).values()
            )
        )
        
        overall_success_rate = successful_tests / total_tests if total_tests > 0 else 0.0
        
        return {
            'migration_readiness': overall_success_rate >= 0.95,
            'overall_success_rate': overall_success_rate,
            'parity_validation_status': 'ACHIEVED' if overall_success_rate >= 0.95 else 'REQUIRES_ATTENTION',
            'total_test_count': total_tests,
            'successful_test_count': successful_tests,
            'failed_test_count': total_tests - successful_tests,
            'environment_startup_success': orchestration_result.environment_startup_success,
            'test_sequence_completion': test_sequence_results.get('overall_success', False),
            'multi_environment_success': multi_env_results.get('overall_success', False),
            'correction_workflow_triggered': orchestration_result.correction_workflow_triggered,
            'critical_issues_detected': len(test_sequence_results.get('critical_failures', [])),
            'execution_time_total': (
                orchestration_result.execution_time or 0 +
                test_sequence_results.get('execution_time', 0) +
                multi_env_results.get('execution_time', 0)
            ),
            'recommendation_priority': 'HIGH' if overall_success_rate < 0.90 else 'MEDIUM' if overall_success_rate < 0.95 else 'LOW'
        }
    
    def _generate_actionable_recommendations(
        self,
        orchestration_result: OrchestrationResult,
        test_sequence_results: Dict[str, Any],
        multi_env_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on test results."""
        recommendations = []
        
        # Environment startup recommendations
        if not orchestration_result.environment_startup_success:
            recommendations.append({
                'category': 'Environment Management',
                'priority': 'HIGH',
                'title': 'Environment Startup Failures Detected',
                'description': 'One or more test environments failed to start properly',
                'actions': [
                    'Verify Node.js and Flask application configurations',
                    'Check port availability and process conflicts',
                    'Review environment startup logs for specific errors',
                    'Validate database connectivity and configuration'
                ]
            })
        
        # Test sequence recommendations
        critical_failures = test_sequence_results.get('critical_failures', [])
        if critical_failures:
            recommendations.append({
                'category': 'Test Execution',
                'priority': 'HIGH',
                'title': f'Critical Test Stage Failures: {len(critical_failures)} stages',
                'description': f'Critical test stages failed: {", ".join(critical_failures)}',
                'actions': [
                    'Review failed test stage logs for root cause analysis',
                    'Validate Flask implementation against Node.js baseline',
                    'Check Service Layer business logic implementation',
                    'Verify database model relationships and query equivalence'
                ]
            })
        
        # Multi-environment recommendations
        env_success_rate = (
            multi_env_results.get('successful_environments', 0) / 
            multi_env_results.get('total_environments', 1)
        )
        if env_success_rate < 0.90:
            recommendations.append({
                'category': 'Multi-Environment Testing',
                'priority': 'MEDIUM',
                'title': 'Multi-Environment Testing Issues',
                'description': f'Environment success rate: {env_success_rate:.1%}',
                'actions': [
                    'Review tox configuration for environment compatibility',
                    'Validate Python 3.13.3 and Flask 3.1.1 dependencies',
                    'Check virtual environment isolation and package conflicts',
                    'Review environment-specific test execution logs'
                ]
            })
        
        # Performance recommendations
        performance_issues = any(
            'performance' in stage_name.lower() and not stage_result.get('success', False)
            for stage_name, stage_result in test_sequence_results.get('stage_results', {}).items()
        )
        if performance_issues:
            recommendations.append({
                'category': 'Performance Optimization',
                'priority': 'MEDIUM',
                'title': 'Performance Benchmark Failures',
                'description': 'Flask implementation performance does not meet Node.js baseline',
                'actions': [
                    'Optimize Flask-SQLAlchemy query patterns and indexing',
                    'Review Flask application factory configuration',
                    'Implement Flask response caching where appropriate',
                    'Profile memory usage and optimize Service Layer patterns'
                ]
            })
        
        # General improvement recommendations
        overall_success = (
            orchestration_result.overall_success and
            test_sequence_results.get('overall_success', False) and
            multi_env_results.get('overall_success', False)
        )
        
        if not overall_success:
            recommendations.append({
                'category': 'General Migration',
                'priority': 'HIGH',
                'title': 'Migration Validation Incomplete',
                'description': 'Overall comparative testing validation has not achieved 95% success threshold',
                'actions': [
                    'Execute automated correction workflow for Flask implementation adjustment',
                    'Review comprehensive discrepancy analysis for specific issues',
                    'Validate API contract compliance and response format equivalence',
                    'Ensure database migration and model relationship preservation',
                    'Re-run comparative testing after implementing corrections'
                ]
            })
        
        return recommendations
    
    def _generate_format_specific_report(
        self,
        report_data: Dict[str, Any],
        report_format: str,
        timestamp: str
    ) -> Optional[Path]:
        """Generate report in specific format."""
        try:
            if report_format == 'json':
                return self._generate_json_report(report_data, timestamp)
            elif report_format == 'html':
                return self._generate_html_report(report_data, timestamp)
            elif report_format == 'xml':
                return self._generate_xml_report(report_data, timestamp)
            elif report_format == 'pdf':
                return self._generate_pdf_report(report_data, timestamp)
            else:
                logger.warning(f"Unsupported report format: {report_format}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to generate {report_format} report: {e}")
            return None
    
    def _generate_json_report(self, report_data: Dict[str, Any], timestamp: str) -> Path:
        """Generate comprehensive JSON report."""
        report_path = self.output_dir / f"comparative_testing_report_{timestamp}.json"
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"Generated JSON report: {report_path}")
        return report_path
    
    def _generate_html_report(self, report_data: Dict[str, Any], timestamp: str) -> Path:
        """Generate comprehensive HTML report."""
        report_path = self.output_dir / f"comparative_testing_report_{timestamp}.html"
        
        # HTML template
        html_template = Template("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comparative Testing Report - {{ timestamp }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; }
        .success { border-left-color: #28a745; }
        .warning { border-left-color: #ffc107; }
        .error { border-left-color: #dc3545; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #007bff; border-bottom: 1px solid #dee2e6; padding-bottom: 10px; }
        .recommendations { background-color: #fff3cd; padding: 15px; border-radius: 5px; border: 1px solid #ffeaa7; }
        .recommendation { margin-bottom: 15px; padding: 10px; background-color: white; border-radius: 3px; }
        .high-priority { border-left: 4px solid #dc3545; }
        .medium-priority { border-left: 4px solid #ffc107; }
        .low-priority { border-left: 4px solid #28a745; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; font-size: 12px; }
        .status-badge { padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
        .status-success { background-color: #d4edda; color: #155724; }
        .status-failure { background-color: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Comparative Testing Report</h1>
            <p>Node.js to Flask Migration Validation</p>
            <p><strong>Generated:</strong> {{ report_data.report_metadata.timestamp }}</p>
            <p><strong>Orchestration ID:</strong> {{ report_data.orchestration_results.orchestration_id }}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card {% if report_data.executive_summary.migration_readiness %}success{% else %}error{% endif %}">
                <h3>Migration Readiness</h3>
                <p><strong>{{ 'READY' if report_data.executive_summary.migration_readiness else 'NOT READY' }}</strong></p>
                <p>Success Rate: {{ "%.1f" | format(report_data.executive_summary.overall_success_rate * 100) }}%</p>
            </div>
            
            <div class="summary-card">
                <h3>Test Results</h3>
                <p>Total Tests: {{ report_data.executive_summary.total_test_count }}</p>
                <p>Successful: {{ report_data.executive_summary.successful_test_count }}</p>
                <p>Failed: {{ report_data.executive_summary.failed_test_count }}</p>
            </div>
            
            <div class="summary-card {% if report_data.executive_summary.environment_startup_success %}success{% else %}error{% endif %}">
                <h3>Environment Status</h3>
                <p>Startup: <span class="status-badge {% if report_data.executive_summary.environment_startup_success %}status-success{% else %}status-failure{% endif %}">
                    {{ 'SUCCESS' if report_data.executive_summary.environment_startup_success else 'FAILED' }}
                </span></p>
            </div>
            
            <div class="summary-card">
                <h3>Execution Time</h3>
                <p>Total: {{ "%.1f" | format(report_data.executive_summary.execution_time_total) }}s</p>
                <p>{{ "%.1f" | format(report_data.executive_summary.execution_time_total / 60) }} minutes</p>
            </div>
        </div>
        
        {% if report_data.recommendations %}
        <div class="section">
            <h2>Recommendations</h2>
            <div class="recommendations">
                {% for rec in report_data.recommendations %}
                <div class="recommendation {{ rec.priority.lower() }}-priority">
                    <h4>{{ rec.title }} <small>[{{ rec.priority }}]</small></h4>
                    <p><strong>Category:</strong> {{ rec.category }}</p>
                    <p>{{ rec.description }}</p>
                    {% if rec.actions %}
                    <ul>
                        {% for action in rec.actions %}
                        <li>{{ action }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        <div class="section">
            <h2>Test Sequence Results</h2>
            <p>Completed Stages: {{ report_data.test_sequence_results.completed_stages }}/{{ report_data.test_sequence_results.total_stages }}</p>
            <p>Successful: {{ report_data.test_sequence_results.successful_stages }}, Failed: {{ report_data.test_sequence_results.failed_stages }}</p>
            {% if report_data.test_sequence_results.critical_failures %}
            <p><strong>Critical Failures:</strong> {{ report_data.test_sequence_results.critical_failures | join(', ') }}</p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Multi-Environment Results</h2>
            <p>Total Environments: {{ report_data.multi_environment_results.total_environments }}</p>
            <p>Successful: {{ report_data.multi_environment_results.successful_environments }}, Failed: {{ report_data.multi_environment_results.failed_environments }}</p>
        </div>
        
        <div class="section">
            <h2>Environment Status</h2>
            {% for env_name, env_data in report_data.orchestration_results.environments.items() %}
            <h4>{{ env_name.title() }} Environment</h4>
            <ul>
                <li>Status: <span class="status-badge {% if env_data.healthy %}status-success{% else %}status-failure{% endif %}">
                    {{ 'HEALTHY' if env_data.healthy else 'UNHEALTHY' }}
                </span></li>
                <li>Base URL: {{ env_data.base_url or 'N/A' }}</li>
                <li>Process ID: {{ env_data.process_id or 'N/A' }}</li>
                {% if env_data.startup_time %}
                <li>Startup Time: {{ "%.2f" | format(env_data.startup_time) }}s</li>
                {% endif %}
                {% if env_data.error_message %}
                <li><strong>Error:</strong> {{ env_data.error_message }}</li>
                {% endif %}
            </ul>
            {% endfor %}
        </div>
    </div>
</body>
</html>
        """)
        
        html_content = html_template.render(
            report_data=report_data,
            timestamp=timestamp
        )
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"Generated HTML report: {report_path}")
        return report_path
    
    def _generate_xml_report(self, report_data: Dict[str, Any], timestamp: str) -> Path:
        """Generate XML report compatible with CI/CD systems."""
        report_path = self.output_dir / f"comparative_testing_report_{timestamp}.xml"
        
        # Simple XML generation (could use lxml for more complex needs)
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<comparative_testing_report>
    <metadata>
        <timestamp>{report_data['report_metadata']['timestamp']}</timestamp>
        <orchestration_id>{report_data['orchestration_results']['orchestration_id']}</orchestration_id>
        <generator>{report_data['report_metadata']['generator']}</generator>
    </metadata>
    
    <executive_summary>
        <migration_readiness>{report_data['executive_summary']['migration_readiness']}</migration_readiness>
        <overall_success_rate>{report_data['executive_summary']['overall_success_rate']}</overall_success_rate>
        <total_test_count>{report_data['executive_summary']['total_test_count']}</total_test_count>
        <successful_test_count>{report_data['executive_summary']['successful_test_count']}</successful_test_count>
        <failed_test_count>{report_data['executive_summary']['failed_test_count']}</failed_test_count>
    </executive_summary>
    
    <test_sequence_results>
        <total_stages>{report_data['test_sequence_results']['total_stages']}</total_stages>
        <successful_stages>{report_data['test_sequence_results']['successful_stages']}</successful_stages>
        <failed_stages>{report_data['test_sequence_results']['failed_stages']}</failed_stages>
        <overall_success>{report_data['test_sequence_results']['overall_success']}</overall_success>
    </test_sequence_results>
    
    <multi_environment_results>
        <total_environments>{report_data['multi_environment_results']['total_environments']}</total_environments>
        <successful_environments>{report_data['multi_environment_results']['successful_environments']}</successful_environments>
        <failed_environments>{report_data['multi_environment_results']['failed_environments']}</failed_environments>
        <overall_success>{report_data['multi_environment_results']['overall_success']}</overall_success>
    </multi_environment_results>
</comparative_testing_report>"""
        
        with open(report_path, 'w') as f:
            f.write(xml_content)
        
        logger.info(f"Generated XML report: {report_path}")
        return report_path
    
    def _generate_pdf_report(self, report_data: Dict[str, Any], timestamp: str) -> Path:
        """Generate PDF report (simplified version)."""
        report_path = self.output_dir / f"comparative_testing_report_{timestamp}.pdf"
        
        # For now, generate a text-based report that could be converted to PDF
        # In a full implementation, would use libraries like reportlab or weasyprint
        text_content = f"""
COMPARATIVE TESTING REPORT
=========================

Generated: {report_data['report_metadata']['timestamp']}
Orchestration ID: {report_data['orchestration_results']['orchestration_id']}

EXECUTIVE SUMMARY
================

Migration Readiness: {'READY' if report_data['executive_summary']['migration_readiness'] else 'NOT READY'}
Overall Success Rate: {report_data['executive_summary']['overall_success_rate']:.1%}
Total Tests: {report_data['executive_summary']['total_test_count']}
Successful Tests: {report_data['executive_summary']['successful_test_count']}
Failed Tests: {report_data['executive_summary']['failed_test_count']}

TEST SEQUENCE RESULTS
====================

Total Stages: {report_data['test_sequence_results']['total_stages']}
Completed Stages: {report_data['test_sequence_results']['completed_stages']}
Successful Stages: {report_data['test_sequence_results']['successful_stages']}
Failed Stages: {report_data['test_sequence_results']['failed_stages']}

MULTI-ENVIRONMENT RESULTS
=========================

Total Environments: {report_data['multi_environment_results']['total_environments']}
Successful Environments: {report_data['multi_environment_results']['successful_environments']}
Failed Environments: {report_data['multi_environment_results']['failed_environments']}

RECOMMENDATIONS
===============

"""
        
        for rec in report_data.get('recommendations', []):
            text_content += f"""
{rec['title']} [{rec['priority']}]
Category: {rec['category']}
{rec['description']}

Actions:
"""
            for action in rec.get('actions', []):
                text_content += f"- {action}\n"
            text_content += "\n"
        
        # Save as text file with .pdf extension for now
        with open(report_path, 'w') as f:
            f.write(text_content)
        
        logger.info(f"Generated PDF report (text format): {report_path}")
        return report_path


class ComparativeTestingOrchestrator:
    """
    Main orchestration class coordinating comprehensive comparative testing.
    
    This is the primary entry point for Section 4.7.2 comparative testing process,
    managing all aspects of multi-environment testing, parallel system coordination,
    and consolidated reporting for migration validation.
    """
    
    def __init__(self, config: Optional[OrchestrationConfig] = None):
        self.config = config or OrchestrationConfig()
        self.orchestration_id = f"orchestration_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"
        
        # Initialize orchestration components
        self.env_manager = SystemEnvironmentManager(self.config)
        self.test_orchestrator = TestSequenceOrchestrator(self.config, self.env_manager)
        self.tox_orchestrator = ToxMultiEnvironmentOrchestrator(self.config)
        self.report_generator = ConsolidatedReportGenerator(self.config)
        
        # Initialize orchestration result tracking
        self.result = OrchestrationResult(orchestration_id=self.orchestration_id)
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info(f"Initialized ComparativeTestingOrchestrator - ID: {self.orchestration_id}")
    
    async def execute_comprehensive_comparative_testing(self) -> Dict[str, Any]:
        """
        Execute comprehensive comparative testing workflow.
        
        This is the main orchestration method implementing Section 4.7.2 requirements
        for tox 4.26.0 multi-environment comparative testing with automated correction
        workflow integration.
        
        Returns:
            Comprehensive orchestration results with all testing outcomes
        """
        logger.info("=" * 80)
        logger.info("STARTING COMPREHENSIVE COMPARATIVE TESTING ORCHESTRATION")
        logger.info("=" * 80)
        logger.info(f"Orchestration ID: {self.orchestration_id}")
        logger.info(f"Configuration: {len(self.config.test_sequence_stages)} test stages, {len(self.tox_orchestrator.tox_environments)} tox environments")
        
        try:
            # Phase 1: Environment Startup and Validation
            logger.info("Phase 1: Environment Startup and Validation")
            environment_success = await self._execute_environment_startup()
            self.result.environment_startup_success = environment_success
            self.result.environments = self.env_manager.environments
            
            if not environment_success and self.config.failure_fast_mode:
                logger.error("Environment startup failed - aborting in fail-fast mode")
                return self._finalize_orchestration_result()
            
            # Phase 2: Automated Test Sequence Execution
            logger.info("Phase 2: Automated Test Sequence Execution")
            test_sequence_results = await self._execute_test_sequence()
            self.result.test_stages = test_sequence_results
            
            # Phase 3: Multi-Environment tox Orchestration
            logger.info("Phase 3: Multi-Environment tox Orchestration")
            multi_env_results = await self._execute_multi_environment_testing()
            self.result.tox_execution_results = multi_env_results
            
            # Phase 4: Discrepancy Analysis and Correction Workflow
            logger.info("Phase 4: Discrepancy Analysis and Correction Workflow")
            discrepancy_analysis = await self._execute_discrepancy_analysis(
                test_sequence_results, multi_env_results
            )
            self.result.discrepancy_analysis = discrepancy_analysis
            
            # Phase 5: Automated Correction Workflow (if needed)
            if self.config.correction_workflow_enabled:
                correction_needed = await self._evaluate_correction_workflow_trigger(discrepancy_analysis)
                if correction_needed:
                    logger.info("Phase 5: Automated Correction Workflow Execution")
                    correction_results = await self._execute_correction_workflow(discrepancy_analysis)
                    self.result.correction_workflow_triggered = True
                    self.result.correction_workflow_results = correction_results
            
            # Phase 6: Consolidated Report Generation
            logger.info("Phase 6: Consolidated Report Generation")
            generated_reports = await self._execute_report_generation(
                test_sequence_results, multi_env_results, discrepancy_analysis
            )
            self.result.generated_reports = generated_reports
            self.result.report_generation_success = len(generated_reports) > 0
            
            # Calculate final orchestration success
            self._calculate_overall_success()
            
            logger.info("=" * 80)
            logger.info("COMPREHENSIVE COMPARATIVE TESTING ORCHESTRATION COMPLETED")
            logger.info("=" * 80)
            logger.info(f"Overall Success: {self.result.overall_success}")
            logger.info(f"Total Execution Time: {self.result.execution_time:.2f}s")
            logger.info(f"Generated Reports: {len(self.result.generated_reports)}")
            
            return self._finalize_orchestration_result()
            
        except Exception as e:
            logger.error(f"Orchestration failed with exception: {e}")
            logger.error(traceback.format_exc())
            self.result.error_message = str(e)
            return self._finalize_orchestration_result()
        
        finally:
            # Cleanup resources
            await self._cleanup_orchestration()
    
    async def _execute_environment_startup(self) -> bool:
        """Execute comprehensive environment startup and validation."""
        logger.info("Starting environment startup sequence")
        
        try:
            startup_success = await self.env_manager.startup_environments()
            
            if startup_success:
                logger.info("Environment startup completed successfully")
                
                # Brief validation period to ensure stability
                await asyncio.sleep(5)
                
                # Final health verification
                env_status = self.env_manager.get_environment_status()
                nodejs_healthy = env_status.get('nodejs', {}).get('healthy', False)
                flask_healthy = env_status.get('flask', {}).get('healthy', False)
                
                if nodejs_healthy and flask_healthy:
                    logger.info("Environment health validation passed")
                    return True
                else:
                    logger.error("Environment health validation failed after startup")
                    return False
            else:
                logger.error("Environment startup sequence failed")
                return False
                
        except Exception as e:
            logger.error(f"Environment startup failed: {e}")
            return False
    
    async def _execute_test_sequence(self) -> Dict[str, Any]:
        """Execute automated test sequence orchestration."""
        logger.info("Executing automated test sequence")
        
        try:
            test_results = await self.test_orchestrator.execute_test_sequence()
            
            # Update orchestration result with test metrics
            for stage_result in test_results.get('stage_results', {}).values():
                stage_test_count = stage_result.get('tox_results', {}).get('test_count', 0)
                self.result.total_test_count += stage_test_count
                
                if stage_result.get('success', False):
                    self.result.successful_test_count += stage_test_count
                else:
                    self.result.failed_test_count += stage_test_count
            
            logger.info(f"Test sequence completed - {test_results.get('successful_stages', 0)}/{test_results.get('total_stages', 0)} stages successful")
            return test_results
            
        except Exception as e:
            logger.error(f"Test sequence execution failed: {e}")
            return {'error': str(e), 'overall_success': False}
    
    async def _execute_multi_environment_testing(self) -> Dict[str, Any]:
        """Execute tox 4.26.0 multi-environment orchestration."""
        logger.info("Executing multi-environment tox orchestration")
        
        try:
            multi_env_results = await self.tox_orchestrator.execute_multi_environment_testing()
            
            # Update orchestration result with tox metrics
            self.result.tox_environments_total_count = multi_env_results.get('total_environments', 0)
            self.result.tox_environments_success_count = multi_env_results.get('successful_environments', 0)
            
            logger.info(f"Multi-environment testing completed - {multi_env_results.get('successful_environments', 0)}/{multi_env_results.get('total_environments', 0)} environments successful")
            return multi_env_results
            
        except Exception as e:
            logger.error(f"Multi-environment testing failed: {e}")
            return {'error': str(e), 'overall_success': False}
    
    async def _execute_discrepancy_analysis(
        self, 
        test_sequence_results: Dict[str, Any],
        multi_env_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute comprehensive discrepancy analysis."""
        logger.info("Executing discrepancy analysis")
        
        try:
            # Initialize discrepancy detector
            detector = DiscrepancyDetector(TestEnvironmentConfig(
                nodejs_base_url=self.config.nodejs_base_url,
                flask_base_url=self.config.flask_base_url
            ))
            
            # Collect comparison results from test sequence
            comparison_results = []
            
            # Extract comparison data from test results
            for stage_name, stage_result in test_sequence_results.get('stage_results', {}).items():
                if stage_result.get('success', False):
                    # Create mock comparison result for analysis
                    comparison_result = ComparisonResult(
                        test_name=stage_name,
                        endpoint=f"/test/{stage_name}",
                        method="GET",
                        request_data=None
                    )
                    comparison_result.success = stage_result.get('success', False)
                    comparison_results.append(comparison_result)
            
            # Perform discrepancy analysis
            analysis = detector.analyze_discrepancies(comparison_results)
            
            logger.info(f"Discrepancy analysis completed - Success rate: {analysis.get('success_rate', 0):.2%}")
            return analysis
            
        except Exception as e:
            logger.error(f"Discrepancy analysis failed: {e}")
            return {'error': str(e), 'success_rate': 0.0}
    
    async def _evaluate_correction_workflow_trigger(self, discrepancy_analysis: Dict[str, Any]) -> bool:
        """Evaluate whether automated correction workflow should be triggered."""
        success_rate = discrepancy_analysis.get('success_rate', 1.0)
        
        if success_rate < (1.0 - self.config.correction_trigger_threshold):
            logger.info(f"Correction workflow triggered - Success rate {success_rate:.2%} below threshold {(1.0 - self.config.correction_trigger_threshold):.2%}")
            return True
        else:
            logger.info(f"Correction workflow not needed - Success rate {success_rate:.2%} above threshold")
            return False
    
    async def _execute_correction_workflow(self, discrepancy_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Execute automated correction workflow for Flask implementation adjustment."""
        logger.info("Executing automated correction workflow")
        
        try:
            # Initialize correction workflow
            correction_start_time = time.time()
            
            # Execute correction tox environment
            correction_cmd = [
                'tox',
                '-e', 'discrepancy-analysis',
                '-c', self.config.tox_config_path,
                '--',
                'tests/integration/comparative/results_analyzer.py'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *correction_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(Path.cwd())
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.correction_timeout
                )
                
                correction_results = {
                    'success': process.returncode == 0,
                    'return_code': process.returncode,
                    'execution_time': time.time() - correction_start_time,
                    'stdout': stdout.decode('utf-8', errors='ignore'),
                    'stderr': stderr.decode('utf-8', errors='ignore')
                }
                
                if correction_results['success']:
                    logger.info("Automated correction workflow completed successfully")
                else:
                    logger.error("Automated correction workflow failed")
                
                return correction_results
                
            except asyncio.TimeoutError:
                logger.error(f"Correction workflow timed out after {self.config.correction_timeout}s")
                process.kill()
                await process.wait()
                return {
                    'success': False,
                    'error': 'Correction workflow timeout',
                    'execution_time': self.config.correction_timeout
                }
                
        except Exception as e:
            logger.error(f"Correction workflow execution failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'execution_time': 0
            }
    
    async def _execute_report_generation(
        self,
        test_sequence_results: Dict[str, Any],
        multi_env_results: Dict[str, Any],
        discrepancy_analysis: Dict[str, Any]
    ) -> List[str]:
        """Execute consolidated report generation."""
        logger.info("Generating consolidated reports")
        
        try:
            generated_reports = self.report_generator.generate_comprehensive_report(
                orchestration_result=self.result,
                test_sequence_results=test_sequence_results,
                multi_env_results=multi_env_results,
                discrepancy_analysis=discrepancy_analysis
            )
            
            logger.info(f"Generated {len(generated_reports)} reports")
            return generated_reports
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return []
    
    def _calculate_overall_success(self):
        """Calculate overall orchestration success based on all metrics."""
        # Environment startup success weight: 20%
        env_success_weight = 0.2 if self.result.environment_startup_success else 0.0
        
        # Test sequence success weight: 40%
        test_success_rate = 0.0
        if self.result.total_test_count > 0:
            test_success_rate = self.result.successful_test_count / self.result.total_test_count
        test_success_weight = test_success_rate * 0.4
        
        # Multi-environment success weight: 30%
        tox_success_rate = 0.0
        if self.result.tox_environments_total_count > 0:
            tox_success_rate = self.result.tox_environments_success_count / self.result.tox_environments_total_count
        tox_success_weight = tox_success_rate * 0.3
        
        # Report generation success weight: 10%
        report_success_weight = 0.1 if self.result.report_generation_success else 0.0
        
        # Calculate overall weighted success score
        overall_score = env_success_weight + test_success_weight + tox_success_weight + report_success_weight
        
        # Overall success requires >= 85% weighted score
        self.result.overall_success = overall_score >= 0.85
        
        logger.info(f"Overall success calculation: {overall_score:.2%} (threshold: 85%)")
    
    def _finalize_orchestration_result(self) -> Dict[str, Any]:
        """Finalize and return orchestration results."""
        self.result.end_time = datetime.now(timezone.utc)
        
        if self.result.start_time and self.result.end_time:
            self.result.execution_time = (self.result.end_time - self.result.start_time).total_seconds()
        
        return self.result.to_dict()
    
    async def _cleanup_orchestration(self):
        """Clean up all orchestration resources."""
        logger.info("Starting orchestration cleanup")
        
        try:
            # Cleanup environment manager
            await self.env_manager.cleanup_environments()
            
            # Cleanup tox orchestrator
            self.tox_orchestrator.cleanup()
            
            logger.info("Orchestration cleanup completed")
            
        except Exception as e:
            logger.error(f"Orchestration cleanup failed: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum} - initiating graceful shutdown")
        
        # Set error state and trigger cleanup
        self.result.error_message = f"Interrupted by signal {signum}"
        
        # Note: In a real async context, would need to properly handle this
        # For now, just log the signal reception
        logger.warning("Graceful shutdown initiated - cleanup will occur on next await")


# CLI Integration and Main Entry Points

def create_cli_parser() -> argparse.ArgumentParser:
    """Create comprehensive CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Comparative Testing Orchestrator for Node.js to Flask Migration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --run-all                           # Run complete orchestration
  %(prog)s --test-sequence                     # Run test sequence only
  %(prog)s --multi-env                         # Run multi-environment testing only
  %(prog)s --ci-mode                           # Run in CI/CD mode
  %(prog)s --config custom_config.yaml        # Use custom configuration
  %(prog)s --output-dir /custom/reports        # Custom report output directory
        """
    )
    
    # Execution modes
    execution_group = parser.add_mutually_exclusive_group()
    execution_group.add_argument(
        '--run-all', 
        action='store_true',
        help='Execute complete comparative testing orchestration'
    )
    execution_group.add_argument(
        '--test-sequence', 
        action='store_true',
        help='Execute test sequence only'
    )
    execution_group.add_argument(
        '--multi-env', 
        action='store_true',
        help='Execute multi-environment tox testing only'
    )
    execution_group.add_argument(
        '--environment-only', 
        action='store_true',
        help='Start and validate environments only'
    )
    
    # Configuration options
    parser.add_argument(
        '--config', 
        type=str,
        help='Path to YAML configuration file'
    )
    parser.add_argument(
        '--output-dir', 
        type=str,
        help='Output directory for reports and logs'
    )
    parser.add_argument(
        '--nodejs-url', 
        type=str,
        default='http://localhost:3000',
        help='Node.js baseline system URL'
    )
    parser.add_argument(
        '--flask-url', 
        type=str,
        default='http://localhost:5000',
        help='Flask target system URL'
    )
    
    # CI/CD integration options
    parser.add_argument(
        '--ci-mode', 
        action='store_true',
        help='Enable CI/CD optimized execution mode'
    )
    parser.add_argument(
        '--ci-timeout', 
        type=int,
        default=3600,
        help='CI/CD execution timeout in seconds'
    )
    parser.add_argument(
        '--parallel-jobs', 
        type=int,
        default=2,
        help='Number of parallel jobs for CI execution'
    )
    
    # Advanced options
    parser.add_argument(
        '--fail-fast', 
        action='store_true',
        help='Stop execution on first critical failure'
    )
    parser.add_argument(
        '--retry-failed', 
        action='store_true',
        default=True,
        help='Retry failed tests (default: enabled)'
    )
    parser.add_argument(
        '--no-correction', 
        action='store_true',
        help='Disable automated correction workflow'
    )
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true',
        help='Enable verbose logging'
    )
    
    # Report options
    parser.add_argument(
        '--report-formats', 
        nargs='+',
        choices=['json', 'html', 'xml', 'pdf'],
        default=['json', 'html'],
        help='Report formats to generate'
    )
    
    return parser


def load_configuration_from_file(config_path: str) -> OrchestrationConfig:
    """Load orchestration configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        # Convert YAML data to OrchestrationConfig
        # This is a simplified implementation - would need full mapping
        config = OrchestrationConfig()
        
        if 'nodejs_base_url' in config_data:
            config.nodejs_base_url = config_data['nodejs_base_url']
        if 'flask_base_url' in config_data:
            config.flask_base_url = config_data['flask_base_url']
        if 'report_output_directory' in config_data:
            config.report_output_directory = config_data['report_output_directory']
        
        logger.info(f"Loaded configuration from {config_path}")
        return config
        
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path}: {e}")
        logger.info("Using default configuration")
        return OrchestrationConfig()


async def main():
    """Main CLI entry point for comparative testing orchestration."""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    if args.config:
        config = load_configuration_from_file(args.config)
    else:
        config = OrchestrationConfig()
    
    # Apply CLI overrides
    if args.output_dir:
        config.report_output_directory = args.output_dir
    if args.nodejs_url:
        config.nodejs_base_url = args.nodejs_url
    if args.flask_url:
        config.flask_base_url = args.flask_url
    if args.ci_mode:
        config.ci_mode = True
        config.ci_timeout = args.ci_timeout
        config.ci_parallel_jobs = args.parallel_jobs
    if args.fail_fast:
        config.failure_fast_mode = True
    if args.no_correction:
        config.correction_workflow_enabled = False
    if args.report_formats:
        config.consolidated_report_formats = args.report_formats
    
    # Initialize orchestrator
    orchestrator = ComparativeTestingOrchestrator(config)
    
    try:
        if args.run_all or not any([args.test_sequence, args.multi_env, args.environment_only]):
            # Execute complete orchestration
            results = await orchestrator.execute_comprehensive_comparative_testing()
        elif args.environment_only:
            # Environment startup only
            logger.info("Executing environment startup only")
            env_success = await orchestrator._execute_environment_startup()
            results = {
                'environment_startup_success': env_success,
                'environments': orchestrator.env_manager.get_environment_status()
            }
        elif args.test_sequence:
            # Test sequence only
            logger.info("Executing test sequence only")
            await orchestrator._execute_environment_startup()
            results = await orchestrator._execute_test_sequence()
        elif args.multi_env:
            # Multi-environment testing only
            logger.info("Executing multi-environment testing only")
            results = await orchestrator._execute_multi_environment_testing()
        
        # Print summary
        print("\n" + "=" * 80)
        print("COMPARATIVE TESTING ORCHESTRATION SUMMARY")
        print("=" * 80)
        
        if 'overall_success' in results:
            print(f"Overall Success: {'✓' if results['overall_success'] else '✗'}")
        
        if 'execution_time' in results:
            print(f"Execution Time: {results['execution_time']:.2f}s")
        
        if 'generated_reports' in results:
            print(f"Generated Reports: {len(results['generated_reports'])}")
            for report in results['generated_reports']:
                print(f"  - {report}")
        
        # Exit with appropriate code
        exit_code = 0 if results.get('overall_success', False) else 1
        print(f"\nExiting with code: {exit_code}")
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        logger.info("Orchestration interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Orchestration failed: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    # Run main function with asyncio
    asyncio.run(main())