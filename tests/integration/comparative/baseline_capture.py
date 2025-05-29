"""
Node.js Baseline Response Capture Utility

This utility systematically captures API responses, performance metrics, and workflow 
outputs from the Node.js implementation to create reference baselines for Flask 
migration validation. It implements comprehensive data capture per Section 4.7.2 
requirements for comparative testing between Node.js and Flask systems.

Key Features:
- Node.js system integration for baseline response capture
- Comprehensive API response recording with JSON schema preservation
- Performance metric capture including response times and resource utilization
- Workflow state capture for business logic validation baselines
- Data serialization for baseline storage and comparative analysis
- Automated baseline refresh mechanisms for maintaining current reference data

Author: Migration Team
Version: 1.0.0
Compatible with: Python 3.13.3, pytest-flask 1.3.0, pytest-benchmark 5.1.0
"""

import json
import time
import hashlib
import logging
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import sys
import os

# Third-party imports for Node.js system integration
import requests
import psutil
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging for baseline capture operations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class BaselineResponseCapture:
    """
    Structured data class for capturing comprehensive Node.js response data.
    
    This class encapsulates all aspects of a Node.js system response including
    HTTP details, performance metrics, workflow state, and metadata required
    for accurate comparative analysis with Flask implementation.
    """
    
    # HTTP Response Details
    endpoint: str
    method: str
    status_code: int
    headers: Dict[str, str]
    response_body: Any
    request_data: Optional[Dict[str, Any]]
    
    # Performance Metrics
    response_time_ms: float
    response_time_seconds: float
    memory_usage_mb: float
    cpu_usage_percent: float
    
    # Workflow State Information
    workflow_id: Optional[str]
    workflow_state: Optional[Dict[str, Any]]
    business_logic_checkpoints: List[Dict[str, Any]]
    database_operations: List[Dict[str, Any]]
    
    # Metadata for Baseline Management
    capture_timestamp: str
    node_version: str
    system_load: float
    baseline_version: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert capture to dictionary for JSON serialization."""
        return asdict(self)
    
    def get_hash(self) -> str:
        """Generate hash for response validation and change detection."""
        # Create hash based on endpoint, method, and response content
        hash_data = f"{self.endpoint}{self.method}{json.dumps(self.response_body, sort_keys=True)}"
        return hashlib.sha256(hash_data.encode()).hexdigest()


@dataclass
class BaselineConfig:
    """
    Configuration class for Node.js baseline capture operations.
    
    Defines connection parameters, capture settings, storage locations,
    and operational parameters for systematic baseline data collection.
    """
    
    # Node.js System Connection Settings
    nodejs_base_url: str = "http://localhost:3000"
    timeout_seconds: int = 30
    max_retries: int = 3
    retry_backoff_factor: float = 0.3
    
    # Capture Settings
    capture_performance_metrics: bool = True
    capture_workflow_states: bool = True
    capture_headers: bool = True
    
    # Storage Configuration
    baseline_storage_path: str = "tests/integration/comparative/baselines"
    baseline_index_file: str = "baseline_index.json"
    
    # Operational Parameters
    parallel_workers: int = 5
    memory_sampling_interval: float = 0.1
    enable_debug_logging: bool = False
    
    # Baseline Management
    auto_refresh_enabled: bool = True
    baseline_expiry_hours: int = 24
    incremental_updates: bool = True


class NodeJSSystemConnector:
    """
    Manages secure and reliable connections to the Node.js system for baseline capture.
    
    This class handles HTTP client configuration, retry logic, connection pooling,
    and error handling for robust Node.js system integration per Section 4.7.2
    comparative testing requirements.
    """
    
    def __init__(self, config: BaselineConfig):
        """
        Initialize Node.js system connector with retry and connection pooling.
        
        Args:
            config: Baseline configuration containing connection parameters
        """
        self.config = config
        self.session = self._create_session()
        self.system_info = self._detect_nodejs_system()
        
        logger.info(f"NodeJS System Connector initialized for {config.nodejs_base_url}")
    
    def _create_session(self) -> requests.Session:
        """
        Create configured HTTP session with retry strategy and connection pooling.
        
        Returns:
            Configured requests session for Node.js system interaction
        """
        session = requests.Session()
        
        # Configure retry strategy for robust connection handling
        retry_strategy = Retry(
            total=self.config.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"],
            backoff_factor=self.config.retry_backoff_factor
        )
        
        # Configure HTTP adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default timeout and headers
        session.timeout = self.config.timeout_seconds
        session.headers.update({
            'User-Agent': 'Flask-Migration-Baseline-Capture/1.0.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        return session
    
    def _detect_nodejs_system(self) -> Dict[str, Any]:
        """
        Detect Node.js system information for baseline metadata.
        
        Returns:
            Dictionary containing Node.js system information
        """
        try:
            # Attempt to get Node.js system information
            response = self.session.get(f"{self.config.nodejs_base_url}/health")
            if response.status_code == 200:
                system_info = response.json()
                logger.info(f"Node.js system detected: {system_info}")
                return system_info
        except Exception as e:
            logger.warning(f"Could not detect Node.js system info: {e}")
        
        # Return default system info if detection fails
        return {
            'version': 'unknown',
            'environment': 'development',
            'status': 'connected'
        }
    
    def health_check(self) -> bool:
        """
        Verify Node.js system connectivity and health status.
        
        Returns:
            True if Node.js system is accessible and healthy
        """
        try:
            response = self.session.get(f"{self.config.nodejs_base_url}/health")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Node.js system health check failed: {e}")
            return False
    
    def execute_request(self, endpoint: str, method: str = "GET", 
                       data: Optional[Dict[str, Any]] = None,
                       headers: Optional[Dict[str, str]] = None) -> Tuple[requests.Response, float]:
        """
        Execute HTTP request against Node.js system with performance timing.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request payload data
            headers: Additional request headers
            
        Returns:
            Tuple of (response object, response time in seconds)
        """
        url = f"{self.config.nodejs_base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Prepare request parameters
        request_kwargs = {
            'url': url,
            'timeout': self.config.timeout_seconds
        }
        
        if headers:
            request_kwargs['headers'] = headers
        
        if data and method.upper() in ['POST', 'PUT', 'PATCH']:
            request_kwargs['json'] = data
        elif data and method.upper() == 'GET':
            request_kwargs['params'] = data
        
        # Execute request with timing
        start_time = time.perf_counter()
        try:
            response = self.session.request(method.upper(), **request_kwargs)
            end_time = time.perf_counter()
            response_time = end_time - start_time
            
            logger.debug(f"Request {method} {endpoint} completed in {response_time:.3f}s")
            return response, response_time
            
        except Exception as e:
            end_time = time.perf_counter()
            response_time = end_time - start_time
            logger.error(f"Request {method} {endpoint} failed after {response_time:.3f}s: {e}")
            raise


class PerformanceMetricsCollector:
    """
    Collects comprehensive performance metrics during Node.js system interaction.
    
    This class monitors system resources, response times, and performance indicators
    to establish accurate baselines for comparative testing with Flask implementation.
    """
    
    def __init__(self, config: BaselineConfig):
        """
        Initialize performance metrics collector.
        
        Args:
            config: Baseline configuration containing performance settings
        """
        self.config = config
        self.process = psutil.Process()
        
    @contextmanager
    def measure_request_performance(self):
        """
        Context manager for comprehensive performance measurement during requests.
        
        Yields:
            Dictionary containing collected performance metrics
        """
        # Initial measurements
        start_time = time.perf_counter()
        start_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        start_cpu = self.process.cpu_percent()
        
        # System load measurement
        system_load = psutil.cpu_percent(interval=0.1)
        
        performance_data = {
            'start_time': start_time,
            'start_memory_mb': start_memory,
            'start_cpu_percent': start_cpu,
            'system_load_percent': system_load
        }
        
        try:
            yield performance_data
        finally:
            # Final measurements
            end_time = time.perf_counter()
            end_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            end_cpu = self.process.cpu_percent()
            
            # Calculate metrics
            performance_data.update({
                'end_time': end_time,
                'response_time_seconds': end_time - start_time,
                'response_time_ms': (end_time - start_time) * 1000,
                'memory_usage_mb': max(end_memory, start_memory),
                'cpu_usage_percent': max(end_cpu, start_cpu),
                'memory_delta_mb': end_memory - start_memory
            })


class WorkflowStateCapture:
    """
    Captures business logic workflow states and execution checkpoints.
    
    This class monitors and records workflow execution patterns, business rule
    validation, and state transitions to ensure equivalent behavior in Flask
    implementation per Section 4.7.2 requirements.
    """
    
    def __init__(self, config: BaselineConfig):
        """
        Initialize workflow state capture system.
        
        Args:
            config: Baseline configuration containing workflow settings
        """
        self.config = config
        self.workflow_checkpoints = []
        self.business_logic_states = []
        
    def capture_workflow_execution(self, endpoint: str, request_data: Optional[Dict[str, Any]], 
                                 response_data: Any) -> Dict[str, Any]:
        """
        Capture comprehensive workflow state information from Node.js execution.
        
        Args:
            endpoint: API endpoint being executed
            request_data: Input request data
            response_data: Output response data
            
        Returns:
            Dictionary containing workflow state information
        """
        workflow_id = self._generate_workflow_id(endpoint, request_data)
        
        workflow_state = {
            'workflow_id': workflow_id,
            'endpoint': endpoint,
            'execution_timestamp': datetime.now(timezone.utc).isoformat(),
            'input_state': self._capture_input_state(request_data),
            'output_state': self._capture_output_state(response_data),
            'business_logic_checkpoints': self._extract_business_checkpoints(response_data),
            'database_operations': self._extract_database_operations(response_data),
            'state_transitions': self._analyze_state_transitions(request_data, response_data)
        }
        
        return workflow_state
    
    def _generate_workflow_id(self, endpoint: str, request_data: Optional[Dict[str, Any]]) -> str:
        """Generate unique workflow identifier for tracking."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        endpoint_hash = hashlib.md5(endpoint.encode()).hexdigest()[:8]
        return f"workflow_{endpoint_hash}_{timestamp}"
    
    def _capture_input_state(self, request_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Capture and analyze input state from request data."""
        if not request_data:
            return {'type': 'empty', 'data': None}
        
        return {
            'type': 'json',
            'data': request_data,
            'size_bytes': len(json.dumps(request_data)),
            'keys': list(request_data.keys()) if isinstance(request_data, dict) else [],
            'data_types': {k: type(v).__name__ for k, v in request_data.items()} 
                         if isinstance(request_data, dict) else {}
        }
    
    def _capture_output_state(self, response_data: Any) -> Dict[str, Any]:
        """Capture and analyze output state from response data."""
        if response_data is None:
            return {'type': 'null', 'data': None}
        
        output_state = {
            'type': type(response_data).__name__,
            'data': response_data
        }
        
        if isinstance(response_data, dict):
            output_state.update({
                'size_bytes': len(json.dumps(response_data)),
                'keys': list(response_data.keys()),
                'data_types': {k: type(v).__name__ for k, v in response_data.items()}
            })
        elif isinstance(response_data, list):
            output_state.update({
                'length': len(response_data),
                'item_types': [type(item).__name__ for item in response_data[:5]]  # Sample first 5
            })
        
        return output_state
    
    def _extract_business_checkpoints(self, response_data: Any) -> List[Dict[str, Any]]:
        """Extract business logic validation checkpoints from response."""
        checkpoints = []
        
        # Look for common business logic indicators in response
        if isinstance(response_data, dict):
            # Check for validation results
            if 'validation' in response_data:
                checkpoints.append({
                    'type': 'validation',
                    'result': response_data['validation'],
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
            
            # Check for business rule applications
            if 'business_rules' in response_data:
                checkpoints.append({
                    'type': 'business_rules',
                    'rules_applied': response_data['business_rules'],
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
            
            # Check for workflow status
            if 'status' in response_data:
                checkpoints.append({
                    'type': 'status_check',
                    'status': response_data['status'],
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
        
        return checkpoints
    
    def _extract_database_operations(self, response_data: Any) -> List[Dict[str, Any]]:
        """Extract database operation information from response."""
        operations = []
        
        # Look for database operation indicators
        if isinstance(response_data, dict):
            # Check for query results
            if 'query_results' in response_data:
                operations.append({
                    'type': 'query',
                    'result_count': len(response_data['query_results']) 
                                  if isinstance(response_data['query_results'], list) else 1,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
            
            # Check for creation operations
            if 'created_id' in response_data or 'id' in response_data:
                operations.append({
                    'type': 'create',
                    'entity_id': response_data.get('created_id') or response_data.get('id'),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
            
            # Check for update operations
            if 'updated' in response_data or 'modified' in response_data:
                operations.append({
                    'type': 'update',
                    'affected_records': response_data.get('updated', 1),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
        
        return operations
    
    def _analyze_state_transitions(self, request_data: Optional[Dict[str, Any]], 
                                 response_data: Any) -> List[Dict[str, Any]]:
        """Analyze state transitions during workflow execution."""
        transitions = []
        
        # Analyze state changes based on request and response patterns
        if isinstance(request_data, dict) and isinstance(response_data, dict):
            # Look for status transitions
            request_status = request_data.get('status')
            response_status = response_data.get('status')
            
            if request_status and response_status and request_status != response_status:
                transitions.append({
                    'type': 'status_transition',
                    'from_state': request_status,
                    'to_state': response_status,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
        
        return transitions


class BaselineDataManager:
    """
    Manages baseline data storage, retrieval, and lifecycle operations.
    
    This class handles persistent storage of captured baseline data, provides
    efficient retrieval mechanisms, manages baseline versioning, and implements
    automated refresh capabilities for maintaining current reference data.
    """
    
    def __init__(self, config: BaselineConfig):
        """
        Initialize baseline data manager with storage configuration.
        
        Args:
            config: Baseline configuration containing storage settings
        """
        self.config = config
        self.storage_path = Path(config.baseline_storage_path)
        self.index_file = self.storage_path / config.baseline_index_file
        
        # Ensure storage directory exists
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize or load baseline index
        self.baseline_index = self._load_baseline_index()
        
        logger.info(f"Baseline data manager initialized with storage: {self.storage_path}")
    
    def _load_baseline_index(self) -> Dict[str, Any]:
        """
        Load existing baseline index or create new one.
        
        Returns:
            Dictionary containing baseline index information
        """
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    index = json.load(f)
                logger.info(f"Loaded existing baseline index with {len(index.get('baselines', {}))} entries")
                return index
            except Exception as e:
                logger.error(f"Failed to load baseline index: {e}")
        
        # Create new index
        index = {
            'version': '1.0.0',
            'created': datetime.now(timezone.utc).isoformat(),
            'last_updated': datetime.now(timezone.utc).isoformat(),
            'baselines': {},
            'metadata': {
                'total_captures': 0,
                'last_refresh': None,
                'nodejs_version': 'unknown'
            }
        }
        
        self._save_baseline_index(index)
        return index
    
    def _save_baseline_index(self, index: Dict[str, Any]) -> None:
        """Save baseline index to storage."""
        try:
            with open(self.index_file, 'w') as f:
                json.dump(index, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save baseline index: {e}")
            raise
    
    def save_baseline_capture(self, capture: BaselineResponseCapture) -> str:
        """
        Save baseline capture to persistent storage.
        
        Args:
            capture: Baseline response capture to save
            
        Returns:
            Unique identifier for the saved baseline capture
        """
        # Generate unique filename
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        endpoint_safe = capture.endpoint.replace('/', '_').replace('?', '_').replace('&', '_')
        filename = f"baseline_{capture.method.lower()}_{endpoint_safe}_{timestamp}.json"
        
        # Save capture data
        capture_file = self.storage_path / filename
        try:
            with open(capture_file, 'w') as f:
                json.dump(capture.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save baseline capture: {e}")
            raise
        
        # Update index
        capture_id = f"{capture.method}:{capture.endpoint}"
        self.baseline_index['baselines'][capture_id] = {
            'filename': filename,
            'endpoint': capture.endpoint,
            'method': capture.method,
            'captured_at': capture.capture_timestamp,
            'hash': capture.get_hash(),
            'file_size': capture_file.stat().st_size
        }
        
        # Update metadata
        self.baseline_index['metadata']['total_captures'] += 1
        self.baseline_index['last_updated'] = datetime.now(timezone.utc).isoformat()
        
        # Save updated index
        self._save_baseline_index(self.baseline_index)
        
        logger.info(f"Saved baseline capture for {capture_id} to {filename}")
        return filename
    
    def get_baseline_capture(self, endpoint: str, method: str = "GET") -> Optional[BaselineResponseCapture]:
        """
        Retrieve existing baseline capture for endpoint.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            
        Returns:
            BaselineResponseCapture object if found, None otherwise
        """
        capture_id = f"{method}:{endpoint}"
        
        if capture_id not in self.baseline_index['baselines']:
            return None
        
        baseline_info = self.baseline_index['baselines'][capture_id]
        capture_file = self.storage_path / baseline_info['filename']
        
        if not capture_file.exists():
            logger.warning(f"Baseline file not found: {capture_file}")
            return None
        
        try:
            with open(capture_file, 'r') as f:
                data = json.load(f)
            
            return BaselineResponseCapture(**data)
        except Exception as e:
            logger.error(f"Failed to load baseline capture: {e}")
            return None
    
    def list_available_baselines(self) -> List[Dict[str, Any]]:
        """
        List all available baseline captures.
        
        Returns:
            List of baseline information dictionaries
        """
        return list(self.baseline_index['baselines'].values())
    
    def cleanup_expired_baselines(self) -> int:
        """
        Remove expired baseline captures based on configuration.
        
        Returns:
            Number of baselines removed
        """
        if not self.config.auto_refresh_enabled:
            return 0
        
        expired_count = 0
        current_time = datetime.now(timezone.utc)
        
        # Identify expired baselines
        expired_captures = []
        for capture_id, baseline_info in self.baseline_index['baselines'].items():
            capture_time = datetime.fromisoformat(baseline_info['captured_at'].replace('Z', '+00:00'))
            age_hours = (current_time - capture_time).total_seconds() / 3600
            
            if age_hours > self.config.baseline_expiry_hours:
                expired_captures.append(capture_id)
        
        # Remove expired baselines
        for capture_id in expired_captures:
            baseline_info = self.baseline_index['baselines'][capture_id]
            capture_file = self.storage_path / baseline_info['filename']
            
            try:
                if capture_file.exists():
                    capture_file.unlink()
                del self.baseline_index['baselines'][capture_id]
                expired_count += 1
            except Exception as e:
                logger.error(f"Failed to remove expired baseline {capture_id}: {e}")
        
        if expired_count > 0:
            self.baseline_index['metadata']['total_captures'] -= expired_count
            self._save_baseline_index(self.baseline_index)
            logger.info(f"Cleaned up {expired_count} expired baselines")
        
        return expired_count


class BaselineCaptureUtility:
    """
    Main utility class orchestrating comprehensive Node.js baseline capture operations.
    
    This class coordinates all aspects of baseline capture including Node.js system
    connection, API response recording, performance metrics collection, workflow
    state capture, and data management per Section 4.7.2 comparative testing requirements.
    """
    
    def __init__(self, config: Optional[BaselineConfig] = None):
        """
        Initialize baseline capture utility with comprehensive component setup.
        
        Args:
            config: Optional baseline configuration (uses defaults if not provided)
        """
        self.config = config or BaselineConfig()
        
        # Initialize component subsystems
        self.connector = NodeJSSystemConnector(self.config)
        self.performance_collector = PerformanceMetricsCollector(self.config)
        self.workflow_capture = WorkflowStateCapture(self.config)
        self.data_manager = BaselineDataManager(self.config)
        
        # Configure debug logging if enabled
        if self.config.enable_debug_logging:
            logging.getLogger().setLevel(logging.DEBUG)
        
        logger.info("Baseline capture utility initialized successfully")
    
    def capture_single_endpoint(self, endpoint: str, method: str = "GET", 
                              data: Optional[Dict[str, Any]] = None,
                              headers: Optional[Dict[str, str]] = None) -> BaselineResponseCapture:
        """
        Capture comprehensive baseline data for a single API endpoint.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request payload data
            headers: Additional request headers
            
        Returns:
            BaselineResponseCapture object containing all captured data
        """
        logger.info(f"Capturing baseline for {method} {endpoint}")
        
        # Performance measurement context
        with self.performance_collector.measure_request_performance() as perf_data:
            try:
                # Execute request against Node.js system
                response, response_time = self.connector.execute_request(
                    endpoint=endpoint,
                    method=method,
                    data=data,
                    headers=headers
                )
                
                # Parse response data
                try:
                    response_body = response.json() if response.content else None
                except json.JSONDecodeError:
                    response_body = response.text
                
                # Capture workflow state if enabled
                workflow_state = None
                business_logic_checkpoints = []
                database_operations = []
                
                if self.config.capture_workflow_states:
                    workflow_data = self.workflow_capture.capture_workflow_execution(
                        endpoint=endpoint,
                        request_data=data,
                        response_data=response_body
                    )
                    workflow_state = workflow_data
                    business_logic_checkpoints = workflow_data.get('business_logic_checkpoints', [])
                    database_operations = workflow_data.get('database_operations', [])
                
                # Create comprehensive baseline capture
                baseline_capture = BaselineResponseCapture(
                    # HTTP Response Details
                    endpoint=endpoint,
                    method=method.upper(),
                    status_code=response.status_code,
                    headers=dict(response.headers) if self.config.capture_headers else {},
                    response_body=response_body,
                    request_data=data,
                    
                    # Performance Metrics
                    response_time_ms=perf_data['response_time_ms'],
                    response_time_seconds=perf_data['response_time_seconds'],
                    memory_usage_mb=perf_data['memory_usage_mb'],
                    cpu_usage_percent=perf_data['cpu_usage_percent'],
                    
                    # Workflow State Information
                    workflow_id=workflow_state.get('workflow_id') if workflow_state else None,
                    workflow_state=workflow_state,
                    business_logic_checkpoints=business_logic_checkpoints,
                    database_operations=database_operations,
                    
                    # Metadata for Baseline Management
                    capture_timestamp=datetime.now(timezone.utc).isoformat(),
                    node_version=self.connector.system_info.get('version', 'unknown'),
                    system_load=perf_data['system_load_percent'],
                    baseline_version="1.0.0"
                )
                
                # Save baseline capture
                self.data_manager.save_baseline_capture(baseline_capture)
                
                logger.info(f"Successfully captured baseline for {method} {endpoint} "
                           f"(status: {response.status_code}, time: {response_time:.3f}s)")
                
                return baseline_capture
                
            except Exception as e:
                logger.error(f"Failed to capture baseline for {method} {endpoint}: {e}")
                raise
    
    def capture_endpoint_batch(self, endpoints: List[Dict[str, Any]]) -> List[BaselineResponseCapture]:
        """
        Capture baselines for multiple endpoints in parallel for efficiency.
        
        Args:
            endpoints: List of endpoint configurations, each containing:
                      {'endpoint': str, 'method': str, 'data': dict, 'headers': dict}
        
        Returns:
            List of BaselineResponseCapture objects for successful captures
        """
        logger.info(f"Starting batch capture for {len(endpoints)} endpoints")
        
        captures = []
        failed_captures = []
        
        with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
            # Submit all capture tasks
            future_to_endpoint = {
                executor.submit(
                    self.capture_single_endpoint,
                    endpoint=ep['endpoint'],
                    method=ep.get('method', 'GET'),
                    data=ep.get('data'),
                    headers=ep.get('headers')
                ): ep for ep in endpoints
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_endpoint):
                endpoint_config = future_to_endpoint[future]
                try:
                    capture = future.result()
                    captures.append(capture)
                except Exception as e:
                    failed_captures.append({
                        'endpoint': endpoint_config,
                        'error': str(e)
                    })
                    logger.error(f"Batch capture failed for {endpoint_config}: {e}")
        
        logger.info(f"Batch capture completed: {len(captures)} successful, "
                   f"{len(failed_captures)} failed")
        
        if failed_captures:
            logger.warning(f"Failed captures: {failed_captures}")
        
        return captures
    
    def refresh_all_baselines(self, endpoints: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Refresh all baseline captures with current Node.js system responses.
        
        Args:
            endpoints: Optional list of specific endpoints to refresh
                      (refreshes all existing if not provided)
        
        Returns:
            Dictionary containing refresh operation results
        """
        logger.info("Starting comprehensive baseline refresh operation")
        
        # Cleanup expired baselines first
        expired_count = self.data_manager.cleanup_expired_baselines()
        
        # Determine endpoints to refresh
        if endpoints is None:
            # Refresh all existing baselines
            existing_baselines = self.data_manager.list_available_baselines()
            endpoints = [
                {
                    'endpoint': baseline['endpoint'],
                    'method': baseline['method'],
                    'data': None,  # Use default data for refresh
                    'headers': None
                }
                for baseline in existing_baselines
            ]
        
        if not endpoints:
            logger.info("No endpoints found for baseline refresh")
            return {
                'refreshed_count': 0,
                'failed_count': 0,
                'expired_cleaned': expired_count,
                'status': 'no_endpoints'
            }
        
        # Perform batch refresh
        refreshed_captures = self.capture_endpoint_batch(endpoints)
        failed_count = len(endpoints) - len(refreshed_captures)
        
        # Update refresh metadata
        self.data_manager.baseline_index['metadata']['last_refresh'] = \
            datetime.now(timezone.utc).isoformat()
        self.data_manager._save_baseline_index(self.data_manager.baseline_index)
        
        refresh_results = {
            'refreshed_count': len(refreshed_captures),
            'failed_count': failed_count,
            'expired_cleaned': expired_count,
            'status': 'completed',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Baseline refresh completed: {refresh_results}")
        return refresh_results
    
    def get_baseline_for_comparison(self, endpoint: str, method: str = "GET") -> Optional[Dict[str, Any]]:
        """
        Retrieve baseline data formatted for comparative testing.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
        
        Returns:
            Dictionary containing baseline data for comparison, or None if not found
        """
        baseline_capture = self.data_manager.get_baseline_capture(endpoint, method)
        
        if not baseline_capture:
            logger.warning(f"No baseline found for {method} {endpoint}")
            return None
        
        # Format for comparative testing
        comparison_data = {
            'response': {
                'status_code': baseline_capture.status_code,
                'headers': baseline_capture.headers,
                'body': baseline_capture.response_body
            },
            'performance': {
                'response_time_ms': baseline_capture.response_time_ms,
                'memory_usage_mb': baseline_capture.memory_usage_mb,
                'cpu_usage_percent': baseline_capture.cpu_usage_percent
            },
            'workflow': {
                'workflow_id': baseline_capture.workflow_id,
                'business_logic_checkpoints': baseline_capture.business_logic_checkpoints,
                'database_operations': baseline_capture.database_operations
            },
            'metadata': {
                'captured_at': baseline_capture.capture_timestamp,
                'node_version': baseline_capture.node_version,
                'baseline_hash': baseline_capture.get_hash()
            }
        }
        
        return comparison_data
    
    def validate_nodejs_system(self) -> Dict[str, Any]:
        """
        Comprehensive validation of Node.js system readiness for baseline capture.
        
        Returns:
            Dictionary containing validation results and system status
        """
        logger.info("Validating Node.js system for baseline capture")
        
        validation_results = {
            'system_reachable': False,
            'health_check_passed': False,
            'system_info': {},
            'performance_baseline': {},
            'validation_timestamp': datetime.now(timezone.utc).isoformat(),
            'errors': []
        }
        
        try:
            # Basic connectivity test
            if self.connector.health_check():
                validation_results['system_reachable'] = True
                validation_results['health_check_passed'] = True
            else:
                validation_results['errors'].append("Health check failed")
            
            # System information collection
            validation_results['system_info'] = self.connector.system_info
            
            # Performance baseline measurement
            with self.performance_collector.measure_request_performance() as perf_data:
                # Simple health endpoint call for performance baseline
                try:
                    response, response_time = self.connector.execute_request("/health")
                    validation_results['performance_baseline'] = {
                        'health_endpoint_response_time': response_time,
                        'system_memory_mb': perf_data['memory_usage_mb'],
                        'system_cpu_percent': perf_data['cpu_usage_percent'],
                        'system_load_percent': perf_data['system_load_percent']
                    }
                except Exception as e:
                    validation_results['errors'].append(f"Performance baseline failed: {e}")
            
        except Exception as e:
            validation_results['errors'].append(f"System validation failed: {e}")
            logger.error(f"Node.js system validation error: {e}")
        
        # Overall validation status
        validation_results['overall_status'] = (
            'ready' if (validation_results['system_reachable'] and 
                       validation_results['health_check_passed'] and 
                       not validation_results['errors'])
            else 'not_ready'
        )
        
        logger.info(f"Node.js system validation completed: {validation_results['overall_status']}")
        return validation_results


# Utility functions for external integration

def create_baseline_capture_utility(nodejs_url: str = "http://localhost:3000",
                                   storage_path: str = "tests/integration/comparative/baselines",
                                   **kwargs) -> BaselineCaptureUtility:
    """
    Factory function to create configured baseline capture utility.
    
    Args:
        nodejs_url: URL of the Node.js system to capture baselines from
        storage_path: Directory path for baseline data storage
        **kwargs: Additional configuration parameters
    
    Returns:
        Configured BaselineCaptureUtility instance
    """
    config = BaselineConfig(
        nodejs_base_url=nodejs_url,
        baseline_storage_path=storage_path,
        **kwargs
    )
    
    return BaselineCaptureUtility(config)


def capture_baseline_for_endpoint(endpoint: str, method: str = "GET", 
                                nodejs_url: str = "http://localhost:3000",
                                data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to capture baseline for a single endpoint.
    
    Args:
        endpoint: API endpoint path
        method: HTTP method
        nodejs_url: URL of the Node.js system
        data: Optional request data
    
    Returns:
        Dictionary containing baseline data for comparison
    """
    utility = create_baseline_capture_utility(nodejs_url)
    capture = utility.capture_single_endpoint(endpoint, method, data)
    return utility.get_baseline_for_comparison(endpoint, method)


if __name__ == "__main__":
    """
    Command-line interface for baseline capture operations.
    
    Example usage:
        python baseline_capture.py --validate
        python baseline_capture.py --capture /api/users GET
        python baseline_capture.py --refresh-all
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="Node.js Baseline Capture Utility")
    parser.add_argument("--validate", action="store_true", 
                       help="Validate Node.js system readiness")
    parser.add_argument("--capture", nargs=2, metavar=("ENDPOINT", "METHOD"),
                       help="Capture baseline for specific endpoint")
    parser.add_argument("--refresh-all", action="store_true",
                       help="Refresh all existing baselines")
    parser.add_argument("--nodejs-url", default="http://localhost:3000",
                       help="Node.js system URL")
    parser.add_argument("--storage-path", 
                       default="tests/integration/comparative/baselines",
                       help="Baseline storage directory")
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Create utility with CLI arguments
    config = BaselineConfig(
        nodejs_base_url=args.nodejs_url,
        baseline_storage_path=args.storage_path,
        enable_debug_logging=args.debug
    )
    
    utility = BaselineCaptureUtility(config)
    
    # Execute requested operation
    if args.validate:
        results = utility.validate_nodejs_system()
        print(json.dumps(results, indent=2))
        sys.exit(0 if results['overall_status'] == 'ready' else 1)
    
    elif args.capture:
        endpoint, method = args.capture
        try:
            capture = utility.capture_single_endpoint(endpoint, method)
            comparison_data = utility.get_baseline_for_comparison(endpoint, method)
            print(json.dumps(comparison_data, indent=2))
        except Exception as e:
            logger.error(f"Capture failed: {e}")
            sys.exit(1)
    
    elif args.refresh_all:
        results = utility.refresh_all_baselines()
        print(json.dumps(results, indent=2))
        sys.exit(0 if results['status'] == 'completed' else 1)
    
    else:
        parser.print_help()
        sys.exit(1)