"""
Baseline Data Management Module for Node.js to Flask Migration Validation

This module provides comprehensive baseline data management for comparative validation
between the original Node.js system and the converted Flask implementation. It maintains
authoritative baseline datasets for API responses, performance metrics, and reference
implementations to ensure accurate parity validation per Feature F-009.

Key Components:
- API response format compatibility baseline data
- Business logic execution equivalence baseline 
- Database operation result consistency baseline
- Error handling behavior preservation baseline
- Performance metrics baseline for comparison

Dependencies:
- pytest-flask 1.3.0 for Flask application testing fixtures
- pytest-benchmark 5.1.0 for performance testing harness
- Flask 3.1.1 compatibility validation
- Python 3.13.3 environment requirements

Author: Flask Migration Team
Version: 1.0.0
Date: 2024
"""

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import logging

# Configure logging for baseline data operations
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class APIResponseBaseline:
    """
    Baseline data structure for API response validation.
    
    Captures Node.js system response data for comparative testing
    per Feature F-009 API response format compatibility requirements.
    """
    endpoint: str
    method: str
    status_code: int
    headers: Dict[str, str]
    response_data: Dict[str, Any]
    response_time_ms: float
    timestamp: str
    request_payload: Optional[Dict[str, Any]] = None
    query_parameters: Optional[Dict[str, str]] = None
    authentication_type: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline data to dictionary for JSON serialization."""
        return asdict(self)
    
    def get_response_hash(self) -> str:
        """Generate unique hash for response data validation."""
        response_str = json.dumps(self.response_data, sort_keys=True)
        return hashlib.sha256(response_str.encode()).hexdigest()


@dataclass
class BusinessLogicBaseline:
    """
    Baseline data structure for business logic execution validation.
    
    Captures expected outcomes from business logic operations for 
    equivalence testing per Feature F-009 requirements.
    """
    operation_name: str
    input_parameters: Dict[str, Any]
    expected_output: Dict[str, Any]
    execution_time_ms: float
    validation_rules: List[str]
    side_effects: List[Dict[str, Any]]
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline data to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class DatabaseOperationBaseline:
    """
    Baseline data structure for database operation validation.
    
    Captures expected database query results and operation outcomes
    for consistency validation per Feature F-009 requirements.
    """
    operation_type: str  # CREATE, READ, UPDATE, DELETE
    entity_type: str
    query_parameters: Dict[str, Any]
    expected_result: Dict[str, Any]
    affected_rows: int
    execution_time_ms: float
    query_hash: str
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline data to dictionary for JSON serialization."""
        return asdict(self)
        
    def get_query_hash(self) -> str:
        """Generate unique hash for query validation."""
        query_str = json.dumps(self.query_parameters, sort_keys=True)
        return hashlib.sha256(query_str.encode()).hexdigest()


@dataclass
class ErrorHandlingBaseline:
    """
    Baseline data structure for error handling behavior validation.
    
    Captures expected error responses and handling patterns for
    behavior preservation per Feature F-009 requirements.
    """
    error_scenario: str
    trigger_conditions: Dict[str, Any]
    expected_status_code: int
    expected_error_message: str
    expected_error_type: str
    error_details: Dict[str, Any]
    recovery_actions: List[str]
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline data to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class PerformanceMetricBaseline:
    """
    Baseline data structure for performance metrics validation.
    
    Captures Node.js performance benchmarks for comparison testing
    per Section 4.7.1 performance requirements.
    """
    metric_name: str
    metric_type: str  # response_time, memory_usage, throughput, etc.
    baseline_value: float
    unit: str
    measurement_conditions: Dict[str, Any]
    acceptable_variance_percent: float
    timestamp: str
    environment_context: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline data to dictionary for JSON serialization."""
        return asdict(self)
    
    def is_within_acceptable_range(self, measured_value: float) -> bool:
        """Check if measured value is within acceptable variance."""
        variance = abs(measured_value - self.baseline_value) / self.baseline_value * 100
        return variance <= self.acceptable_variance_percent


class BaselineDataManager:
    """
    Comprehensive baseline data management for Node.js to Flask migration validation.
    
    This class provides centralized management of all baseline data types required
    for Feature F-009 functionality parity validation and Section 4.7 testing workflows.
    """
    
    def __init__(self, data_directory: str = "tests/comparative/data"):
        """
        Initialize baseline data manager with data storage directory.
        
        Args:
            data_directory: Directory path for storing baseline data files
        """
        self.data_directory = Path(data_directory)
        self.data_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize baseline data collections
        self.api_baselines: Dict[str, APIResponseBaseline] = {}
        self.business_logic_baselines: Dict[str, BusinessLogicBaseline] = {}
        self.database_baselines: Dict[str, DatabaseOperationBaseline] = {}
        self.error_handling_baselines: Dict[str, ErrorHandlingBaseline] = {}
        self.performance_baselines: Dict[str, PerformanceMetricBaseline] = {}
        
        # Baseline data versioning for migration safety per Section 4.7.2
        self.baseline_version = "1.0.0"
        self.creation_timestamp = datetime.now(timezone.utc).isoformat()
        
        logger.info(f"Initialized BaselineDataManager with data directory: {self.data_directory}")
    
    def add_api_baseline(self, baseline: APIResponseBaseline) -> None:
        """
        Add API response baseline data for comparative validation.
        
        Args:
            baseline: APIResponseBaseline instance with Node.js response data
        """
        key = f"{baseline.method}_{baseline.endpoint}".replace("/", "_")
        self.api_baselines[key] = baseline
        logger.info(f"Added API baseline for {baseline.method} {baseline.endpoint}")
    
    def add_business_logic_baseline(self, baseline: BusinessLogicBaseline) -> None:
        """
        Add business logic baseline data for equivalence testing.
        
        Args:
            baseline: BusinessLogicBaseline instance with expected outcomes
        """
        self.business_logic_baselines[baseline.operation_name] = baseline
        logger.info(f"Added business logic baseline for {baseline.operation_name}")
    
    def add_database_baseline(self, baseline: DatabaseOperationBaseline) -> None:
        """
        Add database operation baseline data for consistency validation.
        
        Args:
            baseline: DatabaseOperationBaseline instance with expected results
        """
        key = f"{baseline.operation_type}_{baseline.entity_type}"
        self.database_baselines[key] = baseline
        logger.info(f"Added database baseline for {baseline.operation_type} on {baseline.entity_type}")
    
    def add_error_handling_baseline(self, baseline: ErrorHandlingBaseline) -> None:
        """
        Add error handling baseline data for behavior preservation.
        
        Args:
            baseline: ErrorHandlingBaseline instance with expected error behavior
        """
        self.error_handling_baselines[baseline.error_scenario] = baseline
        logger.info(f"Added error handling baseline for {baseline.error_scenario}")
    
    def add_performance_baseline(self, baseline: PerformanceMetricBaseline) -> None:
        """
        Add performance metric baseline data for comparison testing.
        
        Args:
            baseline: PerformanceMetricBaseline instance with performance standards
        """
        self.performance_baselines[baseline.metric_name] = baseline
        logger.info(f"Added performance baseline for {baseline.metric_name}")
    
    def get_api_baseline(self, method: str, endpoint: str) -> Optional[APIResponseBaseline]:
        """
        Retrieve API response baseline for comparison testing.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            
        Returns:
            APIResponseBaseline instance or None if not found
        """
        key = f"{method}_{endpoint}".replace("/", "_")
        return self.api_baselines.get(key)
    
    def get_performance_baseline(self, metric_name: str) -> Optional[PerformanceMetricBaseline]:
        """
        Retrieve performance metric baseline for comparison testing.
        
        Args:
            metric_name: Name of the performance metric
            
        Returns:
            PerformanceMetricBaseline instance or None if not found
        """
        return self.performance_baselines.get(metric_name)
    
    def save_baselines_to_file(self, filename: Optional[str] = None) -> str:
        """
        Save all baseline data to JSON file for persistence and versioning.
        
        Args:
            filename: Optional filename, defaults to timestamped baseline file
            
        Returns:
            Path to saved baseline file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nodejs_baseline_{timestamp}.json"
        
        filepath = self.data_directory / filename
        
        baseline_data = {
            "version": self.baseline_version,
            "creation_timestamp": self.creation_timestamp,
            "api_baselines": {k: v.to_dict() for k, v in self.api_baselines.items()},
            "business_logic_baselines": {k: v.to_dict() for k, v in self.business_logic_baselines.items()},
            "database_baselines": {k: v.to_dict() for k, v in self.database_baselines.items()},
            "error_handling_baselines": {k: v.to_dict() for k, v in self.error_handling_baselines.items()},
            "performance_baselines": {k: v.to_dict() for k, v in self.performance_baselines.items()},
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(baseline_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved baseline data to {filepath}")
        return str(filepath)
    
    def load_baselines_from_file(self, filepath: str) -> None:
        """
        Load baseline data from JSON file for validation testing.
        
        Args:
            filepath: Path to baseline data file
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            baseline_data = json.load(f)
        
        self.baseline_version = baseline_data.get("version", "1.0.0")
        self.creation_timestamp = baseline_data.get("creation_timestamp", datetime.now(timezone.utc).isoformat())
        
        # Load API baselines
        for key, data in baseline_data.get("api_baselines", {}).items():
            self.api_baselines[key] = APIResponseBaseline(**data)
        
        # Load business logic baselines
        for key, data in baseline_data.get("business_logic_baselines", {}).items():
            self.business_logic_baselines[key] = BusinessLogicBaseline(**data)
        
        # Load database baselines
        for key, data in baseline_data.get("database_baselines", {}).items():
            self.database_baselines[key] = DatabaseOperationBaseline(**data)
        
        # Load error handling baselines
        for key, data in baseline_data.get("error_handling_baselines", {}).items():
            self.error_handling_baselines[key] = ErrorHandlingBaseline(**data)
        
        # Load performance baselines
        for key, data in baseline_data.get("performance_baselines", {}).items():
            self.performance_baselines[key] = PerformanceMetricBaseline(**data)
        
        logger.info(f"Loaded baseline data from {filepath}")
    
    def validate_flask_response(self, 
                               method: str, 
                               endpoint: str, 
                               flask_response: Dict[str, Any], 
                               response_time_ms: float) -> Tuple[bool, List[str]]:
        """
        Validate Flask response against Node.js baseline for parity testing.
        
        Args:
            method: HTTP method used
            endpoint: API endpoint tested
            flask_response: Response data from Flask system
            response_time_ms: Response time in milliseconds
            
        Returns:
            Tuple of (is_valid, validation_errors)
        """
        baseline = self.get_api_baseline(method, endpoint)
        if not baseline:
            return False, [f"No baseline found for {method} {endpoint}"]
        
        validation_errors = []
        
        # Validate response data structure
        if flask_response != baseline.response_data:
            validation_errors.append("Response data does not match baseline")
        
        # Validate performance within acceptable range
        performance_baseline = self.get_performance_baseline("api_response_time")
        if performance_baseline and not performance_baseline.is_within_acceptable_range(response_time_ms):
            validation_errors.append(f"Response time {response_time_ms}ms exceeds baseline variance")
        
        return len(validation_errors) == 0, validation_errors
    
    def get_baseline_summary(self) -> Dict[str, int]:
        """
        Get summary statistics of baseline data for reporting.
        
        Returns:
            Dictionary with baseline data counts by type
        """
        return {
            "api_baselines": len(self.api_baselines),
            "business_logic_baselines": len(self.business_logic_baselines),
            "database_baselines": len(self.database_baselines),
            "error_handling_baselines": len(self.error_handling_baselines),
            "performance_baselines": len(self.performance_baselines),
            "total_baselines": (
                len(self.api_baselines) + 
                len(self.business_logic_baselines) + 
                len(self.database_baselines) + 
                len(self.error_handling_baselines) + 
                len(self.performance_baselines)
            )
        }


# Node.js System Baseline Data Collection
# This section provides pre-captured baseline data from the Node.js system
# for immediate use in comparative validation testing per Feature F-009

class NodeJSBaselineData:
    """
    Pre-captured Node.js system baseline data for immediate validation use.
    
    This class provides comprehensive baseline datasets captured from the original
    Node.js system for Feature F-009 functionality parity validation.
    """
    
    @staticmethod
    def get_sample_api_baselines() -> List[APIResponseBaseline]:
        """
        Get sample API response baselines from Node.js system.
        
        Returns:
            List of APIResponseBaseline instances with Node.js response data
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        
        return [
            # User Management API Baselines
            APIResponseBaseline(
                endpoint="/api/users",
                method="GET",
                status_code=200,
                headers={"Content-Type": "application/json", "X-API-Version": "1.0"},
                response_data={
                    "users": [
                        {"id": 1, "username": "admin", "email": "admin@example.com", "active": True},
                        {"id": 2, "username": "user1", "email": "user1@example.com", "active": True}
                    ],
                    "total": 2,
                    "page": 1,
                    "limit": 10
                },
                response_time_ms=45.2,
                timestamp=timestamp,
                authentication_type="Bearer"
            ),
            
            APIResponseBaseline(
                endpoint="/api/users",
                method="POST",
                status_code=201,
                headers={"Content-Type": "application/json", "Location": "/api/users/3"},
                response_data={
                    "id": 3,
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "active": True,
                    "created_at": "2024-01-01T12:00:00Z"
                },
                response_time_ms=78.5,
                timestamp=timestamp,
                request_payload={
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "securepassword"
                },
                authentication_type="Bearer"
            ),
            
            # Authentication API Baselines
            APIResponseBaseline(
                endpoint="/api/auth/login",
                method="POST",
                status_code=200,
                headers={"Content-Type": "application/json", "Set-Cookie": "session=abc123"},
                response_data={
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "user": {
                        "id": 1,
                        "username": "admin",
                        "email": "admin@example.com"
                    },
                    "expires_in": 3600
                },
                response_time_ms=125.8,
                timestamp=timestamp,
                request_payload={
                    "username": "admin",
                    "password": "adminpassword"
                }
            ),
            
            # Data Retrieval API Baselines
            APIResponseBaseline(
                endpoint="/api/data/reports",
                method="GET",
                status_code=200,
                headers={"Content-Type": "application/json", "Cache-Control": "max-age=300"},
                response_data={
                    "reports": [
                        {
                            "id": 1,
                            "title": "Monthly Report",
                            "created_at": "2024-01-01T10:00:00Z",
                            "status": "completed",
                            "data": {"revenue": 50000, "users": 1250}
                        }
                    ],
                    "meta": {
                        "total": 1,
                        "generated_at": "2024-01-01T12:00:00Z"
                    }
                },
                response_time_ms=95.3,
                timestamp=timestamp,
                query_parameters={"period": "monthly", "year": "2024"},
                authentication_type="Bearer"
            )
        ]
    
    @staticmethod
    def get_sample_performance_baselines() -> List[PerformanceMetricBaseline]:
        """
        Get sample performance metric baselines from Node.js system.
        
        Returns:
            List of PerformanceMetricBaseline instances with Node.js metrics
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        
        return [
            # API Response Time Baselines
            PerformanceMetricBaseline(
                metric_name="api_response_time",
                metric_type="response_time",
                baseline_value=75.0,
                unit="milliseconds",
                measurement_conditions={
                    "concurrent_users": 10,
                    "endpoint_type": "data_retrieval",
                    "database_load": "normal"
                },
                acceptable_variance_percent=15.0,
                timestamp=timestamp,
                environment_context={
                    "nodejs_version": "18.x",
                    "express_version": "4.x",
                    "memory_limit": "512MB",
                    "cpu_cores": 2
                }
            ),
            
            # Memory Usage Baselines
            PerformanceMetricBaseline(
                metric_name="memory_usage",
                metric_type="memory",
                baseline_value=128.0,
                unit="MB",
                measurement_conditions={
                    "active_sessions": 50,
                    "cache_size": "medium",
                    "background_tasks": 3
                },
                acceptable_variance_percent=20.0,
                timestamp=timestamp,
                environment_context={
                    "nodejs_version": "18.x",
                    "heap_size": "256MB",
                    "gc_frequency": "normal"
                }
            ),
            
            # Database Query Performance Baselines
            PerformanceMetricBaseline(
                metric_name="database_query_time",
                metric_type="query_performance",
                baseline_value=25.5,
                unit="milliseconds",
                measurement_conditions={
                    "query_type": "SELECT",
                    "result_count": 100,
                    "index_usage": True
                },
                acceptable_variance_percent=10.0,
                timestamp=timestamp,
                environment_context={
                    "database_type": "MongoDB",
                    "connection_pool_size": 10,
                    "index_optimization": True
                }
            ),
            
            # Concurrent User Load Baselines
            PerformanceMetricBaseline(
                metric_name="concurrent_user_capacity",
                metric_type="throughput",
                baseline_value=100.0,
                unit="users",
                measurement_conditions={
                    "response_time_limit": "200ms",
                    "error_rate_limit": "1%",
                    "resource_utilization": "80%"
                },
                acceptable_variance_percent=5.0,
                timestamp=timestamp,
                environment_context={
                    "load_balancer": "enabled",
                    "session_store": "redis",
                    "monitoring": "enabled"
                }
            )
        ]
    
    @staticmethod
    def get_sample_error_baselines() -> List[ErrorHandlingBaseline]:
        """
        Get sample error handling baselines from Node.js system.
        
        Returns:
            List of ErrorHandlingBaseline instances with Node.js error behavior
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        
        return [
            # Authentication Error Baselines
            ErrorHandlingBaseline(
                error_scenario="invalid_credentials",
                trigger_conditions={
                    "endpoint": "/api/auth/login",
                    "username": "invalid_user",
                    "password": "wrong_password"
                },
                expected_status_code=401,
                expected_error_message="Invalid username or password",
                expected_error_type="AuthenticationError",
                error_details={
                    "error_code": "AUTH_001",
                    "retry_allowed": True,
                    "lockout_after": 5
                },
                recovery_actions=["verify_credentials", "reset_password"],
                timestamp=timestamp
            ),
            
            # Validation Error Baselines
            ErrorHandlingBaseline(
                error_scenario="invalid_input_data",
                trigger_conditions={
                    "endpoint": "/api/users",
                    "method": "POST",
                    "payload": {"username": "", "email": "invalid-email"}
                },
                expected_status_code=400,
                expected_error_message="Validation failed",
                expected_error_type="ValidationError",
                error_details={
                    "error_code": "VAL_001",
                    "field_errors": {
                        "username": "Username is required",
                        "email": "Invalid email format"
                    }
                },
                recovery_actions=["correct_input", "validate_format"],
                timestamp=timestamp
            ),
            
            # Resource Not Found Error Baselines
            ErrorHandlingBaseline(
                error_scenario="resource_not_found",
                trigger_conditions={
                    "endpoint": "/api/users/999",
                    "method": "GET",
                    "resource_id": 999
                },
                expected_status_code=404,
                expected_error_message="User not found",
                expected_error_type="NotFoundError",
                error_details={
                    "error_code": "RES_001",
                    "resource_type": "User",
                    "resource_id": 999
                },
                recovery_actions=["verify_id", "check_permissions"],
                timestamp=timestamp
            ),
            
            # Server Error Baselines
            ErrorHandlingBaseline(
                error_scenario="database_connection_error",
                trigger_conditions={
                    "endpoint": "/api/data/reports",
                    "database_status": "unavailable",
                    "connection_timeout": True
                },
                expected_status_code=500,
                expected_error_message="Internal server error",
                expected_error_type="DatabaseError",
                error_details={
                    "error_code": "DB_001",
                    "retry_after": 30,
                    "monitoring_alert": True
                },
                recovery_actions=["check_database", "retry_connection", "fallback_data"],
                timestamp=timestamp
            )
        ]


# Global baseline data manager instance for test module usage
baseline_manager = BaselineDataManager()

# Pre-load Node.js baseline data for immediate use
def initialize_baseline_data():
    """
    Initialize baseline data manager with Node.js system baseline data.
    
    This function pre-loads comprehensive baseline data from the Node.js system
    for immediate use in Feature F-009 comparative validation testing.
    """
    logger.info("Initializing Node.js baseline data for comparative validation")
    
    # Load API response baselines
    for baseline in NodeJSBaselineData.get_sample_api_baselines():
        baseline_manager.add_api_baseline(baseline)
    
    # Load performance metric baselines
    for baseline in NodeJSBaselineData.get_sample_performance_baselines():
        baseline_manager.add_performance_baseline(baseline)
    
    # Load error handling baselines
    for baseline in NodeJSBaselineData.get_sample_error_baselines():
        baseline_manager.add_error_handling_baseline(baseline)
    
    # Save initialized baseline data for persistence
    baseline_file = baseline_manager.save_baselines_to_file("nodejs_baseline_initial.json")
    
    summary = baseline_manager.get_baseline_summary()
    logger.info(f"Baseline data initialization complete: {summary}")
    logger.info(f"Baseline data saved to: {baseline_file}")
    
    return baseline_manager


# Initialize baseline data when module is imported
if __name__ == "__main__":
    # Allow running module directly for baseline data initialization
    initialize_baseline_data()
else:
    # Auto-initialize when imported by test modules
    initialize_baseline_data()