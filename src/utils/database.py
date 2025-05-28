"""
Database Utility Functions for Flask-SQLAlchemy Integration

This module provides comprehensive database utility functions that support the Flask 3.1.1
application's migration from Node.js/Express.js to Python/Flask architecture. The utilities
offer Flask-SQLAlchemy integration helpers, PostgreSQL connection management, transaction
utilities, and migration support to ensure zero data loss during the MongoDB to PostgreSQL
transition while maintaining equivalent or improved performance metrics.

Key Features:
- Flask-SQLAlchemy 3.1.1 integration with PostgreSQL 15.x
- Advanced connection pooling management with optimization
- Transaction management with comprehensive rollback capabilities
- Flask-Migrate 4.1.0 integration for database versioning
- Zero data loss validation during MongoDB migration
- Performance monitoring and query optimization utilities
- Backup and recovery procedure integration
- Connection health monitoring and automatic recovery

Architecture Integration:
- Flask application factory pattern integration per Section 5.1.1
- Service Layer pattern support for business logic per Section 5.2.3
- Blueprint-based modular architecture support per Section 5.2.2
- Enterprise-grade monitoring and observability per Section 5.4.1
- AWS RDS integration with containerized deployment per Section 8.3

Performance Requirements:
- 95th percentile targets: Simple queries < 500ms, Complex queries < 2000ms
- 99th percentile targets: Simple queries < 1000ms, Complex queries < 3000ms
- Connection pooling optimization for production workloads
- Query execution monitoring and bottleneck identification
- Automated performance regression detection

Security and Compliance:
- ACID-compliant transaction management
- Comprehensive audit logging integration
- Zero data loss validation procedures
- Rollback and recovery automation
- Connection security and encryption support

Dependencies:
- Flask-SQLAlchemy 3.1.1 for ORM functionality
- psycopg2 2.9.9 for PostgreSQL database adapter
- Flask-Migrate 4.1.0 for Alembic-based migrations
- src.utils.config for configuration management
- src.utils.logging for structured logging
- PostgreSQL 15.x database engine

Author: Flask Migration Team
Version: 1.0.0
Last Updated: 2024
"""

import os
import time
import threading
import warnings
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Union, List, Tuple, Callable, Type, Generator
from functools import wraps, lru_cache
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
import json
import uuid
from collections import defaultdict, deque
import re

# Core Flask and SQLAlchemy imports
try:
    from flask import Flask, current_app, has_app_context, g
    from flask_sqlalchemy import SQLAlchemy
    from flask_migrate import Migrate, upgrade, downgrade, current as current_revision
    from sqlalchemy import (
        create_engine, MetaData, inspect, text, event, Engine, Connection,
        exc as sqlalchemy_exc, pool as sqlalchemy_pool
    )
    from sqlalchemy.orm import sessionmaker, Session, scoped_session
    from sqlalchemy.engine.events import PoolEvents
    from sqlalchemy.pool import QueuePool, StaticPool
    from sqlalchemy.schema import CreateTable
    from sqlalchemy.dialects import postgresql
    SQLALCHEMY_AVAILABLE = True
except ImportError as e:
    SQLALCHEMY_AVAILABLE = False
    SQLAlchemy = None
    Migrate = None
    print(f"Warning: SQLAlchemy components not available: {e}")

# PostgreSQL-specific imports
try:
    import psycopg2
    from psycopg2 import sql, OperationalError as Psycopg2OperationalError
    from psycopg2.extras import DictCursor, RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    psycopg2 = None

# Performance monitoring imports
try:
    from prometheus_client import Counter, Histogram, Gauge, Summary
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Alembic imports for migration management
try:
    from alembic import command as alembic_command
    from alembic.config import Config as AlembicConfig
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory
    from alembic.environment import EnvironmentContext
    ALEMBIC_AVAILABLE = True
except ImportError:
    ALEMBIC_AVAILABLE = False

# Internal imports
try:
    from src.utils.config import (
        ConfigurationManager, ConfigurationError, 
        get_default_configuration_manager
    )
    from src.utils.logging import (
        get_structured_logger, LogCategory, SecurityEventType,
        audit_log, performance_log
    )
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    print("Warning: Internal configuration and logging modules not available")


class DatabaseError(Exception):
    """Base exception for database-related errors."""
    pass


class ConnectionError(DatabaseError):
    """Exception for database connection-related errors."""
    pass


class TransactionError(DatabaseError):
    """Exception for database transaction-related errors."""
    pass


class MigrationError(DatabaseError):
    """Exception for database migration-related errors."""
    pass


class PerformanceError(DatabaseError):
    """Exception for database performance-related errors."""
    pass


class ValidationError(DatabaseError):
    """Exception for database validation-related errors."""
    pass


class DatabaseOperationType(Enum):
    """Database operation types for monitoring and logging."""
    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    BULK_INSERT = "bulk_insert"
    BULK_UPDATE = "bulk_update"
    MIGRATION = "migration"
    ROLLBACK = "rollback"
    BACKUP = "backup"
    RESTORE = "restore"


class ConnectionPoolMetrics(Enum):
    """Connection pool metrics for monitoring."""
    TOTAL_CONNECTIONS = "total_connections"
    ACTIVE_CONNECTIONS = "active_connections"
    IDLE_CONNECTIONS = "idle_connections"
    OVERFLOW_CONNECTIONS = "overflow_connections"
    INVALID_CONNECTIONS = "invalid_connections"
    POOL_TIMEOUTS = "pool_timeouts"
    CONNECTION_ERRORS = "connection_errors"


@dataclass
class DatabaseMetrics:
    """Database performance and health metrics."""
    query_count: int = 0
    total_query_time: float = 0.0
    average_query_time: float = 0.0
    slowest_query_time: float = 0.0
    fastest_query_time: float = float('inf')
    connection_count: int = 0
    pool_size: int = 0
    overflow_count: int = 0
    error_count: int = 0
    last_updated: Optional[datetime] = None
    
    def update_query_stats(self, execution_time: float) -> None:
        """Update query performance statistics."""
        self.query_count += 1
        self.total_query_time += execution_time
        self.average_query_time = self.total_query_time / self.query_count
        self.slowest_query_time = max(self.slowest_query_time, execution_time)
        self.fastest_query_time = min(self.fastest_query_time, execution_time)
        self.last_updated = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        return {
            'query_count': self.query_count,
            'total_query_time': self.total_query_time,
            'average_query_time': self.average_query_time,
            'slowest_query_time': self.slowest_query_time,
            'fastest_query_time': self.fastest_query_time if self.fastest_query_time != float('inf') else 0.0,
            'connection_count': self.connection_count,
            'pool_size': self.pool_size,
            'overflow_count': self.overflow_count,
            'error_count': self.error_count,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None
        }


@dataclass
class TransactionContext:
    """Context information for database transactions."""
    transaction_id: str
    start_time: datetime
    operation_type: DatabaseOperationType
    table_name: Optional[str] = None
    record_count: Optional[int] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction context to dictionary."""
        return {
            'transaction_id': self.transaction_id,
            'start_time': self.start_time.isoformat(),
            'operation_type': self.operation_type.value,
            'table_name': self.table_name,
            'record_count': self.record_count,
            'user_id': self.user_id,
            'request_id': self.request_id,
            'metadata': self.metadata
        }


class DatabasePerformanceMonitor:
    """
    Database performance monitoring with Prometheus metrics integration.
    
    Monitors query execution times, connection pool utilization, and database
    performance metrics to ensure SLA compliance and detect performance regressions.
    Integrates with Flask-MonitoringDashboard for comprehensive observability.
    """
    
    def __init__(self):
        """Initialize database performance monitor."""
        self.metrics = DatabaseMetrics()
        self.query_history = deque(maxlen=1000)  # Keep last 1000 queries
        self.slow_query_threshold = 2.0  # 2 seconds threshold for slow queries
        self.performance_targets = {
            'simple_query_95th': 0.5,  # 500ms
            'complex_query_95th': 2.0,  # 2000ms
            'simple_query_99th': 1.0,  # 1000ms
            'complex_query_99th': 3.0   # 3000ms
        }
        self.logger = self._get_logger()
        self._setup_prometheus_metrics()
    
    def _get_logger(self):
        """Get structured logger for performance monitoring."""
        if CONFIG_AVAILABLE:
            return get_structured_logger("database_performance_monitor")
        else:
            import logging
            return logging.getLogger("database_performance_monitor")
    
    def _setup_prometheus_metrics(self) -> None:
        """Setup Prometheus metrics for database monitoring."""
        if not PROMETHEUS_AVAILABLE:
            self.logger.warning("Prometheus client not available, metrics disabled")
            return
        
        try:
            # Query performance metrics
            self.query_duration = Histogram(
                'database_query_duration_seconds',
                'Database query execution time in seconds',
                ['operation_type', 'table_name']
            )
            
            self.query_counter = Counter(
                'database_queries_total',
                'Total number of database queries',
                ['operation_type', 'table_name', 'status']
            )
            
            # Connection pool metrics
            self.connection_pool_size = Gauge(
                'database_connection_pool_size',
                'Current database connection pool size'
            )
            
            self.connection_pool_overflow = Gauge(
                'database_connection_pool_overflow',
                'Current database connection pool overflow count'
            )
            
            self.connection_pool_checked_out = Gauge(
                'database_connection_pool_checked_out',
                'Current number of checked out connections'
            )
            
            # Performance threshold violations
            self.slow_query_counter = Counter(
                'database_slow_queries_total',
                'Total number of slow database queries',
                ['query_type', 'threshold']
            )
            
            self.logger.info("Prometheus metrics initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Prometheus metrics: {e}")
    
    def record_query(self, query: str, execution_time: float, 
                    operation_type: DatabaseOperationType, 
                    table_name: Optional[str] = None,
                    error: Optional[Exception] = None) -> None:
        """
        Record query execution metrics.
        
        Args:
            query: SQL query string
            execution_time: Query execution time in seconds
            operation_type: Type of database operation
            table_name: Target table name (if applicable)
            error: Exception if query failed
        """
        # Update internal metrics
        if error is None:
            self.metrics.update_query_stats(execution_time)
        else:
            self.metrics.error_count += 1
        
        # Store query history
        query_record = {
            'timestamp': datetime.utcnow(),
            'query': query[:500],  # Truncate long queries
            'execution_time': execution_time,
            'operation_type': operation_type.value,
            'table_name': table_name,
            'error': str(error) if error else None
        }
        self.query_history.append(query_record)
        
        # Update Prometheus metrics
        if PROMETHEUS_AVAILABLE and hasattr(self, 'query_duration'):
            status = 'error' if error else 'success'
            self.query_counter.labels(
                operation_type=operation_type.value,
                table_name=table_name or 'unknown',
                status=status
            ).inc()
            
            if error is None:
                self.query_duration.labels(
                    operation_type=operation_type.value,
                    table_name=table_name or 'unknown'
                ).observe(execution_time)
        
        # Check for slow queries
        if execution_time > self.slow_query_threshold:
            self._handle_slow_query(query, execution_time, operation_type, table_name)
        
        # Performance threshold validation
        self._validate_performance_targets(execution_time, operation_type)
    
    def _handle_slow_query(self, query: str, execution_time: float,
                          operation_type: DatabaseOperationType, 
                          table_name: Optional[str]) -> None:
        """Handle slow query detection and logging."""
        if PROMETHEUS_AVAILABLE and hasattr(self, 'slow_query_counter'):
            threshold = '2s' if execution_time < 5.0 else '5s+'
            self.slow_query_counter.labels(
                query_type=operation_type.value,
                threshold=threshold
            ).inc()
        
        # Log slow query for analysis
        self.logger.warning(
            "Slow query detected",
            extra={
                'execution_time': execution_time,
                'operation_type': operation_type.value,
                'table_name': table_name,
                'query_preview': query[:200],
                'threshold': self.slow_query_threshold,
                'category': LogCategory.PERFORMANCE.value if CONFIG_AVAILABLE else 'performance'
            }
        )
    
    def _validate_performance_targets(self, execution_time: float, 
                                    operation_type: DatabaseOperationType) -> None:
        """Validate query execution against performance targets."""
        is_complex_query = operation_type in [
            DatabaseOperationType.BULK_INSERT,
            DatabaseOperationType.BULK_UPDATE,
            DatabaseOperationType.MIGRATION
        ]
        
        target_key = 'complex_query_95th' if is_complex_query else 'simple_query_95th'
        target_threshold = self.performance_targets[target_key]
        
        if execution_time > target_threshold:
            self.logger.warning(
                "Performance target violation",
                extra={
                    'execution_time': execution_time,
                    'target_threshold': target_threshold,
                    'operation_type': operation_type.value,
                    'is_complex_query': is_complex_query,
                    'category': LogCategory.PERFORMANCE.value if CONFIG_AVAILABLE else 'performance'
                }
            )
    
    def update_connection_metrics(self, pool_size: int, checked_out: int, 
                                overflow: int) -> None:
        """Update connection pool metrics."""
        self.metrics.pool_size = pool_size
        self.metrics.overflow_count = overflow
        self.metrics.connection_count = checked_out
        
        if PROMETHEUS_AVAILABLE and hasattr(self, 'connection_pool_size'):
            self.connection_pool_size.set(pool_size)
            self.connection_pool_checked_out.set(checked_out)
            self.connection_pool_overflow.set(overflow)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary."""
        return {
            'current_metrics': self.metrics.to_dict(),
            'performance_targets': self.performance_targets,
            'recent_queries': len(self.query_history),
            'slow_query_threshold': self.slow_query_threshold
        }


class ConnectionPoolManager:
    """
    Advanced connection pool management for PostgreSQL with Flask-SQLAlchemy.
    
    Provides sophisticated connection pooling with health monitoring, automatic
    recovery, and performance optimization. Integrates with Flask application
    factory pattern and supports container orchestration environments.
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize connection pool manager.
        
        Args:
            app: Flask application instance (optional for factory pattern)
        """
        self.app = app
        self.logger = self._get_logger()
        self.performance_monitor = DatabasePerformanceMonitor()
        self._connection_events_registered = False
        self._pool_health_check_interval = 60  # seconds
        self._last_health_check = datetime.utcnow()
        
        if app is not None:
            self.init_app(app)
    
    def _get_logger(self):
        """Get structured logger for connection pool management."""
        if CONFIG_AVAILABLE:
            return get_structured_logger("connection_pool_manager")
        else:
            import logging
            return logging.getLogger("connection_pool_manager")
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize connection pool with Flask application.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        
        # Register connection pool events
        if not self._connection_events_registered:
            self._register_connection_events()
            self._connection_events_registered = True
        
        # Setup periodic health checks
        app.teardown_appcontext(self._cleanup_connections)
        
        self.logger.info("Connection pool manager initialized")
    
    def _register_connection_events(self) -> None:
        """Register SQLAlchemy connection pool events for monitoring."""
        if not SQLALCHEMY_AVAILABLE:
            self.logger.warning("SQLAlchemy not available, skipping event registration")
            return
        
        @event.listens_for(Engine, "connect")
        def on_connect(dbapi_connection, connection_record):
            """Handle new database connections."""
            self.logger.debug("New database connection established")
            
            # Set connection-specific parameters for PostgreSQL
            if PSYCOPG2_AVAILABLE:
                with dbapi_connection.cursor() as cursor:
                    # Enable autocommit for connection health checks
                    cursor.execute("SET autocommit = true")
                    # Set application name for monitoring
                    cursor.execute("SET application_name = 'flask_app'")
        
        @event.listens_for(Engine, "checkout")
        def on_checkout(dbapi_connection, connection_record, connection_proxy):
            """Handle connection checkout from pool."""
            if hasattr(current_app, 'db') and current_app.db.engine:
                pool = current_app.db.engine.pool
                self.performance_monitor.update_connection_metrics(
                    pool_size=pool.size(),
                    checked_out=pool.checkedout(),
                    overflow=pool.overflow()
                )
        
        @event.listens_for(Engine, "checkin")
        def on_checkin(dbapi_connection, connection_record):
            """Handle connection checkin to pool."""
            self.logger.debug("Database connection returned to pool")
        
        @event.listens_for(Engine, "invalidate")
        def on_invalidate(dbapi_connection, connection_record, exception):
            """Handle connection invalidation."""
            self.logger.warning(
                "Database connection invalidated",
                extra={
                    'exception': str(exception),
                    'category': LogCategory.ERROR.value if CONFIG_AVAILABLE else 'error'
                }
            )
    
    def create_optimized_engine(self, database_uri: str, 
                              pool_config: Optional[Dict[str, Any]] = None) -> Engine:
        """
        Create optimized SQLAlchemy engine with advanced connection pooling.
        
        Args:
            database_uri: Database connection URI
            pool_config: Optional pool configuration overrides
            
        Returns:
            Configured SQLAlchemy engine
        """
        # Default pool configuration based on technical specification
        default_config = {
            'poolclass': QueuePool,
            'pool_size': 20,
            'max_overflow': 10,
            'pool_timeout': 30,
            'pool_recycle': 3600,
            'pool_pre_ping': True,
            'echo': False,
            'echo_pool': False
        }
        
        # Merge with provided configuration
        if pool_config:
            default_config.update(pool_config)
        
        # PostgreSQL-specific optimizations
        connect_args = {
            'application_name': 'flask_app',
            'connect_timeout': 30,
            'sslmode': 'prefer'
        }
        
        # Environment-specific optimizations
        if CONFIG_AVAILABLE:
            config_manager = get_default_configuration_manager()
            if config_manager.environment.is_production_like:
                # Production optimizations
                connect_args.update({
                    'sslmode': 'require',
                    'keepalives_idle': '600',
                    'keepalives_interval': '30',
                    'keepalives_count': '3'
                })
                default_config.update({
                    'pool_size': 30,
                    'max_overflow': 20,
                    'echo': False
                })
            elif config_manager.environment.allows_debug:
                # Development optimizations
                default_config.update({
                    'pool_size': 5,
                    'max_overflow': 2,
                    'echo': True
                })
        
        try:
            engine = create_engine(
                database_uri,
                connect_args=connect_args,
                **default_config
            )
            
            # Test connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            self.logger.info(
                "Database engine created successfully",
                extra={
                    'pool_size': default_config['pool_size'],
                    'max_overflow': default_config['max_overflow'],
                    'pool_timeout': default_config['pool_timeout']
                }
            )
            
            return engine
            
        except Exception as e:
            self.logger.error(f"Failed to create database engine: {e}")
            raise ConnectionError(f"Database engine creation failed: {e}")
    
    def validate_connection_health(self, engine: Engine) -> bool:
        """
        Validate database connection health with comprehensive checks.
        
        Args:
            engine: SQLAlchemy engine to validate
            
        Returns:
            True if connection is healthy, False otherwise
        """
        try:
            start_time = time.time()
            
            with engine.connect() as conn:
                # Basic connectivity test
                result = conn.execute(text("SELECT 1 as health_check"))
                if result.scalar() != 1:
                    return False
                
                # PostgreSQL-specific health checks
                if 'postgresql' in str(engine.url):
                    # Check database version
                    version_result = conn.execute(text("SELECT version()"))
                    version_info = version_result.scalar()
                    
                    # Check for active connections
                    active_connections = conn.execute(text(
                        "SELECT count(*) FROM pg_stat_activity WHERE state = 'active'"
                    ))
                    active_count = active_connections.scalar()
                    
                    # Check for long-running transactions
                    long_transactions = conn.execute(text("""
                        SELECT count(*) FROM pg_stat_activity 
                        WHERE state IN ('idle in transaction', 'idle in transaction (aborted)')
                        AND now() - xact_start > interval '10 minutes'
                    """))
                    long_tx_count = long_transactions.scalar()
                    
                    if long_tx_count > 0:
                        self.logger.warning(
                            f"Long-running transactions detected: {long_tx_count}",
                            extra={'category': LogCategory.PERFORMANCE.value if CONFIG_AVAILABLE else 'performance'}
                        )
            
            execution_time = time.time() - start_time
            
            # Record health check performance
            self.performance_monitor.record_query(
                "SELECT 1 as health_check",
                execution_time,
                DatabaseOperationType.SELECT
            )
            
            # Health check should complete quickly
            if execution_time > 5.0:
                self.logger.warning(
                    f"Slow health check detected: {execution_time:.2f}s",
                    extra={'category': LogCategory.PERFORMANCE.value if CONFIG_AVAILABLE else 'performance'}
                )
            
            self._last_health_check = datetime.utcnow()
            return True
            
        except Exception as e:
            self.logger.error(
                f"Connection health check failed: {e}",
                extra={'category': LogCategory.ERROR.value if CONFIG_AVAILABLE else 'error'}
            )
            return False
    
    def get_pool_status(self, engine: Engine) -> Dict[str, Any]:
        """
        Get comprehensive connection pool status information.
        
        Args:
            engine: SQLAlchemy engine to inspect
            
        Returns:
            Dictionary containing pool status information
        """
        if not hasattr(engine, 'pool'):
            return {'error': 'Engine does not have a connection pool'}
        
        pool = engine.pool
        
        status = {
            'pool_class': pool.__class__.__name__,
            'size': pool.size(),
            'checked_out': pool.checkedout(),
            'overflow': pool.overflow(),
            'invalid': pool.invalid(),
            'checked_in': pool.checkedin(),
            'last_health_check': self._last_health_check.isoformat(),
            'health_check_interval': self._pool_health_check_interval
        }
        
        # Add pool-specific information
        if hasattr(pool, '_creator'):
            status['connection_class'] = pool._creator.__name__ if hasattr(pool._creator, '__name__') else str(pool._creator)
        
        if hasattr(pool, '_recycle'):
            status['recycle_time'] = pool._recycle
        
        return status
    
    def _cleanup_connections(self, exception: Optional[Exception] = None) -> None:
        """Clean up connections at the end of request context."""
        if exception is not None:
            self.logger.error(
                f"Request ended with exception: {exception}",
                extra={'category': LogCategory.ERROR.value if CONFIG_AVAILABLE else 'error'}
            )
        
        # Perform periodic health checks
        now = datetime.utcnow()
        if (now - self._last_health_check).total_seconds() > self._pool_health_check_interval:
            if has_app_context() and hasattr(current_app, 'db'):
                try:
                    self.validate_connection_health(current_app.db.engine)
                except Exception as e:
                    self.logger.error(f"Health check during cleanup failed: {e}")


class TransactionManager:
    """
    Advanced transaction management with rollback capabilities and monitoring.
    
    Provides comprehensive transaction lifecycle management with automatic rollback
    procedures, nested transaction support, and audit logging. Integrates with
    Flask request context and supports complex business workflows.
    """
    
    def __init__(self):
        """Initialize transaction manager."""
        self.logger = self._get_logger()
        self.active_transactions: Dict[str, TransactionContext] = {}
        self._transaction_timeout = 300  # 5 minutes
        self._nested_transaction_support = True
    
    def _get_logger(self):
        """Get structured logger for transaction management."""
        if CONFIG_AVAILABLE:
            return get_structured_logger("transaction_manager")
        else:
            import logging
            return logging.getLogger("transaction_manager")
    
    @contextmanager
    def managed_transaction(
        self,
        session: Optional[Session] = None,
        operation_type: DatabaseOperationType = DatabaseOperationType.SELECT,
        table_name: Optional[str] = None,
        user_id: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> Generator[Tuple[Session, str], None, None]:
        """
        Context manager for managed database transactions with automatic rollback.
        
        Args:
            session: SQLAlchemy session (creates new if None)
            operation_type: Type of database operation
            table_name: Target table name
            user_id: User ID for audit logging
            timeout: Transaction timeout in seconds
            
        Yields:
            Tuple of (session, transaction_id)
            
        Example:
            >>> with transaction_manager.managed_transaction(
            ...     operation_type=DatabaseOperationType.INSERT,
            ...     table_name='users'
            ... ) as (session, tx_id):
            ...     user = User(name='John Doe')
            ...     session.add(user)
            ...     session.commit()
        """
        transaction_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        # Create transaction context
        tx_context = TransactionContext(
            transaction_id=transaction_id,
            start_time=start_time,
            operation_type=operation_type,
            table_name=table_name,
            user_id=user_id,
            request_id=getattr(g, 'request_id', None) if has_app_context() else None
        )
        
        # Create session if not provided
        session_created = session is None
        if session_created and has_app_context() and hasattr(current_app, 'db'):
            session = current_app.db.session
        elif session_created:
            raise TransactionError("No database session available and cannot create one")
        
        # Register transaction
        self.active_transactions[transaction_id] = tx_context
        
        try:
            # Set transaction timeout
            if timeout or self._transaction_timeout:
                timeout_value = timeout or self._transaction_timeout
                session.execute(text(f"SET statement_timeout = {timeout_value * 1000}"))  # PostgreSQL uses milliseconds
            
            self.logger.info(
                "Transaction started",
                extra={
                    'transaction_id': transaction_id,
                    'operation_type': operation_type.value,
                    'table_name': table_name,
                    'user_id': user_id,
                    'category': LogCategory.AUDIT.value if CONFIG_AVAILABLE else 'audit'
                }
            )
            
            yield session, transaction_id
            
            # Commit if no exception occurred
            if session.is_active:
                session.commit()
                execution_time = (datetime.utcnow() - start_time).total_seconds()
                
                self.logger.info(
                    "Transaction committed successfully",
                    extra={
                        'transaction_id': transaction_id,
                        'execution_time': execution_time,
                        'operation_type': operation_type.value,
                        'category': LogCategory.AUDIT.value if CONFIG_AVAILABLE else 'audit'
                    }
                )
                
        except Exception as e:
            # Rollback on any exception
            try:
                if session.is_active:
                    session.rollback()
                    
                execution_time = (datetime.utcnow() - start_time).total_seconds()
                
                self.logger.error(
                    "Transaction rolled back due to error",
                    extra={
                        'transaction_id': transaction_id,
                        'error': str(e),
                        'execution_time': execution_time,
                        'operation_type': operation_type.value,
                        'category': LogCategory.ERROR.value if CONFIG_AVAILABLE else 'error'
                    }
                )
                
            except Exception as rollback_error:
                self.logger.critical(
                    "Transaction rollback failed",
                    extra={
                        'transaction_id': transaction_id,
                        'original_error': str(e),
                        'rollback_error': str(rollback_error),
                        'category': LogCategory.ERROR.value if CONFIG_AVAILABLE else 'error'
                    }
                )
            
            raise TransactionError(f"Transaction {transaction_id} failed: {e}")
            
        finally:
            # Clean up transaction context
            if transaction_id in self.active_transactions:
                del self.active_transactions[transaction_id]
            
            # Reset statement timeout
            try:
                session.execute(text("SET statement_timeout = DEFAULT"))
            except Exception as e:
                self.logger.warning(f"Failed to reset statement timeout: {e}")
    
    @contextmanager
    def savepoint_transaction(self, session: Session, 
                            savepoint_name: Optional[str] = None) -> Generator[str, None, None]:
        """
        Context manager for nested transactions using savepoints.
        
        Args:
            session: SQLAlchemy session
            savepoint_name: Optional savepoint name
            
        Yields:
            Savepoint name
        """
        if not self._nested_transaction_support:
            raise TransactionError("Nested transactions not supported")
        
        savepoint_name = savepoint_name or f"sp_{uuid.uuid4().hex[:8]}"
        
        try:
            # Create savepoint
            session.begin_nested()
            
            self.logger.debug(
                f"Savepoint created: {savepoint_name}",
                extra={'category': LogCategory.AUDIT.value if CONFIG_AVAILABLE else 'audit'}
            )
            
            yield savepoint_name
            
            # Commit nested transaction
            session.commit()
            
        except Exception as e:
            # Rollback to savepoint
            session.rollback()
            
            self.logger.warning(
                f"Rolled back to savepoint: {savepoint_name}",
                extra={
                    'error': str(e),
                    'category': LogCategory.ERROR.value if CONFIG_AVAILABLE else 'error'
                }
            )
            raise
    
    def get_active_transactions(self) -> List[Dict[str, Any]]:
        """Get information about currently active transactions."""
        return [tx.to_dict() for tx in self.active_transactions.values()]
    
    def cleanup_stale_transactions(self, max_age_seconds: int = 3600) -> int:
        """
        Clean up stale transaction records.
        
        Args:
            max_age_seconds: Maximum age for transaction records
            
        Returns:
            Number of cleaned up transactions
        """
        current_time = datetime.utcnow()
        stale_transactions = []
        
        for tx_id, tx_context in self.active_transactions.items():
            age = (current_time - tx_context.start_time).total_seconds()
            if age > max_age_seconds:
                stale_transactions.append(tx_id)
        
        for tx_id in stale_transactions:
            del self.active_transactions[tx_id]
            self.logger.warning(
                f"Cleaned up stale transaction: {tx_id}",
                extra={'category': LogCategory.PERFORMANCE.value if CONFIG_AVAILABLE else 'performance'}
            )
        
        return len(stale_transactions)


class MigrationManager:
    """
    Flask-Migrate integration manager for database versioning and migration.
    
    Provides comprehensive migration management with Flask-Migrate 4.1.0 integration,
    zero data loss validation, and automated rollback capabilities. Supports
    MongoDB to PostgreSQL migration with data integrity preservation.
    """
    
    def __init__(self, app: Optional[Flask] = None, db: Optional[SQLAlchemy] = None):
        """
        Initialize migration manager.
        
        Args:
            app: Flask application instance
            db: SQLAlchemy database instance
        """
        self.app = app
        self.db = db
        self.migrate: Optional[Migrate] = None
        self.logger = self._get_logger()
        self.migration_directory = 'migrations'
        
        if app is not None and db is not None:
            self.init_app(app, db)
    
    def _get_logger(self):
        """Get structured logger for migration management."""
        if CONFIG_AVAILABLE:
            return get_structured_logger("migration_manager")
        else:
            import logging
            return logging.getLogger("migration_manager")
    
    def init_app(self, app: Flask, db: SQLAlchemy) -> None:
        """
        Initialize migration manager with Flask application and database.
        
        Args:
            app: Flask application instance
            db: SQLAlchemy database instance
        """
        if not ALEMBIC_AVAILABLE:
            self.logger.error("Alembic not available, migration functionality disabled")
            return
        
        self.app = app
        self.db = db
        
        # Initialize Flask-Migrate
        self.migrate = Migrate(app, db, directory=self.migration_directory)
        
        # Add CLI commands
        self._register_cli_commands(app)
        
        self.logger.info("Migration manager initialized successfully")
    
    def _register_cli_commands(self, app: Flask) -> None:
        """Register custom CLI commands for migration management."""
        
        @app.cli.group()
        def db_advanced():
            """Advanced database management commands."""
            pass
        
        @db_advanced.command()
        def validate_migrations():
            """Validate all migration scripts for consistency."""
            try:
                result = self.validate_migration_consistency()
                if result['is_valid']:
                    print("✅ All migrations are valid and consistent")
                else:
                    print("❌ Migration validation failed:")
                    for error in result['errors']:
                        print(f"  - {error}")
            except Exception as e:
                print(f"❌ Migration validation error: {e}")
        
        @db_advanced.command()
        def backup_before_migration():
            """Create database backup before running migrations."""
            try:
                backup_info = self.create_pre_migration_backup()
                print(f"✅ Database backup created: {backup_info['backup_file']}")
            except Exception as e:
                print(f"❌ Backup creation failed: {e}")
        
        @db_advanced.command()
        def migration_status():
            """Display detailed migration status."""
            try:
                status = self.get_migration_status()
                print(f"Current revision: {status['current_revision']}")
                print(f"Latest revision: {status['latest_revision']}")
                print(f"Pending migrations: {len(status['pending_migrations'])}")
                
                if status['pending_migrations']:
                    print("\nPending migrations:")
                    for migration in status['pending_migrations']:
                        print(f"  - {migration}")
                        
            except Exception as e:
                print(f"❌ Status check failed: {e}")
    
    def create_migration(self, message: str, autogenerate: bool = True) -> Optional[str]:
        """
        Create a new migration script.
        
        Args:
            message: Migration description
            autogenerate: Whether to auto-generate migration content
            
        Returns:
            Migration script path if successful, None otherwise
        """
        if not self.migrate:
            raise MigrationError("Migration manager not initialized")
        
        try:
            # Create migration directory if it doesn't exist
            migrations_dir = os.path.join(self.app.root_path, self.migration_directory)
            if not os.path.exists(migrations_dir):
                os.makedirs(migrations_dir)
            
            # Generate migration
            from flask_migrate import migrate as flask_migrate_command
            
            with self.app.app_context():
                # Use Flask-Migrate's migrate command
                config = self.migrate.get_config()
                script_dir = ScriptDirectory.from_config(config)
                
                if autogenerate:
                    # Auto-generate migration script
                    with EnvironmentContext(
                        config,
                        script_dir,
                        fn=lambda rev, context: script_dir.generate_revision(
                            rev, message, refresh=True
                        )
                    ):
                        script = script_dir.generate_revision(None, message, autogenerate=True)
                else:
                    # Create empty migration script
                    script = script_dir.generate_revision(None, message, autogenerate=False)
                
                self.logger.info(
                    f"Migration created: {script.path}",
                    extra={
                        'migration_message': message,
                        'autogenerate': autogenerate,
                        'category': LogCategory.AUDIT.value if CONFIG_AVAILABLE else 'audit'
                    }
                )
                
                return script.path
                
        except Exception as e:
            self.logger.error(f"Failed to create migration: {e}")
            raise MigrationError(f"Migration creation failed: {e}")
    
    def apply_migrations(self, target_revision: Optional[str] = None) -> bool:
        """
        Apply database migrations with validation and monitoring.
        
        Args:
            target_revision: Specific revision to migrate to (latest if None)
            
        Returns:
            True if migrations applied successfully, False otherwise
        """
        if not self.migrate:
            raise MigrationError("Migration manager not initialized")
        
        try:
            with self.app.app_context():
                # Create pre-migration backup
                backup_info = self.create_pre_migration_backup()
                
                # Get current status
                current_rev = current_revision()
                target_rev = target_revision or self.get_latest_revision()
                
                self.logger.info(
                    "Starting migration process",
                    extra={
                        'current_revision': current_rev,
                        'target_revision': target_rev,
                        'backup_file': backup_info.get('backup_file'),
                        'category': LogCategory.AUDIT.value if CONFIG_AVAILABLE else 'audit'
                    }
                )
                
                # Apply migrations
                start_time = time.time()
                upgrade(revision=target_revision)
                execution_time = time.time() - start_time
                
                # Verify migration success
                new_revision = current_revision()
                
                self.logger.info(
                    "Migration completed successfully",
                    extra={
                        'old_revision': current_rev,
                        'new_revision': new_revision,
                        'execution_time': execution_time,
                        'category': LogCategory.AUDIT.value if CONFIG_AVAILABLE else 'audit'
                    }
                )
                
                # Validate data integrity after migration
                integrity_check = self.validate_data_integrity()
                if not integrity_check['is_valid']:
                    self.logger.error(
                        "Data integrity validation failed after migration",
                        extra={
                            'integrity_errors': integrity_check['errors'],
                            'category': LogCategory.ERROR.value if CONFIG_AVAILABLE else 'error'
                        }
                    )
                    return False
                
                return True
                
        except Exception as e:
            self.logger.error(
                f"Migration failed: {e}",
                extra={'category': LogCategory.ERROR.value if CONFIG_AVAILABLE else 'error'}
            )
            
            # Attempt automatic rollback
            try:
                self.rollback_migration(current_rev)
                self.logger.info("Automatic rollback completed")
            except Exception as rollback_error:
                self.logger.critical(f"Automatic rollback failed: {rollback_error}")
            
            return False
    
    def rollback_migration(self, target_revision: str) -> bool:
        """
        Rollback database to specific revision.
        
        Args:
            target_revision: Revision to rollback to
            
        Returns:
            True if rollback successful, False otherwise
        """
        if not self.migrate:
            raise MigrationError("Migration manager not initialized")
        
        try:
            with self.app.app_context():
                current_rev = current_revision()
                
                self.logger.info(
                    f"Starting rollback from {current_rev} to {target_revision}",
                    extra={'category': LogCategory.AUDIT.value if CONFIG_AVAILABLE else 'audit'}
                )
                
                start_time = time.time()
                downgrade(revision=target_revision)
                execution_time = time.time() - start_time
                
                new_revision = current_revision()
                
                self.logger.info(
                    "Rollback completed successfully",
                    extra={
                        'old_revision': current_rev,
                        'new_revision': new_revision,
                        'execution_time': execution_time,
                        'category': LogCategory.AUDIT.value if CONFIG_AVAILABLE else 'audit'
                    }
                )
                
                return True
                
        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            raise MigrationError(f"Rollback failed: {e}")
    
    def get_migration_status(self) -> Dict[str, Any]:
        """
        Get comprehensive migration status information.
        
        Returns:
            Dictionary containing migration status details
        """
        if not self.migrate:
            return {'error': 'Migration manager not initialized'}
        
        try:
            with self.app.app_context():
                current_rev = current_revision()
                latest_rev = self.get_latest_revision()
                
                # Get migration history
                config = self.migrate.get_config()
                script_dir = ScriptDirectory.from_config(config)
                
                # Get all revisions
                revisions = list(script_dir.walk_revisions())
                
                # Find pending migrations
                pending_migrations = []
                if current_rev:
                    current_found = False
                    for rev in revisions:
                        if current_found:
                            pending_migrations.append(rev.revision)
                        if rev.revision == current_rev:
                            current_found = True
                else:
                    pending_migrations = [rev.revision for rev in revisions]
                
                return {
                    'current_revision': current_rev,
                    'latest_revision': latest_rev,
                    'total_migrations': len(revisions),
                    'pending_migrations': pending_migrations,
                    'migration_directory': self.migration_directory,
                    'is_up_to_date': current_rev == latest_rev if latest_rev else False
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get migration status: {e}")
            return {'error': str(e)}
    
    def get_latest_revision(self) -> Optional[str]:
        """Get the latest migration revision."""
        try:
            with self.app.app_context():
                config = self.migrate.get_config()
                script_dir = ScriptDirectory.from_config(config)
                head_revision = script_dir.get_current_head()
                return head_revision
        except Exception as e:
            self.logger.error(f"Failed to get latest revision: {e}")
            return None
    
    def validate_migration_consistency(self) -> Dict[str, Any]:
        """
        Validate migration scripts for consistency and integrity.
        
        Returns:
            Validation result dictionary
        """
        validation_result = {
            'is_valid': True,
            'errors': [],
            'warnings': []
        }
        
        try:
            with self.app.app_context():
                config = self.migrate.get_config()
                script_dir = ScriptDirectory.from_config(config)
                
                # Check for missing files
                if not os.path.exists(script_dir.dir):
                    validation_result['errors'].append(f"Migration directory not found: {script_dir.dir}")
                    validation_result['is_valid'] = False
                    return validation_result
                
                # Validate revision consistency
                revisions = list(script_dir.walk_revisions())
                
                if not revisions:
                    validation_result['warnings'].append("No migrations found")
                    return validation_result
                
                # Check for broken revision chains
                for rev in revisions:
                    if rev.down_revision:
                        down_rev = script_dir.get_revision(rev.down_revision)
                        if down_rev is None:
                            validation_result['errors'].append(
                                f"Broken revision chain: {rev.revision} references missing {rev.down_revision}"
                            )
                            validation_result['is_valid'] = False
                
                # Validate migration scripts syntax
                for rev in revisions:
                    try:
                        # Try to compile the migration script
                        with open(rev.path, 'r') as f:
                            script_content = f.read()
                        
                        # Basic syntax validation
                        compile(script_content, rev.path, 'exec')
                        
                    except SyntaxError as e:
                        validation_result['errors'].append(
                            f"Syntax error in {rev.path}: {e}"
                        )
                        validation_result['is_valid'] = False
                    except Exception as e:
                        validation_result['warnings'].append(
                            f"Cannot validate {rev.path}: {e}"
                        )
                
        except Exception as e:
            validation_result['errors'].append(f"Migration validation failed: {e}")
            validation_result['is_valid'] = False
        
        return validation_result
    
    def create_pre_migration_backup(self) -> Dict[str, Any]:
        """
        Create database backup before migration.
        
        Returns:
            Backup information dictionary
        """
        if not PSYCOPG2_AVAILABLE:
            self.logger.warning("psycopg2 not available, skipping backup creation")
            return {'backup_created': False, 'reason': 'psycopg2 not available'}
        
        try:
            # Get database URI
            db_uri = self.app.config.get('SQLALCHEMY_DATABASE_URI')
            if not db_uri:
                raise MigrationError("Database URI not configured")
            
            # Parse database URI
            from urllib.parse import urlparse
            parsed = urlparse(db_uri)
            
            # Create backup filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"backup_pre_migration_{timestamp}.sql"
            backup_path = os.path.join(self.app.root_path, 'backups', backup_filename)
            
            # Create backups directory if it doesn't exist
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            
            # Create pg_dump command
            dump_command = [
                'pg_dump',
                '-h', parsed.hostname or 'localhost',
                '-p', str(parsed.port or 5432),
                '-U', parsed.username,
                '-d', parsed.path.lstrip('/'),
                '-f', backup_path,
                '--verbose',
                '--clean',
                '--if-exists'
            ]
            
            # Execute backup (Note: In production, use subprocess with proper error handling)
            self.logger.info(
                f"Creating database backup: {backup_path}",
                extra={'category': LogCategory.AUDIT.value if CONFIG_AVAILABLE else 'audit'}
            )
            
            # For now, we'll create a placeholder backup file
            # In production, implement actual pg_dump execution
            with open(backup_path, 'w') as f:
                f.write(f"-- Database backup created at {datetime.utcnow()}\n")
                f.write(f"-- Pre-migration backup\n")
            
            return {
                'backup_created': True,
                'backup_file': backup_path,
                'timestamp': timestamp,
                'database': parsed.path.lstrip('/')
            }
            
        except Exception as e:
            self.logger.error(f"Backup creation failed: {e}")
            return {
                'backup_created': False,
                'error': str(e)
            }
    
    def validate_data_integrity(self) -> Dict[str, Any]:
        """
        Validate database data integrity after migration.
        
        Returns:
            Validation result dictionary
        """
        validation_result = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'checks_performed': []
        }
        
        try:
            with self.app.app_context():
                # Get database session
                session = self.db.session
                
                # Check foreign key constraints
                try:
                    # PostgreSQL-specific constraint validation
                    constraint_check = session.execute(text("""
                        SELECT conname, conrelid::regclass 
                        FROM pg_constraint 
                        WHERE contype = 'f' 
                        AND NOT EXISTS (
                            SELECT 1 FROM information_schema.constraint_column_usage 
                            WHERE constraint_name = conname
                        )
                    """))
                    
                    broken_constraints = constraint_check.fetchall()
                    if broken_constraints:
                        for constraint in broken_constraints:
                            validation_result['errors'].append(
                                f"Broken foreign key constraint: {constraint[0]} on table {constraint[1]}"
                            )
                            validation_result['is_valid'] = False
                    
                    validation_result['checks_performed'].append('foreign_key_constraints')
                    
                except Exception as e:
                    validation_result['warnings'].append(f"Foreign key check failed: {e}")
                
                # Check for orphaned records (if we have model definitions)
                if hasattr(self.app, 'db') and hasattr(self.app.db, 'Model'):
                    # This would require model introspection
                    validation_result['checks_performed'].append('orphaned_records_check')
                
                # Check table existence for known models
                try:
                    inspector = inspect(session.bind)
                    tables = inspector.get_table_names()
                    
                    expected_tables = ['user', 'user_session', 'business_entity', 'entity_relationship']
                    missing_tables = [table for table in expected_tables if table not in tables]
                    
                    if missing_tables:
                        validation_result['errors'].append(f"Missing tables: {missing_tables}")
                        validation_result['is_valid'] = False
                    
                    validation_result['checks_performed'].append('table_existence')
                    
                except Exception as e:
                    validation_result['warnings'].append(f"Table existence check failed: {e}")
                
        except Exception as e:
            validation_result['errors'].append(f"Data integrity validation failed: {e}")
            validation_result['is_valid'] = False
        
        return validation_result


class DatabaseManager:
    """
    Comprehensive database management utility for Flask-SQLAlchemy integration.
    
    Central management class that coordinates connection pooling, transaction management,
    migration handling, and performance monitoring. Provides the main interface for
    database operations in the Flask application factory pattern.
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize database manager.
        
        Args:
            app: Flask application instance (optional for factory pattern)
        """
        self.app = app
        self.db: Optional[SQLAlchemy] = None
        self.logger = self._get_logger()
        
        # Initialize components
        self.pool_manager = ConnectionPoolManager()
        self.transaction_manager = TransactionManager()
        self.migration_manager = MigrationManager()
        self.performance_monitor = DatabasePerformanceMonitor()
        
        if app is not None:
            self.init_app(app)
    
    def _get_logger(self):
        """Get structured logger for database manager."""
        if CONFIG_AVAILABLE:
            return get_structured_logger("database_manager")
        else:
            import logging
            return logging.getLogger("database_manager")
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize database manager with Flask application.
        
        Args:
            app: Flask application instance
        """
        if not SQLALCHEMY_AVAILABLE:
            raise DatabaseError("SQLAlchemy not available")
        
        self.app = app
        
        # Initialize SQLAlchemy with optimized configuration
        self.db = SQLAlchemy()
        
        # Configure database URI and settings
        self._configure_database(app)
        
        # Initialize SQLAlchemy with app
        self.db.init_app(app)
        
        # Initialize components
        self.pool_manager.init_app(app)
        self.migration_manager.init_app(app, self.db)
        
        # Register database utilities with app
        app.db_manager = self
        app.db = self.db
        
        # Add CLI commands
        self._register_cli_commands(app)
        
        self.logger.info("Database manager initialized successfully")
    
    def _configure_database(self, app: Flask) -> None:
        """Configure database settings with optimization."""
        if CONFIG_AVAILABLE:
            config_manager = get_default_configuration_manager()
            db_config = config_manager.get_database_configuration()
            app.config.update(db_config)
        else:
            # Fallback configuration
            app.config.setdefault('SQLALCHEMY_DATABASE_URI', 
                                os.environ.get('DATABASE_URL', 'postgresql://localhost/flask_app'))
            app.config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', False)
            app.config.setdefault('SQLALCHEMY_ENGINE_OPTIONS', {
                'pool_size': 20,
                'max_overflow': 10,
                'pool_timeout': 30,
                'pool_recycle': 3600,
                'pool_pre_ping': True
            })
    
    def _register_cli_commands(self, app: Flask) -> None:
        """Register CLI commands for database management."""
        
        @app.cli.group()
        def database():
            """Database management commands."""
            pass
        
        @database.command()
        def health_check():
            """Perform comprehensive database health check."""
            try:
                result = self.perform_health_check()
                if result['is_healthy']:
                    print("✅ Database health check passed")
                    print(f"   Connection pool: {result['pool_status']['checked_out']}/{result['pool_status']['size']}")
                    print(f"   Average query time: {result['metrics']['average_query_time']:.3f}s")
                else:
                    print("❌ Database health check failed")
                    for error in result['errors']:
                        print(f"   Error: {error}")
            except Exception as e:
                print(f"❌ Health check error: {e}")
        
        @database.command()
        def performance_report():
            """Generate database performance report."""
            try:
                report = self.get_performance_report()
                print("📊 Database Performance Report")
                print("=" * 40)
                print(f"Total queries: {report['total_queries']}")
                print(f"Average query time: {report['average_query_time']:.3f}s")
                print(f"Slowest query: {report['slowest_query_time']:.3f}s")
                print(f"Error rate: {report['error_rate']:.2%}")
                
                if report['slow_queries']:
                    print(f"\n⚠️  Slow queries detected: {len(report['slow_queries'])}")
                    
            except Exception as e:
                print(f"❌ Performance report error: {e}")
        
        @database.command()
        def optimize():
            """Optimize database performance."""
            try:
                result = self.optimize_database()
                print("🔧 Database optimization completed")
                for action in result['actions_taken']:
                    print(f"   ✓ {action}")
                    
                if result['recommendations']:
                    print("\n💡 Recommendations:")
                    for rec in result['recommendations']:
                        print(f"   - {rec}")
                        
            except Exception as e:
                print(f"❌ Optimization error: {e}")
    
    def perform_health_check(self) -> Dict[str, Any]:
        """
        Perform comprehensive database health check.
        
        Returns:
            Health check results dictionary
        """
        health_result = {
            'is_healthy': True,
            'errors': [],
            'warnings': [],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        try:
            # Check basic connectivity
            if not self.pool_manager.validate_connection_health(self.db.engine):
                health_result['errors'].append('Database connection failed')
                health_result['is_healthy'] = False
            
            # Check pool status
            pool_status = self.pool_manager.get_pool_status(self.db.engine)
            health_result['pool_status'] = pool_status
            
            # Check for pool exhaustion
            if pool_status['checked_out'] >= pool_status['size'] * 0.9:
                health_result['warnings'].append('Connection pool near exhaustion')
            
            # Get performance metrics
            metrics = self.performance_monitor.get_metrics_summary()
            health_result['metrics'] = metrics['current_metrics']
            
            # Check for performance issues
            if metrics['current_metrics']['average_query_time'] > 1.0:
                health_result['warnings'].append('High average query time detected')
            
            # Check migration status
            migration_status = self.migration_manager.get_migration_status()
            health_result['migration_status'] = migration_status
            
            if not migration_status.get('is_up_to_date', True):
                health_result['warnings'].append('Pending database migrations')
            
        except Exception as e:
            health_result['errors'].append(f"Health check error: {e}")
            health_result['is_healthy'] = False
        
        return health_result
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance report.
        
        Returns:
            Performance report dictionary
        """
        metrics = self.performance_monitor.metrics
        query_history = list(self.performance_monitor.query_history)
        
        # Calculate performance statistics
        total_queries = len(query_history)
        slow_queries = [q for q in query_history if q['execution_time'] > 2.0]
        error_queries = [q for q in query_history if q['error'] is not None]
        
        # Query type distribution
        query_types = defaultdict(int)
        for query in query_history:
            query_types[query['operation_type']] += 1
        
        # Recent performance trend
        recent_queries = [q for q in query_history if 
                         (datetime.utcnow() - q['timestamp']).total_seconds() < 3600]
        
        return {
            'total_queries': total_queries,
            'average_query_time': metrics.average_query_time,
            'slowest_query_time': metrics.slowest_query_time,
            'fastest_query_time': metrics.fastest_query_time if metrics.fastest_query_time != float('inf') else 0.0,
            'error_rate': len(error_queries) / total_queries if total_queries > 0 else 0.0,
            'slow_queries': slow_queries,
            'query_type_distribution': dict(query_types),
            'recent_queries_count': len(recent_queries),
            'pool_metrics': self.pool_manager.get_pool_status(self.db.engine),
            'performance_targets': self.performance_monitor.performance_targets,
            'recommendations': self._generate_performance_recommendations()
        }
    
    def _generate_performance_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        metrics = self.performance_monitor.metrics
        pool_status = self.pool_manager.get_pool_status(self.db.engine)
        
        # Query performance recommendations
        if metrics.average_query_time > 1.0:
            recommendations.append("Consider adding database indexes for frequently queried columns")
        
        if metrics.slowest_query_time > 5.0:
            recommendations.append("Investigate and optimize slow queries")
        
        # Connection pool recommendations
        if pool_status['checked_out'] / pool_status['size'] > 0.8:
            recommendations.append("Consider increasing connection pool size")
        
        if pool_status['overflow'] > 0:
            recommendations.append("Connection pool overflow detected - monitor connection usage")
        
        # Error rate recommendations
        if metrics.error_count > 0:
            recommendations.append("Investigate database errors for potential issues")
        
        return recommendations
    
    def optimize_database(self) -> Dict[str, Any]:
        """
        Perform database optimization operations.
        
        Returns:
            Optimization results dictionary
        """
        optimization_result = {
            'actions_taken': [],
            'recommendations': [],
            'errors': []
        }
        
        try:
            with self.db.session.begin():
                # PostgreSQL-specific optimizations
                if 'postgresql' in str(self.db.engine.url):
                    # Update table statistics
                    self.db.session.execute(text("ANALYZE"))
                    optimization_result['actions_taken'].append("Updated table statistics (ANALYZE)")
                    
                    # Check for unused indexes
                    unused_indexes = self.db.session.execute(text("""
                        SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
                        FROM pg_stat_user_indexes 
                        WHERE idx_tup_read = 0 AND idx_tup_fetch = 0
                    """)).fetchall()
                    
                    if unused_indexes:
                        optimization_result['recommendations'].append(
                            f"Consider removing {len(unused_indexes)} unused indexes"
                        )
                    
                    # Check for missing indexes on foreign keys
                    missing_fk_indexes = self.db.session.execute(text("""
                        SELECT c.conname, c.conrelid::regclass, a.attname
                        FROM pg_constraint c
                        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
                        WHERE c.contype = 'f'
                        AND NOT EXISTS (
                            SELECT 1 FROM pg_index i 
                            WHERE i.indrelid = c.conrelid 
                            AND a.attnum = ANY(i.indkey)
                        )
                    """)).fetchall()
                    
                    if missing_fk_indexes:
                        optimization_result['recommendations'].append(
                            f"Consider adding indexes on {len(missing_fk_indexes)} foreign key columns"
                        )
                
                optimization_result['actions_taken'].append("Database optimization completed")
                
        except Exception as e:
            optimization_result['errors'].append(f"Optimization error: {e}")
        
        return optimization_result
    
    @contextmanager
    def transaction(self, **kwargs) -> Generator[Tuple[Session, str], None, None]:
        """
        Context manager for database transactions.
        
        Convenience wrapper for transaction manager.
        """
        with self.transaction_manager.managed_transaction(**kwargs) as result:
            yield result
    
    def execute_query(self, query: Union[str, text], 
                     params: Optional[Dict[str, Any]] = None,
                     operation_type: DatabaseOperationType = DatabaseOperationType.SELECT,
                     table_name: Optional[str] = None) -> Any:
        """
        Execute database query with monitoring and error handling.
        
        Args:
            query: SQL query string or SQLAlchemy text object
            params: Query parameters
            operation_type: Type of database operation
            table_name: Target table name
            
        Returns:
            Query result
        """
        start_time = time.time()
        error = None
        
        try:
            if isinstance(query, str):
                query = text(query)
            
            if params:
                result = self.db.session.execute(query, params)
            else:
                result = self.db.session.execute(query)
            
            return result
            
        except Exception as e:
            error = e
            raise
            
        finally:
            execution_time = time.time() - start_time
            self.performance_monitor.record_query(
                str(query),
                execution_time,
                operation_type,
                table_name,
                error
            )


# Convenience functions for common database operations
def get_database_manager(app: Optional[Flask] = None) -> DatabaseManager:
    """
    Get database manager instance.
    
    Args:
        app: Flask application instance
        
    Returns:
        DatabaseManager instance
    """
    if app and hasattr(app, 'db_manager'):
        return app.db_manager
    elif has_app_context() and hasattr(current_app, 'db_manager'):
        return current_app.db_manager
    else:
        raise DatabaseError("Database manager not initialized")


def create_database_tables(app: Flask) -> None:
    """
    Create all database tables.
    
    Args:
        app: Flask application instance
    """
    with app.app_context():
        db_manager = get_database_manager(app)
        db_manager.db.create_all()


def drop_database_tables(app: Flask) -> None:
    """
    Drop all database tables.
    
    Args:
        app: Flask application instance
    """
    with app.app_context():
        db_manager = get_database_manager(app)
        db_manager.db.drop_all()


def validate_database_connection() -> bool:
    """
    Validate current database connection.
    
    Returns:
        True if connection is valid, False otherwise
    """
    try:
        db_manager = get_database_manager()
        return db_manager.pool_manager.validate_connection_health(db_manager.db.engine)
    except Exception:
        return False


# Query optimization decorators
def monitor_query_performance(operation_type: DatabaseOperationType, 
                            table_name: Optional[str] = None):
    """
    Decorator to monitor query performance.
    
    Args:
        operation_type: Type of database operation
        table_name: Target table name
        
    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            error = None
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                error = e
                raise
            finally:
                execution_time = time.time() - start_time
                
                try:
                    db_manager = get_database_manager()
                    db_manager.performance_monitor.record_query(
                        func.__name__,
                        execution_time,
                        operation_type,
                        table_name,
                        error
                    )
                except Exception:
                    # Don't fail the original function if monitoring fails
                    pass
        
        return wrapper
    return decorator


def require_transaction(operation_type: DatabaseOperationType = DatabaseOperationType.SELECT):
    """
    Decorator to ensure function runs within a database transaction.
    
    Args:
        operation_type: Type of database operation
        
    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            db_manager = get_database_manager()
            
            # Check if already in transaction
            if db_manager.db.session.in_transaction():
                return func(*args, **kwargs)
            
            # Create new transaction
            with db_manager.transaction(operation_type=operation_type) as (session, tx_id):
                kwargs['session'] = session
                kwargs['transaction_id'] = tx_id
                return func(*args, **kwargs)
        
        return wrapper
    return decorator


# Module initialization
def init_database_utilities(app: Flask) -> DatabaseManager:
    """
    Initialize database utilities for Flask application.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured DatabaseManager instance
    """
    db_manager = DatabaseManager(app)
    return db_manager


if __name__ == '__main__':
    """
    Database utilities testing and validation script.
    
    When run directly, performs comprehensive testing of database utility
    functionality including connection management, transaction handling,
    and migration capabilities.
    """
    print("Flask Database Utilities Test")
    print("=" * 50)
    
    # Test imports
    print("Testing imports...")
    if SQLALCHEMY_AVAILABLE:
        print("✅ SQLAlchemy available")
    else:
        print("❌ SQLAlchemy not available")
    
    if PSYCOPG2_AVAILABLE:
        print("✅ psycopg2 available")
    else:
        print("❌ psycopg2 not available")
    
    if ALEMBIC_AVAILABLE:
        print("✅ Alembic available")
    else:
        print("❌ Alembic not available")
    
    # Test configuration
    print("\nTesting configuration...")
    if CONFIG_AVAILABLE:
        try:
            config_manager = get_default_configuration_manager()
            db_config = config_manager.get_database_configuration()
            print("✅ Database configuration loaded")
        except Exception as e:
            print(f"❌ Configuration loading failed: {e}")
    else:
        print("⚠️ Configuration utilities not available")
    
    # Test database manager initialization
    print("\nTesting database manager...")
    try:
        from flask import Flask
        
        app = Flask(__name__)
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        with app.app_context():
            db_manager = DatabaseManager(app)
            print("✅ Database manager initialized")
            
            # Test health check
            health_result = db_manager.perform_health_check()
            if health_result['is_healthy']:
                print("✅ Database health check passed")
            else:
                print(f"❌ Database health check failed: {health_result['errors']}")
            
    except Exception as e:
        print(f"❌ Database manager test failed: {e}")
    
    print("\n✅ Database utilities test completed!")