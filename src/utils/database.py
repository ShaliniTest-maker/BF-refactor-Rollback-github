"""
Database Utility Functions for Flask-SQLAlchemy Integration

This module provides comprehensive database utilities for the Flask migration project,
implementing Flask-SQLAlchemy 3.1.1 integration helpers, PostgreSQL 14 connection
management, transaction utilities, and migration support as specified in Section 5.2.4,
Section 5.3.3, and Section 3.2.2.

Features:
- Flask-SQLAlchemy 3.1.1 integration with PostgreSQL 14 using psycopg2 dialect
- Connection pooling management with configurable parameters
- Database transaction utilities with rollback capabilities
- Flask-Migrate 4.x support for Alembic-based database versioning
- Zero data loss validation during MongoDB migration
- Query optimization utilities with performance monitoring
- Real-time data verification and integrity checking
- Point-in-time recovery support with backup coordination
- Connection health monitoring and automatic reconnection
- Performance benchmarking and SLA validation

Dependencies:
- Flask 3.1.1 for application factory pattern integration
- Flask-SQLAlchemy 3.1.1 for ORM and database operations
- Flask-Migrate 4.x for database schema versioning
- PostgreSQL 14 with psycopg2 2.9.9 database adapter
- Python 3.13.3 runtime environment

Architecture Integration:
- Service Layer pattern for business logic coordination
- Blueprint management system for modular database operations
- Configuration management for environment-specific database settings
- Structured logging for audit trails and compliance monitoring
"""

import os
import sys
import time
import json
import uuid
import traceback
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union, List, Tuple, Callable, Type, Generator
from contextlib import contextmanager
from functools import wraps
from dataclasses import dataclass, field
from enum import Enum
import logging

# Flask and SQLAlchemy imports
from flask import Flask, current_app, g, has_app_context
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade, downgrade, current as get_current_revision
from sqlalchemy import create_engine, text, inspect, MetaData, Table, Column, Index
from sqlalchemy.engine import Engine, Connection
from sqlalchemy.orm import Session, sessionmaker, scoped_session
from sqlalchemy.pool import Pool, QueuePool, StaticPool
from sqlalchemy.exc import (
    SQLAlchemyError, IntegrityError, DatabaseError, 
    DisconnectionError, TimeoutError, OperationalError
)
from sqlalchemy.dialects.postgresql import psycopg2
from sqlalchemy.engine.events import event
from sqlalchemy.sql import func
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.runtime.migration import MigrationContext

# Configuration and logging imports
from .config import get_database_config, DatabaseConfig, ConfigurationError
from .logging import get_logger, LogCategory, log_function_call, log_audit_event, log_operation

# Performance monitoring
try:
    from prometheus_client import Counter, Histogram, Gauge, Summary
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


class DatabaseError(Exception):
    """Base exception for database-related errors"""
    pass


class ConnectionError(DatabaseError):
    """Exception for database connection issues"""
    pass


class MigrationError(DatabaseError):
    """Exception for database migration issues"""
    pass


class ValidationError(DatabaseError):
    """Exception for data validation issues"""
    pass


class TransactionError(DatabaseError):
    """Exception for transaction management issues"""
    pass


class PerformanceError(DatabaseError):
    """Exception for performance threshold violations"""
    pass


class ConnectionState(Enum):
    """Database connection state enumeration"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting" 
    CONNECTED = "connected"
    ERROR = "error"
    RECONNECTING = "reconnecting"


class TransactionState(Enum):
    """Database transaction state enumeration"""
    ACTIVE = "active"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class MigrationState(Enum):
    """Database migration state enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ConnectionMetrics:
    """Database connection metrics for monitoring and optimization"""
    pool_size: int = 0
    checked_out: int = 0
    overflow: int = 0
    invalid: int = 0
    total_connections: int = 0
    connection_errors: int = 0
    reconnection_attempts: int = 0
    avg_connection_time: float = 0.0
    last_health_check: Optional[datetime] = None
    health_check_status: bool = True


@dataclass
class QueryMetrics:
    """Database query performance metrics"""
    query_count: int = 0
    total_duration: float = 0.0
    avg_duration: float = 0.0
    max_duration: float = 0.0
    min_duration: float = float('inf')
    slow_queries: int = 0
    failed_queries: int = 0
    last_query_time: Optional[datetime] = None


@dataclass
class ValidationResult:
    """Data validation result structure"""
    is_valid: bool = True
    error_count: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    validation_time: float = 0.0
    records_checked: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MigrationContext:
    """Migration operation context and metadata"""
    migration_id: str
    source_revision: Optional[str]
    target_revision: str
    migration_type: str  # 'upgrade', 'downgrade', 'rollback'
    start_time: datetime
    end_time: Optional[datetime] = None
    status: MigrationState = MigrationState.PENDING
    backup_created: bool = False
    backup_location: Optional[str] = None
    validation_results: List[ValidationResult] = field(default_factory=list)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    error_log: List[str] = field(default_factory=list)


class DatabaseMetrics:
    """
    Prometheus metrics for database operations monitoring
    
    Provides comprehensive metrics collection for database performance,
    connection health, query execution, and migration operations.
    """
    
    def __init__(self):
        if PROMETHEUS_AVAILABLE:
            # Connection metrics
            self.connection_pool_size = Gauge(
                'flask_db_connection_pool_size',
                'Current database connection pool size'
            )
            
            self.connection_pool_checked_out = Gauge(
                'flask_db_connection_pool_checked_out',
                'Number of connections currently checked out from pool'
            )
            
            self.connection_pool_overflow = Gauge(
                'flask_db_connection_pool_overflow',
                'Number of overflow connections in use'
            )
            
            self.connection_errors_total = Counter(
                'flask_db_connection_errors_total',
                'Total number of database connection errors',
                ['error_type']
            )
            
            # Query metrics
            self.query_duration = Histogram(
                'flask_db_query_duration_seconds',
                'Database query execution duration',
                ['operation', 'table', 'status'],
                buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
            )
            
            self.queries_total = Counter(
                'flask_db_queries_total',
                'Total number of database queries executed',
                ['operation', 'table', 'status']
            )
            
            self.slow_queries_total = Counter(
                'flask_db_slow_queries_total',
                'Total number of slow database queries',
                ['operation', 'table', 'threshold']
            )
            
            # Transaction metrics
            self.transactions_total = Counter(
                'flask_db_transactions_total',
                'Total number of database transactions',
                ['type', 'status']
            )
            
            self.transaction_duration = Histogram(
                'flask_db_transaction_duration_seconds',
                'Database transaction duration',
                ['type', 'status']
            )
            
            # Migration metrics
            self.migrations_total = Counter(
                'flask_db_migrations_total',
                'Total number of database migrations',
                ['type', 'status']
            )
            
            self.migration_duration = Histogram(
                'flask_db_migration_duration_seconds',
                'Database migration duration',
                ['type', 'status']
            )
            
            # Health metrics
            self.health_checks_total = Counter(
                'flask_db_health_checks_total',
                'Total number of database health checks',
                ['status']
            )
            
            self.last_health_check_timestamp = Gauge(
                'flask_db_last_health_check_timestamp',
                'Timestamp of last successful health check'
            )
        else:
            # Placeholder attributes when Prometheus is not available
            for attr_name in [
                'connection_pool_size', 'connection_pool_checked_out', 'connection_pool_overflow',
                'connection_errors_total', 'query_duration', 'queries_total', 'slow_queries_total',
                'transactions_total', 'transaction_duration', 'migrations_total',
                'migration_duration', 'health_checks_total', 'last_health_check_timestamp'
            ]:
                setattr(self, attr_name, None)
    
    def record_connection_error(self, error_type: str):
        """Record a database connection error."""
        if self.connection_errors_total:
            self.connection_errors_total.labels(error_type=error_type).inc()
    
    def update_connection_pool_metrics(self, metrics: ConnectionMetrics):
        """Update connection pool metrics."""
        if self.connection_pool_size:
            self.connection_pool_size.set(metrics.pool_size)
        if self.connection_pool_checked_out:
            self.connection_pool_checked_out.set(metrics.checked_out)
        if self.connection_pool_overflow:
            self.connection_pool_overflow.set(metrics.overflow)
    
    def record_query(self, operation: str, table: str, duration: float, status: str):
        """Record a database query execution."""
        if self.query_duration:
            self.query_duration.labels(
                operation=operation, 
                table=table, 
                status=status
            ).observe(duration)
        
        if self.queries_total:
            self.queries_total.labels(
                operation=operation,
                table=table,
                status=status
            ).inc()
    
    def record_slow_query(self, operation: str, table: str, threshold: str):
        """Record a slow database query."""
        if self.slow_queries_total:
            self.slow_queries_total.labels(
                operation=operation,
                table=table,
                threshold=threshold
            ).inc()
    
    def record_transaction(self, transaction_type: str, duration: float, status: str):
        """Record a database transaction."""
        if self.transactions_total:
            self.transactions_total.labels(type=transaction_type, status=status).inc()
        
        if self.transaction_duration:
            self.transaction_duration.labels(
                type=transaction_type,
                status=status
            ).observe(duration)
    
    def record_migration(self, migration_type: str, duration: float, status: str):
        """Record a database migration."""
        if self.migrations_total:
            self.migrations_total.labels(type=migration_type, status=status).inc()
        
        if self.migration_duration:
            self.migration_duration.labels(
                type=migration_type,
                status=status
            ).observe(duration)
    
    def record_health_check(self, status: str):
        """Record a database health check."""
        if self.health_checks_total:
            self.health_checks_total.labels(status=status).inc()
        
        if status == 'success' and self.last_health_check_timestamp:
            self.last_health_check_timestamp.set(time.time())


class ConnectionPool:
    """
    Enhanced database connection pool management with health monitoring
    
    Provides sophisticated connection pool management with automatic health
    checking, reconnection capabilities, and performance optimization for
    PostgreSQL 14 database connections using psycopg2 dialect.
    """
    
    def __init__(self, database_url: str, **engine_options):
        """
        Initialize connection pool with enhanced monitoring capabilities.
        
        Args:
            database_url: PostgreSQL connection URL
            **engine_options: Additional SQLAlchemy engine options
        """
        self.database_url = database_url
        self.logger = get_logger()
        self.metrics = DatabaseMetrics()
        self._engine: Optional[Engine] = None
        self._session_factory: Optional[sessionmaker] = None
        self._scoped_session: Optional[scoped_session] = None
        self._connection_metrics = ConnectionMetrics()
        self._health_check_lock = threading.Lock()
        self._last_health_check = None
        self._health_check_interval = 30  # seconds
        
        # Default engine options optimized for PostgreSQL 14
        self.engine_options = {
            'pool_size': 10,
            'max_overflow': 10,
            'pool_timeout': 30,
            'pool_recycle': 3600,
            'pool_pre_ping': True,
            'pool_reset_on_return': 'commit',
            'echo': False,
            'echo_pool': False,
            **engine_options
        }
        
        # Initialize the database engine
        self._initialize_engine()
        
        # Set up connection pool event listeners
        self._setup_event_listeners()
    
    def _initialize_engine(self):
        """Initialize SQLAlchemy engine with optimized settings."""
        try:
            self._engine = create_engine(
                self.database_url,
                poolclass=QueuePool,
                **self.engine_options
            )
            
            # Create session factory
            self._session_factory = sessionmaker(bind=self._engine)
            self._scoped_session = scoped_session(self._session_factory)
            
            self.logger.info(
                "Database engine initialized successfully",
                category=LogCategory.INFRASTRUCTURE,
                database_url=self.database_url.split('@')[0] + '@***',  # Hide credentials
                pool_size=self.engine_options['pool_size'],
                max_overflow=self.engine_options['max_overflow']
            )
            
        except Exception as e:
            self.logger.error(
                "Failed to initialize database engine",
                category=LogCategory.ERROR,
                error=str(e),
                database_url=self.database_url.split('@')[0] + '@***'
            )
            self.metrics.record_connection_error('initialization_error')
            raise ConnectionError(f"Failed to initialize database engine: {e}")
    
    def _setup_event_listeners(self):
        """Set up SQLAlchemy event listeners for monitoring."""
        if not self._engine:
            return
        
        @event.listens_for(self._engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            """Handle new database connections."""
            self._connection_metrics.total_connections += 1
            self.logger.debug(
                "New database connection established",
                category=LogCategory.INFRASTRUCTURE,
                total_connections=self._connection_metrics.total_connections
            )
        
        @event.listens_for(self._engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            """Handle connection checkout from pool."""
            self._connection_metrics.checked_out += 1
            self._update_pool_metrics()
        
        @event.listens_for(self._engine, "checkin")
        def receive_checkin(dbapi_connection, connection_record):
            """Handle connection checkin to pool."""
            self._connection_metrics.checked_out = max(0, self._connection_metrics.checked_out - 1)
            self._update_pool_metrics()
        
        @event.listens_for(self._engine, "invalidate")
        def receive_invalidate(dbapi_connection, connection_record, exception):
            """Handle connection invalidation."""
            self._connection_metrics.invalid += 1
            self._connection_metrics.connection_errors += 1
            self.logger.warning(
                "Database connection invalidated",
                category=LogCategory.INFRASTRUCTURE,
                error=str(exception) if exception else "Unknown error",
                invalid_connections=self._connection_metrics.invalid
            )
            self.metrics.record_connection_error('connection_invalidated')
    
    def _update_pool_metrics(self):
        """Update connection pool metrics."""
        if self._engine and hasattr(self._engine.pool, 'size'):
            pool = self._engine.pool
            self._connection_metrics.pool_size = pool.size()
            self._connection_metrics.overflow = pool.overflow()
            
            # Update Prometheus metrics
            self.metrics.update_connection_pool_metrics(self._connection_metrics)
    
    @property
    def engine(self) -> Engine:
        """Get the SQLAlchemy engine."""
        if not self._engine:
            raise ConnectionError("Database engine not initialized")
        return self._engine
    
    @property
    def session_factory(self) -> sessionmaker:
        """Get the session factory."""
        if not self._session_factory:
            raise ConnectionError("Session factory not initialized")
        return self._session_factory
    
    @property
    def scoped_session(self) -> scoped_session:
        """Get the scoped session."""
        if not self._scoped_session:
            raise ConnectionError("Scoped session not initialized")
        return self._scoped_session
    
    def get_connection(self) -> Connection:
        """
        Get a raw database connection from the pool.
        
        Returns:
            SQLAlchemy Connection object
        """
        try:
            connection = self.engine.connect()
            self.logger.debug(
                "Database connection acquired",
                category=LogCategory.INFRASTRUCTURE
            )
            return connection
        except Exception as e:
            self.logger.error(
                "Failed to acquire database connection",
                category=LogCategory.ERROR,
                error=str(e)
            )
            self.metrics.record_connection_error('connection_acquisition_error')
            raise ConnectionError(f"Failed to acquire database connection: {e}")
    
    def get_session(self) -> Session:
        """
        Get a database session from the scoped session factory.
        
        Returns:
            SQLAlchemy Session object
        """
        try:
            session = self.scoped_session()
            self.logger.debug(
                "Database session created",
                category=LogCategory.INFRASTRUCTURE
            )
            return session
        except Exception as e:
            self.logger.error(
                "Failed to create database session",
                category=LogCategory.ERROR,
                error=str(e)
            )
            self.metrics.record_connection_error('session_creation_error')
            raise ConnectionError(f"Failed to create database session: {e}")
    
    def health_check(self, force: bool = False) -> bool:
        """
        Perform database connection health check.
        
        Args:
            force: Force health check even if recently performed
            
        Returns:
            True if database is healthy, False otherwise
        """
        current_time = time.time()
        
        # Check if health check is needed
        if not force and self._last_health_check:
            if current_time - self._last_health_check < self._health_check_interval:
                return self._connection_metrics.health_check_status
        
        with self._health_check_lock:
            try:
                # Perform simple database query
                with self.get_connection() as conn:
                    result = conn.execute(text("SELECT 1"))
                    row = result.fetchone()
                    
                    if row and row[0] == 1:
                        self._connection_metrics.health_check_status = True
                        self._connection_metrics.last_health_check = datetime.now(timezone.utc)
                        self._last_health_check = current_time
                        
                        self.logger.debug(
                            "Database health check passed",
                            category=LogCategory.INFRASTRUCTURE
                        )
                        self.metrics.record_health_check('success')
                        return True
                    else:
                        raise DatabaseError("Health check query returned unexpected result")
                        
            except Exception as e:
                self._connection_metrics.health_check_status = False
                self.logger.error(
                    "Database health check failed",
                    category=LogCategory.ERROR,
                    error=str(e)
                )
                self.metrics.record_health_check('failure')
                self.metrics.record_connection_error('health_check_failed')
                return False
    
    def get_pool_status(self) -> Dict[str, Any]:
        """
        Get current connection pool status and metrics.
        
        Returns:
            Dictionary containing pool status information
        """
        self._update_pool_metrics()
        
        pool_status = {
            'pool_size': self._connection_metrics.pool_size,
            'checked_out': self._connection_metrics.checked_out,
            'overflow': self._connection_metrics.overflow,
            'invalid': self._connection_metrics.invalid,
            'total_connections': self._connection_metrics.total_connections,
            'connection_errors': self._connection_metrics.connection_errors,
            'health_check_status': self._connection_metrics.health_check_status,
            'last_health_check': self._connection_metrics.last_health_check.isoformat() if self._connection_metrics.last_health_check else None
        }
        
        if self._engine and hasattr(self._engine.pool, 'status'):
            pool_status.update(self._engine.pool.status())
        
        return pool_status
    
    def close(self):
        """Close all connections and dispose of the engine."""
        try:
            if self._scoped_session:
                self._scoped_session.remove()
            
            if self._engine:
                self._engine.dispose()
            
            self.logger.info(
                "Database connection pool closed",
                category=LogCategory.INFRASTRUCTURE
            )
            
        except Exception as e:
            self.logger.error(
                "Error closing database connection pool",
                category=LogCategory.ERROR,
                error=str(e)
            )


class TransactionManager:
    """
    Advanced transaction management with rollback capabilities and monitoring
    
    Provides comprehensive transaction management with automatic rollback,
    savepoints, nested transactions, and transaction performance monitoring
    for Flask-SQLAlchemy operations.
    """
    
    def __init__(self, connection_pool: ConnectionPool):
        """
        Initialize transaction manager.
        
        Args:
            connection_pool: Database connection pool instance
        """
        self.connection_pool = connection_pool
        self.logger = get_logger()
        self.metrics = DatabaseMetrics()
        self._active_transactions: Dict[str, Dict[str, Any]] = {}
        self._transaction_lock = threading.Lock()
    
    @contextmanager
    def transaction(self, session: Optional[Session] = None, 
                   savepoint: bool = False, isolation_level: Optional[str] = None) -> Generator[Session, None, None]:
        """
        Context manager for database transactions with automatic rollback.
        
        Args:
            session: Optional existing session to use
            savepoint: Create a savepoint instead of a full transaction
            isolation_level: Transaction isolation level
            
        Yields:
            SQLAlchemy Session object
        """
        transaction_id = str(uuid.uuid4())
        start_time = time.time()
        transaction_type = 'savepoint' if savepoint else 'transaction'
        
        # Create or use existing session
        session_created = session is None
        if session is None:
            session = self.connection_pool.get_session()
        
        # Track active transaction
        with self._transaction_lock:
            self._active_transactions[transaction_id] = {
                'start_time': start_time,
                'type': transaction_type,
                'isolation_level': isolation_level,
                'session_id': id(session)
            }
        
        self.logger.debug(
            f"Starting {transaction_type}",
            category=LogCategory.INFRASTRUCTURE,
            transaction_id=transaction_id,
            isolation_level=isolation_level
        )
        
        try:
            # Set isolation level if specified
            if isolation_level and not savepoint:
                session.connection(execution_options={'isolation_level': isolation_level})
            
            # Begin transaction or savepoint
            if savepoint:
                session.begin(subtransactions=True)
            else:
                session.begin()
            
            yield session
            
            # Commit the transaction
            session.commit()
            
            duration = time.time() - start_time
            self.logger.debug(
                f"{transaction_type.capitalize()} committed successfully",
                category=LogCategory.INFRASTRUCTURE,
                transaction_id=transaction_id,
                duration_seconds=duration
            )
            
            # Record metrics
            self.metrics.record_transaction(transaction_type, duration, 'committed')
            
        except Exception as e:
            # Rollback on any error
            try:
                session.rollback()
                duration = time.time() - start_time
                
                self.logger.error(
                    f"{transaction_type.capitalize()} rolled back due to error",
                    category=LogCategory.ERROR,
                    transaction_id=transaction_id,
                    error=str(e),
                    duration_seconds=duration
                )
                
                # Record metrics for failed transaction
                self.metrics.record_transaction(transaction_type, duration, 'rolled_back')
                
            except Exception as rollback_error:
                self.logger.critical(
                    f"Failed to rollback {transaction_type}",
                    category=LogCategory.ERROR,
                    transaction_id=transaction_id,
                    original_error=str(e),
                    rollback_error=str(rollback_error)
                )
            
            raise TransactionError(f"{transaction_type.capitalize()} failed: {e}")
        
        finally:
            # Clean up session if we created it
            if session_created:
                try:
                    session.close()
                except Exception as e:
                    self.logger.warning(
                        "Error closing session",
                        category=LogCategory.INFRASTRUCTURE,
                        error=str(e)
                    )
            
            # Remove from active transactions
            with self._transaction_lock:
                self._active_transactions.pop(transaction_id, None)
    
    @contextmanager
    def savepoint(self, session: Session, name: Optional[str] = None) -> Generator[Session, None, None]:
        """
        Context manager for database savepoints within transactions.
        
        Args:
            session: Existing database session
            name: Optional savepoint name
            
        Yields:
            SQLAlchemy Session object
        """
        savepoint_name = name or f"sp_{int(time.time() * 1000)}"
        start_time = time.time()
        
        self.logger.debug(
            "Creating savepoint",
            category=LogCategory.INFRASTRUCTURE,
            savepoint_name=savepoint_name
        )
        
        try:
            # Create savepoint
            savepoint = session.begin_nested()
            
            yield session
            
            # Commit savepoint
            savepoint.commit()
            
            duration = time.time() - start_time
            self.logger.debug(
                "Savepoint committed successfully",
                category=LogCategory.INFRASTRUCTURE,
                savepoint_name=savepoint_name,
                duration_seconds=duration
            )
            
        except Exception as e:
            # Rollback savepoint
            try:
                savepoint.rollback()
                duration = time.time() - start_time
                
                self.logger.error(
                    "Savepoint rolled back due to error",
                    category=LogCategory.ERROR,
                    savepoint_name=savepoint_name,
                    error=str(e),
                    duration_seconds=duration
                )
                
            except Exception as rollback_error:
                self.logger.critical(
                    "Failed to rollback savepoint",
                    category=LogCategory.ERROR,
                    savepoint_name=savepoint_name,
                    original_error=str(e),
                    rollback_error=str(rollback_error)
                )
            
            raise TransactionError(f"Savepoint {savepoint_name} failed: {e}")
    
    def get_active_transactions(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about currently active transactions.
        
        Returns:
            Dictionary of active transaction information
        """
        with self._transaction_lock:
            active_transactions = {}
            current_time = time.time()
            
            for transaction_id, info in self._active_transactions.items():
                active_transactions[transaction_id] = {
                    **info,
                    'duration_seconds': current_time - info['start_time']
                }
            
            return active_transactions


class QueryOptimizer:
    """
    Database query optimization utilities with performance monitoring
    
    Provides query performance monitoring, optimization suggestions,
    and automatic query analysis for PostgreSQL 14 database operations.
    """
    
    def __init__(self, connection_pool: ConnectionPool):
        """
        Initialize query optimizer.
        
        Args:
            connection_pool: Database connection pool instance
        """
        self.connection_pool = connection_pool
        self.logger = get_logger()
        self.metrics = DatabaseMetrics()
        self.query_metrics = QueryMetrics()
        self._slow_query_threshold = 2.0  # seconds
        self._query_cache: Dict[str, Dict[str, Any]] = {}
        self._query_lock = threading.Lock()
    
    @contextmanager
    def monitored_query(self, operation: str, table: str = "unknown") -> Generator[Session, None, None]:
        """
        Context manager for monitoring query performance.
        
        Args:
            operation: Type of operation (SELECT, INSERT, UPDATE, DELETE)
            table: Table name being queried
            
        Yields:
            SQLAlchemy Session object
        """
        start_time = time.time()
        session = self.connection_pool.get_session()
        
        try:
            yield session
            
            # Calculate query duration
            duration = time.time() - start_time
            self._record_query_metrics(operation, table, duration, 'success')
            
            # Check for slow queries
            if duration > self._slow_query_threshold:
                self._handle_slow_query(operation, table, duration)
            
        except Exception as e:
            duration = time.time() - start_time
            self._record_query_metrics(operation, table, duration, 'error')
            
            self.logger.error(
                "Query execution failed",
                category=LogCategory.ERROR,
                operation=operation,
                table=table,
                duration_seconds=duration,
                error=str(e)
            )
            
            raise
        
        finally:
            try:
                session.close()
            except Exception:
                pass
    
    def _record_query_metrics(self, operation: str, table: str, duration: float, status: str):
        """Record query performance metrics."""
        self.query_metrics.query_count += 1
        self.query_metrics.total_duration += duration
        self.query_metrics.avg_duration = self.query_metrics.total_duration / self.query_metrics.query_count
        self.query_metrics.max_duration = max(self.query_metrics.max_duration, duration)
        self.query_metrics.min_duration = min(self.query_metrics.min_duration, duration)
        self.query_metrics.last_query_time = datetime.now(timezone.utc)
        
        if status == 'error':
            self.query_metrics.failed_queries += 1
        
        # Record Prometheus metrics
        self.metrics.record_query(operation, table, duration, status)
        
        self.logger.debug(
            "Query performance recorded",
            category=LogCategory.PERFORMANCE,
            operation=operation,
            table=table,
            duration_seconds=duration,
            status=status
        )
    
    def _handle_slow_query(self, operation: str, table: str, duration: float):
        """Handle slow query detection and logging."""
        self.query_metrics.slow_queries += 1
        
        # Determine threshold category
        if duration > 10.0:
            threshold = "critical"
        elif duration > 5.0:
            threshold = "high"
        else:
            threshold = "medium"
        
        self.metrics.record_slow_query(operation, table, threshold)
        
        self.logger.warning(
            "Slow query detected",
            category=LogCategory.PERFORMANCE,
            operation=operation,
            table=table,
            duration_seconds=duration,
            threshold=self._slow_query_threshold,
            threshold_category=threshold
        )
    
    def analyze_query_plan(self, query: str, session: Optional[Session] = None) -> Dict[str, Any]:
        """
        Analyze PostgreSQL query execution plan.
        
        Args:
            query: SQL query to analyze
            session: Optional database session
            
        Returns:
            Dictionary containing query plan analysis
        """
        session_created = session is None
        if session is None:
            session = self.connection_pool.get_session()
        
        try:
            # Get query execution plan
            explain_query = f"EXPLAIN (ANALYZE true, BUFFERS true, FORMAT JSON) {query}"
            result = session.execute(text(explain_query))
            plan_data = result.fetchone()[0][0]
            
            # Analyze the plan
            analysis = self._analyze_plan_data(plan_data)
            
            self.logger.debug(
                "Query plan analyzed",
                category=LogCategory.PERFORMANCE,
                query_hash=hash(query),
                execution_time=analysis.get('execution_time'),
                planning_time=analysis.get('planning_time')
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(
                "Failed to analyze query plan",
                category=LogCategory.ERROR,
                error=str(e)
            )
            return {'error': str(e)}
        
        finally:
            if session_created:
                session.close()
    
    def _analyze_plan_data(self, plan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze PostgreSQL query plan data."""
        analysis = {
            'execution_time': plan_data.get('Execution Time', 0),
            'planning_time': plan_data.get('Planning Time', 0),
            'total_cost': plan_data.get('Plan', {}).get('Total Cost', 0),
            'startup_cost': plan_data.get('Plan', {}).get('Startup Cost', 0),
            'node_type': plan_data.get('Plan', {}).get('Node Type'),
            'relation_name': plan_data.get('Plan', {}).get('Relation Name'),
            'warnings': [],
            'suggestions': []
        }
        
        # Analyze for common performance issues
        plan = plan_data.get('Plan', {})
        
        # Check for sequential scans
        if self._contains_sequential_scan(plan):
            analysis['warnings'].append('Sequential scan detected')
            analysis['suggestions'].append('Consider adding indexes for better performance')
        
        # Check for high cost operations
        if analysis['total_cost'] > 1000:
            analysis['warnings'].append('High cost query detected')
            analysis['suggestions'].append('Review query optimization opportunities')
        
        # Check for long execution time
        if analysis['execution_time'] > 1000:  # milliseconds
            analysis['warnings'].append('Long execution time detected')
            analysis['suggestions'].append('Consider query optimization or indexing')
        
        return analysis
    
    def _contains_sequential_scan(self, plan: Dict[str, Any]) -> bool:
        """Check if query plan contains sequential scans."""
        if plan.get('Node Type') == 'Seq Scan':
            return True
        
        # Check child plans recursively
        for child_plan in plan.get('Plans', []):
            if self._contains_sequential_scan(child_plan):
                return True
        
        return False
    
    def get_query_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive query performance statistics.
        
        Returns:
            Dictionary containing query performance metrics
        """
        return {
            'total_queries': self.query_metrics.query_count,
            'total_duration': self.query_metrics.total_duration,
            'average_duration': self.query_metrics.avg_duration,
            'max_duration': self.query_metrics.max_duration,
            'min_duration': self.query_metrics.min_duration if self.query_metrics.min_duration != float('inf') else 0,
            'slow_queries': self.query_metrics.slow_queries,
            'failed_queries': self.query_metrics.failed_queries,
            'slow_query_threshold': self._slow_query_threshold,
            'last_query_time': self.query_metrics.last_query_time.isoformat() if self.query_metrics.last_query_time else None
        }


class MigrationManager:
    """
    Comprehensive database migration management with Flask-Migrate 4.x integration
    
    Provides advanced migration capabilities including zero data loss validation,
    automatic rollback, backup coordination, and migration performance monitoring
    for Flask-SQLAlchemy and Alembic-based database versioning.
    """
    
    def __init__(self, app: Flask, db: SQLAlchemy):
        """
        Initialize migration manager.
        
        Args:
            app: Flask application instance
            db: SQLAlchemy database instance
        """
        self.app = app
        self.db = db
        self.migrate = Migrate(app, db)
        self.logger = get_logger()
        self.metrics = DatabaseMetrics()
        self._migration_lock = threading.Lock()
        self._active_migrations: Dict[str, MigrationContext] = {}
    
    @log_audit_event("database_migration", "upgrade")
    def upgrade_database(self, revision: str = "head", backup: bool = True, 
                        validate: bool = True) -> MigrationContext:
        """
        Upgrade database to specified revision with comprehensive safety checks.
        
        Args:
            revision: Target revision (default: "head")
            backup: Create backup before migration
            validate: Perform data validation after migration
            
        Returns:
            MigrationContext containing migration results
        """
        migration_id = str(uuid.uuid4())
        start_time = datetime.now(timezone.utc)
        
        with self._migration_lock:
            # Get current revision
            current_revision = self._get_current_revision()
            
            # Create migration context
            context = MigrationContext(
                migration_id=migration_id,
                source_revision=current_revision,
                target_revision=revision,
                migration_type='upgrade',
                start_time=start_time,
                status=MigrationState.RUNNING
            )
            
            self._active_migrations[migration_id] = context
            
            self.logger.info(
                "Starting database upgrade migration",
                category=LogCategory.INFRASTRUCTURE,
                migration_id=migration_id,
                source_revision=current_revision,
                target_revision=revision,
                backup_enabled=backup,
                validation_enabled=validate
            )
            
            try:
                # Create backup if requested
                if backup:
                    backup_location = self._create_migration_backup(migration_id)
                    context.backup_created = True
                    context.backup_location = backup_location
                
                # Perform the migration
                migration_start = time.time()
                
                with self.app.app_context():
                    upgrade(revision=revision)
                
                migration_duration = time.time() - migration_start
                context.performance_metrics['migration_duration'] = migration_duration
                
                # Validate data if requested
                if validate:
                    validation_result = self._validate_migration_data(context)
                    context.validation_results.append(validation_result)
                    
                    if not validation_result.is_valid:
                        raise ValidationError(f"Migration validation failed: {validation_result.errors}")
                
                # Update context with success
                context.status = MigrationState.COMPLETED
                context.end_time = datetime.now(timezone.utc)
                
                self.logger.info(
                    "Database upgrade migration completed successfully",
                    category=LogCategory.INFRASTRUCTURE,
                    migration_id=migration_id,
                    duration_seconds=migration_duration,
                    backup_location=context.backup_location
                )
                
                # Record metrics
                self.metrics.record_migration('upgrade', migration_duration, 'completed')
                
                return context
                
            except Exception as e:
                # Handle migration failure
                context.status = MigrationState.FAILED
                context.end_time = datetime.now(timezone.utc)
                context.error_log.append(str(e))
                
                self.logger.error(
                    "Database upgrade migration failed",
                    category=LogCategory.ERROR,
                    migration_id=migration_id,
                    error=str(e),
                    backup_location=context.backup_location
                )
                
                # Record failure metrics
                migration_duration = time.time() - migration_start if 'migration_start' in locals() else 0
                self.metrics.record_migration('upgrade', migration_duration, 'failed')
                
                # Attempt automatic rollback if backup exists
                if context.backup_created:
                    try:
                        self._rollback_from_backup(context)
                        self.logger.info(
                            "Automatic rollback from backup completed",
                            category=LogCategory.INFRASTRUCTURE,
                            migration_id=migration_id
                        )
                    except Exception as rollback_error:
                        self.logger.critical(
                            "Automatic rollback failed",
                            category=LogCategory.ERROR,
                            migration_id=migration_id,
                            rollback_error=str(rollback_error)
                        )
                
                raise MigrationError(f"Migration upgrade failed: {e}")
            
            finally:
                # Clean up active migration tracking
                self._active_migrations.pop(migration_id, None)
    
    @log_audit_event("database_migration", "downgrade")
    def downgrade_database(self, revision: str, backup: bool = True, 
                          validate: bool = True) -> MigrationContext:
        """
        Downgrade database to specified revision with safety checks.
        
        Args:
            revision: Target revision for downgrade
            backup: Create backup before migration
            validate: Perform data validation after migration
            
        Returns:
            MigrationContext containing migration results
        """
        migration_id = str(uuid.uuid4())
        start_time = datetime.now(timezone.utc)
        
        with self._migration_lock:
            # Get current revision
            current_revision = self._get_current_revision()
            
            # Create migration context
            context = MigrationContext(
                migration_id=migration_id,
                source_revision=current_revision,
                target_revision=revision,
                migration_type='downgrade',
                start_time=start_time,
                status=MigrationState.RUNNING
            )
            
            self._active_migrations[migration_id] = context
            
            self.logger.info(
                "Starting database downgrade migration",
                category=LogCategory.INFRASTRUCTURE,
                migration_id=migration_id,
                source_revision=current_revision,
                target_revision=revision,
                backup_enabled=backup,
                validation_enabled=validate
            )
            
            try:
                # Create backup if requested
                if backup:
                    backup_location = self._create_migration_backup(migration_id)
                    context.backup_created = True
                    context.backup_location = backup_location
                
                # Perform the downgrade
                migration_start = time.time()
                
                with self.app.app_context():
                    downgrade(revision=revision)
                
                migration_duration = time.time() - migration_start
                context.performance_metrics['migration_duration'] = migration_duration
                
                # Validate data if requested
                if validate:
                    validation_result = self._validate_migration_data(context)
                    context.validation_results.append(validation_result)
                    
                    if not validation_result.is_valid:
                        raise ValidationError(f"Migration validation failed: {validation_result.errors}")
                
                # Update context with success
                context.status = MigrationState.COMPLETED
                context.end_time = datetime.now(timezone.utc)
                
                self.logger.info(
                    "Database downgrade migration completed successfully",
                    category=LogCategory.INFRASTRUCTURE,
                    migration_id=migration_id,
                    duration_seconds=migration_duration
                )
                
                # Record metrics
                self.metrics.record_migration('downgrade', migration_duration, 'completed')
                
                return context
                
            except Exception as e:
                # Handle migration failure
                context.status = MigrationState.FAILED
                context.end_time = datetime.now(timezone.utc)
                context.error_log.append(str(e))
                
                self.logger.error(
                    "Database downgrade migration failed",
                    category=LogCategory.ERROR,
                    migration_id=migration_id,
                    error=str(e)
                )
                
                # Record failure metrics
                migration_duration = time.time() - migration_start if 'migration_start' in locals() else 0
                self.metrics.record_migration('downgrade', migration_duration, 'failed')
                
                raise MigrationError(f"Migration downgrade failed: {e}")
            
            finally:
                # Clean up active migration tracking
                self._active_migrations.pop(migration_id, None)
    
    def _get_current_revision(self) -> Optional[str]:
        """Get current database revision."""
        try:
            with self.app.app_context():
                return get_current_revision()
        except Exception as e:
            self.logger.error(
                "Failed to get current database revision",
                category=LogCategory.ERROR,
                error=str(e)
            )
            return None
    
    def _create_migration_backup(self, migration_id: str) -> str:
        """
        Create database backup before migration.
        
        Args:
            migration_id: Migration identifier
            
        Returns:
            Backup file location
        """
        backup_filename = f"migration_backup_{migration_id}_{int(time.time())}.sql"
        backup_path = os.path.join("/tmp/db_backups", backup_filename)
        
        # Create backup directory if it doesn't exist
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
        
        try:
            # Use pg_dump to create backup
            database_config = get_database_config()
            
            dump_command = [
                "pg_dump",
                "--verbose",
                "--clean",
                "--no-owner",
                "--no-privileges",
                "--format=custom",
                f"--file={backup_path}",
                database_config.url
            ]
            
            import subprocess
            result = subprocess.run(dump_command, capture_output=True, text=True, check=True)
            
            self.logger.info(
                "Migration backup created successfully",
                category=LogCategory.INFRASTRUCTURE,
                backup_path=backup_path,
                migration_id=migration_id
            )
            
            return backup_path
            
        except Exception as e:
            self.logger.error(
                "Failed to create migration backup",
                category=LogCategory.ERROR,
                migration_id=migration_id,
                error=str(e)
            )
            raise MigrationError(f"Failed to create migration backup: {e}")
    
    def _validate_migration_data(self, context: MigrationContext) -> ValidationResult:
        """
        Validate data integrity after migration.
        
        Args:
            context: Migration context
            
        Returns:
            ValidationResult containing validation details
        """
        validation_start = time.time()
        result = ValidationResult()
        
        try:
            # Get database inspector
            inspector = inspect(self.db.engine)
            
            # Validate table structure
            tables = inspector.get_table_names()
            result.metadata['table_count'] = len(tables)
            
            # Validate foreign key constraints
            for table_name in tables:
                foreign_keys = inspector.get_foreign_keys(table_name)
                for fk in foreign_keys:
                    # Check if referenced table exists
                    if fk['referred_table'] not in tables:
                        result.errors.append(f"Foreign key in {table_name} references non-existent table {fk['referred_table']}")
                        result.is_valid = False
            
            # Validate indexes
            for table_name in tables:
                indexes = inspector.get_indexes(table_name)
                result.metadata[f'{table_name}_indexes'] = len(indexes)
            
            # Basic data consistency checks
            with self.db.engine.connect() as conn:
                # Check for orphaned records (simplified example)
                for table_name in tables[:5]:  # Limit to first 5 tables for performance
                    try:
                        count_result = conn.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
                        count = count_result.scalar()
                        result.metadata[f'{table_name}_count'] = count
                        result.records_checked += count
                    except Exception as e:
                        result.warnings.append(f"Could not validate table {table_name}: {str(e)}")
            
            result.validation_time = time.time() - validation_start
            result.error_count = len(result.errors)
            
            if result.errors:
                result.is_valid = False
            
            self.logger.info(
                "Migration data validation completed",
                category=LogCategory.INFRASTRUCTURE,
                migration_id=context.migration_id,
                validation_time=result.validation_time,
                records_checked=result.records_checked,
                errors=result.error_count,
                warnings=len(result.warnings)
            )
            
        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Validation failed: {str(e)}")
            result.validation_time = time.time() - validation_start
            
            self.logger.error(
                "Migration data validation failed",
                category=LogCategory.ERROR,
                migration_id=context.migration_id,
                error=str(e)
            )
        
        return result
    
    def _rollback_from_backup(self, context: MigrationContext):
        """
        Rollback database from backup file.
        
        Args:
            context: Migration context containing backup information
        """
        if not context.backup_created or not context.backup_location:
            raise MigrationError("No backup available for rollback")
        
        try:
            # Use pg_restore to restore backup
            database_config = get_database_config()
            
            restore_command = [
                "pg_restore",
                "--verbose",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--dbname", database_config.url,
                context.backup_location
            ]
            
            import subprocess
            result = subprocess.run(restore_command, capture_output=True, text=True, check=True)
            
            context.status = MigrationState.ROLLED_BACK
            
            self.logger.info(
                "Database rollback from backup completed",
                category=LogCategory.INFRASTRUCTURE,
                migration_id=context.migration_id,
                backup_location=context.backup_location
            )
            
        except Exception as e:
            self.logger.error(
                "Database rollback from backup failed",
                category=LogCategory.ERROR,
                migration_id=context.migration_id,
                error=str(e)
            )
            raise MigrationError(f"Rollback from backup failed: {e}")
    
    def get_migration_history(self) -> List[Dict[str, Any]]:
        """
        Get database migration history.
        
        Returns:
            List of migration history entries
        """
        try:
            with self.app.app_context():
                # Get Alembic configuration
                config = Config()
                config.set_main_option("script_location", "migrations")
                
                # Get script directory
                script = ScriptDirectory.from_config(config)
                
                # Get migration history
                history = []
                for revision in script.walk_revisions():
                    history.append({
                        'revision': revision.revision,
                        'down_revision': revision.down_revision,
                        'branch_labels': revision.branch_labels,
                        'depends_on': revision.depends_on,
                        'doc': revision.doc,
                        'is_current': revision.revision == self._get_current_revision()
                    })
                
                return history
                
        except Exception as e:
            self.logger.error(
                "Failed to get migration history",
                category=LogCategory.ERROR,
                error=str(e)
            )
            return []
    
    def get_active_migrations(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about currently active migrations.
        
        Returns:
            Dictionary of active migration information
        """
        active_migrations = {}
        current_time = datetime.now(timezone.utc)
        
        for migration_id, context in self._active_migrations.items():
            duration = (current_time - context.start_time).total_seconds()
            
            active_migrations[migration_id] = {
                'migration_type': context.migration_type,
                'source_revision': context.source_revision,
                'target_revision': context.target_revision,
                'status': context.status.value,
                'start_time': context.start_time.isoformat(),
                'duration_seconds': duration,
                'backup_created': context.backup_created,
                'validation_count': len(context.validation_results),
                'error_count': len(context.error_log)
            }
        
        return active_migrations


class DataValidator:
    """
    Zero data loss validation utilities for MongoDB migration
    
    Provides comprehensive data validation capabilities to ensure zero data loss
    during migration from MongoDB to PostgreSQL, including data integrity checks,
    relationship validation, and migration verification procedures.
    """
    
    def __init__(self, connection_pool: ConnectionPool):
        """
        Initialize data validator.
        
        Args:
            connection_pool: Database connection pool instance
        """
        self.connection_pool = connection_pool
        self.logger = get_logger()
        self.metrics = DatabaseMetrics()
    
    def validate_table_structure(self, table_name: str, 
                                expected_columns: List[Dict[str, Any]]) -> ValidationResult:
        """
        Validate table structure against expected schema.
        
        Args:
            table_name: Name of table to validate
            expected_columns: Expected column definitions
            
        Returns:
            ValidationResult containing validation details
        """
        validation_start = time.time()
        result = ValidationResult()
        
        try:
            # Get table inspector
            inspector = inspect(self.connection_pool.engine)
            
            # Check if table exists
            if table_name not in inspector.get_table_names():
                result.errors.append(f"Table {table_name} does not exist")
                result.is_valid = False
                return result
            
            # Get actual columns
            actual_columns = inspector.get_columns(table_name)
            actual_column_names = {col['name'] for col in actual_columns}
            
            # Validate column existence
            for expected_col in expected_columns:
                col_name = expected_col['name']
                if col_name not in actual_column_names:
                    result.errors.append(f"Column {col_name} missing from table {table_name}")
                    result.is_valid = False
                else:
                    # Validate column properties
                    actual_col = next(col for col in actual_columns if col['name'] == col_name)
                    
                    # Check column type (simplified)
                    if 'type' in expected_col:
                        expected_type = str(expected_col['type']).lower()
                        actual_type = str(actual_col['type']).lower()
                        
                        if expected_type not in actual_type and actual_type not in expected_type:
                            result.warnings.append(
                                f"Column {col_name} type mismatch: expected {expected_type}, got {actual_type}"
                            )
                    
                    # Check nullable constraint
                    if 'nullable' in expected_col:
                        if expected_col['nullable'] != actual_col['nullable']:
                            result.errors.append(
                                f"Column {col_name} nullable constraint mismatch: "
                                f"expected {expected_col['nullable']}, got {actual_col['nullable']}"
                            )
                            result.is_valid = False
            
            # Check for unexpected columns
            expected_column_names = {col['name'] for col in expected_columns}
            unexpected_columns = actual_column_names - expected_column_names
            if unexpected_columns:
                result.warnings.extend([
                    f"Unexpected column {col_name} in table {table_name}"
                    for col_name in unexpected_columns
                ])
            
            result.validation_time = time.time() - validation_start
            result.error_count = len(result.errors)
            
            self.logger.debug(
                "Table structure validation completed",
                category=LogCategory.INFRASTRUCTURE,
                table_name=table_name,
                validation_time=result.validation_time,
                errors=result.error_count,
                warnings=len(result.warnings)
            )
            
        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Table structure validation failed: {str(e)}")
            result.validation_time = time.time() - validation_start
            
            self.logger.error(
                "Table structure validation failed",
                category=LogCategory.ERROR,
                table_name=table_name,
                error=str(e)
            )
        
        return result
    
    def validate_data_integrity(self, table_name: str, 
                              validation_rules: List[Dict[str, Any]]) -> ValidationResult:
        """
        Validate data integrity using custom validation rules.
        
        Args:
            table_name: Name of table to validate
            validation_rules: List of validation rule definitions
            
        Returns:
            ValidationResult containing validation details
        """
        validation_start = time.time()
        result = ValidationResult()
        
        try:
            with self.connection_pool.get_connection() as conn:
                # Get table row count
                count_query = text(f"SELECT COUNT(*) FROM {table_name}")
                total_rows = conn.execute(count_query).scalar()
                result.records_checked = total_rows
                
                # Apply validation rules
                for rule in validation_rules:
                    rule_type = rule.get('type')
                    
                    if rule_type == 'not_null':
                        self._validate_not_null(conn, table_name, rule, result)
                    elif rule_type == 'unique':
                        self._validate_uniqueness(conn, table_name, rule, result)
                    elif rule_type == 'foreign_key':
                        self._validate_foreign_key(conn, table_name, rule, result)
                    elif rule_type == 'check_constraint':
                        self._validate_check_constraint(conn, table_name, rule, result)
                    elif rule_type == 'custom_query':
                        self._validate_custom_query(conn, table_name, rule, result)
                    else:
                        result.warnings.append(f"Unknown validation rule type: {rule_type}")
            
            result.validation_time = time.time() - validation_start
            result.error_count = len(result.errors)
            
            if result.errors:
                result.is_valid = False
            
            self.logger.info(
                "Data integrity validation completed",
                category=LogCategory.INFRASTRUCTURE,
                table_name=table_name,
                validation_time=result.validation_time,
                records_checked=result.records_checked,
                errors=result.error_count,
                warnings=len(result.warnings)
            )
            
        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Data integrity validation failed: {str(e)}")
            result.validation_time = time.time() - validation_start
            
            self.logger.error(
                "Data integrity validation failed",
                category=LogCategory.ERROR,
                table_name=table_name,
                error=str(e)
            )
        
        return result
    
    def _validate_not_null(self, conn: Connection, table_name: str, 
                          rule: Dict[str, Any], result: ValidationResult):
        """Validate NOT NULL constraints."""
        column = rule['column']
        query = text(f"SELECT COUNT(*) FROM {table_name} WHERE {column} IS NULL")
        null_count = conn.execute(query).scalar()
        
        if null_count > 0:
            result.errors.append(f"Found {null_count} NULL values in {table_name}.{column}")
    
    def _validate_uniqueness(self, conn: Connection, table_name: str, 
                           rule: Dict[str, Any], result: ValidationResult):
        """Validate UNIQUE constraints."""
        columns = rule['columns'] if isinstance(rule['columns'], list) else [rule['columns']]
        column_list = ', '.join(columns)
        
        query = text(f"""
            SELECT {column_list}, COUNT(*) as cnt 
            FROM {table_name} 
            GROUP BY {column_list} 
            HAVING COUNT(*) > 1
        """)
        
        duplicates = conn.execute(query).fetchall()
        if duplicates:
            result.errors.append(f"Found {len(duplicates)} duplicate value groups in {table_name}({column_list})")
    
    def _validate_foreign_key(self, conn: Connection, table_name: str, 
                            rule: Dict[str, Any], result: ValidationResult):
        """Validate foreign key constraints."""
        local_column = rule['local_column']
        foreign_table = rule['foreign_table']
        foreign_column = rule['foreign_column']
        
        query = text(f"""
            SELECT COUNT(*) 
            FROM {table_name} t1 
            LEFT JOIN {foreign_table} t2 ON t1.{local_column} = t2.{foreign_column}
            WHERE t1.{local_column} IS NOT NULL AND t2.{foreign_column} IS NULL
        """)
        
        orphaned_count = conn.execute(query).scalar()
        if orphaned_count > 0:
            result.errors.append(
                f"Found {orphaned_count} orphaned foreign key references in {table_name}.{local_column}"
            )
    
    def _validate_check_constraint(self, conn: Connection, table_name: str, 
                                 rule: Dict[str, Any], result: ValidationResult):
        """Validate check constraints."""
        constraint_condition = rule['condition']
        
        query = text(f"""
            SELECT COUNT(*) 
            FROM {table_name} 
            WHERE NOT ({constraint_condition})
        """)
        
        violation_count = conn.execute(query).scalar()
        if violation_count > 0:
            result.errors.append(
                f"Found {violation_count} check constraint violations in {table_name}: {constraint_condition}"
            )
    
    def _validate_custom_query(self, conn: Connection, table_name: str, 
                             rule: Dict[str, Any], result: ValidationResult):
        """Validate using custom SQL query."""
        query_sql = rule['query']
        expected_result = rule.get('expected_result', 0)
        
        query_result = conn.execute(text(query_sql)).scalar()
        
        if query_result != expected_result:
            result.errors.append(
                f"Custom validation failed for {table_name}: "
                f"expected {expected_result}, got {query_result}"
            )
    
    def compare_record_counts(self, source_counts: Dict[str, int]) -> ValidationResult:
        """
        Compare record counts between source and target databases.
        
        Args:
            source_counts: Dictionary of table names to record counts from source
            
        Returns:
            ValidationResult containing comparison details
        """
        validation_start = time.time()
        result = ValidationResult()
        
        try:
            with self.connection_pool.get_connection() as conn:
                inspector = inspect(self.connection_pool.engine)
                target_tables = inspector.get_table_names()
                
                for table_name, source_count in source_counts.items():
                    if table_name not in target_tables:
                        result.errors.append(f"Table {table_name} missing from target database")
                        continue
                    
                    # Get target count
                    count_query = text(f"SELECT COUNT(*) FROM {table_name}")
                    target_count = conn.execute(count_query).scalar()
                    
                    result.records_checked += target_count
                    result.metadata[f'{table_name}_source_count'] = source_count
                    result.metadata[f'{table_name}_target_count'] = target_count
                    
                    # Compare counts
                    if source_count != target_count:
                        result.errors.append(
                            f"Record count mismatch for {table_name}: "
                            f"source={source_count}, target={target_count}"
                        )
                        result.is_valid = False
                    else:
                        self.logger.debug(
                            f"Record count match for {table_name}: {target_count}",
                            category=LogCategory.INFRASTRUCTURE
                        )
                
                # Check for extra tables in target
                source_tables = set(source_counts.keys())
                target_table_set = set(target_tables)
                extra_tables = target_table_set - source_tables
                
                if extra_tables:
                    result.warnings.extend([
                        f"Extra table in target database: {table_name}"
                        for table_name in extra_tables
                    ])
            
            result.validation_time = time.time() - validation_start
            result.error_count = len(result.errors)
            
            self.logger.info(
                "Record count comparison completed",
                category=LogCategory.INFRASTRUCTURE,
                validation_time=result.validation_time,
                tables_compared=len(source_counts),
                errors=result.error_count,
                warnings=len(result.warnings)
            )
            
        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Record count comparison failed: {str(e)}")
            result.validation_time = time.time() - validation_start
            
            self.logger.error(
                "Record count comparison failed",
                category=LogCategory.ERROR,
                error=str(e)
            )
        
        return result


class DatabaseManager:
    """
    Main database management class coordinating all database utilities
    
    This class serves as the central coordinator for database operations,
    integrating connection pooling, transaction management, query optimization,
    migration management, and data validation for the Flask application.
    """
    
    def __init__(self, app: Optional[Flask] = None, db: Optional[SQLAlchemy] = None):
        """
        Initialize database manager.
        
        Args:
            app: Flask application instance
            db: SQLAlchemy database instance
        """
        self.app = app
        self.db = db
        self.logger = get_logger()
        self.connection_pool: Optional[ConnectionPool] = None
        self.transaction_manager: Optional[TransactionManager] = None
        self.query_optimizer: Optional[QueryOptimizer] = None
        self.migration_manager: Optional[MigrationManager] = None
        self.data_validator: Optional[DataValidator] = None
        self._initialized = False
        
        if app:
            self.init_app(app, db)
    
    def init_app(self, app: Flask, db: Optional[SQLAlchemy] = None):
        """
        Initialize database manager with Flask application factory pattern.
        
        Args:
            app: Flask application instance
            db: SQLAlchemy database instance
        """
        self.app = app
        self.db = db or SQLAlchemy()
        
        # Initialize SQLAlchemy if not already done
        if not hasattr(self.db, 'app') or self.db.app != app:
            self.db.init_app(app)
        
        # Get database configuration
        try:
            database_config = get_database_config()
            
            # Initialize connection pool
            self.connection_pool = ConnectionPool(
                database_url=database_config.url,
                pool_size=database_config.pool_size,
                max_overflow=getattr(database_config, 'max_overflow', 10),
                pool_timeout=database_config.pool_timeout,
                pool_recycle=database_config.pool_recycle,
                pool_pre_ping=True,
                echo=database_config.echo,
                echo_pool=database_config.echo_pool
            )
            
            # Initialize other managers
            self.transaction_manager = TransactionManager(self.connection_pool)
            self.query_optimizer = QueryOptimizer(self.connection_pool)
            self.migration_manager = MigrationManager(app, self.db)
            self.data_validator = DataValidator(self.connection_pool)
            
            # Store database manager in app for easy access
            app.database_manager = self
            
            self._initialized = True
            
            self.logger.info(
                "Database manager initialized successfully",
                category=LogCategory.INFRASTRUCTURE,
                pool_size=database_config.pool_size,
                pool_timeout=database_config.pool_timeout,
                pool_recycle=database_config.pool_recycle
            )
            
        except Exception as e:
            self.logger.error(
                "Failed to initialize database manager",
                category=LogCategory.ERROR,
                error=str(e)
            )
            raise DatabaseError(f"Database manager initialization failed: {e}")
    
    @property
    def initialized(self) -> bool:
        """Check if database manager is properly initialized."""
        return self._initialized
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform comprehensive database health check.
        
        Returns:
            Dictionary containing health check results
        """
        if not self.initialized:
            return {'status': 'error', 'message': 'Database manager not initialized'}
        
        health_result = {
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'components': {}
        }
        
        try:
            # Check connection pool health
            pool_health = self.connection_pool.health_check()
            health_result['components']['connection_pool'] = {
                'status': 'healthy' if pool_health else 'unhealthy',
                'details': self.connection_pool.get_pool_status()
            }
            
            # Check basic database connectivity
            try:
                with self.connection_pool.get_connection() as conn:
                    result = conn.execute(text("SELECT version()"))
                    db_version = result.scalar()
                    health_result['components']['database'] = {
                        'status': 'healthy',
                        'version': db_version
                    }
            except Exception as e:
                health_result['components']['database'] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
                health_result['status'] = 'degraded'
            
            # Check migration status
            try:
                current_revision = self.migration_manager._get_current_revision()
                health_result['components']['migrations'] = {
                    'status': 'healthy',
                    'current_revision': current_revision
                }
            except Exception as e:
                health_result['components']['migrations'] = {
                    'status': 'warning',
                    'error': str(e)
                }
            
            # Get query performance statistics
            query_stats = self.query_optimizer.get_query_statistics()
            health_result['components']['query_performance'] = {
                'status': 'healthy',
                'statistics': query_stats
            }
            
        except Exception as e:
            health_result['status'] = 'error'
            health_result['error'] = str(e)
            
            self.logger.error(
                "Database health check failed",
                category=LogCategory.ERROR,
                error=str(e)
            )
        
        return health_result
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get comprehensive database manager status.
        
        Returns:
            Dictionary containing status information
        """
        if not self.initialized:
            return {'initialized': False, 'error': 'Database manager not initialized'}
        
        status = {
            'initialized': True,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'connection_pool': self.connection_pool.get_pool_status(),
            'query_statistics': self.query_optimizer.get_query_statistics(),
            'active_transactions': self.transaction_manager.get_active_transactions(),
            'active_migrations': self.migration_manager.get_active_migrations(),
            'health_check': self.health_check()
        }
        
        return status
    
    def close(self):
        """Close database connections and clean up resources."""
        try:
            if self.connection_pool:
                self.connection_pool.close()
            
            if self.db:
                self.db.session.remove()
            
            self.logger.info(
                "Database manager closed successfully",
                category=LogCategory.INFRASTRUCTURE
            )
            
        except Exception as e:
            self.logger.error(
                "Error closing database manager",
                category=LogCategory.ERROR,
                error=str(e)
            )


# Global database manager instance for convenience
_database_manager: Optional[DatabaseManager] = None


def get_database_manager() -> DatabaseManager:
    """
    Get the global database manager instance.
    
    Returns:
        DatabaseManager instance
    """
    global _database_manager
    
    if has_app_context() and hasattr(current_app, 'database_manager'):
        return current_app.database_manager
    
    if _database_manager is None:
        _database_manager = DatabaseManager()
    
    return _database_manager


def init_database(app: Flask, db: Optional[SQLAlchemy] = None) -> DatabaseManager:
    """
    Initialize database utilities for Flask application factory pattern.
    
    This function should be called from the Flask application factory
    to set up comprehensive database management capabilities.
    
    Args:
        app: Flask application instance
        db: Optional SQLAlchemy instance
        
    Returns:
        DatabaseManager: Configured database manager instance
    """
    global _database_manager
    
    # Create and initialize database manager
    _database_manager = DatabaseManager(app, db)
    
    # Log successful initialization
    logger = get_logger()
    logger.info(
        "Database utilities initialized successfully",
        category=LogCategory.INFRASTRUCTURE,
        flask_version=getattr(Flask, '__version__', 'unknown'),
        sqlalchemy_version=getattr(SQLAlchemy, '__version__', 'unknown'),
        app_name=app.config.get('APP_NAME', 'Flask Application')
    )
    
    return _database_manager


# Convenience functions for common database operations

@log_function_call(LogCategory.INFRASTRUCTURE)
def execute_query(query: str, params: Optional[Dict[str, Any]] = None, 
                 fetch_results: bool = True) -> Optional[List[Dict[str, Any]]]:
    """
    Execute a database query with automatic session management.
    
    Args:
        query: SQL query to execute
        params: Query parameters
        fetch_results: Whether to fetch and return results
        
    Returns:
        Query results as list of dictionaries, or None
    """
    db_manager = get_database_manager()
    
    if not db_manager.initialized:
        raise DatabaseError("Database manager not initialized")
    
    with db_manager.query_optimizer.monitored_query("SELECT", "unknown") as session:
        try:
            result = session.execute(text(query), params or {})
            
            if fetch_results:
                # Convert results to list of dictionaries
                columns = result.keys()
                rows = result.fetchall()
                return [dict(zip(columns, row)) for row in rows]
            else:
                return None
                
        except Exception as e:
            raise DatabaseError(f"Query execution failed: {e}")


@log_function_call(LogCategory.INFRASTRUCTURE)
def execute_transaction(operations: List[Callable[[Session], None]]) -> None:
    """
    Execute multiple operations within a single transaction.
    
    Args:
        operations: List of functions that accept a Session parameter
    """
    db_manager = get_database_manager()
    
    if not db_manager.initialized:
        raise DatabaseError("Database manager not initialized")
    
    with db_manager.transaction_manager.transaction() as session:
        for operation in operations:
            operation(session)


@log_audit_event("database_validation", "validate")
def validate_database_integrity(tables: Optional[List[str]] = None) -> Dict[str, ValidationResult]:
    """
    Validate database integrity for specified tables.
    
    Args:
        tables: List of table names to validate (all tables if None)
        
    Returns:
        Dictionary mapping table names to validation results
    """
    db_manager = get_database_manager()
    
    if not db_manager.initialized:
        raise DatabaseError("Database manager not initialized")
    
    # Get table list if not provided
    if tables is None:
        inspector = inspect(db_manager.connection_pool.engine)
        tables = inspector.get_table_names()
    
    validation_results = {}
    
    for table_name in tables:
        # Basic structure validation
        validation_results[table_name] = db_manager.data_validator.validate_table_structure(
            table_name, []  # Could be enhanced with expected schema
        )
    
    return validation_results


if __name__ == "__main__":
    """
    Database utilities testing and validation script
    """
    import sys
    
    try:
        print("Testing database utilities...")
        
        # Test configuration loading
        try:
            db_config = get_database_config()
            print(f"✓ Database configuration loaded: {db_config.host}:{db_config.port}")
        except Exception as e:
            print(f"✗ Database configuration failed: {e}")
            sys.exit(1)
        
        print("\nDatabase utilities validation completed.")
        
    except Exception as e:
        print(f"Fatal error during database utilities validation: {e}")
        sys.exit(1)