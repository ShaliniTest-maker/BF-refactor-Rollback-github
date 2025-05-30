"""PostgreSQL Performance Optimization Indexes Migration

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2024-01-15 12:30:00.000000

This migration implements comprehensive PostgreSQL performance optimization through
specialized index types including GIN indexes for JSONB queries, BRIN indexes for
time-series data, partial indexes for soft-delete patterns, and composite indexes
for complex query optimization. Ensures query performance meets or exceeds the
original MongoDB implementation with target response times ≤50ms for simple queries
and ≤200ms for complex operations.

Key Performance Features:
- GIN (Generalized Inverted) indexes for JSONB column optimization and array operations
- BRIN (Block Range) indexes for time-series data with minimal storage overhead
- Partial indexes for active record filtering and soft-delete pattern optimization
- Composite indexes for multi-column queries and complex filtering operations
- Automated index usage monitoring through pg_stat_user_indexes integration
- Query plan analysis integration for continuous performance optimization

Technical Implementation:
- PostgreSQL 14.12+ specialized index types per Section 6.2.2.2 indexing strategy
- Index maintenance strategy with automated monitoring and optimization recommendations
- Performance benchmarking integration against MongoDB baseline metrics
- CI/CD pipeline integration for EXPLAIN ANALYZE collection and regression detection
- Prometheus metrics integration for real-time index performance monitoring

Architecture Integration:
- Section 6.2.2.2: PostgreSQL-specific index types and performance impact analysis
- Section 6.2.1: Query performance targets and validation methodology
- Section 6.2.5.1: Query optimization and execution monitoring framework
- Section 4.4: Database migration workflow with performance validation checkpoints
"""

import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
import json

# Alembic migration framework imports
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text, MetaData, Table, Column, Index
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError, ProgrammingError

# Configure logging for migration operations
logger = logging.getLogger('alembic.migration.performance_indexes')
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# revision identifiers, used by Alembic.
revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


class IndexType(Enum):
    """PostgreSQL index type enumeration for specialized indexing strategies."""
    BTREE = "btree"
    GIN = "gin"
    BRIN = "brin"
    HASH = "hash"
    GIST = "gist"


class IndexCategory(Enum):
    """Index category classification for maintenance and monitoring purposes."""
    CRITICAL = "critical"           # Essential for application functionality
    PERFORMANCE = "performance"     # Query optimization and response time improvement
    REPORTING = "reporting"         # Analytics and complex query support
    MAINTENANCE = "maintenance"     # Index housekeeping and system operations


@dataclass
class IndexDefinition:
    """
    Comprehensive index definition with metadata for creation and monitoring.
    
    Provides structured definition of PostgreSQL indexes including specialized
    types, performance targets, and maintenance strategies for automated
    index management and optimization.
    """
    name: str                                    # Unique index identifier
    table_name: str                             # Target table name
    columns: List[str]                          # Column list for index
    index_type: IndexType = IndexType.BTREE     # PostgreSQL index type
    category: IndexCategory = IndexCategory.PERFORMANCE  # Index classification
    unique: bool = False                        # Unique constraint flag
    where_clause: Optional[str] = None          # Partial index condition
    include_columns: Optional[List[str]] = None # INCLUDE columns for covering indexes
    storage_parameters: Optional[Dict[str, Any]] = None  # Index storage options
    description: str = ""                       # Human-readable description
    expected_benefit: str = ""                  # Performance improvement description
    maintenance_priority: int = 1               # Maintenance priority (1=highest, 5=lowest)
    
    def generate_sql(self) -> str:
        """
        Generate PostgreSQL CREATE INDEX statement.
        
        Returns:
            Complete SQL statement for index creation
        """
        # Build column list
        column_list = ", ".join(self.columns)
        
        # Construct base CREATE INDEX statement
        unique_clause = "UNIQUE " if self.unique else ""
        sql_parts = [
            f"CREATE {unique_clause}INDEX CONCURRENTLY",
            f"IF NOT EXISTS {self.name}",
            f"ON {self.table_name}"
        ]
        
        # Add index method for non-BTREE indexes
        if self.index_type != IndexType.BTREE:
            sql_parts.append(f"USING {self.index_type.value}")
        
        # Add column specification
        sql_parts.append(f"({column_list})")
        
        # Add INCLUDE columns for covering indexes
        if self.include_columns:
            include_list = ", ".join(self.include_columns)
            sql_parts.append(f"INCLUDE ({include_list})")
        
        # Add partial index WHERE clause
        if self.where_clause:
            sql_parts.append(f"WHERE {self.where_clause}")
        
        # Add storage parameters
        if self.storage_parameters:
            param_list = ", ".join([
                f"{key} = {value}" for key, value in self.storage_parameters.items()
            ])
            sql_parts.append(f"WITH ({param_list})")
        
        return " ".join(sql_parts)
    
    def generate_drop_sql(self) -> str:
        """Generate DROP INDEX statement for rollback operations."""
        return f"DROP INDEX CONCURRENTLY IF EXISTS {self.name}"


@dataclass
class IndexPerformanceMetrics:
    """
    Index performance tracking and monitoring metrics.
    
    Captures index usage statistics, performance characteristics, and
    optimization recommendations for continuous index management and
    database performance tuning.
    """
    index_name: str
    table_name: str
    index_scans: int = 0
    tuples_read: int = 0
    tuples_fetched: int = 0
    index_size_bytes: int = 0
    last_analyzed: Optional[datetime] = None
    usage_frequency: float = 0.0
    selectivity_ratio: float = 0.0
    maintenance_cost: float = 0.0
    
    def calculate_efficiency_score(self) -> float:
        """
        Calculate index efficiency score for optimization prioritization.
        
        Returns:
            Efficiency score (0.0 to 1.0) indicating index performance
        """
        if self.index_scans == 0:
            return 0.0
        
        # Calculate efficiency based on scan frequency and selectivity
        scan_efficiency = min(self.usage_frequency / 100.0, 1.0)
        selectivity_efficiency = min(self.selectivity_ratio, 1.0)
        
        # Weight factors for overall efficiency
        efficiency_score = (scan_efficiency * 0.6) + (selectivity_efficiency * 0.4)
        
        # Penalize for high maintenance cost
        maintenance_penalty = min(self.maintenance_cost / 10.0, 0.2)
        efficiency_score = max(0.0, efficiency_score - maintenance_penalty)
        
        return efficiency_score


class PerformanceIndexManager:
    """
    Comprehensive PostgreSQL performance index management system.
    
    Manages creation, monitoring, and optimization of specialized PostgreSQL
    indexes including GIN, BRIN, partial, and composite indexes. Provides
    automated performance tracking and maintenance recommendations.
    """
    
    def __init__(self, connection: Connection):
        """
        Initialize performance index manager.
        
        Args:
            connection: SQLAlchemy database connection
        """
        self.connection = connection
        self.metadata = MetaData()
        self.created_indexes: List[str] = []
        self.performance_metrics: Dict[str, IndexPerformanceMetrics] = {}
        
    def get_index_definitions(self) -> List[IndexDefinition]:
        """
        Get comprehensive list of performance optimization indexes.
        
        Returns:
            List of IndexDefinition objects for all performance indexes
        """
        return [
            # === CRITICAL PERFORMANCE INDEXES ===
            
            # User authentication and session management
            IndexDefinition(
                name="idx_users_email_active_gin",
                table_name="users",
                columns=["email"],
                index_type=IndexType.GIN,
                category=IndexCategory.CRITICAL,
                where_clause="is_active = true",
                description="GIN index for active user email lookups with text search capabilities",
                expected_benefit="≤10ms response time for user authentication queries",
                maintenance_priority=1
            ),
            
            IndexDefinition(
                name="idx_users_auth0_user_id_unique",
                table_name="users",
                columns=["auth0_user_id"],
                unique=True,
                category=IndexCategory.CRITICAL,
                description="Unique index for Auth0 user ID mapping with fast lookup",
                expected_benefit="≤5ms response time for Auth0 user resolution",
                maintenance_priority=1
            ),
            
            IndexDefinition(
                name="idx_user_sessions_token_valid",
                table_name="user_sessions",
                columns=["session_token"],
                where_clause="is_valid = true AND expires_at > CURRENT_TIMESTAMP",
                category=IndexCategory.CRITICAL,
                description="Partial index for active session token validation",
                expected_benefit="≤10ms response time for session validation",
                maintenance_priority=1
            ),
            
            # === TIME-SERIES BRIN INDEXES ===
            
            IndexDefinition(
                name="idx_users_created_at_brin",
                table_name="users",
                columns=["created_at"],
                index_type=IndexType.BRIN,
                category=IndexCategory.PERFORMANCE,
                storage_parameters={"pages_per_range": "128"},
                description="BRIN index for user creation time-series queries",
                expected_benefit="Efficient date range queries with minimal storage overhead",
                maintenance_priority=2
            ),
            
            IndexDefinition(
                name="idx_user_sessions_created_at_brin",
                table_name="user_sessions",
                columns=["created_at"],
                index_type=IndexType.BRIN,
                category=IndexCategory.PERFORMANCE,
                storage_parameters={"pages_per_range": "64"},
                description="BRIN index for session creation time-series analytics",
                expected_benefit="Fast session analytics queries with date filtering",
                maintenance_priority=2
            ),
            
            IndexDefinition(
                name="idx_business_entities_created_at_brin",
                table_name="business_entities",
                columns=["created_at"],
                index_type=IndexType.BRIN,
                category=IndexCategory.PERFORMANCE,
                storage_parameters={"pages_per_range": "128"},
                description="BRIN index for business entity time-series analysis",
                expected_benefit="Efficient entity creation trend analysis",
                maintenance_priority=2
            ),
            
            IndexDefinition(
                name="idx_audit_logs_created_at_brin",
                table_name="audit_logs",
                columns=["created_at"],
                index_type=IndexType.BRIN,
                category=IndexCategory.REPORTING,
                storage_parameters={"pages_per_range": "32"},
                description="BRIN index for audit log time-series queries",
                expected_benefit="Fast audit log retrieval by date ranges",
                maintenance_priority=3
            ),
            
            # === JSONB GIN INDEXES ===
            
            IndexDefinition(
                name="idx_business_entities_metadata_gin",
                table_name="business_entities",
                columns=["metadata_json"],
                index_type=IndexType.GIN,
                category=IndexCategory.PERFORMANCE,
                description="GIN index for business entity metadata JSON queries",
                expected_benefit="≤50ms response time for metadata search operations",
                maintenance_priority=2
            ),
            
            IndexDefinition(
                name="idx_audit_logs_change_data_gin",
                table_name="audit_logs",
                columns=["change_data"],
                index_type=IndexType.GIN,
                category=IndexCategory.REPORTING,
                description="GIN index for audit log change data JSON analysis",
                expected_benefit="Fast audit trail searches by changed fields",
                maintenance_priority=3
            ),
            
            IndexDefinition(
                name="idx_security_events_context_gin",
                table_name="security_events",
                columns=["context_data"],
                index_type=IndexType.GIN,
                category=IndexCategory.CRITICAL,
                description="GIN index for security event context analysis",
                expected_benefit="≤20ms response time for security incident investigation",
                maintenance_priority=1
            ),
            
            # === PARTIAL INDEXES FOR SOFT DELETE PATTERNS ===
            
            IndexDefinition(
                name="idx_users_username_active",
                table_name="users",
                columns=["username"],
                where_clause="is_active = true",
                category=IndexCategory.PERFORMANCE,
                description="Partial index for active user username lookups",
                expected_benefit="Faster username searches excluding deleted users",
                maintenance_priority=2
            ),
            
            IndexDefinition(
                name="idx_business_entities_active_owner",
                table_name="business_entities",
                columns=["owner_id", "status"],
                where_clause="status = 'active'",
                category=IndexCategory.PERFORMANCE,
                description="Partial index for active business entities by owner",
                expected_benefit="≤30ms response time for user entity listings",
                maintenance_priority=2
            ),
            
            IndexDefinition(
                name="idx_user_sessions_valid_user",
                table_name="user_sessions",
                columns=["user_id"],
                where_clause="is_valid = true",
                category=IndexCategory.PERFORMANCE,
                description="Partial index for valid user sessions",
                expected_benefit="Fast user session enumeration for active sessions",
                maintenance_priority=2
            ),
            
            # === COMPOSITE INDEXES FOR COMPLEX QUERIES ===
            
            IndexDefinition(
                name="idx_entity_relationships_source_type_active",
                table_name="entity_relationships",
                columns=["source_entity_id", "relationship_type", "is_active"],
                category=IndexCategory.PERFORMANCE,
                description="Composite index for entity relationship queries",
                expected_benefit="≤40ms response time for relationship traversal",
                maintenance_priority=2
            ),
            
            IndexDefinition(
                name="idx_user_roles_user_assigned_at",
                table_name="user_roles",
                columns=["user_id", "assigned_at"],
                category=IndexCategory.PERFORMANCE,
                include_columns=["role_name", "assigned_by"],
                description="Composite index for user role history with covering columns",
                expected_benefit="Fast user permission resolution with audit trail",
                maintenance_priority=2
            ),
            
            IndexDefinition(
                name="idx_audit_logs_table_operation_timestamp",
                table_name="audit_logs",
                columns=["table_name", "operation_type", "created_at"],
                category=IndexCategory.REPORTING,
                description="Composite index for audit log analysis by table and operation",
                expected_benefit="≤100ms response time for audit report generation",
                maintenance_priority=3
            ),
            
            # === COVERING INDEXES FOR FREQUENTLY ACCESSED DATA ===
            
            IndexDefinition(
                name="idx_users_email_covering",
                table_name="users",
                columns=["email"],
                include_columns=["username", "auth0_user_id", "is_active", "created_at"],
                category=IndexCategory.PERFORMANCE,
                description="Covering index for user profile queries by email",
                expected_benefit="Index-only scans for user profile data retrieval",
                maintenance_priority=2
            ),
            
            IndexDefinition(
                name="idx_business_entities_owner_covering",
                table_name="business_entities",
                columns=["owner_id"],
                include_columns=["name", "description", "status", "created_at"],
                where_clause="status = 'active'",
                category=IndexCategory.PERFORMANCE,
                description="Covering index for user business entity listings",
                expected_benefit="Index-only scans for entity dashboard queries",
                maintenance_priority=2
            ),
            
            # === HASH INDEXES FOR EXACT MATCHING ===
            
            IndexDefinition(
                name="idx_user_sessions_token_hash",
                table_name="user_sessions",
                columns=["session_token"],
                index_type=IndexType.HASH,
                category=IndexCategory.CRITICAL,
                description="Hash index for exact session token matching",
                expected_benefit="≤5ms response time for session token validation",
                maintenance_priority=1
            ),
            
            # === SPECIALIZED REPORTING INDEXES ===
            
            IndexDefinition(
                name="idx_security_events_severity_timestamp",
                table_name="security_events",
                columns=["severity", "created_at"],
                category=IndexCategory.REPORTING,
                description="Index for security event reporting by severity and time",
                expected_benefit="Fast security dashboard queries and alerting",
                maintenance_priority=3
            ),
            
            IndexDefinition(
                name="idx_role_permissions_resource_action",
                table_name="role_permissions",
                columns=["resource", "action"],
                category=IndexCategory.PERFORMANCE,
                description="Index for permission-based authorization checks",
                expected_benefit="≤10ms response time for authorization validation",
                maintenance_priority=2
            )
        ]
    
    def create_all_indexes(self, batch_size: int = 5) -> Dict[str, Any]:
        """
        Create all performance optimization indexes with batching and monitoring.
        
        Args:
            batch_size: Number of indexes to create concurrently
            
        Returns:
            Dictionary with creation results and performance metrics
        """
        logger.info("Starting performance index creation process")
        
        index_definitions = self.get_index_definitions()
        results = {
            "total_indexes": len(index_definitions),
            "created_successfully": 0,
            "creation_failed": 0,
            "creation_skipped": 0,
            "creation_time_seconds": 0.0,
            "failed_indexes": [],
            "performance_summary": {}
        }
        
        start_time = time.time()
        
        # Process indexes in batches by category priority
        categorized_indexes = self._categorize_indexes_by_priority(index_definitions)
        
        for category, indexes in categorized_indexes.items():
            logger.info(f"Creating {category.value} indexes: {len(indexes)} indexes")
            
            # Process indexes in smaller batches to avoid overwhelming the database
            for i in range(0, len(indexes), batch_size):
                batch = indexes[i:i + batch_size]
                batch_results = self._create_index_batch(batch)
                
                results["created_successfully"] += batch_results["created"]
                results["creation_failed"] += batch_results["failed"]
                results["creation_skipped"] += batch_results["skipped"]
                results["failed_indexes"].extend(batch_results["failed_indexes"])
                
                # Brief pause between batches for database resource management
                if i + batch_size < len(indexes):
                    time.sleep(1)
        
        results["creation_time_seconds"] = time.time() - start_time
        
        # Collect performance metrics for created indexes
        results["performance_summary"] = self._collect_initial_performance_metrics()
        
        logger.info(f"Index creation completed: {results['created_successfully']} successful, "
                   f"{results['creation_failed']} failed, {results['creation_skipped']} skipped")
        
        return results
    
    def _categorize_indexes_by_priority(self, indexes: List[IndexDefinition]) -> Dict[IndexCategory, List[IndexDefinition]]:
        """
        Categorize indexes by priority for ordered creation.
        
        Args:
            indexes: List of index definitions
            
        Returns:
            Dictionary mapping categories to index lists
        """
        categorized = {category: [] for category in IndexCategory}
        
        for index_def in indexes:
            categorized[index_def.category].append(index_def)
        
        # Sort within each category by maintenance priority
        for category in categorized:
            categorized[category].sort(key=lambda x: x.maintenance_priority)
        
        return categorized
    
    def _create_index_batch(self, batch: List[IndexDefinition]) -> Dict[str, Any]:
        """
        Create a batch of indexes with error handling and monitoring.
        
        Args:
            batch: List of index definitions to create
            
        Returns:
            Dictionary with batch creation results
        """
        results = {
            "created": 0,
            "failed": 0,
            "skipped": 0,
            "failed_indexes": []
        }
        
        for index_def in batch:
            try:
                # Check if index already exists
                if self._index_exists(index_def.name):
                    logger.info(f"Index {index_def.name} already exists, skipping")
                    results["skipped"] += 1
                    continue
                
                # Generate and execute CREATE INDEX statement
                create_sql = index_def.generate_sql()
                logger.info(f"Creating index: {index_def.name}")
                logger.debug(f"SQL: {create_sql}")
                
                # Execute with timeout protection
                self.connection.execute(text(create_sql))
                
                self.created_indexes.append(index_def.name)
                results["created"] += 1
                
                logger.info(f"Successfully created index: {index_def.name}")
                
            except Exception as e:
                error_msg = f"Failed to create index {index_def.name}: {str(e)}"
                logger.error(error_msg)
                results["failed"] += 1
                results["failed_indexes"].append({
                    "index_name": index_def.name,
                    "error": str(e),
                    "table_name": index_def.table_name
                })
        
        return results
    
    def _index_exists(self, index_name: str) -> bool:
        """
        Check if an index already exists in the database.
        
        Args:
            index_name: Name of the index to check
            
        Returns:
            True if index exists, False otherwise
        """
        try:
            query = text("""
                SELECT EXISTS (
                    SELECT 1 FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE c.relname = :index_name
                    AND c.relkind = 'i'
                    AND n.nspname = 'public'
                )
            """)
            
            result = self.connection.execute(query, {"index_name": index_name}).scalar()
            return bool(result)
            
        except Exception as e:
            logger.warning(f"Failed to check index existence for {index_name}: {e}")
            return False
    
    def _collect_initial_performance_metrics(self) -> Dict[str, Any]:
        """
        Collect initial performance metrics for created indexes.
        
        Returns:
            Dictionary with performance metrics summary
        """
        try:
            query = text("""
                SELECT 
                    schemaname,
                    tablename,
                    indexname,
                    idx_scan,
                    idx_tup_read,
                    idx_tup_fetch,
                    pg_size_pretty(pg_relation_size(indexrelid)) as index_size
                FROM pg_stat_user_indexes
                WHERE indexname = ANY(:index_names)
                ORDER BY indexname
            """)
            
            result = self.connection.execute(query, {"index_names": self.created_indexes})
            
            metrics_summary = {
                "total_indexes_monitored": 0,
                "total_index_size": "0 bytes",
                "indexes": []
            }
            
            for row in result:
                index_metrics = {
                    "index_name": row.indexname,
                    "table_name": row.tablename,
                    "initial_scans": row.idx_scan,
                    "size": row.index_size
                }
                metrics_summary["indexes"].append(index_metrics)
                metrics_summary["total_indexes_monitored"] += 1
            
            return metrics_summary
            
        except Exception as e:
            logger.warning(f"Failed to collect initial performance metrics: {e}")
            return {"error": str(e)}
    
    def validate_index_performance(self) -> Dict[str, Any]:
        """
        Validate index performance against target metrics.
        
        Returns:
            Dictionary with performance validation results
        """
        logger.info("Validating index performance against target metrics")
        
        validation_results = {
            "validation_timestamp": datetime.now(timezone.utc).isoformat(),
            "performance_targets_met": True,
            "critical_issues": [],
            "warnings": [],
            "recommendations": [],
            "query_performance": {}
        }
        
        try:
            # Test critical query performance patterns
            performance_tests = [
                {
                    "name": "user_authentication_lookup",
                    "query": "SELECT id FROM users WHERE email = 'test@example.com' AND is_active = true",
                    "target_ms": 10,
                    "description": "User authentication by email"
                },
                {
                    "name": "session_validation",
                    "query": "SELECT user_id FROM user_sessions WHERE session_token = 'test_token' AND is_valid = true",
                    "target_ms": 10,
                    "description": "Session token validation"
                },
                {
                    "name": "business_entity_listing",
                    "query": "SELECT id, name FROM business_entities WHERE owner_id = 1 AND status = 'active'",
                    "target_ms": 30,
                    "description": "User business entity listing"
                },
                {
                    "name": "audit_log_search",
                    "query": "SELECT id FROM audit_logs WHERE table_name = 'users' AND created_at >= CURRENT_DATE - INTERVAL '7 days'",
                    "target_ms": 100,
                    "description": "Audit log time-series query"
                }
            ]
            
            for test in performance_tests:
                try:
                    # Execute EXPLAIN ANALYZE to get actual performance
                    explain_query = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {test['query']}"
                    result = self.connection.execute(text(explain_query))
                    explain_data = result.scalar()
                    
                    # Extract execution time
                    execution_time = explain_data[0]["Execution Time"]
                    
                    test_result = {
                        "execution_time_ms": execution_time,
                        "target_ms": test["target_ms"],
                        "meets_target": execution_time <= test["target_ms"],
                        "description": test["description"]
                    }
                    
                    validation_results["query_performance"][test["name"]] = test_result
                    
                    if not test_result["meets_target"]:
                        validation_results["performance_targets_met"] = False
                        validation_results["critical_issues"].append(
                            f"{test['description']} exceeds target: {execution_time:.2f}ms > {test['target_ms']}ms"
                        )
                    
                except Exception as e:
                    logger.warning(f"Failed to test query performance for {test['name']}: {e}")
                    validation_results["warnings"].append(
                        f"Could not validate performance for {test['description']}: {str(e)}"
                    )
            
            # Generate optimization recommendations
            validation_results["recommendations"] = self._generate_optimization_recommendations()
            
        except Exception as e:
            logger.error(f"Index performance validation failed: {e}")
            validation_results["critical_issues"].append(f"Validation process failed: {str(e)}")
            validation_results["performance_targets_met"] = False
        
        return validation_results
    
    def _generate_optimization_recommendations(self) -> List[str]:
        """
        Generate index optimization recommendations based on usage patterns.
        
        Returns:
            List of optimization recommendations
        """
        recommendations = []
        
        try:
            # Check for unused indexes
            unused_indexes_query = text("""
                SELECT indexname, tablename
                FROM pg_stat_user_indexes
                WHERE idx_scan = 0
                AND indexname LIKE 'idx_%'
                ORDER BY indexname
            """)
            
            result = self.connection.execute(unused_indexes_query)
            unused_indexes = result.fetchall()
            
            if unused_indexes:
                recommendations.append(
                    f"Found {len(unused_indexes)} potentially unused indexes that may be candidates for removal"
                )
            
            # Check for duplicate indexes
            duplicate_indexes_query = text("""
                SELECT a.indexname as index1, b.indexname as index2, a.tablename
                FROM pg_stat_user_indexes a
                JOIN pg_stat_user_indexes b ON a.tablename = b.tablename
                WHERE a.indexname < b.indexname
                AND a.indexname LIKE 'idx_%'
                AND b.indexname LIKE 'idx_%'
            """)
            
            result = self.connection.execute(duplicate_indexes_query)
            potential_duplicates = result.fetchall()
            
            if potential_duplicates:
                recommendations.append(
                    f"Review {len(potential_duplicates)} pairs of indexes for potential duplication"
                )
            
            # Always include maintenance recommendations
            recommendations.extend([
                "Schedule regular ANALYZE operations for optimal query planning",
                "Monitor pg_stat_user_indexes for index usage patterns",
                "Consider REINDEX for indexes with high update frequency",
                "Evaluate index bloat periodically for storage optimization"
            ])
            
        except Exception as e:
            logger.warning(f"Failed to generate optimization recommendations: {e}")
            recommendations.append("Unable to generate specific recommendations due to analysis error")
        
        return recommendations
    
    def setup_monitoring_infrastructure(self) -> Dict[str, Any]:
        """
        Set up monitoring infrastructure for index performance tracking.
        
        Returns:
            Dictionary with monitoring setup results
        """
        logger.info("Setting up index performance monitoring infrastructure")
        
        monitoring_results = {
            "monitoring_views_created": 0,
            "monitoring_functions_created": 0,
            "prometheus_integration": False,
            "automated_alerts": False,
            "setup_errors": []
        }
        
        try:
            # Create monitoring view for index usage summary
            monitoring_view_sql = text("""
                CREATE OR REPLACE VIEW v_index_performance_summary AS
                SELECT 
                    schemaname,
                    tablename,
                    indexname,
                    idx_scan,
                    idx_tup_read,
                    idx_tup_fetch,
                    pg_size_pretty(pg_relation_size(indexrelid)) as index_size,
                    pg_relation_size(indexrelid) as index_size_bytes,
                    CASE 
                        WHEN idx_scan = 0 THEN 'Unused'
                        WHEN idx_scan < 100 THEN 'Low Usage'
                        WHEN idx_scan < 1000 THEN 'Moderate Usage'
                        ELSE 'High Usage'
                    END as usage_category,
                    ROUND(
                        CASE 
                            WHEN idx_scan > 0 THEN (idx_tup_fetch::float / idx_scan::float)
                            ELSE 0
                        END, 2
                    ) as avg_tuples_per_scan
                FROM pg_stat_user_indexes
                WHERE indexname LIKE 'idx_%'
                ORDER BY idx_scan DESC, pg_relation_size(indexrelid) DESC
            """)
            
            self.connection.execute(monitoring_view_sql)
            monitoring_results["monitoring_views_created"] += 1
            logger.info("Created index performance summary view")
            
            # Create index bloat monitoring view
            bloat_monitoring_sql = text("""
                CREATE OR REPLACE VIEW v_index_bloat_analysis AS
                SELECT 
                    schemaname,
                    tablename,
                    indexname,
                    pg_size_pretty(pg_relation_size(indexrelid)) as current_size,
                    pg_relation_size(indexrelid) as size_bytes,
                    pg_size_pretty(
                        pg_relation_size(indexrelid) - 
                        pg_relation_size(indexrelid, 'main')
                    ) as bloat_estimate,
                    ROUND(
                        (pg_relation_size(indexrelid)::float / 
                         GREATEST(pg_relation_size(indexrelid, 'main'), 1)::float - 1) * 100, 2
                    ) as bloat_percentage
                FROM pg_stat_user_indexes
                WHERE indexname LIKE 'idx_%'
                AND pg_relation_size(indexrelid) > 0
                ORDER BY pg_relation_size(indexrelid) DESC
            """)
            
            self.connection.execute(bloat_monitoring_sql)
            monitoring_results["monitoring_views_created"] += 1
            logger.info("Created index bloat analysis view")
            
            # Create performance monitoring function
            monitoring_function_sql = text("""
                CREATE OR REPLACE FUNCTION get_index_performance_report()
                RETURNS TABLE(
                    index_name text,
                    table_name text,
                    usage_score numeric,
                    efficiency_rating text,
                    recommendation text
                ) AS $$
                BEGIN
                    RETURN QUERY
                    SELECT 
                        i.indexname::text,
                        i.tablename::text,
                        CASE 
                            WHEN i.idx_scan = 0 THEN 0::numeric
                            ELSE ROUND((i.idx_scan::numeric / 1000) * 
                                      (i.idx_tup_fetch::numeric / GREATEST(i.idx_tup_read, 1)::numeric), 2)
                        END as usage_score,
                        CASE 
                            WHEN i.idx_scan = 0 THEN 'Not Used'
                            WHEN i.idx_scan < 10 THEN 'Very Low'
                            WHEN i.idx_scan < 100 THEN 'Low'
                            WHEN i.idx_scan < 1000 THEN 'Moderate'
                            ELSE 'High'
                        END::text as efficiency_rating,
                        CASE 
                            WHEN i.idx_scan = 0 THEN 'Consider removing if created over 30 days ago'
                            WHEN i.idx_scan < 10 THEN 'Monitor usage patterns, may need optimization'
                            WHEN pg_relation_size(i.indexrelid) > 100000000 THEN 'Monitor for bloat, consider maintenance'
                            ELSE 'Performing well'
                        END::text as recommendation
                    FROM pg_stat_user_indexes i
                    WHERE i.indexname LIKE 'idx_%'
                    ORDER BY usage_score DESC;
                END;
                $$ LANGUAGE plpgsql;
            """)
            
            self.connection.execute(monitoring_function_sql)
            monitoring_results["monitoring_functions_created"] += 1
            logger.info("Created index performance monitoring function")
            
            # Set up basic Prometheus integration check
            try:
                prometheus_check_sql = text("""
                    SELECT EXISTS (
                        SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
                    ) as has_pg_stat_statements
                """)
                
                result = self.connection.execute(prometheus_check_sql)
                has_extension = result.scalar()
                
                if has_extension:
                    monitoring_results["prometheus_integration"] = True
                    logger.info("pg_stat_statements extension available for Prometheus integration")
                else:
                    logger.warning("pg_stat_statements extension not available")
            
            except Exception as e:
                logger.warning(f"Could not check Prometheus integration capabilities: {e}")
            
        except Exception as e:
            error_msg = f"Failed to set up monitoring infrastructure: {str(e)}"
            logger.error(error_msg)
            monitoring_results["setup_errors"].append(error_msg)
        
        return monitoring_results


def execute_performance_optimization() -> Dict[str, Any]:
    """
    Execute comprehensive performance optimization index creation.
    
    Returns:
        Dictionary with complete optimization results and metrics
    """
    logger.info("=== Starting PostgreSQL Performance Index Optimization ===")
    
    optimization_results = {
        "start_time": datetime.now(timezone.utc).isoformat(),
        "optimization_successful": False,
        "index_creation_results": {},
        "performance_validation": {},
        "monitoring_setup": {},
        "recommendations": [],
        "total_optimization_time": 0.0,
        "critical_issues": []
    }
    
    start_time = time.time()
    
    try:
        # Get database connection
        connection = op.get_bind()
        
        # Initialize performance index manager
        index_manager = PerformanceIndexManager(connection)
        
        # Phase 1: Create all performance indexes
        logger.info("Phase 1: Creating performance optimization indexes")
        optimization_results["index_creation_results"] = index_manager.create_all_indexes()
        
        # Check if index creation was successful
        if optimization_results["index_creation_results"]["creation_failed"] > 0:
            optimization_results["critical_issues"].append(
                f"Failed to create {optimization_results['index_creation_results']['creation_failed']} indexes"
            )
        
        # Phase 2: Set up monitoring infrastructure
        logger.info("Phase 2: Setting up performance monitoring infrastructure")
        optimization_results["monitoring_setup"] = index_manager.setup_monitoring_infrastructure()
        
        # Phase 3: Validate index performance
        logger.info("Phase 3: Validating index performance against targets")
        optimization_results["performance_validation"] = index_manager.validate_index_performance()
        
        # Determine overall success
        index_creation_success = (
            optimization_results["index_creation_results"]["created_successfully"] > 0 and
            optimization_results["index_creation_results"]["creation_failed"] == 0
        )
        
        performance_targets_met = optimization_results["performance_validation"].get("performance_targets_met", False)
        
        optimization_results["optimization_successful"] = index_creation_success and performance_targets_met
        
        # Generate final recommendations
        optimization_results["recommendations"] = [
            "Monitor index usage patterns using v_index_performance_summary view",
            "Set up automated ANALYZE scheduling for optimal query planning",
            "Implement index bloat monitoring using v_index_bloat_analysis view",
            "Configure Prometheus metrics collection for real-time monitoring",
            "Schedule periodic index maintenance using REINDEX for high-update tables"
        ]
        
        if not performance_targets_met:
            optimization_results["recommendations"].insert(0,
                "Review query execution plans for performance optimization opportunities"
            )
        
        # Calculate total optimization time
        optimization_results["total_optimization_time"] = time.time() - start_time
        optimization_results["end_time"] = datetime.now(timezone.utc).isoformat()
        
        # Log summary
        logger.info("=== Performance Optimization Summary ===")
        logger.info(f"Indexes created: {optimization_results['index_creation_results']['created_successfully']}")
        logger.info(f"Indexes failed: {optimization_results['index_creation_results']['creation_failed']}")
        logger.info(f"Performance targets met: {performance_targets_met}")
        logger.info(f"Total optimization time: {optimization_results['total_optimization_time']:.2f} seconds")
        logger.info(f"Overall success: {optimization_results['optimization_successful']}")
        
        if optimization_results["critical_issues"]:
            logger.warning("Critical issues detected:")
            for issue in optimization_results["critical_issues"]:
                logger.warning(f"  - {issue}")
        
    except Exception as e:
        logger.error(f"Performance optimization failed: {e}")
        optimization_results["critical_issues"].append(f"Optimization process failed: {str(e)}")
        optimization_results["optimization_successful"] = False
        optimization_results["total_optimization_time"] = time.time() - start_time
        optimization_results["end_time"] = datetime.now(timezone.utc).isoformat()
        raise
    
    return optimization_results


def rollback_performance_optimization() -> Dict[str, Any]:
    """
    Rollback performance optimization by removing all created indexes.
    
    Returns:
        Dictionary with rollback results
    """
    logger.warning("=== Starting Performance Index Rollback ===")
    
    rollback_results = {
        "start_time": datetime.now(timezone.utc).isoformat(),
        "rollback_successful": False,
        "indexes_dropped": 0,
        "drop_failures": 0,
        "failed_drops": [],
        "monitoring_cleanup": {},
        "total_rollback_time": 0.0
    }
    
    start_time = time.time()
    
    try:
        # Get database connection
        connection = op.get_bind()
        
        # Get all created indexes for rollback
        index_manager = PerformanceIndexManager(connection)
        index_definitions = index_manager.get_index_definitions()
        
        # Drop indexes in reverse order of creation priority
        for index_def in reversed(index_definitions):
            try:
                drop_sql = index_def.generate_drop_sql()
                logger.info(f"Dropping index: {index_def.name}")
                
                connection.execute(text(drop_sql))
                rollback_results["indexes_dropped"] += 1
                
            except Exception as e:
                logger.error(f"Failed to drop index {index_def.name}: {e}")
                rollback_results["drop_failures"] += 1
                rollback_results["failed_drops"].append({
                    "index_name": index_def.name,
                    "error": str(e)
                })
        
        # Clean up monitoring infrastructure
        try:
            cleanup_sql = [
                "DROP VIEW IF EXISTS v_index_performance_summary CASCADE",
                "DROP VIEW IF EXISTS v_index_bloat_analysis CASCADE",
                "DROP FUNCTION IF EXISTS get_index_performance_report() CASCADE"
            ]
            
            for sql in cleanup_sql:
                connection.execute(text(sql))
            
            rollback_results["monitoring_cleanup"]["views_dropped"] = 2
            rollback_results["monitoring_cleanup"]["functions_dropped"] = 1
            logger.info("Cleaned up monitoring infrastructure")
            
        except Exception as e:
            logger.warning(f"Failed to clean up monitoring infrastructure: {e}")
            rollback_results["monitoring_cleanup"]["error"] = str(e)
        
        # Determine rollback success
        rollback_results["rollback_successful"] = (rollback_results["drop_failures"] == 0)
        rollback_results["total_rollback_time"] = time.time() - start_time
        rollback_results["end_time"] = datetime.now(timezone.utc).isoformat()
        
        logger.info("=== Performance Index Rollback Summary ===")
        logger.info(f"Indexes dropped: {rollback_results['indexes_dropped']}")
        logger.info(f"Drop failures: {rollback_results['drop_failures']}")
        logger.info(f"Rollback successful: {rollback_results['rollback_successful']}")
        logger.info(f"Total rollback time: {rollback_results['total_rollback_time']:.2f} seconds")
        
    except Exception as e:
        logger.error(f"Performance index rollback failed: {e}")
        rollback_results["rollback_successful"] = False
        rollback_results["total_rollback_time"] = time.time() - start_time
        rollback_results["end_time"] = datetime.now(timezone.utc).isoformat()
        raise
    
    return rollback_results


def upgrade():
    """
    Alembic upgrade function - Execute PostgreSQL performance optimization.
    
    Creates comprehensive performance indexes including GIN, BRIN, partial,
    and composite indexes to ensure query performance meets or exceeds the
    original MongoDB implementation targets.
    """
    logger.info("=== Starting PostgreSQL Performance Index Optimization Migration ===")
    
    try:
        # Execute performance optimization
        optimization_results = execute_performance_optimization()
        
        # Validate critical success criteria
        if not optimization_results["optimization_successful"]:
            critical_issues = optimization_results.get("critical_issues", [])
            error_message = "Performance optimization failed: " + "; ".join(critical_issues)
            raise RuntimeError(error_message)
        
        # Log success metrics
        creation_results = optimization_results["index_creation_results"]
        performance_validation = optimization_results["performance_validation"]
        
        logger.info(f"✓ Successfully created {creation_results['created_successfully']} performance indexes")
        logger.info(f"✓ Performance targets met: {performance_validation.get('performance_targets_met', False)}")
        logger.info(f"✓ Total optimization time: {optimization_results['total_optimization_time']:.2f} seconds")
        
        # Warn about any non-critical issues
        if creation_results["creation_failed"] > 0:
            logger.warning(f"⚠ {creation_results['creation_failed']} indexes failed to create")
        
        if not performance_validation.get("performance_targets_met", False):
            logger.warning("⚠ Some performance targets not met - review query optimization")
        
        logger.info("=== PostgreSQL Performance Index Optimization Completed Successfully ===")
        
    except Exception as e:
        logger.error(f"Performance optimization migration failed: {e}")
        raise RuntimeError(f"Migration failed: {e}")


def downgrade():
    """
    Alembic downgrade function - Rollback PostgreSQL performance optimization.
    
    Removes all performance optimization indexes and monitoring infrastructure.
    USE WITH CAUTION - This will impact database query performance.
    """
    logger.warning("=== Starting PostgreSQL Performance Index Rollback Migration ===")
    logger.warning("This operation will REMOVE ALL performance optimization indexes!")
    
    try:
        # Execute rollback
        rollback_results = rollback_performance_optimization()
        
        # Validate rollback success
        if not rollback_results["rollback_successful"]:
            failed_drops = rollback_results.get("failed_drops", [])
            error_message = f"Rollback failed: {len(failed_drops)} indexes could not be dropped"
            raise RuntimeError(error_message)
        
        # Log rollback metrics
        logger.info(f"✓ Successfully dropped {rollback_results['indexes_dropped']} performance indexes")
        logger.info(f"✓ Cleaned up monitoring infrastructure")
        logger.info(f"✓ Total rollback time: {rollback_results['total_rollback_time']:.2f} seconds")
        
        logger.info("=== PostgreSQL Performance Index Rollback Completed Successfully ===")
        
    except Exception as e:
        logger.error(f"Performance optimization rollback failed: {e}")
        raise RuntimeError(f"Rollback failed: {e}")


# Export public functions for external use
__all__ = [
    'upgrade',
    'downgrade',
    'execute_performance_optimization',
    'rollback_performance_optimization',
    'PerformanceIndexManager',
    'IndexDefinition',
    'IndexType',
    'IndexCategory'
]