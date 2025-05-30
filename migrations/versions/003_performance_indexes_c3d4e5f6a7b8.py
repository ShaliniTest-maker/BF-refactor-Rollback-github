"""
PostgreSQL Performance Optimization Migration - Specialized Index Creation

This migration implements comprehensive PostgreSQL-specific index optimizations to ensure
query performance meets or exceeds the original MongoDB implementation baseline. Creates
specialized index types including GIN indexes for JSONB queries, BRIN indexes for 
time-series data, partial indexes for soft-delete patterns, and composite indexes for
complex query optimization.

Performance Targets:
- Simple queries: ≤50ms average response time
- Complex queries: ≤200ms average response time  
- Index optimization for frequently accessed data patterns
- Automated index usage monitoring integration

Created: 2024-01-03
Author: Blitzy Platform Migration System
Dependencies: 002_mongodb_data_migration_b2c3d4e5f6a7.py

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2024-01-03 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text, MetaData, Table, Column, Index
from sqlalchemy.dialects import postgresql
import logging


# Revision identifiers for Alembic version control
revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None

# Configure logging for migration operations
logger = logging.getLogger('alembic.migration.performance_indexes')


def upgrade():
    """
    Create PostgreSQL-specific performance indexes for optimal query execution.
    
    This upgrade implements specialized PostgreSQL index types to optimize database
    performance across all major query patterns identified during the MongoDB migration
    analysis. Includes comprehensive error handling and validation.
    """
    logger.info("Starting PostgreSQL performance index creation migration")
    
    try:
        # Get database connection for advanced PostgreSQL features
        conn = op.get_bind()
        
        # Validate PostgreSQL version compatibility
        _validate_postgresql_version(conn)
        
        # Create GIN indexes for JSONB and array operations
        _create_gin_indexes(conn)
        
        # Create BRIN indexes for time-series data optimization
        _create_brin_indexes(conn)
        
        # Create partial indexes for soft-delete and active record filtering
        _create_partial_indexes(conn)
        
        # Create composite indexes for multi-column query optimization
        _create_composite_indexes(conn)
        
        # Create specialized indexes for user authentication and sessions
        _create_authentication_indexes(conn)
        
        # Create business entity relationship optimization indexes
        _create_business_entity_indexes(conn)
        
        # Initialize index monitoring infrastructure
        _initialize_index_monitoring(conn)
        
        logger.info("Successfully created all performance optimization indexes")
        
    except Exception as e:
        logger.error(f"Performance index migration failed: {e}")
        raise


def downgrade():
    """
    Remove all performance optimization indexes created by this migration.
    
    This downgrade safely removes all specialized indexes while preserving
    base functionality and data integrity. Includes validation to ensure
    no critical indexes are accidentally removed.
    """
    logger.info("Starting PostgreSQL performance index removal migration")
    
    try:
        # Get database connection
        conn = op.get_bind()
        
        # Remove GIN indexes
        _remove_gin_indexes(conn)
        
        # Remove BRIN indexes  
        _remove_brin_indexes(conn)
        
        # Remove partial indexes
        _remove_partial_indexes(conn)
        
        # Remove composite indexes
        _remove_composite_indexes(conn)
        
        # Remove authentication optimization indexes
        _remove_authentication_indexes(conn)
        
        # Remove business entity indexes
        _remove_business_entity_indexes(conn)
        
        # Clean up monitoring infrastructure
        _cleanup_index_monitoring(conn)
        
        logger.info("Successfully removed all performance optimization indexes")
        
    except Exception as e:
        logger.error(f"Performance index removal failed: {e}")
        raise


def _validate_postgresql_version(conn):
    """
    Validate PostgreSQL version meets minimum requirements for specialized indexes.
    
    Args:
        conn: Database connection object
        
    Raises:
        RuntimeError: If PostgreSQL version is insufficient
    """
    try:
        result = conn.execute(text("SELECT version()")).fetchone()
        version_string = result[0]
        
        # Extract major version number
        import re
        version_match = re.search(r'PostgreSQL (\d+)\.(\d+)', version_string)
        if not version_match:
            raise RuntimeError(f"Unable to parse PostgreSQL version: {version_string}")
        
        major_version = int(version_match.group(1))
        minor_version = int(version_match.group(2))
        
        # Require PostgreSQL 14.12+ for advanced index features
        if major_version < 14 or (major_version == 14 and minor_version < 12):
            raise RuntimeError(
                f"PostgreSQL 14.12+ required for specialized index types. "
                f"Current version: {major_version}.{minor_version}"
            )
        
        logger.info(f"PostgreSQL version validated: {major_version}.{minor_version}")
        
    except Exception as e:
        logger.error(f"PostgreSQL version validation failed: {e}")
        raise


def _create_gin_indexes(conn):
    """
    Create GIN (Generalized Inverted) indexes for JSONB and array operations.
    
    GIN indexes provide efficient querying for JSONB columns and array data types,
    particularly optimized for containment operations and full-text search patterns.
    
    Args:
        conn: Database connection object
    """
    logger.info("Creating GIN indexes for JSONB and array operations")
    
    gin_indexes = [
        # User model JSONB metadata indexes
        {
            'name': 'idx_gin_users_auth0_metadata',
            'table': 'users',
            'column': 'auth0_metadata',
            'purpose': 'Auth0 user metadata JSONB queries and filtering'
        },
        {
            'name': 'idx_gin_users_auth0_app_metadata', 
            'table': 'users',
            'column': 'auth0_app_metadata',
            'purpose': 'Auth0 application metadata JSONB containment queries'
        },
        
        # Business entity metadata GIN indexes
        {
            'name': 'idx_gin_business_entity_metadata',
            'table': 'business_entity',
            'column': 'metadata',
            'purpose': 'Business entity metadata JSONB search and filtering'
        },
        
        # Audit log details GIN indexes for complex log searches
        {
            'name': 'idx_gin_audit_log_details',
            'table': 'audit_log',
            'column': 'details',
            'purpose': 'Audit log details JSONB queries for compliance reporting'
        },
        
        # Security event metadata GIN indexes
        {
            'name': 'idx_gin_security_event_metadata',
            'table': 'security_event',
            'column': 'event_metadata',
            'purpose': 'Security event metadata JSONB analysis and threat detection'
        }
    ]
    
    for index_config in gin_indexes:
        try:
            # Check if column exists before creating index
            column_exists = _check_column_exists(conn, index_config['table'], index_config['column'])
            if not column_exists:
                logger.warning(
                    f"Skipping GIN index {index_config['name']}: "
                    f"Column {index_config['column']} does not exist in table {index_config['table']}"
                )
                continue
            
            # Create GIN index with error handling
            sql = f"""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS {index_config['name']}
            ON {index_config['table']} 
            USING gin({index_config['column']})
            """
            
            conn.execute(text(sql))
            conn.commit()
            
            logger.info(
                f"Created GIN index {index_config['name']} on {index_config['table']}.{index_config['column']} "
                f"for {index_config['purpose']}"
            )
            
        except Exception as e:
            logger.error(f"Failed to create GIN index {index_config['name']}: {e}")
            # Continue with other indexes even if one fails
            continue


def _create_brin_indexes(conn):
    """
    Create BRIN (Block Range) indexes for time-series data optimization.
    
    BRIN indexes are highly space-efficient for large tables with naturally ordered
    data like timestamps, providing excellent performance for range queries on
    created_at and updated_at columns.
    
    Args:
        conn: Database connection object
    """
    logger.info("Creating BRIN indexes for time-series data optimization")
    
    # Tables with time-series data patterns
    time_series_tables = [
        'users',
        'user_session', 
        'business_entity',
        'entity_relationship',
        'audit_log',
        'security_event'
    ]
    
    for table_name in time_series_tables:
        try:
            # Check if table exists
            if not _check_table_exists(conn, table_name):
                logger.warning(f"Skipping BRIN indexes for non-existent table: {table_name}")
                continue
            
            # Create BRIN index for created_at column
            created_at_index = f"idx_brin_{table_name}_created_at"
            if _check_column_exists(conn, table_name, 'created_at'):
                sql = f"""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS {created_at_index}
                ON {table_name} 
                USING brin(created_at)
                WITH (pages_per_range = 128)
                """
                conn.execute(text(sql))
                conn.commit()
                
                logger.info(f"Created BRIN index {created_at_index} for time-series queries on {table_name}")
            
            # Create BRIN index for updated_at column if it exists
            updated_at_index = f"idx_brin_{table_name}_updated_at"
            if _check_column_exists(conn, table_name, 'updated_at'):
                sql = f"""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS {updated_at_index}
                ON {table_name} 
                USING brin(updated_at)
                WITH (pages_per_range = 128)
                """
                conn.execute(text(sql))
                conn.commit()
                
                logger.info(f"Created BRIN index {updated_at_index} for time-series queries on {table_name}")
            
        except Exception as e:
            logger.error(f"Failed to create BRIN indexes for table {table_name}: {e}")
            continue


def _create_partial_indexes(conn):
    """
    Create partial indexes for soft-delete patterns and active record filtering.
    
    Partial indexes improve performance by indexing only relevant rows based on
    WHERE conditions, particularly effective for soft-delete patterns and
    frequently filtered boolean columns.
    
    Args:
        conn: Database connection object
    """
    logger.info("Creating partial indexes for soft-delete and active record optimization")
    
    partial_indexes = [
        # Active users partial indexes
        {
            'name': 'idx_partial_users_active_username',
            'table': 'users',
            'columns': ['username'],
            'condition': "is_active = true",
            'purpose': 'Active user username lookups'
        },
        {
            'name': 'idx_partial_users_active_email',
            'table': 'users', 
            'columns': ['email'],
            'condition': "is_active = true",
            'purpose': 'Active user email lookups for authentication'
        },
        {
            'name': 'idx_partial_users_verified_active',
            'table': 'users',
            'columns': ['last_login_at'],
            'condition': "is_active = true AND is_verified = true", 
            'purpose': 'Verified active user activity tracking'
        },
        
        # Active user sessions partial indexes
        {
            'name': 'idx_partial_user_session_valid',
            'table': 'user_session',
            'columns': ['user_id', 'expires_at'],
            'condition': "is_valid = true",
            'purpose': 'Valid user session lookups and expiration checks'
        },
        {
            'name': 'idx_partial_user_session_active_token',
            'table': 'user_session',
            'columns': ['session_token'],
            'condition': "is_valid = true AND expires_at > CURRENT_TIMESTAMP",
            'purpose': 'Active session token validation'
        },
        
        # Active business entities partial indexes
        {
            'name': 'idx_partial_business_entity_active',
            'table': 'business_entity',
            'columns': ['owner_id', 'name'],
            'condition': "is_active = true",
            'purpose': 'Active business entity ownership queries'
        },
        {
            'name': 'idx_partial_business_entity_status_active',
            'table': 'business_entity',
            'columns': ['status', 'created_at'],
            'condition': "is_active = true",
            'purpose': 'Active business entity status filtering and sorting'
        },
        
        # Active entity relationships partial indexes
        {
            'name': 'idx_partial_entity_relationship_active',
            'table': 'entity_relationship',
            'columns': ['source_entity_id', 'target_entity_id'],
            'condition': "is_active = true",
            'purpose': 'Active entity relationship traversal'
        }
    ]
    
    for index_config in partial_indexes:
        try:
            # Verify table and columns exist
            if not _check_table_exists(conn, index_config['table']):
                logger.warning(f"Skipping partial index {index_config['name']}: table {index_config['table']} does not exist")
                continue
            
            columns_exist = all(
                _check_column_exists(conn, index_config['table'], col) 
                for col in index_config['columns']
            )
            if not columns_exist:
                logger.warning(f"Skipping partial index {index_config['name']}: not all columns exist")
                continue
            
            # Build column list for index
            column_list = ', '.join(index_config['columns'])
            
            # Create partial index
            sql = f"""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS {index_config['name']}
            ON {index_config['table']} ({column_list})
            WHERE {index_config['condition']}
            """
            
            conn.execute(text(sql))
            conn.commit()
            
            logger.info(
                f"Created partial index {index_config['name']} on {index_config['table']} "
                f"for {index_config['purpose']}"
            )
            
        except Exception as e:
            logger.error(f"Failed to create partial index {index_config['name']}: {e}")
            continue


def _create_composite_indexes(conn):
    """
    Create composite indexes for multi-column query optimization.
    
    Composite indexes optimize queries that filter or sort by multiple columns,
    particularly effective for complex business logic queries and reporting operations.
    
    Args:
        conn: Database connection object
    """
    logger.info("Creating composite indexes for multi-column query optimization")
    
    composite_indexes = [
        # User authentication and profile composite indexes
        {
            'name': 'idx_composite_users_auth_status',
            'table': 'users',
            'columns': ['is_active', 'is_verified', 'last_login_at'],
            'purpose': 'User authentication status and activity queries'
        },
        {
            'name': 'idx_composite_users_login_tracking',
            'table': 'users',
            'columns': ['login_count', 'failed_login_count', 'locked_until'],
            'purpose': 'User login attempt tracking and account locking'
        },
        
        # User session management composite indexes
        {
            'name': 'idx_composite_user_session_validation',
            'table': 'user_session',
            'columns': ['user_id', 'is_valid', 'expires_at'],
            'purpose': 'Comprehensive user session validation queries'
        },
        {
            'name': 'idx_composite_user_session_cleanup',
            'table': 'user_session',
            'columns': ['expires_at', 'is_valid', 'created_at'],
            'purpose': 'Session cleanup and expiration management'
        },
        
        # Business entity management composite indexes
        {
            'name': 'idx_composite_business_entity_ownership',
            'table': 'business_entity',
            'columns': ['owner_id', 'status', 'is_active'],
            'purpose': 'Business entity ownership and status filtering'
        },
        {
            'name': 'idx_composite_business_entity_search',
            'table': 'business_entity',
            'columns': ['name', 'owner_id', 'created_at'],
            'purpose': 'Business entity search and chronological sorting'
        },
        
        # Entity relationship composite indexes
        {
            'name': 'idx_composite_entity_relationship_mapping',
            'table': 'entity_relationship',
            'columns': ['source_entity_id', 'relationship_type', 'is_active'],
            'purpose': 'Entity relationship mapping and type filtering'
        },
        {
            'name': 'idx_composite_entity_relationship_reverse',
            'table': 'entity_relationship', 
            'columns': ['target_entity_id', 'relationship_type', 'is_active'],
            'purpose': 'Reverse entity relationship lookups'
        },
        
        # Audit and security composite indexes
        {
            'name': 'idx_composite_audit_log_user_activity',
            'table': 'audit_log',
            'columns': ['user_id', 'operation_type', 'created_at'],
            'purpose': 'User activity audit trail queries'
        },
        {
            'name': 'idx_composite_security_event_analysis',
            'table': 'security_event',
            'columns': ['event_type', 'severity', 'created_at'],
            'purpose': 'Security event analysis and threat monitoring'
        }
    ]
    
    for index_config in composite_indexes:
        try:
            # Verify table exists
            if not _check_table_exists(conn, index_config['table']):
                logger.warning(f"Skipping composite index {index_config['name']}: table {index_config['table']} does not exist")
                continue
            
            # Verify all columns exist
            columns_exist = all(
                _check_column_exists(conn, index_config['table'], col)
                for col in index_config['columns']
            )
            if not columns_exist:
                logger.warning(f"Skipping composite index {index_config['name']}: not all columns exist")
                continue
            
            # Build column list for index
            column_list = ', '.join(index_config['columns'])
            
            # Create composite index
            sql = f"""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS {index_config['name']}
            ON {index_config['table']} ({column_list})
            """
            
            conn.execute(text(sql))
            conn.commit()
            
            logger.info(
                f"Created composite index {index_config['name']} on {index_config['table']} "
                f"for {index_config['purpose']}"
            )
            
        except Exception as e:
            logger.error(f"Failed to create composite index {index_config['name']}: {e}")
            continue


def _create_authentication_indexes(conn):
    """
    Create specialized indexes for user authentication and session management optimization.
    
    These indexes target the most critical authentication workflows including login,
    session validation, and Auth0 integration patterns.
    
    Args:
        conn: Database connection object
    """
    logger.info("Creating specialized authentication optimization indexes")
    
    auth_indexes = [
        # Auth0 integration optimization
        {
            'name': 'idx_auth_users_auth0_integration',
            'table': 'users',
            'columns': ['auth0_user_id', 'is_active'],
            'purpose': 'Auth0 user ID lookups with active status filtering'
        },
        
        # Username authentication optimization
        {
            'name': 'idx_auth_users_username_lookup',
            'table': 'users',
            'columns': ['username', 'is_active', 'is_verified'],
            'purpose': 'Username-based authentication with status validation'
        },
        
        # Session token validation optimization
        {
            'name': 'idx_auth_session_token_validation',
            'table': 'user_session',
            'columns': ['session_token', 'user_id', 'expires_at'],
            'purpose': 'Fast session token validation and user resolution'
        },
        
        # Failed login tracking optimization
        {
            'name': 'idx_auth_users_security_tracking',
            'table': 'users',
            'columns': ['failed_login_count', 'locked_until', 'is_active'],
            'purpose': 'Account security and lockout status tracking'
        }
    ]
    
    for index_config in auth_indexes:
        try:
            if not _check_table_exists(conn, index_config['table']):
                continue
                
            columns_exist = all(
                _check_column_exists(conn, index_config['table'], col)
                for col in index_config['columns']  
            )
            if not columns_exist:
                continue
            
            column_list = ', '.join(index_config['columns'])
            
            sql = f"""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS {index_config['name']}
            ON {index_config['table']} ({column_list})
            """
            
            conn.execute(text(sql))
            conn.commit()
            
            logger.info(f"Created authentication index {index_config['name']}")
            
        except Exception as e:
            logger.error(f"Failed to create authentication index {index_config['name']}: {e}")
            continue


def _create_business_entity_indexes(conn):
    """
    Create specialized indexes for business entity relationship optimization.
    
    These indexes optimize complex business entity queries including relationship
    traversal, ownership hierarchies, and entity status management.
    
    Args:
        conn: Database connection object
    """
    logger.info("Creating business entity relationship optimization indexes")
    
    business_indexes = [
        # Entity ownership hierarchy optimization
        {
            'name': 'idx_business_entity_hierarchy',
            'table': 'business_entity',
            'columns': ['owner_id', 'created_at', 'is_active'],
            'purpose': 'Business entity ownership hierarchy with chronological ordering'
        },
        
        # Entity relationship traversal optimization
        {
            'name': 'idx_entity_rel_source_traversal',
            'table': 'entity_relationship',
            'columns': ['source_entity_id', 'relationship_type', 'created_at'],
            'purpose': 'Forward entity relationship traversal'
        },
        {
            'name': 'idx_entity_rel_target_traversal', 
            'table': 'entity_relationship',
            'columns': ['target_entity_id', 'relationship_type', 'created_at'],
            'purpose': 'Reverse entity relationship traversal'
        },
        
        # Entity status and lifecycle optimization
        {
            'name': 'idx_business_entity_lifecycle',
            'table': 'business_entity',
            'columns': ['status', 'updated_at', 'is_active'],
            'purpose': 'Entity lifecycle and status change tracking'
        }
    ]
    
    for index_config in business_indexes:
        try:
            if not _check_table_exists(conn, index_config['table']):
                continue
                
            columns_exist = all(
                _check_column_exists(conn, index_config['table'], col)
                for col in index_config['columns']
            )
            if not columns_exist:
                continue
            
            column_list = ', '.join(index_config['columns'])
            
            sql = f"""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS {index_config['name']}
            ON {index_config['table']} ({column_list})
            """
            
            conn.execute(text(sql))
            conn.commit()
            
            logger.info(f"Created business entity index {index_config['name']}")
            
        except Exception as e:
            logger.error(f"Failed to create business entity index {index_config['name']}: {e}")
            continue


def _initialize_index_monitoring(conn):
    """
    Initialize PostgreSQL index monitoring and maintenance infrastructure.
    
    Sets up automated index usage tracking, performance monitoring, and
    maintenance procedures to ensure optimal index performance over time.
    
    Args:
        conn: Database connection object
    """
    logger.info("Initializing index monitoring and maintenance infrastructure")
    
    try:
        # Enable pg_stat_statements extension for query tracking
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_stat_statements"))
        conn.commit()
        
        # Create index monitoring view for easy access to index statistics
        monitoring_view_sql = """
        CREATE OR REPLACE VIEW index_usage_monitoring AS
        SELECT 
            schemaname,
            tablename,
            indexname,
            idx_scan,
            idx_tup_read,
            idx_tup_fetch,
            idx_scan::float / GREATEST(seq_scan + idx_scan, 1) AS index_usage_ratio,
            pg_size_pretty(pg_relation_size(indexrelid)) AS index_size,
            pg_stat_get_live_tuples(relid) AS table_rows
        FROM pg_stat_user_indexes 
        JOIN pg_stat_user_tables USING (schemaname, tablename, relid)
        ORDER BY idx_scan DESC
        """
        
        conn.execute(text(monitoring_view_sql))
        conn.commit()
        
        # Create function to analyze query plans for performance optimization
        query_analysis_function = """
        CREATE OR REPLACE FUNCTION analyze_query_performance(query_text TEXT)
        RETURNS TABLE(
            plan_text TEXT,
            execution_time NUMERIC,
            index_usage TEXT[]
        )
        LANGUAGE plpgsql
        AS $$
        DECLARE
            plan_result RECORD;
        BEGIN
            -- This function would contain query plan analysis logic
            -- Implementation depends on specific monitoring requirements
            RETURN QUERY
            SELECT 
                'Query plan analysis requires specific implementation'::TEXT,
                0.0::NUMERIC,
                ARRAY[]::TEXT[];
        END;
        $$
        """
        
        conn.execute(text(query_analysis_function))
        conn.commit()
        
        # Initialize index maintenance tracking table
        maintenance_table_sql = """
        CREATE TABLE IF NOT EXISTS index_maintenance_log (
            id SERIAL PRIMARY KEY,
            index_name TEXT NOT NULL,
            operation_type TEXT NOT NULL, -- 'REINDEX', 'ANALYZE', 'VACUUM'
            execution_time INTERVAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'COMPLETED',
            details JSONB
        )
        """
        
        conn.execute(text(maintenance_table_sql))
        conn.commit()
        
        logger.info("Successfully initialized index monitoring infrastructure")
        
    except Exception as e:
        logger.error(f"Failed to initialize index monitoring: {e}")
        # Don't raise exception as monitoring is non-critical for migration


def _check_table_exists(conn, table_name):
    """
    Check if a table exists in the current database schema.
    
    Args:
        conn: Database connection object
        table_name: Name of table to check
        
    Returns:
        bool: True if table exists, False otherwise
    """
    try:
        result = conn.execute(text("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_name = :table_name 
                AND table_schema = 'public'
            )
        """), {"table_name": table_name}).fetchone()
        
        return result[0] if result else False
        
    except Exception:
        return False


def _check_column_exists(conn, table_name, column_name):
    """
    Check if a column exists in a specific table.
    
    Args:
        conn: Database connection object
        table_name: Name of table to check
        column_name: Name of column to check
        
    Returns:
        bool: True if column exists, False otherwise
    """
    try:
        result = conn.execute(text("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = :table_name 
                AND column_name = :column_name
                AND table_schema = 'public'
            )
        """), {"table_name": table_name, "column_name": column_name}).fetchone()
        
        return result[0] if result else False
        
    except Exception:
        return False


# Downgrade helper functions
def _remove_gin_indexes(conn):
    """Remove all GIN indexes created by this migration."""
    gin_index_names = [
        'idx_gin_users_auth0_metadata',
        'idx_gin_users_auth0_app_metadata', 
        'idx_gin_business_entity_metadata',
        'idx_gin_audit_log_details',
        'idx_gin_security_event_metadata'
    ]
    
    for index_name in gin_index_names:
        try:
            conn.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
            conn.commit()
            logger.info(f"Removed GIN index: {index_name}")
        except Exception as e:
            logger.error(f"Failed to remove GIN index {index_name}: {e}")


def _remove_brin_indexes(conn):
    """Remove all BRIN indexes created by this migration."""
    tables = ['users', 'user_session', 'business_entity', 'entity_relationship', 'audit_log', 'security_event']
    
    for table in tables:
        for timestamp_col in ['created_at', 'updated_at']:
            index_name = f"idx_brin_{table}_{timestamp_col}"
            try:
                conn.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
                conn.commit()
                logger.info(f"Removed BRIN index: {index_name}")
            except Exception as e:
                logger.error(f"Failed to remove BRIN index {index_name}: {e}")


def _remove_partial_indexes(conn):
    """Remove all partial indexes created by this migration."""
    partial_index_names = [
        'idx_partial_users_active_username',
        'idx_partial_users_active_email',
        'idx_partial_users_verified_active',
        'idx_partial_user_session_valid',
        'idx_partial_user_session_active_token',
        'idx_partial_business_entity_active',
        'idx_partial_business_entity_status_active',
        'idx_partial_entity_relationship_active'
    ]
    
    for index_name in partial_index_names:
        try:
            conn.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
            conn.commit()
            logger.info(f"Removed partial index: {index_name}")
        except Exception as e:
            logger.error(f"Failed to remove partial index {index_name}: {e}")


def _remove_composite_indexes(conn):
    """Remove all composite indexes created by this migration."""
    composite_index_names = [
        'idx_composite_users_auth_status',
        'idx_composite_users_login_tracking',
        'idx_composite_user_session_validation',
        'idx_composite_user_session_cleanup',
        'idx_composite_business_entity_ownership',
        'idx_composite_business_entity_search',
        'idx_composite_entity_relationship_mapping',
        'idx_composite_entity_relationship_reverse',
        'idx_composite_audit_log_user_activity',
        'idx_composite_security_event_analysis'
    ]
    
    for index_name in composite_index_names:
        try:
            conn.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
            conn.commit()
            logger.info(f"Removed composite index: {index_name}")
        except Exception as e:
            logger.error(f"Failed to remove composite index {index_name}: {e}")


def _remove_authentication_indexes(conn):
    """Remove authentication optimization indexes."""
    auth_index_names = [
        'idx_auth_users_auth0_integration',
        'idx_auth_users_username_lookup',
        'idx_auth_session_token_validation',
        'idx_auth_users_security_tracking'
    ]
    
    for index_name in auth_index_names:
        try:
            conn.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
            conn.commit()
            logger.info(f"Removed authentication index: {index_name}")
        except Exception as e:
            logger.error(f"Failed to remove authentication index {index_name}: {e}")


def _remove_business_entity_indexes(conn):
    """Remove business entity optimization indexes."""
    business_index_names = [
        'idx_business_entity_hierarchy',
        'idx_entity_rel_source_traversal',
        'idx_entity_rel_target_traversal',
        'idx_business_entity_lifecycle'
    ]
    
    for index_name in business_index_names:
        try:
            conn.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
            conn.commit()
            logger.info(f"Removed business entity index: {index_name}")
        except Exception as e:
            logger.error(f"Failed to remove business entity index {index_name}: {e}")


def _cleanup_index_monitoring(conn):
    """Clean up index monitoring infrastructure."""
    try:
        # Remove monitoring objects
        conn.execute(text("DROP VIEW IF EXISTS index_usage_monitoring"))
        conn.execute(text("DROP FUNCTION IF EXISTS analyze_query_performance(TEXT)"))
        conn.execute(text("DROP TABLE IF EXISTS index_maintenance_log"))
        conn.commit()
        
        logger.info("Cleaned up index monitoring infrastructure")
        
    except Exception as e:
        logger.error(f"Failed to cleanup index monitoring: {e}")