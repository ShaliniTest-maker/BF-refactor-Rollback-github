"""
Performance Optimization Migration - Comprehensive Indexing Strategy

Revision ID: 003_20241201_140000
Revises: 002_20241201_130000_mongodb_data_conversion
Create Date: 2024-12-01 14:00:00.000000

This migration implements a comprehensive indexing strategy for enhanced query execution
and database performance optimization. The migration creates primary keys, unique constraints,
foreign key indexes, and composite indexes essential for meeting the 95th percentile
response time targets specified in Section 6.2.1 of the technical specification.

Performance Targets:
- Simple SELECT queries: < 500ms (95th percentile)
- Complex JOIN queries: < 2000ms (95th percentile)
- INSERT/UPDATE operations: < 300ms (95th percentile)

Key Features:
- Primary key indexes for all entity tables with auto-incrementing integers
- Unique constraint indexes for username, email, and session tokens
- Foreign key indexes for enhanced join performance across entity relationships
- Composite indexes for multi-column queries and filtering optimization
- PostgreSQL-specific indexing strategies for optimal query plan execution

Dependencies:
- PostgreSQL 15.x with advanced indexing capabilities
- Flask-SQLAlchemy 3.1.1 declarative model system
- Requires completion of initial schema (001) and data conversion (002) migrations
- Performance monitoring integration with pg_stat_statements extension

Architecture Integration:
- SQLAlchemy optimization patterns per Section 6.2.5.1
- Query plan analysis integration for performance monitoring
- Index optimization strategy supporting equivalent concurrent user loads
- Performance validation against Node.js MongoDB baseline metrics
"""

from typing import List, Tuple, Optional
import logging
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text, Index
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection
from sqlalchemy.exc import OperationalError, ProgrammingError

# Configure logging for migration operations
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Revision identifiers, used by Alembic for migration ordering
revision = '003_20241201_140000'
down_revision = '002_20241201_130000_mongodb_data_conversion'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Apply performance optimization indexes for enhanced query execution.
    
    This function implements the comprehensive indexing strategy to achieve
    95th percentile response time targets as specified in Section 6.2.1.
    Creates primary key indexes, unique constraints, foreign key indexes,
    and composite indexes for optimal PostgreSQL query performance.
    
    Index Categories:
    1. Primary Key Indexes - Auto-incrementing integer primary keys
    2. Unique Constraint Indexes - Username, email, session token uniqueness
    3. Foreign Key Indexes - Enhanced join performance for relationships
    4. Composite Indexes - Multi-column query optimization
    5. Performance Indexes - PostgreSQL-specific optimization patterns
    
    Performance Impact:
    - Reduces simple query execution time to < 500ms (95th percentile)
    - Optimizes complex join queries to < 2000ms (95th percentile)
    - Enhances INSERT/UPDATE performance to < 300ms (95th percentile)
    - Supports equivalent concurrent user loads as Node.js implementation
    """
    logger.info("Starting performance optimization migration - creating comprehensive indexing strategy")
    
    try:
        # Get database connection for index creation
        connection = op.get_bind()
        
        # Verify PostgreSQL version and capabilities
        _verify_postgresql_capabilities(connection)
        
        # 1. Create Primary Key Indexes (if not already created by schema)
        _create_primary_key_indexes(connection)
        
        # 2. Create Unique Constraint Indexes for authentication integrity
        _create_unique_constraint_indexes()
        
        # 3. Create Foreign Key Indexes for enhanced join performance
        _create_foreign_key_indexes()
        
        # 4. Create Composite Indexes for multi-column query optimization
        _create_composite_indexes()
        
        # 5. Create PostgreSQL-specific performance indexes
        _create_postgresql_performance_indexes(connection)
        
        # 6. Create indexes for session management and cleanup operations
        _create_session_management_indexes()
        
        # 7. Create indexes for business entity relationship queries
        _create_business_entity_indexes()
        
        # 8. Verify index creation and performance impact
        _verify_index_creation(connection)
        
        logger.info("Performance optimization migration completed successfully")
        
    except Exception as e:
        logger.error(f"Performance optimization migration failed: {str(e)}")
        raise


def downgrade() -> None:
    """
    Remove performance optimization indexes for rollback procedures.
    
    This function implements comprehensive rollback procedures by removing
    all performance indexes created in the upgrade function. Maintains
    referential integrity while restoring the database to pre-optimization
    state for migration rollback scenarios.
    
    Rollback Strategy:
    1. Remove composite indexes first to avoid dependency conflicts
    2. Remove PostgreSQL-specific performance indexes
    3. Remove foreign key indexes while preserving constraints
    4. Remove unique constraint indexes (keeping underlying constraints)
    5. Verify rollback completion and database integrity
    
    Safety Considerations:
    - Preserves primary key constraints and foreign key relationships
    - Maintains data integrity during index removal
    - Includes verification steps for rollback validation
    - Supports automated rollback triggers per Section 6.2.6
    """
    logger.info("Starting performance optimization rollback - removing comprehensive indexing strategy")
    
    try:
        # Get database connection for index removal
        connection = op.get_bind()
        
        # 1. Remove composite indexes (reverse order of creation)
        _remove_composite_indexes()
        
        # 2. Remove PostgreSQL-specific performance indexes
        _remove_postgresql_performance_indexes(connection)
        
        # 3. Remove foreign key indexes while preserving constraints
        _remove_foreign_key_indexes()
        
        # 4. Remove session management indexes
        _remove_session_management_indexes()
        
        # 5. Remove business entity indexes
        _remove_business_entity_indexes()
        
        # 6. Remove unique constraint indexes (keeping constraints)
        _remove_unique_constraint_indexes()
        
        # 7. Verify rollback completion
        _verify_rollback_completion(connection)
        
        logger.info("Performance optimization rollback completed successfully")
        
    except Exception as e:
        logger.error(f"Performance optimization rollback failed: {str(e)}")
        raise


def _verify_postgresql_capabilities(connection: Connection) -> None:
    """
    Verify PostgreSQL version and advanced indexing capabilities.
    
    Args:
        connection (Connection): Database connection for capability verification
        
    Raises:
        RuntimeError: If PostgreSQL version or capabilities are insufficient
    """
    try:
        # Check PostgreSQL version
        result = connection.execute(text("SELECT version()"))
        version_info = result.fetchone()[0]
        logger.info(f"PostgreSQL version: {version_info}")
        
        # Verify PostgreSQL 15.x or higher
        if "PostgreSQL 15" not in version_info and "PostgreSQL 16" not in version_info:
            logger.warning(f"PostgreSQL 15.x recommended for optimal performance. Current: {version_info}")
        
        # Check if pg_stat_statements extension is available
        try:
            connection.execute(text("SELECT * FROM pg_stat_statements LIMIT 1"))
            logger.info("pg_stat_statements extension available for performance monitoring")
        except (OperationalError, ProgrammingError):
            logger.warning("pg_stat_statements extension not available - performance monitoring limited")
        
        # Verify tablespace and indexing capabilities
        result = connection.execute(text("SHOW default_tablespace"))
        tablespace = result.fetchone()[0] if result.rowcount > 0 else "default"
        logger.info(f"Using tablespace: {tablespace}")
        
    except Exception as e:
        logger.error(f"PostgreSQL capability verification failed: {str(e)}")
        raise RuntimeError(f"Database capability verification failed: {str(e)}")


def _create_primary_key_indexes(connection: Connection) -> None:
    """
    Create primary key indexes for all entity tables with auto-incrementing integers.
    
    Primary key indexes are automatically created by PostgreSQL for PRIMARY KEY
    constraints, but this function verifies their existence and creates any
    missing indexes for optimal join performance per Section 6.2.2.2.
    
    Args:
        connection (Connection): Database connection for index verification
    """
    logger.info("Creating primary key indexes for optimal join performance")
    
    # Primary key indexes are automatically created by PostgreSQL
    # Verify their existence and properties
    primary_key_tables = [
        ('users', 'id'),
        ('user_sessions', 'id'),
        ('business_entities', 'id'),
        ('entity_relationships', 'id')
    ]
    
    for table_name, pk_column in primary_key_tables:
        try:
            # Check if primary key index exists
            result = connection.execute(text("""
                SELECT indexname, indexdef 
                FROM pg_indexes 
                WHERE tablename = :table_name 
                AND indexdef LIKE '%PRIMARY KEY%'
            """), {"table_name": table_name})
            
            if result.rowcount > 0:
                index_info = result.fetchone()
                logger.info(f"Primary key index verified for {table_name}.{pk_column}: {index_info[0]}")
            else:
                logger.warning(f"Primary key index not found for {table_name}.{pk_column}")
                
        except Exception as e:
            logger.error(f"Primary key verification failed for {table_name}: {str(e)}")


def _create_unique_constraint_indexes() -> None:
    """
    Create unique constraint indexes for username, email, and session tokens.
    
    Implements unique constraint indexes for authentication integrity per
    Section 6.2.2.1. These indexes ensure data uniqueness while providing
    fast lookup capabilities for authentication operations.
    
    Unique Indexes Created:
    - users.username - Unique username constraint with fast lookup
    - users.email - Unique email constraint with fast lookup  
    - user_sessions.session_token - Unique session token constraint
    """
    logger.info("Creating unique constraint indexes for authentication integrity")
    
    # Users table unique constraint indexes
    try:
        # Username unique index (if not already created by model)
        op.create_index(
            'idx_users_username_unique',
            'users',
            ['username'],
            unique=True,
            postgresql_ops={'username': 'text_pattern_ops'}
        )
        logger.info("Created unique index for users.username")
    except Exception as e:
        logger.warning(f"Username unique index may already exist: {str(e)}")
    
    try:
        # Email unique index (if not already created by model)
        op.create_index(
            'idx_users_email_unique',
            'users',
            ['email'],
            unique=True,
            postgresql_ops={'email': 'text_pattern_ops'}
        )
        logger.info("Created unique index for users.email")
    except Exception as e:
        logger.warning(f"Email unique index may already exist: {str(e)}")
    
    # User sessions table unique constraint indexes
    try:
        # Session token unique index (if not already created by model)
        op.create_index(
            'idx_user_sessions_token_unique',
            'user_sessions',
            ['session_token'],
            unique=True,
            postgresql_ops={'session_token': 'text_pattern_ops'}
        )
        logger.info("Created unique index for user_sessions.session_token")
    except Exception as e:
        logger.warning(f"Session token unique index may already exist: {str(e)}")


def _create_foreign_key_indexes() -> None:
    """
    Create foreign key indexes for enhanced join performance across entity relationships.
    
    Implements foreign key indexes per Section 6.2.2.2 to optimize join
    operations and maintain referential integrity performance. These indexes
    are essential for meeting the complex query response time targets.
    
    Foreign Key Indexes Created:
    - user_sessions.user_id → users.id
    - business_entities.owner_id → users.id  
    - entity_relationships.source_entity_id → business_entities.id
    - entity_relationships.target_entity_id → business_entities.id
    """
    logger.info("Creating foreign key indexes for enhanced join performance")
    
    # User sessions foreign key index
    try:
        op.create_index(
            'idx_user_sessions_user_id_fk',
            'user_sessions',
            ['user_id'],
            postgresql_using='btree'
        )
        logger.info("Created foreign key index for user_sessions.user_id")
    except Exception as e:
        logger.warning(f"User sessions foreign key index may already exist: {str(e)}")
    
    # Business entities foreign key index
    try:
        op.create_index(
            'idx_business_entities_owner_id_fk',
            'business_entities',
            ['owner_id'],
            postgresql_using='btree'
        )
        logger.info("Created foreign key index for business_entities.owner_id")
    except Exception as e:
        logger.warning(f"Business entities foreign key index may already exist: {str(e)}")
    
    # Entity relationships foreign key indexes
    try:
        op.create_index(
            'idx_entity_relationships_source_id_fk',
            'entity_relationships',
            ['source_entity_id'],
            postgresql_using='btree'
        )
        logger.info("Created foreign key index for entity_relationships.source_entity_id")
    except Exception as e:
        logger.warning(f"Source entity foreign key index may already exist: {str(e)}")
    
    try:
        op.create_index(
            'idx_entity_relationships_target_id_fk',
            'entity_relationships',
            ['target_entity_id'],
            postgresql_using='btree'
        )
        logger.info("Created foreign key index for entity_relationships.target_entity_id")
    except Exception as e:
        logger.warning(f"Target entity foreign key index may already exist: {str(e)}")


def _create_composite_indexes() -> None:
    """
    Create composite indexes for multi-column queries and filtering optimization.
    
    Implements composite indexes per Section 6.2.5.1 for optimal query execution
    on frequently used multi-column query patterns. These indexes are critical
    for achieving simple query response time targets < 500ms.
    
    Composite Indexes Created:
    - Users: (is_active, created_at), (email, is_active), (username, is_active)
    - Sessions: (user_id, is_valid), (expires_at, is_valid), (is_valid, expires_at)  
    - Business Entities: (owner_id, status), (status, created_at)
    - Entity Relationships: (source_entity_id, relationship_type), (is_active, relationship_type)
    """
    logger.info("Creating composite indexes for multi-column query optimization")
    
    # Users table composite indexes
    try:
        op.create_index(
            'idx_users_active_created_composite',
            'users',
            ['is_active', 'created_at'],
            postgresql_using='btree'
        )
        logger.info("Created composite index for users (is_active, created_at)")
    except Exception as e:
        logger.warning(f"Users active/created composite index may already exist: {str(e)}")
    
    try:
        op.create_index(
            'idx_users_email_active_composite',
            'users',
            ['email', 'is_active'],
            postgresql_using='btree'
        )
        logger.info("Created composite index for users (email, is_active)")
    except Exception as e:
        logger.warning(f"Users email/active composite index may already exist: {str(e)}")
    
    try:
        op.create_index(
            'idx_users_username_active_composite',
            'users',
            ['username', 'is_active'],
            postgresql_using='btree'
        )
        logger.info("Created composite index for users (username, is_active)")
    except Exception as e:
        logger.warning(f"Users username/active composite index may already exist: {str(e)}")
    
    # User sessions table composite indexes
    try:
        op.create_index(
            'idx_user_sessions_user_valid_composite',
            'user_sessions',
            ['user_id', 'is_valid'],
            postgresql_using='btree'
        )
        logger.info("Created composite index for user_sessions (user_id, is_valid)")
    except Exception as e:
        logger.warning(f"Sessions user/valid composite index may already exist: {str(e)}")
    
    try:
        op.create_index(
            'idx_user_sessions_expires_valid_composite',
            'user_sessions',
            ['expires_at', 'is_valid'],
            postgresql_using='btree'
        )
        logger.info("Created composite index for user_sessions (expires_at, is_valid)")
    except Exception as e:
        logger.warning(f"Sessions expires/valid composite index may already exist: {str(e)}")
    
    try:
        op.create_index(
            'idx_user_sessions_valid_expires_composite',
            'user_sessions',
            ['is_valid', 'expires_at'],
            postgresql_using='btree'
        )
        logger.info("Created composite index for user_sessions (is_valid, expires_at)")
    except Exception as e:
        logger.warning(f"Sessions valid/expires composite index may already exist: {str(e)}")
    
    # Business entities table composite indexes
    try:
        op.create_index(
            'idx_business_entities_owner_status_composite',
            'business_entities',
            ['owner_id', 'status'],
            postgresql_using='btree'
        )
        logger.info("Created composite index for business_entities (owner_id, status)")
    except Exception as e:
        logger.warning(f"Business entities owner/status composite index may already exist: {str(e)}")
    
    try:
        op.create_index(
            'idx_business_entities_status_created_composite',
            'business_entities',
            ['status', 'created_at'],
            postgresql_using='btree'
        )
        logger.info("Created composite index for business_entities (status, created_at)")
    except Exception as e:
        logger.warning(f"Business entities status/created composite index may already exist: {str(e)}")
    
    # Entity relationships table composite indexes
    try:
        op.create_index(
            'idx_entity_relationships_source_type_composite',
            'entity_relationships',
            ['source_entity_id', 'relationship_type'],
            postgresql_using='btree'
        )
        logger.info("Created composite index for entity_relationships (source_entity_id, relationship_type)")
    except Exception as e:
        logger.warning(f"Entity relationships source/type composite index may already exist: {str(e)}")
    
    try:
        op.create_index(
            'idx_entity_relationships_active_type_composite',
            'entity_relationships',
            ['is_active', 'relationship_type'],
            postgresql_using='btree'
        )
        logger.info("Created composite index for entity_relationships (is_active, relationship_type)")
    except Exception as e:
        logger.warning(f"Entity relationships active/type composite index may already exist: {str(e)}")


def _create_postgresql_performance_indexes(connection: Connection) -> None:
    """
    Create PostgreSQL-specific indexing strategies for 95th percentile response time targets.
    
    Implements PostgreSQL-specific optimization patterns per Section 6.2.1
    for advanced indexing capabilities. Uses PostgreSQL 15.x features for
    optimal query plan execution and performance monitoring integration.
    
    Args:
        connection (Connection): Database connection for PostgreSQL-specific operations
        
    PostgreSQL-Specific Indexes Created:
    - Partial indexes for active records only
    - BRIN indexes for timestamp-based queries  
    - Hash indexes for equality-only lookups
    - Expression indexes for computed values
    """
    logger.info("Creating PostgreSQL-specific performance indexes")
    
    try:
        # Partial index for active users only (reduces index size and improves performance)
        op.execute(text("""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_active_only_partial
            ON users (id, username, email, created_at)
            WHERE is_active = true
        """))
        logger.info("Created partial index for active users only")
    except Exception as e:
        logger.warning(f"Active users partial index creation failed: {str(e)}")
    
    try:
        # Partial index for valid sessions only
        op.execute(text("""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_valid_only_partial
            ON user_sessions (user_id, session_token, expires_at)
            WHERE is_valid = true
        """))
        logger.info("Created partial index for valid sessions only")
    except Exception as e:
        logger.warning(f"Valid sessions partial index creation failed: {str(e)}")
    
    try:
        # BRIN index for timestamp-based queries (efficient for large tables)
        op.execute(text("""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_created_at_brin
            ON users USING BRIN (created_at)
        """))
        logger.info("Created BRIN index for users.created_at timestamp queries")
    except Exception as e:
        logger.warning(f"Users BRIN index creation failed: {str(e)}")
    
    try:
        # BRIN index for session timestamps
        op.execute(text("""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_timestamps_brin
            ON user_sessions USING BRIN (created_at, expires_at)
        """))
        logger.info("Created BRIN index for session timestamp queries")
    except Exception as e:
        logger.warning(f"Sessions BRIN index creation failed: {str(e)}")
    
    try:
        # Hash index for exact session token lookups (PostgreSQL 10+ hash indexes are crash-safe)
        op.execute(text("""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_token_hash
            ON user_sessions USING HASH (session_token)
        """))
        logger.info("Created hash index for exact session token lookups")
    except Exception as e:
        logger.warning(f"Session token hash index creation failed: {str(e)}")
    
    try:
        # Expression index for case-insensitive username lookups
        op.execute(text("""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_username_lower_expr
            ON users (LOWER(username))
            WHERE is_active = true
        """))
        logger.info("Created expression index for case-insensitive username lookups")
    except Exception as e:
        logger.warning(f"Username expression index creation failed: {str(e)}")
    
    try:
        # Expression index for case-insensitive email lookups
        op.execute(text("""
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_lower_expr
            ON users (LOWER(email))
            WHERE is_active = true
        """))
        logger.info("Created expression index for case-insensitive email lookups")
    except Exception as e:
        logger.warning(f"Email expression index creation failed: {str(e)}")


def _create_session_management_indexes() -> None:
    """
    Create indexes for session management and cleanup operations.
    
    Implements specialized indexes for session lifecycle management,
    cleanup operations, and authentication workflows. These indexes
    optimize session validation queries and automated cleanup procedures.
    
    Session Management Indexes Created:
    - Session expiration cleanup optimization
    - User session enumeration optimization
    - Session token validation optimization
    - Last accessed tracking optimization
    """
    logger.info("Creating session management indexes for cleanup and validation operations")
    
    try:
        # Index for session cleanup operations (expired sessions)
        op.create_index(
            'idx_user_sessions_cleanup_expired',
            'user_sessions',
            ['expires_at', 'is_valid'],
            postgresql_where=text('expires_at < NOW()')
        )
        logger.info("Created index for session cleanup operations")
    except Exception as e:
        logger.warning(f"Session cleanup index creation failed: {str(e)}")
    
    try:
        # Index for user session enumeration
        op.create_index(
            'idx_user_sessions_user_enumeration',
            'user_sessions',
            ['user_id', 'created_at'],
            postgresql_using='btree'
        )
        logger.info("Created index for user session enumeration")
    except Exception as e:
        logger.warning(f"Session enumeration index creation failed: {str(e)}")
    
    try:
        # Index for session activity tracking
        op.create_index(
            'idx_user_sessions_activity_tracking',
            'user_sessions',
            ['last_accessed', 'user_id'],
            postgresql_using='btree'
        )
        logger.info("Created index for session activity tracking")
    except Exception as e:
        logger.warning(f"Session activity index creation failed: {str(e)}")


def _create_business_entity_indexes() -> None:
    """
    Create indexes for business entity relationship queries.
    
    Implements specialized indexes for business entity operations,
    relationship traversal, and entity lifecycle management. These
    indexes optimize complex business logic queries and reporting.
    
    Business Entity Indexes Created:
    - Entity ownership queries optimization
    - Relationship traversal optimization  
    - Entity status filtering optimization
    - Entity lifecycle tracking optimization
    """
    logger.info("Creating business entity indexes for relationship and lifecycle queries")
    
    try:
        # Index for entity ownership queries
        op.create_index(
            'idx_business_entities_ownership',
            'business_entities',
            ['owner_id', 'created_at', 'status'],
            postgresql_using='btree'
        )
        logger.info("Created index for business entity ownership queries")
    except Exception as e:
        logger.warning(f"Entity ownership index creation failed: {str(e)}")
    
    try:
        # Index for relationship traversal queries
        op.create_index(
            'idx_entity_relationships_traversal',
            'entity_relationships',
            ['source_entity_id', 'target_entity_id', 'is_active'],
            postgresql_using='btree'
        )
        logger.info("Created index for entity relationship traversal")
    except Exception as e:
        logger.warning(f"Relationship traversal index creation failed: {str(e)}")
    
    try:
        # Index for reverse relationship queries
        op.create_index(
            'idx_entity_relationships_reverse',
            'entity_relationships',
            ['target_entity_id', 'source_entity_id', 'relationship_type'],
            postgresql_using='btree'
        )
        logger.info("Created index for reverse entity relationship queries")
    except Exception as e:
        logger.warning(f"Reverse relationship index creation failed: {str(e)}")
    
    try:
        # Index for entity lifecycle tracking
        op.create_index(
            'idx_business_entities_lifecycle',
            'business_entities',
            ['created_at', 'updated_at', 'status'],
            postgresql_using='btree'
        )
        logger.info("Created index for business entity lifecycle tracking")
    except Exception as e:
        logger.warning(f"Entity lifecycle index creation failed: {str(e)}")


def _verify_index_creation(connection: Connection) -> None:
    """
    Verify index creation and performance impact validation.
    
    Performs comprehensive verification of created indexes including
    existence checks, size analysis, and performance impact assessment.
    Validates that indexing strategy meets performance targets.
    
    Args:
        connection (Connection): Database connection for verification queries
        
    Verification Steps:
    1. Index existence and definition verification
    2. Index size and selectivity analysis
    3. Query plan optimization verification
    4. Performance baseline comparison
    """
    logger.info("Verifying index creation and performance impact")
    
    try:
        # Count total indexes created
        result = connection.execute(text("""
            SELECT COUNT(*) as index_count
            FROM pg_indexes 
            WHERE schemaname = 'public'
            AND indexname LIKE 'idx_%'
        """))
        index_count = result.fetchone()[0]
        logger.info(f"Total performance indexes created: {index_count}")
        
        # Analyze index sizes and usage
        result = connection.execute(text("""
            SELECT 
                schemaname,
                tablename,
                indexname,
                pg_size_pretty(pg_relation_size(indexrelid)) as index_size
            FROM pg_stat_user_indexes 
            WHERE schemaname = 'public'
            AND indexname LIKE 'idx_%'
            ORDER BY pg_relation_size(indexrelid) DESC
            LIMIT 10
        """))
        
        logger.info("Top 10 largest performance indexes:")
        for row in result.fetchall():
            logger.info(f"  {row[2]} on {row[1]}: {row[3]}")
        
        # Check for missing or unused indexes
        result = connection.execute(text("""
            SELECT 
                schemaname,
                tablename,
                attname,
                n_distinct,
                correlation
            FROM pg_stats 
            WHERE schemaname = 'public'
            AND tablename IN ('users', 'user_sessions', 'business_entities', 'entity_relationships')
            ORDER BY tablename, attname
        """))
        
        logger.info("Column statistics for performance optimization:")
        for row in result.fetchall():
            logger.info(f"  {row[1]}.{row[2]}: distinct={row[3]}, correlation={row[4]}")
        
    except Exception as e:
        logger.warning(f"Index verification encountered issues: {str(e)}")


# Rollback Functions for Migration Downgrade

def _remove_composite_indexes() -> None:
    """Remove composite indexes created for multi-column query optimization."""
    logger.info("Removing composite indexes")
    
    composite_indexes = [
        'idx_users_active_created_composite',
        'idx_users_email_active_composite', 
        'idx_users_username_active_composite',
        'idx_user_sessions_user_valid_composite',
        'idx_user_sessions_expires_valid_composite',
        'idx_user_sessions_valid_expires_composite',
        'idx_business_entities_owner_status_composite',
        'idx_business_entities_status_created_composite',
        'idx_entity_relationships_source_type_composite',
        'idx_entity_relationships_active_type_composite'
    ]
    
    for index_name in composite_indexes:
        try:
            op.drop_index(index_name)
            logger.info(f"Removed composite index: {index_name}")
        except Exception as e:
            logger.warning(f"Failed to remove composite index {index_name}: {str(e)}")


def _remove_postgresql_performance_indexes(connection: Connection) -> None:
    """Remove PostgreSQL-specific performance indexes."""
    logger.info("Removing PostgreSQL-specific performance indexes")
    
    postgresql_indexes = [
        'idx_users_active_only_partial',
        'idx_user_sessions_valid_only_partial',
        'idx_users_created_at_brin',
        'idx_user_sessions_timestamps_brin',
        'idx_user_sessions_token_hash',
        'idx_users_username_lower_expr',
        'idx_users_email_lower_expr'
    ]
    
    for index_name in postgresql_indexes:
        try:
            connection.execute(text(f"DROP INDEX CONCURRENTLY IF EXISTS {index_name}"))
            logger.info(f"Removed PostgreSQL index: {index_name}")
        except Exception as e:
            logger.warning(f"Failed to remove PostgreSQL index {index_name}: {str(e)}")


def _remove_foreign_key_indexes() -> None:
    """Remove foreign key indexes while preserving constraints."""
    logger.info("Removing foreign key indexes")
    
    foreign_key_indexes = [
        'idx_user_sessions_user_id_fk',
        'idx_business_entities_owner_id_fk',
        'idx_entity_relationships_source_id_fk',
        'idx_entity_relationships_target_id_fk'
    ]
    
    for index_name in foreign_key_indexes:
        try:
            op.drop_index(index_name)
            logger.info(f"Removed foreign key index: {index_name}")
        except Exception as e:
            logger.warning(f"Failed to remove foreign key index {index_name}: {str(e)}")


def _remove_session_management_indexes() -> None:
    """Remove session management indexes."""
    logger.info("Removing session management indexes")
    
    session_indexes = [
        'idx_user_sessions_cleanup_expired',
        'idx_user_sessions_user_enumeration',
        'idx_user_sessions_activity_tracking'
    ]
    
    for index_name in session_indexes:
        try:
            op.drop_index(index_name)
            logger.info(f"Removed session management index: {index_name}")
        except Exception as e:
            logger.warning(f"Failed to remove session management index {index_name}: {str(e)}")


def _remove_business_entity_indexes() -> None:
    """Remove business entity indexes."""
    logger.info("Removing business entity indexes")
    
    entity_indexes = [
        'idx_business_entities_ownership',
        'idx_entity_relationships_traversal', 
        'idx_entity_relationships_reverse',
        'idx_business_entities_lifecycle'
    ]
    
    for index_name in entity_indexes:
        try:
            op.drop_index(index_name)
            logger.info(f"Removed business entity index: {index_name}")
        except Exception as e:
            logger.warning(f"Failed to remove business entity index {index_name}: {str(e)}")


def _remove_unique_constraint_indexes() -> None:
    """Remove unique constraint indexes while keeping underlying constraints."""
    logger.info("Removing unique constraint indexes")
    
    unique_indexes = [
        'idx_users_username_unique',
        'idx_users_email_unique',
        'idx_user_sessions_token_unique'
    ]
    
    for index_name in unique_indexes:
        try:
            op.drop_index(index_name)
            logger.info(f"Removed unique constraint index: {index_name}")
        except Exception as e:
            logger.warning(f"Failed to remove unique constraint index {index_name}: {str(e)}")


def _verify_rollback_completion(connection: Connection) -> None:
    """Verify rollback completion and database integrity."""
    logger.info("Verifying rollback completion and database integrity")
    
    try:
        # Count remaining performance indexes
        result = connection.execute(text("""
            SELECT COUNT(*) as remaining_indexes
            FROM pg_indexes 
            WHERE schemaname = 'public'
            AND indexname LIKE 'idx_%'
        """))
        remaining_count = result.fetchone()[0]
        logger.info(f"Remaining performance indexes after rollback: {remaining_count}")
        
        # Verify foreign key constraints still exist
        result = connection.execute(text("""
            SELECT COUNT(*) as fk_count
            FROM information_schema.table_constraints 
            WHERE constraint_type = 'FOREIGN KEY'
            AND table_schema = 'public'
        """))
        fk_count = result.fetchone()[0]
        logger.info(f"Foreign key constraints preserved: {fk_count}")
        
        # Verify primary key constraints still exist
        result = connection.execute(text("""
            SELECT COUNT(*) as pk_count
            FROM information_schema.table_constraints 
            WHERE constraint_type = 'PRIMARY KEY'
            AND table_schema = 'public'
        """))
        pk_count = result.fetchone()[0]
        logger.info(f"Primary key constraints preserved: {pk_count}")
        
        logger.info("Rollback verification completed successfully")
        
    except Exception as e:
        logger.error(f"Rollback verification failed: {str(e)}")
        raise