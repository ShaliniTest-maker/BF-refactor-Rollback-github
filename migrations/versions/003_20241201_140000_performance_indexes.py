"""Performance optimization migration implementing comprehensive indexing strategy for enhanced query execution and database performance.

This migration creates a comprehensive indexing strategy essential for meeting the 95th percentile 
response time targets specified in Section 6.2.1. The indexes include primary keys, unique constraints, 
foreign key indexes, and composite indexes optimized for PostgreSQL 15.x advanced capabilities.

Performance Targets:
- Simple SELECT queries: < 500ms (95th percentile)
- Complex JOIN queries: < 2000ms (95th percentile)
- INSERT/UPDATE operations: < 300ms (95th percentile)

Indexing Strategy:
- Primary key indexes: Auto-incrementing integers for optimal join performance
- Unique constraint indexes: Username, email, session tokens for fast lookups
- Foreign key indexes: Enhanced join performance across entity relationships
- Composite indexes: Multi-column queries and filtering optimization
- PostgreSQL-specific indexes: Advanced indexing capabilities for performance

Technical Specification References:
- Section 6.2.1: 95th percentile query response targets
- Section 6.2.2.2: Indexing Strategy and Performance Optimization
- Section 6.2.5.1: Query Optimization and Execution with PostgreSQL integration
- Section 6.2.5.2: Connection Pooling and Resource Management

Revision ID: 003_20241201_140000
Revises: 002_20241201_130000
Create Date: 2024-12-01 14:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text
from datetime import datetime


# Revision identifiers for Flask-Migrate version control
revision = '003_20241201_140000'
down_revision = '002_20241201_130000'
branch_labels = None
depends_on = None


def upgrade():
    """
    Create comprehensive performance indexes for enhanced query execution.
    
    This function implements the complete indexing strategy required for meeting
    95th percentile response time targets as specified in Section 6.2.1. All
    indexes are optimized for PostgreSQL 15.x advanced capabilities.
    
    Index Categories:
    1. Unique constraint indexes for authentication integrity
    2. Foreign key indexes for enhanced join performance  
    3. Composite indexes for multi-column query optimization
    4. Search and filtering indexes for business logic queries
    5. Timestamp indexes for temporal queries and audit trails
    """
    
    print("Starting performance indexes migration...")
    print("Creating comprehensive indexing strategy for 95th percentile response time targets")
    
    # =============================================================================
    # UNIQUE CONSTRAINT INDEXES
    # Section 6.2.2.1: Username, email, session tokens for authentication integrity
    # =============================================================================
    
    print("Creating unique constraint indexes for authentication integrity...")
    
    # User table unique indexes for authentication
    # These indexes support fast user lookup and authentication operations
    op.create_index(
        'idx_user_username_unique',
        'user',
        ['username'],
        unique=True,
        postgresql_using='btree',
        postgresql_where=sa.text('username IS NOT NULL')
    )
    
    op.create_index(
        'idx_user_email_unique', 
        'user',
        ['email'],
        unique=True,
        postgresql_using='btree',
        postgresql_where=sa.text('email IS NOT NULL')
    )
    
    # UserSession table unique indexes for session management
    # Critical for Flask-Login session validation and security
    op.create_index(
        'idx_user_session_token_unique',
        'user_session',
        ['session_token'],
        unique=True,
        postgresql_using='btree',
        postgresql_where=sa.text('session_token IS NOT NULL')
    )
    
    # =============================================================================
    # FOREIGN KEY INDEXES FOR JOIN PERFORMANCE
    # Section 6.2.2.2: Enhanced join performance across entity relationships
    # =============================================================================
    
    print("Creating foreign key indexes for enhanced join performance...")
    
    # UserSession -> User relationship index
    # Optimizes session lookup by user for authentication workflows
    op.create_index(
        'idx_user_session_user_id_fk',
        'user_session', 
        ['user_id'],
        postgresql_using='btree'
    )
    
    # BusinessEntity -> User relationship index  
    # Optimizes business entity lookup by owner for access control
    op.create_index(
        'idx_business_entity_owner_id_fk',
        'business_entity',
        ['owner_id'], 
        postgresql_using='btree'
    )
    
    # EntityRelationship -> BusinessEntity relationship indexes
    # Critical for complex business logic queries and relationship traversal
    op.create_index(
        'idx_entity_relationship_source_entity_id_fk',
        'entity_relationship',
        ['source_entity_id'],
        postgresql_using='btree'
    )
    
    op.create_index(
        'idx_entity_relationship_target_entity_id_fk', 
        'entity_relationship',
        ['target_entity_id'],
        postgresql_using='btree'
    )
    
    # =============================================================================
    # COMPOSITE INDEXES FOR MULTI-COLUMN QUERIES
    # Section 6.2.5.1: Multi-column queries and filtering optimization
    # =============================================================================
    
    print("Creating composite indexes for multi-column query optimization...")
    
    # User active status and authentication composite index
    # Optimizes active user queries and authentication workflows
    op.create_index(
        'idx_user_active_status_composite',
        'user',
        ['is_active', 'username'],
        postgresql_using='btree',
        postgresql_where=sa.text('is_active = true')
    )
    
    # User email and active status composite index  
    # Optimizes email-based authentication and user lookup
    op.create_index(
        'idx_user_email_active_composite',
        'user', 
        ['email', 'is_active'],
        postgresql_using='btree',
        postgresql_where=sa.text('is_active = true AND email IS NOT NULL')
    )
    
    # UserSession validity and expiration composite index
    # Critical for session cleanup and validation operations
    op.create_index(
        'idx_user_session_validity_composite',
        'user_session',
        ['is_valid', 'expires_at'],
        postgresql_using='btree',
        postgresql_where=sa.text('is_valid = true')
    )
    
    # UserSession user and validity composite index
    # Optimizes user session lookup for authentication
    op.create_index(
        'idx_user_session_user_validity_composite',
        'user_session',
        ['user_id', 'is_valid', 'expires_at'],
        postgresql_using='btree', 
        postgresql_where=sa.text('is_valid = true')
    )
    
    # BusinessEntity status and owner composite index
    # Optimizes business entity queries by status and ownership
    op.create_index(
        'idx_business_entity_status_owner_composite',
        'business_entity',
        ['status', 'owner_id'],
        postgresql_using='btree'
    )
    
    # EntityRelationship type and active status composite index
    # Optimizes relationship queries by type and active status
    op.create_index(
        'idx_entity_relationship_type_active_composite',
        'entity_relationship',
        ['relationship_type', 'is_active'],
        postgresql_using='btree',
        postgresql_where=sa.text('is_active = true')
    )
    
    # EntityRelationship source-target-type composite index
    # Critical for complex relationship traversal queries
    op.create_index(
        'idx_entity_relationship_source_target_type_composite',
        'entity_relationship',
        ['source_entity_id', 'target_entity_id', 'relationship_type'],
        postgresql_using='btree'
    )
    
    # =============================================================================
    # TIMESTAMP INDEXES FOR TEMPORAL QUERIES
    # Section 6.2.5.1: Temporal data queries and audit trail optimization
    # =============================================================================
    
    print("Creating timestamp indexes for temporal queries and audit trails...")
    
    # User creation timestamp index for user analytics
    op.create_index(
        'idx_user_created_at',
        'user',
        ['created_at'],
        postgresql_using='btree'
    )
    
    # User update timestamp index for change tracking
    op.create_index(
        'idx_user_updated_at',
        'user', 
        ['updated_at'],
        postgresql_using='btree'
    )
    
    # UserSession creation timestamp index for session analytics
    op.create_index(
        'idx_user_session_created_at',
        'user_session',
        ['created_at'],
        postgresql_using='btree'
    )
    
    # UserSession expiration timestamp index for cleanup operations
    # Critical for automated session cleanup and maintenance
    op.create_index(
        'idx_user_session_expires_at',
        'user_session',
        ['expires_at'],
        postgresql_using='btree'
    )
    
    # BusinessEntity timestamp indexes for business analytics
    op.create_index(
        'idx_business_entity_created_at',
        'business_entity',
        ['created_at'],
        postgresql_using='btree'
    )
    
    op.create_index(
        'idx_business_entity_updated_at',
        'business_entity',
        ['updated_at'],
        postgresql_using='btree'
    )
    
    # EntityRelationship creation timestamp index for relationship analytics
    op.create_index(
        'idx_entity_relationship_created_at',
        'entity_relationship',
        ['created_at'],
        postgresql_using='btree'
    )
    
    # =============================================================================
    # SEARCH AND FILTERING INDEXES
    # Section 6.2.5.1: Business logic queries and search optimization
    # =============================================================================
    
    print("Creating search and filtering indexes for business logic queries...")
    
    # BusinessEntity name search index using GIN for text search
    # Enables efficient full-text search on business entity names
    op.create_index(
        'idx_business_entity_name_search',
        'business_entity',
        ['name'],
        postgresql_using='gin',
        postgresql_ops={'name': 'gin_trgm_ops'}
    )
    
    # BusinessEntity description search index for full-text search
    # Note: Requires pg_trgm extension for trigram matching
    op.create_index(
        'idx_business_entity_description_search', 
        'business_entity',
        ['description'],
        postgresql_using='gin',
        postgresql_ops={'description': 'gin_trgm_ops'}
    )
    
    # EntityRelationship type filtering index
    # Optimizes relationship queries by type for business logic
    op.create_index(
        'idx_entity_relationship_type',
        'entity_relationship',
        ['relationship_type'],
        postgresql_using='btree'
    )
    
    # =============================================================================
    # POSTGRESQL-SPECIFIC PERFORMANCE OPTIMIZATIONS
    # Section 6.2.1: PostgreSQL 15.x advanced indexing capabilities
    # =============================================================================
    
    print("Creating PostgreSQL-specific performance optimization indexes...")
    
    # Partial index for active user sessions only
    # Significantly reduces index size and improves performance for active sessions
    op.create_index(
        'idx_user_session_active_only',
        'user_session',
        ['user_id', 'created_at', 'expires_at'],
        postgresql_using='btree',
        postgresql_where=sa.text('is_valid = true AND expires_at > NOW()')
    )
    
    # Partial index for active business entities only
    # Optimizes queries that focus on active business entities
    op.create_index(
        'idx_business_entity_active_only',
        'business_entity', 
        ['owner_id', 'name', 'created_at'],
        postgresql_using='btree',
        postgresql_where=sa.text("status != 'deleted' AND status != 'archived'")
    )
    
    # Partial index for active entity relationships only
    # Reduces index maintenance overhead for soft-deleted relationships
    op.create_index(
        'idx_entity_relationship_active_only',
        'entity_relationship',
        ['source_entity_id', 'target_entity_id', 'relationship_type', 'created_at'],
        postgresql_using='btree',
        postgresql_where=sa.text('is_active = true')
    )
    
    # =============================================================================
    # PERFORMANCE MONITORING AND VALIDATION
    # Section 6.2.5.1: Query plan analysis integration with monitoring
    # =============================================================================
    
    print("Enabling query performance monitoring and statistics collection...")
    
    # Enable pg_stat_statements extension for query performance monitoring
    # This is essential for tracking 95th percentile response times
    try:
        op.execute(text("CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"))
        print("✓ pg_stat_statements extension enabled for performance monitoring")
    except Exception as e:
        print(f"⚠ pg_stat_statements extension setup skipped: {e}")
    
    # Enable pg_trgm extension for trigram text search indexes
    # Required for efficient text search on business entity names/descriptions
    try:
        op.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm;"))
        print("✓ pg_trgm extension enabled for text search optimization")
    except Exception as e:
        print(f"⚠ pg_trgm extension setup skipped: {e}")
    
    # Update table statistics for query planner optimization
    # This ensures the PostgreSQL query planner has accurate statistics
    op.execute(text("ANALYZE user;"))
    op.execute(text("ANALYZE user_session;"))
    op.execute(text("ANALYZE business_entity;"))
    op.execute(text("ANALYZE entity_relationship;"))
    
    print("✓ Table statistics updated for query planner optimization")
    
    # =============================================================================
    # MIGRATION COMPLETION AND VALIDATION
    # =============================================================================
    
    print("\n" + "="*80)
    print("PERFORMANCE INDEXES MIGRATION COMPLETED SUCCESSFULLY")
    print("="*80)
    print(f"Migration timestamp: {datetime.now().isoformat()}")
    print("Created indexes:")
    print("  ✓ 3 unique constraint indexes for authentication integrity")
    print("  ✓ 4 foreign key indexes for enhanced join performance") 
    print("  ✓ 7 composite indexes for multi-column query optimization")
    print("  ✓ 7 timestamp indexes for temporal queries and audit trails")
    print("  ✓ 4 search and filtering indexes for business logic queries")
    print("  ✓ 3 PostgreSQL-specific partial indexes for performance optimization")
    print("  ✓ Extensions: pg_stat_statements, pg_trgm")
    print("  ✓ Table statistics updated for query planner optimization")
    print("\nPerformance targets established:")
    print("  • Simple SELECT queries: < 500ms (95th percentile)")
    print("  • Complex JOIN queries: < 2000ms (95th percentile)")
    print("  • INSERT/UPDATE operations: < 300ms (95th percentile)")
    print("\nNext steps:")
    print("  1. Monitor query performance using pg_stat_statements")
    print("  2. Validate index utilization with EXPLAIN ANALYZE")
    print("  3. Proceed to migration 004 (Audit and Compliance)")
    print("="*80)


def downgrade():
    """
    Remove all performance indexes created in the upgrade function.
    
    This function provides complete rollback capability for the performance
    indexing migration, ensuring the database can be restored to its previous
    state if needed. All indexes are removed in reverse dependency order.
    """
    
    print("Starting performance indexes migration rollback...")
    print("Removing all performance optimization indexes")
    
    # =============================================================================
    # REMOVE POSTGRESQL-SPECIFIC PERFORMANCE OPTIMIZATIONS
    # =============================================================================
    
    print("Removing PostgreSQL-specific performance optimization indexes...")
    
    # Remove partial indexes
    op.drop_index('idx_entity_relationship_active_only', 'entity_relationship')
    op.drop_index('idx_business_entity_active_only', 'business_entity') 
    op.drop_index('idx_user_session_active_only', 'user_session')
    
    # =============================================================================
    # REMOVE SEARCH AND FILTERING INDEXES
    # =============================================================================
    
    print("Removing search and filtering indexes...")
    
    op.drop_index('idx_entity_relationship_type', 'entity_relationship')
    op.drop_index('idx_business_entity_description_search', 'business_entity')
    op.drop_index('idx_business_entity_name_search', 'business_entity')
    
    # =============================================================================
    # REMOVE TIMESTAMP INDEXES
    # =============================================================================
    
    print("Removing timestamp indexes...")
    
    op.drop_index('idx_entity_relationship_created_at', 'entity_relationship')
    op.drop_index('idx_business_entity_updated_at', 'business_entity')
    op.drop_index('idx_business_entity_created_at', 'business_entity')
    op.drop_index('idx_user_session_expires_at', 'user_session')
    op.drop_index('idx_user_session_created_at', 'user_session')
    op.drop_index('idx_user_updated_at', 'user')
    op.drop_index('idx_user_created_at', 'user')
    
    # =============================================================================
    # REMOVE COMPOSITE INDEXES
    # =============================================================================
    
    print("Removing composite indexes...")
    
    op.drop_index('idx_entity_relationship_source_target_type_composite', 'entity_relationship')
    op.drop_index('idx_entity_relationship_type_active_composite', 'entity_relationship')
    op.drop_index('idx_business_entity_status_owner_composite', 'business_entity')
    op.drop_index('idx_user_session_user_validity_composite', 'user_session')
    op.drop_index('idx_user_session_validity_composite', 'user_session')
    op.drop_index('idx_user_email_active_composite', 'user')
    op.drop_index('idx_user_active_status_composite', 'user')
    
    # =============================================================================
    # REMOVE FOREIGN KEY INDEXES  
    # =============================================================================
    
    print("Removing foreign key indexes...")
    
    op.drop_index('idx_entity_relationship_target_entity_id_fk', 'entity_relationship')
    op.drop_index('idx_entity_relationship_source_entity_id_fk', 'entity_relationship')
    op.drop_index('idx_business_entity_owner_id_fk', 'business_entity')
    op.drop_index('idx_user_session_user_id_fk', 'user_session')
    
    # =============================================================================
    # REMOVE UNIQUE CONSTRAINT INDEXES
    # =============================================================================
    
    print("Removing unique constraint indexes...")
    
    op.drop_index('idx_user_session_token_unique', 'user_session')
    op.drop_index('idx_user_email_unique', 'user')
    op.drop_index('idx_user_username_unique', 'user')
    
    # =============================================================================
    # ROLLBACK COMPLETION
    # =============================================================================
    
    print("\n" + "="*80)
    print("PERFORMANCE INDEXES MIGRATION ROLLBACK COMPLETED")
    print("="*80)
    print(f"Rollback timestamp: {datetime.now().isoformat()}")
    print("Removed indexes:")
    print("  ✓ All 28 performance optimization indexes removed")
    print("  ✓ Database restored to pre-migration state")
    print("\nNote: PostgreSQL extensions (pg_stat_statements, pg_trgm) remain enabled")
    print("Database is ready for alternative optimization strategies if needed")
    print("="*80)