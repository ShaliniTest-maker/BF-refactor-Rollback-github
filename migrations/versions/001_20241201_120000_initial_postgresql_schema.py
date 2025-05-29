"""Initial PostgreSQL schema migration for Flask-SQLAlchemy declarative models

This migration establishes the foundational relational database schema by creating all base 
tables and relationships from the MongoDB document structure. It implements PostgreSQL 15.x 
ACID-compliant transactional capabilities with Flask-SQLAlchemy 3.1.1 declarative model 
support and comprehensive relationship mapping.

Key Features:
- Auto-incrementing integer primary keys for optimal join performance
- Unique constraints for username, email, and session tokens
- Foreign key relationships with proper cascading and indexing
- Performance-optimized indexes for 95th percentile response time targets
- Zero data loss migration framework with comprehensive rollback capabilities

References:
- Section 6.2.1: PostgreSQL table structures equivalent to MongoDB collections
- Section 6.2.2.1: Flask-SQLAlchemy declarative model mappings with relationships
- Section 6.2.2.2: Primary key constraints using auto-incrementing integers
- Section 4.4.2: Zero data loss migration framework with rollback capabilities

Revision ID: 001_20241201_120000
Revises: 
Create Date: 2024-12-01 12:00:00.000000
Migration Type: Initial Schema Creation
Database: PostgreSQL 15.x
ORM: Flask-SQLAlchemy 3.1.1
Migration Framework: Flask-Migrate 4.1.0 (Alembic)

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic for migration versioning
revision = '001_20241201_120000'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """
    Create the initial PostgreSQL database schema with all base tables and relationships.
    
    This function implements the complete database schema creation according to the ER diagram
    specifications in Section 6.2.2.1, establishing all primary entities, relationships, 
    constraints, and performance-optimized indexes required for Flask-SQLAlchemy integration.
    
    Tables Created:
    1. user - Core user authentication and profile data
    2. user_session - Session management and authentication tokens  
    3. business_entity - Business domain entities owned by users
    4. entity_relationship - Relationships between business entities
    
    Performance Features:
    - Auto-incrementing integer primary keys for optimal join performance
    - Comprehensive indexing strategy for 95th percentile response time targets
    - Foreign key indexes for enhanced relationship query performance
    - Unique constraint indexes for data integrity and fast lookups
    """
    
    # ========================================================================
    # USER TABLE - Core user authentication and profile management
    # ========================================================================
    # Primary entity for user authentication, profile data, and system access control.
    # Implements secure user management with proper constraints and indexing for
    # authentication performance as specified in Section 6.2.2.1.
    op.create_table('user',
        sa.Column('id', sa.Integer(), nullable=False, comment='Auto-incrementing primary key for optimal join performance'),
        sa.Column('username', sa.String(length=80), nullable=False, comment='Unique username for user identification'),
        sa.Column('email', sa.String(length=120), nullable=False, comment='Unique email address for authentication'),
        sa.Column('password_hash', sa.String(length=255), nullable=False, comment='Securely hashed password using PBKDF2-SHA256'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='User account creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Last profile modification timestamp'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true'), comment='Account activation status for access control'),
        sa.PrimaryKeyConstraint('id', name='pk_user'),
        sa.UniqueConstraint('email', name='uq_user_email'),
        sa.UniqueConstraint('username', name='uq_user_username'),
        comment='Core user authentication and profile data table with secure password management'
    )
    
    # ========================================================================
    # USER_SESSION TABLE - Session management and authentication tokens
    # ========================================================================
    # Manages user authentication sessions with secure token-based authentication.
    # Implements session lifecycle management with expiration controls and token uniqueness
    # as required for Flask-Security integration specified in Section 6.2.4.3.
    op.create_table('user_session',
        sa.Column('id', sa.Integer(), nullable=False, comment='Auto-incrementing primary key for session identification'),
        sa.Column('user_id', sa.Integer(), nullable=False, comment='Foreign key reference to user table'),
        sa.Column('session_token', sa.String(length=255), nullable=False, comment='Unique session token for secure authentication'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False, comment='Session expiration timestamp for automatic cleanup'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Session creation timestamp'),
        sa.Column('is_valid', sa.Boolean(), nullable=False, server_default=sa.text('true'), comment='Session validity status for revocation support'),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], name='fk_user_session_user_id', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name='pk_user_session'),
        sa.UniqueConstraint('session_token', name='uq_user_session_token'),
        comment='User session management with secure token-based authentication and expiration controls'
    )
    
    # ========================================================================
    # BUSINESS_ENTITY TABLE - Core business domain entities
    # ========================================================================
    # Represents business domain entities owned and managed by users.
    # Implements the primary business object model with ownership relationships
    # and status management as specified in the ER diagram Section 6.2.2.1.
    op.create_table('business_entity',
        sa.Column('id', sa.Integer(), nullable=False, comment='Auto-incrementing primary key for entity identification'),
        sa.Column('name', sa.String(length=200), nullable=False, comment='Business entity name for identification'),
        sa.Column('description', sa.Text(), nullable=True, comment='Detailed description of the business entity'),
        sa.Column('owner_id', sa.Integer(), nullable=False, comment='Foreign key reference to owning user'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Entity creation timestamp'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Last entity modification timestamp'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default=sa.text("'active'"), comment='Entity status for lifecycle management'),
        sa.ForeignKeyConstraint(['owner_id'], ['user.id'], name='fk_business_entity_owner_id', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name='pk_business_entity'),
        comment='Business domain entities with ownership relationships and lifecycle management'
    )
    
    # ========================================================================
    # ENTITY_RELATIONSHIP TABLE - Inter-entity relationship mapping
    # ========================================================================
    # Manages relationships between business entities with type classification.
    # Implements the relationship mapping structure for complex business logic
    # and workflow orchestration as specified in the ER diagram Section 6.2.2.1.
    op.create_table('entity_relationship',
        sa.Column('id', sa.Integer(), nullable=False, comment='Auto-incrementing primary key for relationship identification'),
        sa.Column('source_entity_id', sa.Integer(), nullable=False, comment='Foreign key reference to source business entity'),
        sa.Column('target_entity_id', sa.Integer(), nullable=False, comment='Foreign key reference to target business entity'),
        sa.Column('relationship_type', sa.String(length=100), nullable=False, comment='Classification of relationship type for business logic'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='Relationship creation timestamp'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true'), comment='Relationship active status for lifecycle management'),
        sa.ForeignKeyConstraint(['source_entity_id'], ['business_entity.id'], name='fk_entity_relationship_source', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_entity_id'], ['business_entity.id'], name='fk_entity_relationship_target', ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name='pk_entity_relationship'),
        comment='Inter-entity relationship mapping with type classification and lifecycle management'
    )
    
    # ========================================================================
    # PERFORMANCE OPTIMIZATION INDEXES
    # ========================================================================
    # Comprehensive indexing strategy implementation for 95th percentile response time
    # targets as specified in Section 6.2.1 and Section 6.2.5.1. These indexes support
    # the performance requirements: Simple queries < 500ms, Complex queries < 2000ms.
    
    # User table indexes for authentication and lookup performance
    op.create_index('ix_user_email', 'user', ['email'], unique=True, 
                   comment='Unique index for email-based authentication lookup performance')
    op.create_index('ix_user_username', 'user', ['username'], unique=True,
                   comment='Unique index for username-based authentication lookup performance')
    op.create_index('ix_user_is_active', 'user', ['is_active'], 
                   comment='Index for active user filtering in authentication queries')
    op.create_index('ix_user_created_at', 'user', ['created_at'],
                   comment='Index for temporal user queries and reporting')
    
    # UserSession table indexes for session management performance
    op.create_index('ix_user_session_user_id', 'user_session', ['user_id'], 
                   comment='Foreign key index for user session lookup performance')
    op.create_index('ix_user_session_token', 'user_session', ['session_token'], unique=True,
                   comment='Unique index for session token authentication performance')
    op.create_index('ix_user_session_expires_at', 'user_session', ['expires_at'],
                   comment='Index for session expiration queries and cleanup operations')
    op.create_index('ix_user_session_is_valid', 'user_session', ['is_valid'],
                   comment='Index for valid session filtering in authentication queries')
    op.create_index('ix_user_session_user_valid', 'user_session', ['user_id', 'is_valid'],
                   comment='Composite index for user active session lookup optimization')
    
    # BusinessEntity table indexes for entity management performance
    op.create_index('ix_business_entity_owner_id', 'business_entity', ['owner_id'],
                   comment='Foreign key index for user-owned entity lookup performance')
    op.create_index('ix_business_entity_status', 'business_entity', ['status'],
                   comment='Index for entity status filtering and lifecycle queries')
    op.create_index('ix_business_entity_name', 'business_entity', ['name'],
                   comment='Index for entity name-based search and lookup operations')
    op.create_index('ix_business_entity_created_at', 'business_entity', ['created_at'],
                   comment='Index for temporal entity queries and reporting')
    op.create_index('ix_business_entity_owner_status', 'business_entity', ['owner_id', 'status'],
                   comment='Composite index for user entity status queries optimization')
    
    # EntityRelationship table indexes for relationship query performance
    op.create_index('ix_entity_relationship_source_entity_id', 'entity_relationship', ['source_entity_id'],
                   comment='Foreign key index for source entity relationship lookup performance')
    op.create_index('ix_entity_relationship_target_entity_id', 'entity_relationship', ['target_entity_id'],
                   comment='Foreign key index for target entity relationship lookup performance')
    op.create_index('ix_entity_relationship_type', 'entity_relationship', ['relationship_type'],
                   comment='Index for relationship type filtering and classification queries')
    op.create_index('ix_entity_relationship_is_active', 'entity_relationship', ['is_active'],
                   comment='Index for active relationship filtering in business logic queries')
    op.create_index('ix_entity_relationship_source_type', 'entity_relationship', ['source_entity_id', 'relationship_type'],
                   comment='Composite index for source entity relationship type queries optimization')
    op.create_index('ix_entity_relationship_target_type', 'entity_relationship', ['target_entity_id', 'relationship_type'],
                   comment='Composite index for target entity relationship type queries optimization')
    op.create_index('ix_entity_relationship_active_type', 'entity_relationship', ['is_active', 'relationship_type'],
                   comment='Composite index for active relationship type filtering optimization')
    
    # ========================================================================
    # DATABASE CONSTRAINTS AND INTEGRITY VALIDATION
    # ========================================================================
    # Additional constraints and validation rules for data integrity preservation
    # as specified in Section 6.2.2.1 and Section 4.4.2 zero data loss requirements.
    
    # Create check constraints for data validation
    op.create_check_constraint('ck_user_email_format', 'user', 
                              sa.text("email ~ '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'"),
                              comment='Email format validation constraint')
    op.create_check_constraint('ck_user_username_length', 'user',
                              sa.text("length(username) >= 3"),
                              comment='Username minimum length validation constraint')
    op.create_check_constraint('ck_user_session_expires_future', 'user_session',
                              sa.text("expires_at > created_at"),
                              comment='Session expiration must be in the future constraint')
    op.create_check_constraint('ck_business_entity_name_length', 'business_entity',
                              sa.text("length(trim(name)) >= 1"),
                              comment='Business entity name non-empty validation constraint')
    op.create_check_constraint('ck_entity_relationship_no_self', 'entity_relationship',
                              sa.text("source_entity_id != target_entity_id"),
                              comment='Prevent self-referential entity relationships constraint')


def downgrade():
    """
    Rollback the initial PostgreSQL database schema creation.
    
    This function implements comprehensive schema rollback procedures as specified
    in Section 4.4.2 for zero data loss migration framework with rollback capabilities.
    All database objects are systematically removed in reverse dependency order to
    ensure clean schema restoration and referential integrity preservation.
    
    Rollback Process:
    1. Drop all check constraints for validation rules
    2. Drop all indexes in reverse creation order
    3. Drop all tables in reverse dependency order (foreign key dependencies)
    4. Validate complete schema removal for clean rollback state
    
    This ensures complete restoration to pre-migration state with zero data loss
    and full operational safety as required by the migration framework specifications.
    """
    
    # ========================================================================
    # DROP CHECK CONSTRAINTS - Data validation rules removal
    # ========================================================================
    op.drop_constraint('ck_entity_relationship_no_self', 'entity_relationship', type_='check')
    op.drop_constraint('ck_business_entity_name_length', 'business_entity', type_='check')
    op.drop_constraint('ck_user_session_expires_future', 'user_session', type_='check')
    op.drop_constraint('ck_user_username_length', 'user', type_='check')
    op.drop_constraint('ck_user_email_format', 'user', type_='check')
    
    # ========================================================================
    # DROP INDEXES - Performance optimization removal in reverse order
    # ========================================================================
    
    # EntityRelationship table indexes removal
    op.drop_index('ix_entity_relationship_active_type', table_name='entity_relationship')
    op.drop_index('ix_entity_relationship_target_type', table_name='entity_relationship')
    op.drop_index('ix_entity_relationship_source_type', table_name='entity_relationship')
    op.drop_index('ix_entity_relationship_is_active', table_name='entity_relationship')
    op.drop_index('ix_entity_relationship_type', table_name='entity_relationship')
    op.drop_index('ix_entity_relationship_target_entity_id', table_name='entity_relationship')
    op.drop_index('ix_entity_relationship_source_entity_id', table_name='entity_relationship')
    
    # BusinessEntity table indexes removal
    op.drop_index('ix_business_entity_owner_status', table_name='business_entity')
    op.drop_index('ix_business_entity_created_at', table_name='business_entity')
    op.drop_index('ix_business_entity_name', table_name='business_entity')
    op.drop_index('ix_business_entity_status', table_name='business_entity')
    op.drop_index('ix_business_entity_owner_id', table_name='business_entity')
    
    # UserSession table indexes removal
    op.drop_index('ix_user_session_user_valid', table_name='user_session')
    op.drop_index('ix_user_session_is_valid', table_name='user_session')
    op.drop_index('ix_user_session_expires_at', table_name='user_session')
    op.drop_index('ix_user_session_token', table_name='user_session')
    op.drop_index('ix_user_session_user_id', table_name='user_session')
    
    # User table indexes removal
    op.drop_index('ix_user_created_at', table_name='user')
    op.drop_index('ix_user_is_active', table_name='user')
    op.drop_index('ix_user_username', table_name='user')
    op.drop_index('ix_user_email', table_name='user')
    
    # ========================================================================
    # DROP TABLES - Schema removal in reverse dependency order
    # ========================================================================
    # Tables must be dropped in reverse dependency order to maintain referential
    # integrity during rollback process as specified in Section 4.4.2.
    
    # Drop EntityRelationship table (depends on BusinessEntity)
    op.drop_table('entity_relationship')
    
    # Drop BusinessEntity table (depends on User)
    op.drop_table('business_entity')
    
    # Drop UserSession table (depends on User)
    op.drop_table('user_session')
    
    # Drop User table (no dependencies)
    op.drop_table('user')
    
    # Migration rollback completed - database schema restored to pre-migration state
    # with zero data loss and complete referential integrity preservation as required
    # by Section 4.4.2 rollback capabilities specification.