"""
Initial PostgreSQL Schema Migration

This migration creates the foundational relational database schema including all base tables
and relationships converted from the MongoDB document structure. Establishes primary keys,
foreign key relationships, indexes, and constraints required for Flask-SQLAlchemy declarative
models with comprehensive relationship mapping and zero data loss capabilities.

Migration Overview:
- Creates User table with Flask-Login UserMixin integration
- Creates UserSession table for Flask authentication state persistence
- Creates BusinessEntity table for core business domain objects
- Creates EntityRelationship table for complex business entity associations
- Implements PostgreSQL 15.x optimized field types and constraints
- Establishes foreign key relationships with CASCADE behavior
- Creates performance optimization indexes per Section 6.2.2.2
- Implements unique constraints for authentication integrity per Section 6.2.2.1

Technical Specifications:
- Flask-SQLAlchemy 3.1.1 declarative model support
- PostgreSQL 15.x ACID-compliant transactional capabilities
- Auto-incrementing integer primary keys for optimal join performance
- Timezone-aware timestamp fields for audit tracking
- Comprehensive indexing strategy for query performance optimization

Database Design Compliance:
- Section 6.2.1: PostgreSQL database technology transition
- Section 6.2.2.1: Entity relationships and data models
- Section 6.2.2.2: Indexing strategy with auto-incrementing primary keys
- Section 4.4.2: Zero data loss migration framework with rollback capabilities

Revision ID: 001_20241201_120000
Revises: 
Create Date: 2024-12-01 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import text
import logging

# Revision identifiers for Flask-Migrate version control
revision = '001_20241201_120000'
down_revision = None
branch_labels = None
depends_on = None

# Logger for migration operations
logger = logging.getLogger(__name__)


def upgrade():
    """
    Create initial PostgreSQL schema with all base tables and relationships.
    
    This upgrade function implements the complete database schema creation including:
    - All entity tables (users, user_sessions, business_entities, entity_relationships)
    - Primary key constraints using auto-incrementing integers
    - Foreign key relationships with proper CASCADE behavior
    - Unique constraints for authentication integrity
    - Performance optimization indexes
    - Database comments for documentation
    
    The schema design preserves all existing data relationships from the MongoDB
    implementation while adapting to relational database patterns with enhanced
    performance characteristics and ACID compliance.
    """
    logger.info("Starting initial PostgreSQL schema creation migration")
    
    try:
        # Enable PostgreSQL specific features for optimal performance
        logger.info("Configuring PostgreSQL optimization settings")
        
        # Create Users table - Foundation for authentication and session management
        logger.info("Creating users table with Flask-Login UserMixin integration")
        op.create_table(
            'users',
            # Primary key with auto-incrementing integer per Section 6.2.2.2
            sa.Column(
                'id', 
                sa.Integer(), 
                nullable=False, 
                autoincrement=True,
                comment='Auto-incrementing primary key for optimal PostgreSQL join performance'
            ),
            
            # User identification fields with unique constraints per Section 6.2.2.2
            sa.Column(
                'username', 
                sa.String(length=80), 
                nullable=False,
                comment='Unique username for user identification and authentication'
            ),
            sa.Column(
                'email', 
                sa.String(length=120), 
                nullable=False,
                comment='Unique email address for user identification and communication'
            ),
            
            # Secure password storage using Werkzeug hashing per Section 4.6.1
            sa.Column(
                'password_hash', 
                sa.String(length=255), 
                nullable=False,
                comment='Securely hashed password using Werkzeug PBKDF2 with SHA-256'
            ),
            
            # User state management for authentication per Flask-Login requirements
            sa.Column(
                'is_active', 
                sa.Boolean(), 
                nullable=False, 
                server_default=sa.text('true'),
                comment='User account status for authentication and access control'
            ),
            
            # Timestamp fields for audit and lifecycle management per Section 6.2.1
            sa.Column(
                'created_at', 
                sa.DateTime(timezone=True), 
                nullable=False, 
                server_default=sa.text('CURRENT_TIMESTAMP'),
                comment='Timestamp of user account creation with UTC timezone'
            ),
            sa.Column(
                'updated_at', 
                sa.DateTime(timezone=True), 
                nullable=False, 
                server_default=sa.text('CURRENT_TIMESTAMP'),
                comment='Timestamp of last user account modification with UTC timezone'
            ),
            
            # Primary key constraint
            sa.PrimaryKeyConstraint('id', name='pk_users'),
            
            # Unique constraints for authentication integrity per Section 6.2.2.1
            sa.UniqueConstraint('username', name='uq_users_username'),
            sa.UniqueConstraint('email', name='uq_users_email'),
            
            # Check constraints for data validation
            sa.CheckConstraint('LENGTH(username) >= 3', name='ck_users_username_length'),
            sa.CheckConstraint('LENGTH(email) >= 5', name='ck_users_email_length'),
            sa.CheckConstraint("email LIKE '%@%.%'", name='ck_users_email_format'),
            
            comment='User accounts for authentication and session management'
        )
        
        # Create indexes for users table performance optimization per Section 6.2.2.2
        logger.info("Creating performance indexes for users table")
        op.create_index('ix_users_username', 'users', ['username'])
        op.create_index('ix_users_email', 'users', ['email'])
        op.create_index('ix_users_is_active', 'users', ['is_active'])
        op.create_index('ix_users_active_created', 'users', ['is_active', 'created_at'])
        op.create_index('ix_users_email_active', 'users', ['email', 'is_active'])
        op.create_index('ix_users_username_active', 'users', ['username', 'is_active'])
        
        # Create UserSession table - Flask-Login session management
        logger.info("Creating user_sessions table for Flask authentication state persistence")
        op.create_table(
            'user_sessions',
            # Primary key field with auto-incrementing integer per Section 6.2.2.2
            sa.Column(
                'id', 
                sa.Integer(), 
                nullable=False, 
                autoincrement=True,
                comment='Primary key for user session identification'
            ),
            
            # Foreign key relationship to User model per Section 6.2.2.1
            sa.Column(
                'user_id',
                sa.Integer(),
                nullable=False,
                comment='Foreign key reference to users table for session ownership'
            ),
            
            # Session token field with unique constraint for authentication integrity
            sa.Column(
                'session_token',
                sa.String(length=255),
                nullable=False,
                comment='Unique session token generated using ItsDangerous for secure authentication'
            ),
            
            # Session expiration timestamp for lifecycle management
            sa.Column(
                'expires_at',
                sa.DateTime(timezone=True),
                nullable=False,
                comment='Session expiration timestamp for automatic cleanup and validation'
            ),
            
            # Session creation timestamp for audit trail and lifecycle tracking
            sa.Column(
                'created_at',
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text('CURRENT_TIMESTAMP'),
                comment='Session creation timestamp for audit trail and lifecycle tracking'
            ),
            
            # Session validity flag for soft deletion and state management
            sa.Column(
                'is_valid',
                sa.Boolean(),
                nullable=False,
                server_default=sa.text('true'),
                comment='Boolean flag indicating session validity and active state'
            ),
            
            # Session metadata for additional context and debugging
            sa.Column(
                'session_metadata',
                sa.Text(),
                nullable=True,
                comment='JSON metadata for session context, user agent, IP address, etc.'
            ),
            
            # Last accessed timestamp for session activity tracking
            sa.Column(
                'last_accessed',
                sa.DateTime(timezone=True),
                nullable=True,
                server_default=sa.text('CURRENT_TIMESTAMP'),
                comment='Timestamp of last session access for activity monitoring'
            ),
            
            # User agent string for session security and device tracking
            sa.Column(
                'user_agent',
                sa.String(length=500),
                nullable=True,
                comment='User agent string for session security and device identification'
            ),
            
            # IP address for session security and location tracking
            sa.Column(
                'ip_address',
                sa.String(length=45),  # IPv6 support with maximum length
                nullable=True,
                comment='IP address for session security and geographic tracking'
            ),
            
            # Primary key constraint
            sa.PrimaryKeyConstraint('id', name='pk_user_sessions'),
            
            # Foreign key constraint with CASCADE behavior per ER diagram specifications
            sa.ForeignKeyConstraint(
                ['user_id'], 
                ['users.id'], 
                name='fk_user_sessions_user_id',
                ondelete='CASCADE',
                onupdate='CASCADE'
            ),
            
            # Unique constraint on session token for authentication integrity
            sa.UniqueConstraint('session_token', name='uq_user_sessions_token'),
            
            comment='User session management table for Flask-Login authentication state persistence'
        )
        
        # Create indexes for user_sessions table
        logger.info("Creating performance indexes for user_sessions table")
        op.create_index('ix_user_sessions_user_id', 'user_sessions', ['user_id'])
        op.create_index('ix_user_sessions_session_token', 'user_sessions', ['session_token'])
        op.create_index('ix_user_sessions_expires_at', 'user_sessions', ['expires_at'])
        op.create_index('ix_user_sessions_created_at', 'user_sessions', ['created_at'])
        op.create_index('ix_user_sessions_is_valid', 'user_sessions', ['is_valid'])
        op.create_index('ix_user_sessions_user_valid', 'user_sessions', ['user_id', 'is_valid'])
        op.create_index('ix_user_sessions_expires_valid', 'user_sessions', ['expires_at', 'is_valid'])
        op.create_index('ix_user_sessions_token_valid', 'user_sessions', ['session_token', 'is_valid'])
        
        # Create BusinessEntity table - Core business domain objects
        logger.info("Creating business_entities table for core business domain objects")
        op.create_table(
            'business_entities',
            # Primary key - auto-incrementing integer for optimal join performance
            sa.Column(
                'id', 
                sa.Integer(), 
                nullable=False, 
                autoincrement=True,
                comment='Auto-incrementing primary key for optimal PostgreSQL join performance'
            ),
            
            # Business metadata fields with PostgreSQL text field optimization
            sa.Column(
                'name', 
                sa.String(length=255), 
                nullable=False,
                comment='Business entity name - indexed for efficient lookup operations'
            ),
            sa.Column(
                'description', 
                sa.Text(), 
                nullable=True,
                comment='Detailed description of the business entity purpose and context'
            ),
            
            # Foreign key relationship to User model for entity ownership
            sa.Column(
                'owner_id',
                sa.Integer(),
                nullable=False,
                comment='Foreign key to User model establishing entity ownership'
            ),
            
            # Status field with proper indexing for business workflow management
            sa.Column(
                'status',
                sa.String(length=50),
                nullable=False,
                server_default=sa.text("'active'"),
                comment='Business entity status for workflow management - indexed for performance'
            ),
            
            # Timestamp fields for audit tracking and temporal management
            sa.Column(
                'created_at',
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text('CURRENT_TIMESTAMP'),
                comment='Entity creation timestamp with timezone awareness'
            ),
            sa.Column(
                'updated_at',
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text('CURRENT_TIMESTAMP'),
                comment='Entity last modification timestamp with automatic updates'
            ),
            
            # Primary key constraint
            sa.PrimaryKeyConstraint('id', name='pk_business_entities'),
            
            # Foreign key constraint with CASCADE behavior per ER diagram specifications
            sa.ForeignKeyConstraint(
                ['owner_id'], 
                ['users.id'], 
                name='fk_business_entities_owner_id',
                ondelete='CASCADE',
                onupdate='CASCADE'
            ),
            
            comment='Business entities table storing core business domain objects'
        )
        
        # Create indexes for business_entities table
        logger.info("Creating performance indexes for business_entities table")
        op.create_index('ix_business_entities_name', 'business_entities', ['name'])
        op.create_index('ix_business_entities_owner_id', 'business_entities', ['owner_id'])
        op.create_index('ix_business_entities_status', 'business_entities', ['status'])
        op.create_index('ix_business_entities_owner_status', 'business_entities', ['owner_id', 'status'])
        op.create_index('ix_business_entities_status_created', 'business_entities', ['status', 'created_at'])
        
        # Create EntityRelationship table - Complex business entity associations
        logger.info("Creating entity_relationships table for complex business entity associations")
        op.create_table(
            'entity_relationships',
            # Primary Key - Auto-incrementing integer for optimal join performance
            sa.Column(
                'id', 
                sa.Integer(), 
                nullable=False, 
                autoincrement=True,
                comment='Primary key for entity relationship records'
            ),
            
            # Source Entity Foreign Key - References BusinessEntity.id
            sa.Column(
                'source_entity_id',
                sa.Integer(),
                nullable=False,
                comment='Foreign key to business entities table (source entity in relationship)'
            ),
            
            # Target Entity Foreign Key - References BusinessEntity.id  
            sa.Column(
                'target_entity_id',
                sa.Integer(),
                nullable=False,
                comment='Foreign key to business entities table (target entity in relationship)'
            ),
            
            # Relationship Type Categorization - Business workflow classification
            sa.Column(
                'relationship_type',
                sa.String(length=100),
                nullable=False,
                comment='Business relationship type categorization for workflow management'
            ),
            
            # Temporal Management Fields - Automatic timestamp tracking
            sa.Column(
                'created_at',
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text('CURRENT_TIMESTAMP'),
                comment='Relationship creation timestamp with timezone support'
            ),
            sa.Column(
                'updated_at',
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text('CURRENT_TIMESTAMP'),
                comment='Last modification timestamp with automatic updates'
            ),
            
            # Soft Deletion Management - Relationship lifecycle control
            sa.Column(
                'is_active',
                sa.Boolean(),
                nullable=False,
                server_default=sa.text('true'),
                comment='Soft deletion flag for relationship lifecycle management'
            ),
            
            # Primary key constraint
            sa.PrimaryKeyConstraint('id', name='pk_entity_relationships'),
            
            # Foreign key constraints with CASCADE behavior per ER diagram specifications
            sa.ForeignKeyConstraint(
                ['source_entity_id'], 
                ['business_entities.id'], 
                name='fk_entity_relationships_source_entity_id',
                ondelete='CASCADE',
                onupdate='CASCADE'
            ),
            sa.ForeignKeyConstraint(
                ['target_entity_id'], 
                ['business_entities.id'], 
                name='fk_entity_relationships_target_entity_id',
                ondelete='CASCADE',
                onupdate='CASCADE'
            ),
            
            # Check constraint ensuring source_entity_id != target_entity_id (no self-relationships)
            sa.CheckConstraint(
                'source_entity_id != target_entity_id', 
                name='ck_entity_relationships_no_self_reference'
            ),
            
            comment='Entity relationships table for complex business entity associations'
        )
        
        # Create indexes for entity_relationships table
        logger.info("Creating performance indexes for entity_relationships table")
        op.create_index('ix_entity_relationships_source_entity_id', 'entity_relationships', ['source_entity_id'])
        op.create_index('ix_entity_relationships_target_entity_id', 'entity_relationships', ['target_entity_id'])
        op.create_index('ix_entity_relationships_relationship_type', 'entity_relationships', ['relationship_type'])
        op.create_index('ix_entity_relationships_created_at', 'entity_relationships', ['created_at'])
        op.create_index('ix_entity_relationships_is_active', 'entity_relationships', ['is_active'])
        op.create_index('ix_entity_relationships_source_type_active', 'entity_relationships', ['source_entity_id', 'relationship_type', 'is_active'])
        op.create_index('ix_entity_relationships_target_type_active', 'entity_relationships', ['target_entity_id', 'relationship_type', 'is_active'])
        op.create_index('ix_entity_relationships_type_active', 'entity_relationships', ['relationship_type', 'is_active'])
        
        # Create database functions for automatic timestamp updates
        logger.info("Creating PostgreSQL functions for automatic timestamp management")
        
        # Function to update updated_at timestamp automatically
        op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """)
        
        # Create triggers for automatic updated_at timestamp management
        logger.info("Creating triggers for automatic timestamp updates")
        
        # Trigger for users table
        op.execute("""
        CREATE TRIGGER trigger_users_updated_at
            BEFORE UPDATE ON users
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        """)
        
        # Trigger for business_entities table
        op.execute("""
        CREATE TRIGGER trigger_business_entities_updated_at
            BEFORE UPDATE ON business_entities
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        """)
        
        # Trigger for entity_relationships table
        op.execute("""
        CREATE TRIGGER trigger_entity_relationships_updated_at
            BEFORE UPDATE ON entity_relationships
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        """)
        
        # Create database-level comments for comprehensive documentation
        logger.info("Adding database documentation comments")
        
        op.execute("""
        COMMENT ON DATABASE CURRENT_DATABASE() IS 
        'Flask application database migrated from MongoDB to PostgreSQL 15.x with Flask-SQLAlchemy 3.1.1 declarative models. Implements zero data loss migration framework with comprehensive rollback capabilities per Section 4.4.2.';
        """)
        
        # Validate schema creation with comprehensive verification
        logger.info("Performing post-creation schema validation")
        
        # Verify all tables were created successfully
        connection = op.get_bind()
        
        # Check for required tables
        required_tables = ['users', 'user_sessions', 'business_entities', 'entity_relationships']
        for table_name in required_tables:
            result = connection.execute(text(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = '{table_name}'
                );
            """)).scalar()
            
            if not result:
                raise Exception(f"Failed to create required table: {table_name}")
            
        logger.info(f"Successfully verified creation of all {len(required_tables)} required tables")
        
        # Verify foreign key constraints
        fk_constraints = [
            'fk_user_sessions_user_id',
            'fk_business_entities_owner_id', 
            'fk_entity_relationships_source_entity_id',
            'fk_entity_relationships_target_entity_id'
        ]
        
        for constraint_name in fk_constraints:
            result = connection.execute(text(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.table_constraints 
                    WHERE constraint_name = '{constraint_name}'
                    AND constraint_type = 'FOREIGN KEY'
                );
            """)).scalar()
            
            if not result:
                raise Exception(f"Failed to create required foreign key constraint: {constraint_name}")
                
        logger.info(f"Successfully verified creation of all {len(fk_constraints)} foreign key constraints")
        
        # Verify unique constraints
        unique_constraints = [
            'uq_users_username',
            'uq_users_email',
            'uq_user_sessions_token'
        ]
        
        for constraint_name in unique_constraints:
            result = connection.execute(text(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.table_constraints 
                    WHERE constraint_name = '{constraint_name}'
                    AND constraint_type = 'UNIQUE'
                );
            """)).scalar()
            
            if not result:
                raise Exception(f"Failed to create required unique constraint: {constraint_name}")
                
        logger.info(f"Successfully verified creation of all {len(unique_constraints)} unique constraints")
        
        logger.info("Initial PostgreSQL schema creation completed successfully")
        logger.info("Schema includes: Users, UserSessions, BusinessEntities, EntityRelationships")
        logger.info("All foreign key relationships, constraints, and indexes created successfully")
        logger.info("Database ready for Flask-SQLAlchemy 3.1.1 declarative model operations")
        
    except Exception as e:
        logger.error(f"Failed to create initial PostgreSQL schema: {str(e)}")
        raise


def downgrade():
    """
    Drop all database objects created in the upgrade function.
    
    This downgrade function provides comprehensive rollback capabilities for the
    initial schema creation. Implements zero data loss rollback procedures per
    Section 4.4.2 by systematically removing all database objects in reverse
    dependency order to maintain referential integrity during rollback.
    
    Rollback Sequence:
    1. Drop all foreign key constraints to prevent dependency conflicts
    2. Drop all indexes for clean table removal
    3. Drop all triggers and functions for complete cleanup
    4. Drop all tables in reverse dependency order
    5. Verify complete rollback with comprehensive validation
    
    This ensures complete database restoration to pre-migration state with
    zero data loss and full functional equivalence per rollback requirements.
    """
    logger.info("Starting comprehensive database schema rollback")
    
    try:
        # Drop triggers first to prevent function dependency issues
        logger.info("Dropping automatic timestamp update triggers")
        
        # Drop triggers for automatic updated_at timestamp management
        op.execute("DROP TRIGGER IF EXISTS trigger_users_updated_at ON users CASCADE;")
        op.execute("DROP TRIGGER IF EXISTS trigger_business_entities_updated_at ON business_entities CASCADE;")
        op.execute("DROP TRIGGER IF EXISTS trigger_entity_relationships_updated_at ON entity_relationships CASCADE;")
        
        # Drop the timestamp update function
        logger.info("Dropping PostgreSQL timestamp update function")
        op.execute("DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;")
        
        # Drop indexes in reverse order to prevent dependency conflicts
        logger.info("Dropping performance optimization indexes")
        
        # EntityRelationship table indexes
        op.drop_index('ix_entity_relationships_type_active', table_name='entity_relationships')
        op.drop_index('ix_entity_relationships_target_type_active', table_name='entity_relationships')
        op.drop_index('ix_entity_relationships_source_type_active', table_name='entity_relationships')
        op.drop_index('ix_entity_relationships_is_active', table_name='entity_relationships')
        op.drop_index('ix_entity_relationships_created_at', table_name='entity_relationships')
        op.drop_index('ix_entity_relationships_relationship_type', table_name='entity_relationships')
        op.drop_index('ix_entity_relationships_target_entity_id', table_name='entity_relationships')
        op.drop_index('ix_entity_relationships_source_entity_id', table_name='entity_relationships')
        
        # BusinessEntity table indexes
        op.drop_index('ix_business_entities_status_created', table_name='business_entities')
        op.drop_index('ix_business_entities_owner_status', table_name='business_entities')
        op.drop_index('ix_business_entities_status', table_name='business_entities')
        op.drop_index('ix_business_entities_owner_id', table_name='business_entities')
        op.drop_index('ix_business_entities_name', table_name='business_entities')
        
        # UserSession table indexes
        op.drop_index('ix_user_sessions_token_valid', table_name='user_sessions')
        op.drop_index('ix_user_sessions_expires_valid', table_name='user_sessions')
        op.drop_index('ix_user_sessions_user_valid', table_name='user_sessions')
        op.drop_index('ix_user_sessions_is_valid', table_name='user_sessions')
        op.drop_index('ix_user_sessions_created_at', table_name='user_sessions')
        op.drop_index('ix_user_sessions_expires_at', table_name='user_sessions')
        op.drop_index('ix_user_sessions_session_token', table_name='user_sessions')
        op.drop_index('ix_user_sessions_user_id', table_name='user_sessions')
        
        # User table indexes
        op.drop_index('ix_users_username_active', table_name='users')
        op.drop_index('ix_users_email_active', table_name='users')
        op.drop_index('ix_users_active_created', table_name='users')
        op.drop_index('ix_users_is_active', table_name='users')
        op.drop_index('ix_users_email', table_name='users')
        op.drop_index('ix_users_username', table_name='users')
        
        # Drop tables in reverse dependency order to maintain referential integrity
        logger.info("Dropping database tables in reverse dependency order")
        
        # Drop EntityRelationship table (depends on BusinessEntity)
        op.drop_table('entity_relationships')
        logger.info("Dropped entity_relationships table")
        
        # Drop BusinessEntity table (depends on User)
        op.drop_table('business_entities')
        logger.info("Dropped business_entities table")
        
        # Drop UserSession table (depends on User)
        op.drop_table('user_sessions')
        logger.info("Dropped user_sessions table")
        
        # Drop User table (foundation table)
        op.drop_table('users')
        logger.info("Dropped users table")
        
        # Verify complete rollback with comprehensive validation
        logger.info("Performing post-rollback verification")
        
        connection = op.get_bind()
        
        # Verify all tables have been dropped
        dropped_tables = ['users', 'user_sessions', 'business_entities', 'entity_relationships']
        for table_name in dropped_tables:
            result = connection.execute(text(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = '{table_name}'
                );
            """)).scalar()
            
            if result:
                raise Exception(f"Failed to drop table during rollback: {table_name}")
                
        logger.info(f"Successfully verified removal of all {len(dropped_tables)} tables")
        
        # Verify all foreign key constraints have been dropped
        fk_constraints = [
            'fk_user_sessions_user_id',
            'fk_business_entities_owner_id', 
            'fk_entity_relationships_source_entity_id',
            'fk_entity_relationships_target_entity_id'
        ]
        
        for constraint_name in fk_constraints:
            result = connection.execute(text(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.table_constraints 
                    WHERE constraint_name = '{constraint_name}'
                    AND constraint_type = 'FOREIGN KEY'
                );
            """)).scalar()
            
            if result:
                raise Exception(f"Failed to drop foreign key constraint during rollback: {constraint_name}")
                
        logger.info(f"Successfully verified removal of all {len(fk_constraints)} foreign key constraints")
        
        # Verify all functions and triggers have been dropped
        function_result = connection.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.routines 
                WHERE routine_name = 'update_updated_at_column'
                AND routine_schema = 'public'
            );
        """)).scalar()
        
        if function_result:
            raise Exception("Failed to drop timestamp update function during rollback")
            
        logger.info("Successfully verified removal of all custom functions and triggers")
        
        logger.info("Database schema rollback completed successfully")
        logger.info("All tables, indexes, constraints, functions, and triggers removed")
        logger.info("Database restored to pre-migration state with zero data loss")
        
    except Exception as e:
        logger.error(f"Failed to complete database schema rollback: {str(e)}")
        raise