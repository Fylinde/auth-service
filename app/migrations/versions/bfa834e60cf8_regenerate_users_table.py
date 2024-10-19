"""Regenerate users table

Revision ID: bfa834e60cf8
Revises: 7bbb0c2f47b7
Create Date: 2024-09-07 09:28:33.589121

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = 'bfa834e60cf8'
down_revision = '7bbb0c2f47b7'
branch_labels = None
depends_on = None

def upgrade():
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    tables = inspector.get_table_names()

    # Only create the 'users' table if it doesn't already exist
    if 'users' not in tables:
        op.create_table(
            'users',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('username', sa.String(), nullable=False),
            sa.Column('email', sa.String(), nullable=False),
            sa.Column('hashed_password', sa.String(), nullable=False),
            sa.Column('is_active', sa.Boolean(), nullable=True),
            sa.Column('is_admin', sa.Boolean(), nullable=True),
            sa.Column('verification_code', sa.String(), nullable=True),
            sa.Column('two_factor_enabled', sa.Boolean(), nullable=True),
            sa.Column('two_factor_secret', sa.String(), nullable=True),
            sa.Column('password_last_updated', sa.DateTime(), nullable=True),
            sa.Column('failed_login_attempts', sa.Integer(), nullable=True),
            sa.Column('account_locked', sa.Boolean(), nullable=True),
            sa.Column('backup_codes', sa.ARRAY(sa.String()), nullable=True),
            sa.Column('jwt_token_key', sa.String(length=36), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )
    
    # Check for indexes on the 'users' table
    indexes = [ix['name'] for ix in inspector.get_indexes('users')]

    if 'ix_users_email' not in indexes:
        op.create_index('ix_users_email', 'users', ['email'], unique=True)
    if 'ix_users_id' not in indexes:
        op.create_index('ix_users_id', 'users', ['id'], unique=False)
    if 'ix_users_username' not in indexes:
        op.create_index('ix_users_username', 'users', ['username'], unique=True)

    # Check if the 'sessions' table exists and the foreign key constraint is not already present
    if 'sessions' in tables:
        fks = [fk['name'] for fk in inspector.get_foreign_keys('sessions')]
        if 'fk_sessions_users_user_id' not in fks:
            op.create_foreign_key('fk_sessions_users_user_id', 'sessions', 'users', ['user_id'], ['id'])

def downgrade():
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    tables = inspector.get_table_names()

    if 'sessions' in tables:
        fks = [fk['name'] for fk in inspector.get_foreign_keys('sessions')]
        if 'fk_sessions_users_user_id' in fks:
            op.drop_constraint('fk_sessions_users_user_id', 'sessions', type_='foreignkey')

    if 'users' in tables:
        indexes = [ix['name'] for ix in inspector.get_indexes('users')]
        if 'ix_users_username' in indexes:
            op.drop_index('ix_users_username', table_name='users')
        if 'ix_users_id' in indexes:
            op.drop_index('ix_users_id', table_name='users')
        if 'ix_users_email' in indexes:
            op.drop_index('ix_users_email', table_name='users')
        op.drop_table('users')
