"""Increase jwt_token_key length to 36

Revision ID: e5536f684724
Revises: 95b7cc50b9fe
Create Date: 2024-09-06 13:02:28.024518

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = 'e5536f684724'
down_revision = '95b7cc50b9fe'
branch_labels = None
depends_on = None

def upgrade():
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    tables = inspector.get_table_names()

    # Only proceed if the 'users' table exists
    if 'users' in tables:
        # Check if the 'jwt_token_key' column exists
        columns = [col['name'] for col in inspector.get_columns('users')]
        if 'jwt_token_key' in columns:
            op.alter_column('users', 'jwt_token_key',
                            existing_type=sa.String(length=12),
                            type_=sa.String(length=36),
                            existing_nullable=True)
        
        # Check and drop constraints if they exist
        unique_constraints = [uc['name'] for uc in inspector.get_unique_constraints('users')]
        if 'users_email_key' in unique_constraints:
            op.drop_constraint('users_email_key', 'users', type_='unique')
        if 'users_username_key' in unique_constraints:
            op.drop_constraint('users_username_key', 'users', type_='unique')
        
        # Check if the index already exists before creating it
        indexes = [ix['name'] for ix in inspector.get_indexes('users')]
        if 'ix_users_id' not in indexes:
            op.create_index('ix_users_id', 'users', ['id'], unique=False)
        
        # Check and create foreign key if necessary
        if 'sessions' in tables and 'users' in tables:
            fks = [fk['name'] for fk in inspector.get_foreign_keys('sessions')]
            if 'fk_sessions_users_user_id' not in fks:
                op.create_foreign_key('fk_sessions_users_user_id', 'sessions', 'users', ['user_id'], ['id'])


def downgrade():
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    tables = inspector.get_table_names()

    if 'users' in tables:
        # Revert the 'jwt_token_key' column if it exists
        columns = [col['name'] for col in inspector.get_columns('users')]
        if 'jwt_token_key' in columns:
            op.alter_column('users', 'jwt_token_key',
                            existing_type=sa.String(length=36),
                            type_=sa.String(length=12),
                            existing_nullable=True)
        
        # Drop and recreate constraints only if they exist
        indexes = [ix['name'] for ix in inspector.get_indexes('users')]
        if 'ix_users_id' in indexes:
            op.drop_index('ix_users_id', table_name='users')

        if 'username' in columns:
            op.create_unique_constraint('users_username_key', 'users', ['username'])
        if 'email' in columns:
            op.create_unique_constraint('users_email_key', 'users', ['email'])

        # Check if the foreign key constraint exists before dropping it
        if 'sessions' in tables:
            fks = [fk['name'] for fk in inspector.get_foreign_keys('sessions')]
            if 'fk_sessions_users_user_id' in fks:
                op.drop_constraint('fk_sessions_users_user_id', 'sessions', type_='foreignkey')
