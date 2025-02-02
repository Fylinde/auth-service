from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = '6caa741d07ca'
down_revision = None
branch_labels = None
depends_on = None


def table_exists(table_name, connection):
    """Check if a table exists in the database."""
    inspector = inspect(connection)
    return table_name in inspector.get_table_names()


def column_exists(table_name, column_name, connection):
    """Check if a column exists in a specific table."""
    inspector = inspect(connection)
    columns = [col["name"] for col in inspector.get_columns(table_name)]
    return column_name in columns


def upgrade() -> None:
    connection = op.get_bind()

    # Check and create 'users' table
    if not table_exists('users', connection):
        op.create_table(
            'users',
            sa.Column('id', sa.String(), nullable=False),  # Changed from Integer to String
            sa.Column('username', sa.String(), nullable=False),
            sa.Column('email', sa.String(), nullable=False),
            sa.Column('hashed_password', sa.String(), nullable=False),
            sa.Column('is_active', sa.Boolean(), nullable=True),
            sa.Column('role', sa.String(), nullable=True),
            sa.Column('two_factor_enabled', sa.Boolean(), nullable=True),
            sa.Column('two_factor_secret', sa.String(), nullable=True),
            sa.Column('password_last_updated', sa.DateTime(), nullable=True),
            sa.Column('failed_login_attempts', sa.Integer(), nullable=True),
            sa.Column('account_locked', sa.Boolean(), nullable=True),
            sa.Column('backup_codes', sa.ARRAY(sa.String()), nullable=True),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
        op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
        op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    else:
        print("Table 'users' already exists. Skipping creation.")

    # Check and create 'sessions' table
    if not table_exists('sessions', connection):
        op.create_table(
            'sessions',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.String(), nullable=True),  # Changed from Integer to String
            sa.Column('session_token', sa.String(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('expires_at', sa.DateTime(), nullable=False),
            sa.Column('is_valid', sa.Boolean(), nullable=True),
            sa.ForeignKeyConstraint(['user_id'], ['users.id']),  # Matches the updated users.id type
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index(op.f('ix_sessions_id'), 'sessions', ['id'], unique=False)
        op.create_index(op.f('ix_sessions_session_token'), 'sessions', ['session_token'], unique=True)
    else:
        print("Table 'sessions' already exists. Skipping creation.")
