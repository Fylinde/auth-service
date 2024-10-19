"""Added username to users table

Revision ID: 95b7cc50b9fe
Revises: b761911e4a58
Create Date: 2024-09-06 12:36:28.656707

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection


# revision identifiers, used by Alembic.
revision = '95b7cc50b9fe'
down_revision = 'b761911e4a58'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = reflection.Inspector.from_engine(conn)
    tables = inspector.get_table_names()

    # Check if the 'users' table exists
    if 'users' not in tables:
        op.create_table(
            'users',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('username', sa.String(), nullable=False, unique=True),
            sa.Column('email', sa.String(), nullable=False, unique=True),
            sa.Column('hashed_password', sa.String(), nullable=False),
            sa.Column('is_active', sa.Boolean(), default=True),
            sa.Column('two_factor_enabled', sa.Boolean(), default=False),
            sa.Column('two_factor_secret', sa.String(), nullable=True),
            sa.Column('password_last_updated', sa.DateTime(), nullable=True),
            sa.Column('failed_login_attempts', sa.Integer(), nullable=True),
            sa.Column('account_locked', sa.Boolean(), nullable=True),
            sa.Column('backup_codes', sa.ARRAY(sa.String()), nullable=True),
            sa.Column('jwt_token_key', sa.String(length=12), nullable=True),
            sa.Column('is_admin', sa.Boolean(), nullable=True),
        )
        op.create_index('ix_users_email', 'users', ['email'], unique=True)
        op.create_index('ix_users_username', 'users', ['username'], unique=True)
    else:
        # If the table exists, add missing columns
        existing_columns = [column['name'] for column in inspector.get_columns('users')]
        columns_to_add = {
            'username': sa.String(),
            'email': sa.String(),
            'hashed_password': sa.String(),
            'is_active': sa.Boolean(),
            'two_factor_enabled': sa.Boolean(),
            'two_factor_secret': sa.String(),
            'password_last_updated': sa.DateTime(),
            'failed_login_attempts': sa.Integer(),
            'account_locked': sa.Boolean(),
            'backup_codes': sa.ARRAY(sa.String()),
            'jwt_token_key': sa.String(length=12),
            'is_admin': sa.Boolean(),
        }

        for column_name, column_type in columns_to_add.items():
            if column_name not in existing_columns:
                op.add_column('users', sa.Column(column_name, column_type, nullable=True))

def downgrade():
    conn = op.get_bind()
    inspector = reflection.Inspector.from_engine(conn)
    tables = inspector.get_table_names()

    if 'users' in tables:
        op.drop_index('ix_users_email', table_name='users')
        op.drop_index('ix_users_username', table_name='users')
        op.drop_table('users')
