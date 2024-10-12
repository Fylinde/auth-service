"""Add user_type column to UserModel

Revision ID: a99d776c5711
Revises: e5536f684724
Create Date: 2024-09-06 14:51:35.157043

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a99d776c5711'
down_revision = 'e5536f684724'
branch_labels = None
depends_on = None


def upgrade():
    # Add the new user_type column with default 'user'
    op.add_column('users', sa.Column('user_type', sa.String(), nullable=False, server_default='user'))

    # After adding the column, you can set user_type to 'admin' where is_admin=True
    op.execute("UPDATE users SET user_type='admin' WHERE is_admin=True")


def downgrade():
    # Drop the user_type column on downgrade
    op.drop_column('users', 'user_type')
