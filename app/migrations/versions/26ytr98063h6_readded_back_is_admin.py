"""readded back is_admin

Revision ID: 26ytr98063h6
Revises: cc8be4e52860
Create Date: 2024-09-06 16:06:30.678701

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '26ytr98063h6'
down_revision = 'cc8be4e52860'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('users', sa.Column('is_admin', sa.Boolean(), nullable=False, server_default='false'))

def downgrade():
    op.drop_column('users', 'is_admin')

