"""Remove token column from sessions table

Revision ID: c59303aab339
Revises: 477fabb3be8a
Create Date: 2024-10-11 10:51:55.081665

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'c59303aab339'
down_revision = '477fabb3be8a'
branch_labels = None
depends_on = None

def upgrade():
    op.drop_column('sessions', 'token')

def downgrade():
    op.add_column('sessions', sa.Column('token', sa.String(), nullable=True, unique=True))