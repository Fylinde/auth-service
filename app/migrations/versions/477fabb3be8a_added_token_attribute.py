"""Added token attribute

Revision ID: 477fabb3be8a
Revises: b323ab616ae0
Create Date: 2024-10-11 08:57:45.809450

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '477fabb3be8a'
down_revision = 'b323ab616ae0'
branch_labels = None
depends_on = None


def upgrade():
    # Add the token column to the sessions table
    op.add_column('sessions', sa.Column('token', sa.String(), nullable=True))
    op.create_index(op.f('ix_sessions_token'), 'sessions', ['token'], unique=True)


def downgrade():
    # Remove the token column from the sessions table
    op.drop_index(op.f('ix_sessions_token'), table_name='sessions')
    op.drop_column('sessions', 'token')
