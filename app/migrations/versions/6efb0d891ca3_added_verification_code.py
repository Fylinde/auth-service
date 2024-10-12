"""Added verification_code

Revision ID: 6efb0d891ca3
Revises: 9dc7718db288
Create Date: 2024-08-30 14:14:03.340055

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6efb0d891ca3'
down_revision = '9dc7718db288'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('verification_code', sa.String(), nullable=True))

def downgrade():
    op.drop_column('users', 'verification_code')

