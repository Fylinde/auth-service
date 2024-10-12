"""Added OTPModel

Revision ID: 22c336016ff1
Revises: e77279f474a4
Create Date: 2024-10-10 13:26:21.668764

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime


# revision identifiers, used by Alembic.
revision = '22c336016ff1'
down_revision = 'e77279f474a4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'otp_codes',
        sa.Column('id', sa.String, primary_key=True, index=True),
        sa.Column('user_id', sa.String, nullable=False, index=True),
        sa.Column('otp_code', sa.String, nullable=False),
        sa.Column('created_at', sa.DateTime, default=datetime.utcnow)
    )

def downgrade():
    op.drop_table('otp_codes')
