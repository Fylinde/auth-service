"""Added OTPModel

Revision ID: 22c336016ff1
Revises: e77279f474a4
Create Date: 2024-10-10 13:26:21.668764

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from datetime import datetime


# revision identifiers, used by Alembic.
revision = '22c336016ff1'
down_revision = 'e77279f474a4'
branch_labels = None
depends_on = None


def table_exists(table_name, connection):
    """Check if a table exists in the database."""
    inspector = inspect(connection)
    return table_name in inspector.get_table_names()


def upgrade():
    connection = op.get_bind()

    # Check and create 'otp_codes' table
    if not table_exists('otp_codes', connection):
        op.create_table(
            'otp_codes',
            sa.Column('id', sa.String, primary_key=True, index=True),
            sa.Column('user_id', sa.String, nullable=False, index=True),
            sa.Column('otp_code', sa.String, nullable=False),
            sa.Column('created_at', sa.DateTime, default=datetime.utcnow)
        )
        print("Table 'otp_codes' created successfully.")
    else:
        print("Table 'otp_codes' already exists. Skipping creation.")


def downgrade():
    connection = op.get_bind()

    # Check and drop 'otp_codes' table if it exists
    if table_exists('otp_codes', connection):
        op.drop_table('otp_codes')
        print("Table 'otp_codes' dropped successfully.")
    else:
        print("Table 'otp_codes' does not exist. Skipping drop.")
