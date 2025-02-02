"""Create sessions, otp_codes, and verification_codes tables if not exist.

Revision ID: 47c32b578482
Revises: 27c34b578986
Create Date: 2025-01-09 13:05:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime

# revision identifiers, used by Alembic.
revision = '47c32b578482'
down_revision = '27c34b578986'
branch_labels = None
depends_on = None

def upgrade():
    # Inspect database metadata to check for existing tables
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Create 'sessions' table if not exists
    if 'sessions' not in inspector.get_table_names():
        op.create_table(
            'sessions',
            sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
            sa.Column('session_token', sa.String, unique=True, index=True, nullable=False),
            sa.Column('user_id', sa.Integer, nullable=True),
            sa.Column('sellerId', sa.String, nullable=True),
            sa.Column('created_at', sa.DateTime, default=datetime.utcnow, nullable=False),
            sa.Column('expires_at', sa.DateTime, nullable=True),
            sa.Column('is_valid', sa.Boolean, default=True, nullable=False),
        )
        print("Table 'sessions' created successfully.")

    # Create 'otp_codes' table if not exists
    if 'otp_codes' not in inspector.get_table_names():
        op.create_table(
            'otp_codes',
            sa.Column('id', UUID(as_uuid=True), primary_key=True, default=sa.text("uuid_generate_v4()")),
            sa.Column('user_id', sa.String, nullable=False, index=True),
            sa.Column('sellerId', sa.String, nullable=False, index=True),
            sa.Column('otp_code', sa.String, nullable=False),
            sa.Column('created_at', sa.DateTime, default=datetime.utcnow, nullable=False),
        )
        print("Table 'otp_codes' created successfully.")

    # Create 'verification_codes' table if not exists
    if 'verification_codes' not in inspector.get_table_names():
        op.create_table(
            'verification_codes',
            sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
            sa.Column('email', sa.String, nullable=True),
            sa.Column('phoneNumber', sa.String, nullable=True),
            sa.Column('code', sa.String, nullable=False),
            sa.Column('expires_at', sa.DateTime, nullable=False),
            sa.Column('is_email', sa.Boolean, nullable=False),
            sa.Column('sellerId', sa.String, nullable=True),
        )
        print("Table 'verification_codes' created successfully.")


def downgrade():
    # Inspect database metadata to check for existing tables
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Drop 'verification_codes' table if exists
    if 'verification_codes' in inspector.get_table_names():
        op.drop_table('verification_codes')
        print("Table 'verification_codes' dropped successfully.")

    # Drop 'otp_codes' table if exists
    if 'otp_codes' in inspector.get_table_names():
        op.drop_table('otp_codes')
        print("Table 'otp_codes' dropped successfully.")

    # Drop 'sessions' table if exists
    if 'sessions' in inspector.get_table_names():
        op.drop_table('sessions')
        print("Table 'sessions' dropped successfully.")
