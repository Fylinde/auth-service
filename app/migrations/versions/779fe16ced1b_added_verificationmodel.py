"""Added VerificationModel

Revision ID: c19401518334
Revises: c59303aab339
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "779fe16ced1b"
down_revision = "e26230a4b8e0"
branch_labels = None
depends_on = None

def upgrade():
    # Check if the verification_codes table exists
    inspector = inspect(op.get_bind())
    if not inspector.has_table('verification_codes'):
        # Create the verification_codes table
        op.create_table(
            'verification_codes',
            sa.Column('id', sa.String(), primary_key=True, unique=True, nullable=False),
            sa.Column('email', sa.String(), nullable=False, index=True),
            sa.Column('code', sa.String(), nullable=False),
            sa.Column('expires_at', sa.DateTime(), nullable=False)
        )

    # Check if the index exists before creating
    if "ix_verification_codes_email" not in [ix['name'] for ix in inspector.get_indexes("verification_codes")]:
        op.create_index("ix_verification_codes_email", "verification_codes", ["email"])

def downgrade():
    # Drop the index and table during downgrade
    op.drop_index("ix_verification_codes_email", table_name="verification_codes")
    op.drop_table('verification_codes')
