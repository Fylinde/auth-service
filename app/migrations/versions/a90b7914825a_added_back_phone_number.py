"""Added back phone number

Revision ID: a90b7914825a
Revises: 6100c385d8b7
Create Date: 2024-11-13 10:40:51.149390

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "a90b7914825a"
down_revision = "6100c385d8b7"
branch_labels = None
depends_on = None


def upgrade():
    # Add the new 'phoneNumber' column to the 'verification_codes' table
    op.add_column(
        "verification_codes", sa.Column("phoneNumber", sa.String(), nullable=True)
    )


def downgrade():
    # Remove the 'phoneNumber' column from the 'verification_codes' table if we need to roll back
    op.drop_column("verification_codes", "phoneNumber")
