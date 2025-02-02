"""Added back email

Revision ID: 6100c385d8b7
Revises: 82a2cfc22a37
Create Date: 2024-11-13 10:27:25.827272

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "6100c385d8b7"
down_revision = "82a2cfc22a37"
branch_labels = None
depends_on = None


def upgrade():
    # Add the new 'email' column to the 'verification_codes' table
    op.add_column("verification_codes", sa.Column("email", sa.String(), nullable=True))


def downgrade():
    # Remove the 'email' column from the 'verification_codes' table if we need to roll back
    op.drop_column("verification_codes", "email")
