"""Remove contact

Revision ID: 57c3bab6ef58
Revises: a90b7914825a
Create Date: 2024-11-13 10:51:12.429395

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "57c3bab6ef58"
down_revision = "a90b7914825a"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_column("verification_codes", "contact")


def downgrade():
    op.add_column(
        "verification_codes", sa.Column("contact", sa.String(), nullable=False)
    )
    # ### end Alembic commands ###
