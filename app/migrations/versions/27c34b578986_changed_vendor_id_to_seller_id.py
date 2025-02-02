"""changed vendor_id to sellerId

Revision ID: 27c34b578986
Revises: 57c3bab6ef58
Create Date: 2025-01-09 12:41:24.635156

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "27c34b578986"
down_revision = "57c3bab6ef58"
branch_labels = None
depends_on = None


def upgrade():
    # Check if the 'sessions' table exists
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if "sessions" in inspector.get_table_names():
        # Add 'sellerId' column if not exists
        columns = [col["name"] for col in inspector.get_columns("sessions")]
        if "sellerId" not in columns:
            op.add_column(
                "sessions", sa.Column("sellerId", sa.String(), nullable=True)
            )

        # Drop 'vendor_id' column if it exists
        if "vendor_id" in columns:
            op.drop_column("sessions", "vendor_id")

    # Drop the 'verification_codes' table if it exists
    if "verification_codes" in inspector.get_table_names():
        op.drop_table("verification_codes")


def downgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if "sessions" in inspector.get_table_names():
        # Add back 'vendor_id' column if not exists
        columns = [col["name"] for col in inspector.get_columns("sessions")]
        if "vendor_id" not in columns:
            op.add_column(
                "sessions",
                sa.Column(
                    "vendor_id", sa.INTEGER(), autoincrement=False, nullable=True
                ),
            )

        # Drop 'sellerId' column if it exists
        if "sellerId" in columns:
            op.drop_column("sessions", "sellerId")

    # Recreate the 'verification_codes' table if not exists
    if "verification_codes" not in inspector.get_table_names():
        op.create_table(
            "verification_codes",
            sa.Column("id", sa.INTEGER(), autoincrement=True, nullable=False),
            sa.Column("code", sa.VARCHAR(), autoincrement=False, nullable=False),
            sa.Column(
                "expires_at",
                postgresql.TIMESTAMP(),
                autoincrement=False,
                nullable=False,
            ),
            sa.Column("is_email", sa.BOOLEAN(), autoincrement=False, nullable=False),
            sa.Column("vendor_id", sa.INTEGER(), autoincrement=False, nullable=True),
            sa.Column("email", sa.VARCHAR(), autoincrement=False, nullable=True),
            sa.Column("phone_number", sa.VARCHAR(), autoincrement=False, nullable=True),
            sa.PrimaryKeyConstraint("id", name="verification_codes_pkey"),
        )
