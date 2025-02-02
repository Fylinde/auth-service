"""Added sellerId

Revision ID: c19401518334
Revises: c59303aab339
Create Date: 2024-11-09 11:37:33.243438

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = "c19401518334"
down_revision = "c59303aab339"
branch_labels = None
depends_on = None


def index_exists(connection, table_name, index_name):
    """Check if an index exists for a table."""
    inspector = Inspector.from_engine(connection)
    indexes = inspector.get_indexes(table_name)
    return any(index["name"] == index_name for index in indexes)


def upgrade():
    connection = op.get_bind()

    # Check and drop indexes for `otp_codes` table
    if index_exists(connection, "otp_codes", "ix_otp_codes_id"):
        op.drop_index("ix_otp_codes_id", table_name="otp_codes")
        print("Dropped index: ix_otp_codes_id")
    else:
        print("Index ix_otp_codes_id does not exist. Skipping drop.")

    if index_exists(connection, "otp_codes", "ix_otp_codes_user_id"):
        op.drop_index("ix_otp_codes_user_id", table_name="otp_codes")
        print("Dropped index: ix_otp_codes_user_id")
    else:
        print("Index ix_otp_codes_user_id does not exist. Skipping drop.")

    # Add `sellerId` column to `sessions` table
    op.add_column("sessions", sa.Column("sellerId", sa.Integer(), nullable=True))

    # Add `sellerId` column to `otp_codes` table
    op.add_column(
        "otp_codes", sa.Column("sellerId", sa.String(), nullable=True, index=True)
    )

    # Alter existing columns in `sessions` to allow null values
    op.alter_column(
        "sessions", "session_token", existing_type=sa.VARCHAR(), nullable=True
    )
    op.alter_column(
        "sessions", "created_at", existing_type=postgresql.TIMESTAMP(), nullable=True
    )
    op.alter_column(
        "sessions", "expires_at", existing_type=postgresql.TIMESTAMP(), nullable=True
    )


def downgrade():
    connection = op.get_bind()

    # Revert changes to `sessions` table
    op.alter_column(
        "sessions", "expires_at", existing_type=postgresql.TIMESTAMP(), nullable=False
    )
    op.alter_column(
        "sessions", "created_at", existing_type=postgresql.TIMESTAMP(), nullable=False
    )
    op.alter_column(
        "sessions", "session_token", existing_type=sa.VARCHAR(), nullable=False
    )
    op.drop_column("sessions", "sellerId")

    # Revert changes to `otp_codes` table by dropping `sellerId`
    op.drop_column("otp_codes", "sellerId")

    # Recreate indexes for `otp_codes` table
    if not index_exists(connection, "otp_codes", "ix_otp_codes_id"):
        op.create_index("ix_otp_codes_id", "otp_codes", ["id"], unique=False)
        print("Recreated index: ix_otp_codes_id")

    if not index_exists(connection, "otp_codes", "ix_otp_codes_user_id"):
        op.create_index("ix_otp_codes_user_id", "otp_codes", ["user_id"], unique=False)
        print("Recreated index: ix_otp_codes_user_id")
