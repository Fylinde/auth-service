"""Added contact and sellerId

Revision ID: 82a2cfc22a37
Revises: 1e87a2978253
Create Date: 2024-11-13 08:20:09.620606

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text  # Import `text` for raw SQL execution


# revision identifiers, used by Alembic.
revision = "82a2cfc22a37"
down_revision = "1e87a2978253"
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Add 'contact' and 'sellerId' columns, with 'contact' nullable initially
    op.add_column(
        "verification_codes", sa.Column("contact", sa.String(), nullable=True)
    )
    op.add_column(
        "verification_codes", sa.Column("sellerId", sa.Integer(), nullable=True)
    )

    # Step 2: Migrate data from 'email' or 'phoneNumber' to 'contact'
    conn = op.get_bind()

    # Check if the column `phoneNumber` exists
    column_check_query = text("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'verification_codes' AND column_name = 'phoneNumber';
    """)
    column_exists = conn.execute(column_check_query).fetchone()

    if column_exists:
        # Use the correct column name with proper quoting
        update_query = text("""
            UPDATE verification_codes
            SET contact = COALESCE(email, NULLIF("phoneNumber", ''))
        """)
    else:
        # If `phoneNumber` doesn't exist, fallback to using only `email`
        update_query = text("""
            UPDATE verification_codes
            SET contact = email
        """)

    conn.execute(update_query)

    # Step 3: Drop 'email' and 'phoneNumber' columns if they exist
    drop_columns_query = text("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'verification_codes' AND column_name IN ('email', 'phoneNumber');
    """)
    existing_columns = conn.execute(drop_columns_query).fetchall()

    for column in existing_columns:
        if column[0] == "email":
            op.drop_column("verification_codes", "email")
        elif column[0] == "phoneNumber":
            op.drop_column("verification_codes", "phoneNumber")

    # Step 4: Alter 'contact' to be non-nullable now that it has data
    op.alter_column("verification_codes", "contact", nullable=False)


def downgrade():
    # Step 1: Re-add the 'email' and 'phoneNumber' columns as nullable
    op.add_column("verification_codes", sa.Column("email", sa.String(), nullable=True))
    op.add_column(
        "verification_codes",
        sa.Column("phoneNumber", sa.String(length=20), nullable=True),
    )

    # Step 2: Migrate data from 'contact' back to 'email' or 'phoneNumber'
    op.execute("""
        UPDATE verification_codes
        SET email = contact
        WHERE is_email = true
    """)
    op.execute("""
        UPDATE verification_codes
        SET phoneNumber = contact
        WHERE is_email = false
    """)

    # Step 3: Drop the 'contact' and 'sellerId' columns
    op.drop_column("verification_codes", "contact")
    op.drop_column("verification_codes", "sellerId")
