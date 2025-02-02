"""Added is_email and changed id to integer

Revision ID: 1e87a2978253
Revises: a24774f9dbfa
Create Date: 2024-11-11 15:53:20.479467

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = "1e87a2978253"
down_revision = "a24774f9dbfa"
branch_labels = None
depends_on = None


def column_exists(connection, table_name, column_name):
    """Check if a column exists in a table."""
    inspector = Inspector.from_engine(connection)
    columns = [col["name"] for col in inspector.get_columns(table_name)]
    return column_name in columns


def upgrade():
    connection = op.get_bind()

    # Check if the `id` column exists
    if column_exists(connection, "verification_codes", "id"):
        print("Column 'id' already exists in 'verification_codes'. Skipping drop and re-add.")
    else:
        # Drop the existing `id` column if it exists
        try:
            op.execute("ALTER TABLE verification_codes DROP COLUMN id CASCADE")
            print("Dropped column 'id' from 'verification_codes'.")
        except Exception as e:
            print(f"Failed to drop 'id' column: {e}")

        # Add the `id` column with auto-incrementing integer type
        op.add_column(
            "verification_codes",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        )
        print("Added 'id' column to 'verification_codes'.")

    # Check if the `is_email` column exists
    if not column_exists(connection, "verification_codes", "is_email"):
        # Add the `is_email` column as a Boolean type
        op.add_column(
            "verification_codes",
            sa.Column("is_email", sa.Boolean(), nullable=False),
        )
        print("Added 'is_email' column to 'verification_codes'.")
    else:
        print("Column 'is_email' already exists in 'verification_codes'. Skipping.")


def downgrade():
    connection = op.get_bind()

    # Check if the `is_email` column exists
    if column_exists(connection, "verification_codes", "is_email"):
        op.drop_column("verification_codes", "is_email")
        print("Dropped 'is_email' column from 'verification_codes'.")
    else:
        print("Column 'is_email' does not exist in 'verification_codes'. Skipping drop.")

    # Check if the `id` column exists
    if column_exists(connection, "verification_codes", "id"):
        op.drop_column("verification_codes", "id")
        print("Dropped 'id' column from 'verification_codes'.")
    else:
        print("Column 'id' does not exist in 'verification_codes'. Skipping drop.")

    # Add back the original `id` column as a string type
    op.add_column(
        "verification_codes", sa.Column("id", sa.String(), primary_key=True)
    )
    print("Re-added 'id' column to 'verification_codes' with original type.")
