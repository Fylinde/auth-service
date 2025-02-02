"""Added phone number

Revision ID: a24774f9dbfa
Revises: 779fe16ced1b
Create Date: 2024-11-11 14:48:07.044541

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = "a24774f9dbfa"
down_revision = "779fe16ced1b"
branch_labels = None
depends_on = None


def column_exists(connection, table_name, column_name):
    """Check if a column exists in a table."""
    inspector = Inspector.from_engine(connection)
    columns = [col["name"] for col in inspector.get_columns(table_name)]
    return column_name in columns


def upgrade():
    connection = op.get_bind()

    # Add the phoneNumber column to the verification_codes table if it doesn't exist
    if not column_exists(connection, "verification_codes", "phoneNumber"):
        op.add_column(
            "verification_codes",
            sa.Column("phoneNumber", sa.String(length=20), nullable=True),
        )
        print("Added column 'phoneNumber' to table 'verification_codes'.")
    else:
        print("Column 'phoneNumber' already exists in table 'verification_codes'. Skipping.")


def downgrade():
    connection = op.get_bind()

    # Remove the phoneNumber column only if it exists
    if column_exists(connection, "verification_codes", "phoneNumber"):
        op.drop_column("verification_codes", "phoneNumber")
        print("Dropped column 'phoneNumber' from table 'verification_codes'.")
    else:
        print("Column 'phoneNumber' does not exist in table 'verification_codes'. Skipping.")
