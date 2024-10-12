from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9f929fc4be3c'
down_revision = '9fefe3b98aea'
branch_labels = None
depends_on = None


def upgrade():
    # Add the username column as nullable since it is not currently used
    op.add_column('users', sa.Column('username', sa.String(length=255), nullable=True))


def downgrade():
    # Drop the username column if downgrading
    op.drop_column('users', 'username')
