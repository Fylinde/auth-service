from alembic import op
import sqlalchemy as sa

revision = '76gre1098hy3'
down_revision = '0a552e0deaff'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('users', sa.Column('verification_token', sa.String(), nullable=True))

def downgrade():
    op.drop_column('users', 'verification_token')
