# migration file

from alembic import op
import sqlalchemy as sa
import uuid

revision = 'b323ab616ae0'
down_revision = '22c336016ff1'
branch_labels = None
depends_on = None

def upgrade():
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";')
    op.execute('ALTER TABLE otp_codes ALTER COLUMN id SET DEFAULT uuid_generate_v4();')

def downgrade():
    op.execute('ALTER TABLE otp_codes ALTER COLUMN id DROP DEFAULT;')
