"""Add hashed_password to VendorModel

Revision ID: 32fcc179c417
Revises: e767f257915a
Create Date: 2024-08-10 23:43:45.091549

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '32fcc179c417'
down_revision = 'e767f257915a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('vendors', sa.Column('hashed_password', sa.String(), nullable=False, server_default=''))
    op.alter_column('vendors', 'hashed_password', server_default=None)
    op.drop_index('ix_vendors_email', table_name='vendors')
    op.create_unique_constraint(None, 'vendors', ['email'])
    # ### end Alembic commands ###

def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'vendors', type_='unique')
    op.create_index('ix_vendors_email', 'vendors', ['email'], unique=True)
    op.drop_column('vendors', 'hashed_password')
    # ### end Alembic commands ###
