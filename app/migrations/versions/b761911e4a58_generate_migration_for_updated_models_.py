"""Generate migration for updated models in auth-service

Revision ID: b761911e4a58
Revises: 6efb0d891ca3
Create Date: 2024-09-06 10:47:11.152658

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection

# revision identifiers, used by Alembic.
revision = 'b761911e4a58'
down_revision = '6efb0d891ca3'
branch_labels = None
depends_on = None

def upgrade():
    conn = op.get_bind()
    inspector = reflection.Inspector.from_engine(conn)
    tables = inspector.get_table_names()

    if 'admins' in tables:
        op.drop_table('admins')
    if 'user_groups' in tables:
        op.drop_table('user_groups')
    if 'groups' in tables:
        op.drop_index('ix_groups_id', table_name='groups')
        op.drop_table('groups')

    columns = inspector.get_columns('users')
    user_columns = [column['name'] for column in columns]

    if 'is_admin' not in user_columns:
        op.add_column('users', sa.Column('is_admin', sa.Boolean(), nullable=True))
    
    if 'username' in user_columns:
        op.drop_index('ix_users_username', table_name='users')
        op.drop_column('users', 'username')
    
    for column_name in ['otp_code', 'avatar', 'role', 'verification_code', 'is_verified', 'verification_token', 'language_code']:
        if column_name in user_columns:
            op.drop_column('users', column_name)

def downgrade():
    conn = op.get_bind()
    inspector = reflection.Inspector.from_engine(conn)
    user_columns = [column['name'] for column in inspector.get_columns('users')]

    op.add_column('users', sa.Column('language_code', sa.VARCHAR(length=35), nullable=True))
    op.add_column('users', sa.Column('verification_token', sa.VARCHAR(), nullable=True))
    op.add_column('users', sa.Column('is_verified', sa.BOOLEAN(), server_default=sa.text('false'), nullable=True))
    op.add_column('users', sa.Column('verification_code', sa.VARCHAR(), nullable=True))
    op.add_column('users', sa.Column('username', sa.VARCHAR(), nullable=False))
    op.add_column('users', sa.Column('role', sa.VARCHAR(), nullable=True))
    op.add_column('users', sa.Column('avatar', sa.VARCHAR(length=255), nullable=True))
    op.add_column('users', sa.Column('otp_code', sa.VARCHAR(), nullable=True))
    op.create_index('ix_users_username', 'users', ['username'], unique=True)
    
    if 'is_admin' in user_columns:
        op.drop_column('users', 'is_admin')

    op.create_table('groups',
        sa.Column('id', sa.INTEGER(), server_default=sa.text("nextval('groups_id_seq'::regclass)"), autoincrement=True, nullable=False),
        sa.Column('name', sa.VARCHAR(length=150), nullable=False),
        sa.PrimaryKeyConstraint('id', name='groups_pkey'),
        sa.UniqueConstraint('name', name='groups_name_key')
    )
    op.create_index('ix_groups_id', 'groups', ['id'], unique=False)
    
    op.create_table('user_groups',
        sa.Column('user_id', sa.INTEGER(), nullable=True),
        sa.Column('group_id', sa.INTEGER(), nullable=True),
        sa.ForeignKeyConstraint(['group_id'], ['groups.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'])
    )
    
    op.create_table('admins',
        sa.Column('id', sa.INTEGER(), nullable=False),
        sa.Column('role', sa.VARCHAR(), nullable=True),
        sa.ForeignKeyConstraint(['id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
