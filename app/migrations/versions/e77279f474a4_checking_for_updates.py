from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = 'e77279f474a4'
down_revision = '9f929fc4be3c'
branch_labels = None
depends_on = None

def upgrade():
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    tables = inspector.get_table_names()

    # Drop the foreign key constraint on 'sessions' table, if it exists
    if 'sessions' in tables:
        fk_constraints = [fk['name'] for fk in inspector.get_foreign_keys('sessions')]
        if 'sessions_user_id_fkey' in fk_constraints:
            op.drop_constraint('sessions_user_id_fkey', 'sessions', type_='foreignkey')
        # Set the user_id column to nullable since it no longer references 'users'
        op.alter_column('sessions', 'user_id', existing_type=sa.Integer(), nullable=True)

    # Drop 'users' table with cascade using raw SQL
    if 'users' in tables:
        conn.execute(text("DROP TABLE users CASCADE"))

    # Drop 'vendors' table and associated indexes
    if 'vendors' in tables:
        indexes = [ix['name'] for ix in inspector.get_indexes('vendors')]
        if 'ix_vendors_email' in indexes:
            op.drop_index('ix_vendors_email', table_name='vendors')
        if 'ix_vendors_id' in indexes:
            op.drop_index('ix_vendors_id', table_name='vendors')
        if 'ix_vendors_name' in indexes:
            op.drop_index('ix_vendors_name', table_name='vendors')
        conn.execute(text("DROP TABLE vendors CASCADE"))

def downgrade():
    # Recreate 'users' and 'vendors' tables, indexes, and the foreign key constraint on 'sessions'
    op.create_table('users',
        sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column('email', sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column('hashed_password', sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column('is_active', sa.BOOLEAN(), autoincrement=False, nullable=True),
        sa.Column('is_admin', sa.BOOLEAN(), autoincrement=False, nullable=True),
        sa.Column('verification_code', sa.VARCHAR(), autoincrement=False, nullable=True),
        sa.Column('two_factor_enabled', sa.BOOLEAN(), autoincrement=False, nullable=True),
        sa.Column('two_factor_secret', sa.VARCHAR(), autoincrement=False, nullable=True),
        sa.Column('password_last_updated', sa.DateTime(), autoincrement=False, nullable=True),
        sa.Column('failed_login_attempts', sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column('account_locked', sa.BOOLEAN(), autoincrement=False, nullable=True),
        sa.Column('backup_codes', sa.ARRAY(sa.VARCHAR()), autoincrement=False, nullable=True),
        sa.Column('jwt_token_key', sa.VARCHAR(length=36), autoincrement=False, nullable=True),
        sa.Column('full_name', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
        sa.Column('phone_number', sa.VARCHAR(length=15), autoincrement=False, nullable=True),
        sa.Column('username', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.PrimaryKeyConstraint('id', name='users_pkey'),
        sa.UniqueConstraint('email', name='users_email_key'),
        sa.UniqueConstraint('phone_number', name='users_phone_number_key')
    )
    op.create_index('ix_users_id', 'users', ['id'], unique=False)

    op.create_table('vendors',
        sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column('name', sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column('description', sa.VARCHAR(), autoincrement=False, nullable=True),
        sa.Column('rating', sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column('email', sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column('hashed_password', sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column('profile_picture', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.Column('preferences', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.PrimaryKeyConstraint('id', name='vendors_pkey')
    )
    op.create_index('ix_vendors_name', 'vendors', ['name'], unique=False)
    op.create_index('ix_vendors_id', 'vendors', ['id'], unique=False)
    op.create_index('ix_vendors_email', 'vendors', ['email'], unique=True)

    # Restore the foreign key constraint for the sessions table
    op.create_foreign_key('sessions_user_id_fkey', 'sessions', 'users', ['user_id'], ['id'])
