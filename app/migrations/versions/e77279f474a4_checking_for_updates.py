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

    # Drop 'sellers' table and associated indexes
    if 'sellers' in tables:
        indexes = [ix['name'] for ix in inspector.get_indexes('sellers')]
        if 'ix_sellers_email' in indexes:
            op.drop_index('ix_sellers_email', table_name='sellers')
        if 'ix_sellers_id' in indexes:
            op.drop_index('ix_sellers_id', table_name='sellers')
        if 'ix_sellers_name' in indexes:
            op.drop_index('ix_sellers_name', table_name='sellers')
        conn.execute(text("DROP TABLE sellers CASCADE"))

def downgrade():
    # Recreate 'users' and 'sellers' tables, indexes, and the foreign key constraint on 'sessions'
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
        sa.Column('phoneNumber', sa.VARCHAR(length=15), autoincrement=False, nullable=True),
        sa.Column('username', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.PrimaryKeyConstraint('id', name='users_pkey'),
        sa.UniqueConstraint('email', name='users_email_key'),
        sa.UniqueConstraint('phoneNumber', name='users_phoneNumber_key')
    )
    op.create_index('ix_users_id', 'users', ['id'], unique=False)

    op.create_table('sellers',
        sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column('name', sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column('description', sa.VARCHAR(), autoincrement=False, nullable=True),
        sa.Column('rating', sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column('email', sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column('hashed_password', sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column('profile_picture', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.Column('preferences', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.PrimaryKeyConstraint('id', name='sellers_pkey')
    )
    op.create_index('ix_sellers_name', 'sellers', ['name'], unique=False)
    op.create_index('ix_sellers_id', 'sellers', ['id'], unique=False)
    op.create_index('ix_sellers_email', 'sellers', ['email'], unique=True)

    # Restore the foreign key constraint for the sessions table
    op.create_foreign_key('sessions_user_id_fkey', 'sessions', 'users', ['user_id'], ['id'])
