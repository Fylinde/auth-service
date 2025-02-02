from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '30be4fc3d336'
down_revision = 'bfa834e60cf8'
branch_labels = None
depends_on = None


def upgrade():
    # Add the full_name and phoneNumber columns
    op.add_column('users', sa.Column('full_name', sa.String(length=255), nullable=False))
    op.add_column('users', sa.Column('phoneNumber', sa.String(length=20), nullable=True))  # Added phoneNumber

    # Optionally, update full_name for existing records where it might be NULL
    op.execute("""
        UPDATE users SET full_name = 'Default User' WHERE full_name IS NULL;
    """)

    # Modify the jwt_token_key to have a length of 36
    op.alter_column('users', 'jwt_token_key',
                    existing_type=sa.VARCHAR(length=12),
                    type_=sa.String(length=36),
                    existing_nullable=True)

    # Remove any server_default for full_name if previously set (this is optional)
    op.alter_column('users', 'full_name', server_default=None)

    # Do not drop any columns as they are still required


def downgrade():
    # Recreate the columns if downgrading
    op.add_column('users', sa.Column('avatar', sa.VARCHAR(length=255), nullable=True))
    op.add_column('users', sa.Column('is_staff', sa.BOOLEAN(), nullable=True))
    op.add_column('users', sa.Column('last_name', sa.VARCHAR(length=128), nullable=True))
    op.add_column('users', sa.Column('first_name', sa.VARCHAR(length=128), nullable=True))
    op.add_column('users', sa.Column('type', sa.VARCHAR(length=50), nullable=True))
    op.add_column('users', sa.Column('verification_token', sa.VARCHAR(), nullable=True))
    op.add_column('users', sa.Column('role', sa.VARCHAR(), nullable=True))
    op.add_column('users', sa.Column('is_verified', sa.BOOLEAN(), nullable=True))
    op.add_column('users', sa.Column('otp_code', sa.VARCHAR(), nullable=True))
    op.add_column('users', sa.Column('language_code', sa.VARCHAR(length=35), nullable=True))

    # Modify jwt_token_key back to length 12
    op.alter_column('users', 'jwt_token_key',
                    existing_type=sa.String(length=36),
                    type_=sa.VARCHAR(length=12),
                    existing_nullable=True)
