from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
import os
import sys


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))


# this is the Alembic Config object, which provides access to the values within the .ini file in use.
config = context.config


# Interpret the config file for Python logging.
fileConfig(config.config_file_name)


# add your model's MetaData object here
# for 'autogenerate' support
from app.database import BaseModel
from app.models.user import UserModel  # Ensure 'Base' is correctly imported from your models
from app.models.session import Session
from app.models.vendor import VendorModel
from app.models.admin import AdminModel
target_metadata = BaseModel.metadata


# other values from the config, defined by the needs of env.py, can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.




def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url, target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"}
    )


    with context.begin_transaction():
        context.run_migrations()




def run_migrations_online():
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section), prefix="sqlalchemy.", poolclass=pool.NullPool
    )


    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)


        with context.begin_transaction():
            context.run_migrations()




if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
