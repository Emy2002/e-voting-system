# backend/database/migrations/env.py

from __future__ import with_statement
from logging.config import fileConfig
import os
from alembic import context

from backend import db
from backend.database.models import User, Vote, Candidate

config = context.config
fileConfig(config.config_file_name)
target_metadata = db.metadata

def run_migrations_offline():
    url = os.getenv('DATABASE_URL', 'postgresql://evoting:password@db/evoting')
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    connectable = db.engine
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
