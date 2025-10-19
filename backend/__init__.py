# backend/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
import os

# SR-03: TLS Enforcement via Flask app running with adhoc certificate (configured in Dockerfile CMD)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'postgresql://evoting:password@db/evoting'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Fix proxy headers for HTTPS
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Initialize extensions
db = SQLAlchemy(app)  # Database ORM
migrate = Migrate(app, db)  # DB migrations

# Configure rate limiter with Redis storage
redis_uri = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
limiter = Limiter(key_func=get_remote_address, default_limits=["200/day", "50/hour"])
limiter.init_app(app)


# Ensure model modules are imported so SQLAlchemy metadata is populated
# This makes models discoverable by Flask-Migrate / Alembic when running
# `flask db migrate`.
from backend.database import models  # noqa: F401

from backend import routes  # Import Flask routes
