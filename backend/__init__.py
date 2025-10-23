# backend/__init__.py

from flask import Flask, jsonify, redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
import os
from flask_jwt_extended import JWTManager
from datetime import timedelta


# SR-03: TLS Enforcement via Flask app running with adhoc certificate (configured in Dockerfile CMD)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-production')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'change-me-in-production-suprtjwt')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=2)   # 2 mins
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(minutes=3)  # 3 mins for testing
app.config['JWT_TOKEN_LOCATION'] = ['cookies']          # Send via headers (Bearer)
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'  # available everywhere
app.config['JWT_COOKIE_SECURE'] = False  

jwt = JWTManager(app)

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    # If browser request, redirect to login
    if request.accept_mimetypes.accept_html:
        return redirect(url_for('login'))
    # If AJAX/API, return JSON
    return jsonify({"msg": "Token has expired"}), 401

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'postgresql://evoting:password@localhost:5434/evoting'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Fix proxy headers for HTTPS
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Initialize extensions
db = SQLAlchemy(app)  # Database ORM
migrate = Migrate(app, db)  # DB migrations

# Configure rate limiter with Redis storage
redis_uri = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
limiter = Limiter(key_func=get_remote_address, default_limits=["10000/hour"])  # Very high for development
limiter.init_app(app)


# Ensure model modules are imported so SQLAlchemy metadata is populated
# This makes models discoverable by Flask-Migrate / Alembic when running
# `flask db migrate`.
from backend.database import models  # noqa: F401

from backend import routes  # Import Flask routes
