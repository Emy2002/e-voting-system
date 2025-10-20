# backend/routes.py

# Routes and views for Flask app combining all roles into a unified interface
# Calls underlying security services from authentication, voting, audit, etc.

from flask import render_template, request, jsonify, session, redirect, url_for
from backend import app, limiter, db
from backend.authentication.mfa import MFAService
from backend.authentication.rbac import RBACService, require_permission, Permission
from backend.database.models import User
from backend.encryption.data_encryption import DataEncryptionService
from backend.encryption.digital_signatures import DigitalSignatureService
from backend.encryption.password_hashing import PasswordHashingService
from backend.security.input_validator import InputValidator
from backend.audit.audit_logger import AuditLogger
from datetime import datetime
from flask_jwt_extended import create_access_token, set_access_cookies, create_refresh_token, set_refresh_cookies, unset_jwt_cookies, jwt_required, get_jwt_identity

# Initialize security services (SR-01 to SR-20)
mfa_service = MFAService()
rbac_service = RBACService()
encryption_service = DataEncryptionService()
signature_service = DigitalSignatureService()
password_service = PasswordHashingService()
validator = InputValidator()
audit_logger = AuditLogger()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    try:
        email = validator.sanitize_string(request.form.get('email'))
        password = request.form.get('password')
        totp_code = request.form.get('totp_code')

        # SR-07 Input Validation & SR-06 Password hashing verification
        if not validator.validate_email(email):
            audit_logger.log_security_event('invalid_login_attempt', {'email': email, 'reason': 'invalid_email'})
            return render_template('login.html', error='Invalid email or password.')

        # Load user from DB: placeholder get_user_by_email
        user = get_user_by_email(email)
        if not user or not password_service.verify_password(password, user.password_hash):
            audit_logger.log_security_event('failed_login', {'email': email, 'ip': request.remote_addr})
            return render_template('login.html', error='Invalid email or password.')

        # SR-01 MFA TOTP Verification
        if not mfa_service.verify_totp(user.mfa_secret, totp_code):
            audit_logger.log_security_event('failed_mfa', {'user_id': user.id, 'ip': request.remote_addr})
            return render_template('login.html', error='Invalid MFA code.')

        session['user_id'] = user.id
        session['user_role'] = user.role
        session['login_time'] = datetime.utcnow().isoformat()
        audit_logger.log_security_event('successful_login', {'user_id': user.id, 'role': user.role})

        # JWT: create short-lived access token and refresh token, set in cookies
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))
        resp = redirect(url_for('dashboard'))
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        return resp
    except Exception as e:
        audit_logger.log_security_event('login_error', {'error': str(e), 'ip': request.remote_addr})
        return render_template('login.html', error='An error occurred, please try again.')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()
    role = session.get('user_role')
    # Ensure role comparison is robust
    if str(role).lower() == 'administrator':
        return render_template('admin.html')
    elif str(role).lower() == 'commissioner':
        return render_template('commissioner.html')
    elif str(role).lower() == 'aec_employee':
        return render_template('aec_employee.html')
    else:
        return render_template('dashboard.html')

@app.route('/vote', methods=['POST'])
@jwt_required()
@limiter.limit("1/hour")  # SR-15 Rate limit
@require_permission(Permission.VOTE)  # SR-02 RBAC permission
def vote():
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        vote_data = request.json
        # SR-07 Input validation of voting data
        vote_data_validated = validator.validate_vote_data(vote_data)

        # Prevent double voting: placeholder has_voted
        if has_voted(user_id):
            audit_logger.log_security_event('duplicate_vote_attempt', {'user_id': user_id})
            return jsonify({'error': 'User has already voted'}), 403

        vote_data_validated['voter_id'] = user_id
        vote_data_validated['timestamp'] = datetime.utcnow().isoformat()

        # Sign vote (SR-05)
        signed_vote = signature_service.sign_vote(vote_data_validated)
        # Encrypt vote (SR-04)
        encrypted_vote = encryption_service.encrypt_vote(signed_vote, user_id)
        # Store vote to DB placeholder store_vote()
        vote_id = store_vote(encrypted_vote)

        receipt = signature_service.create_vote_receipt(signed_vote)
        audit_logger.log_security_event('vote_cast', {'vote_id': vote_id, 'voter_id_hash': encryption_service._hash_voter_id(user_id)})

        return jsonify({'message': 'Vote cast successfully', 'vote_id': vote_id, 'receipt': receipt})
    except Exception as e:
        audit_logger.log_security_event('vote_error', {'user_id': user_id, 'error': str(e)})
        return jsonify({'error': 'Failed to cast vote'}), 500

@app.route('/results')
@jwt_required()
@require_permission(Permission.VIEW_RESULTS)
def results():
    user_id = get_jwt_identity()
    try:
        # Placeholder get_all_votes() from DB
        votes_encrypted = get_all_votes()
        valid_votes = []
        for vote_encrypted in votes_encrypted:
            decrypted = encryption_service.decrypt_vote(vote_encrypted.data)
            if signature_service.verify_vote_signature(decrypted):
                valid_votes.append(decrypted['vote_data'])
        results = calculate_results(valid_votes)

        audit_logger.log_security_event('results_accessed', {'user_id': user_id, 'votes_count': len(valid_votes)})

        return render_template('results.html', results=results)
    except Exception as e:
        audit_logger.log_security_event('results_error', {'user_id': user_id, 'error': str(e)})
        return 'Error loading results', 500

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    # Rotate refresh token and issue new access token
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    refresh_token = create_refresh_token(identity=current_user)
    resp = jsonify({'refresh': True})
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)
    return resp

@app.route('/logout')
def logout():
    session.clear()
    resp = redirect(url_for('home'))
    unset_jwt_cookies(resp)
    return resp

@app.route('/register_voters')
@jwt_required()
@require_permission(Permission.REGISTER_VOTERS)
def register_voters():
    return render_template('register_voters.html')

@app.route('/view_voter_list')
@jwt_required()
@require_permission(Permission.VIEW_VOTER_LIST)
def view_voter_list():
    return render_template('view_voter_list.html')

@app.route('/view_own_status')
@jwt_required()
@require_permission(Permission.VIEW_OWN_STATUS)
def view_own_status():
    return render_template('view_own_status.html')

@app.route('/manage_users')
@jwt_required()
@require_permission(Permission.MANAGE_USERS)
def manage_users():
    # Placeholder: In production, fetch and display users from the database
    return render_template('manage_users.html')

@app.route('/view_audit_logs')
@jwt_required()
@require_permission(Permission.VIEW_AUDIT_LOGS)
def view_audit_logs():
    # Placeholder: In production, load and display audit logs from file or DB
    return render_template('view_audit_logs.html')

@app.route('/configure_system')
@jwt_required()
@require_permission(Permission.CONFIGURE_SYSTEM)
def configure_system():
    # Placeholder: In production, provide system configuration options
    return render_template('configure_system.html')

@app.route('/manage_candidates')
@jwt_required()
@require_permission(Permission.MANAGE_CANDIDATES)
def manage_candidates():
    # Placeholder: In production, manage candidate records
    return render_template('manage_candidates.html')

@app.route('/manage_elections')
@jwt_required()
@require_permission(Permission.MANAGE_ELECTIONS)
def manage_elections():
    # Placeholder: In production, manage election events
    return render_template('manage_elections.html')

@app.route('/update_address')
@jwt_required()
@require_permission(Permission.UPDATE_ADDRESS)
def update_address():
    # Placeholder: In production, allow voters to update their address
    return render_template('update_address.html')

# Placeholder functions - implement DB integration later in database/models.py
def get_user_by_email(email):
    return db.session.query(User).filter_by(email=email).first()

def has_voted(user_id):
    # Check DB if user has voted
    return False

def store_vote(encrypted_vote):
    # Store encrypted vote in DB and return vote id
    return 'vote123'

def get_all_votes():
    # Get all votes from DB
    return []

def calculate_results(votes):
    # Calculate and return voting results
    return {}
