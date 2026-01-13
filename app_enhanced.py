from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
from datetime import timedelta, datetime
import os

from config import Config
from database_enhanced import Database
from crypto_enhanced import CryptoManager
from password_generator import PasswordGenerator

app = Flask(__name__)
app.config.from_object(Config)

# Initialize components with enhanced security
crypto = CryptoManager()
db = Database(app.config['DATABASE_PATH'], crypto_manager=crypto)
pw_gen = PasswordGenerator()

# Rate limiting configuration
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30
RATE_LIMIT_WINDOW_MINUTES = 15


def get_client_ip():
    """Get client IP address from request"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0]
    return request.environ.get('REMOTE_ADDR', 'unknown')


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response


def check_rate_limit(ip_address):
    """Check if IP address has exceeded rate limit"""
    attempts = db.get_recent_attempts(ip_address, minutes=RATE_LIMIT_WINDOW_MINUTES)
    return attempts < MAX_LOGIN_ATTEMPTS


def is_account_locked():
    """Check if account is locked due to too many failed attempts"""
    return db.is_locked_out()


# Session decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


# Routes
@app.route('/')
def index():
    """Serve the main application page"""
    return render_template('index.html')


# Authentication endpoints
@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    """Check if master password is set and if user is authenticated"""
    has_master = db.has_master_password()
    is_authenticated = session.get('authenticated', False)
    locked_out = is_account_locked()

    return jsonify({
        'has_master_password': has_master,
        'is_authenticated': is_authenticated,
        'locked_out': locked_out
    })


@app.route('/api/auth/setup', methods=['POST'])
def setup_master_password():
    """Set up the initial master password"""
    if db.has_master_password():
        return jsonify({'error': 'Master password already set'}), 400

    data = request.json
    master_password = data.get('master_password')
    ip_address = get_client_ip()

    if not master_password or len(master_password) < 8:
        return jsonify({'error': 'Master password must be at least 8 characters'}), 400

    # Hash and store master password
    password_hash, salt = crypto.hash_master_password(master_password)
    db.set_master_password(password_hash, salt)

    # Authenticate the user
    session['authenticated'] = True
    session['salt'] = salt
    session.permanent = True

    # Log the event
    db.log_event('master_password_created', ip_address, 'Initial master password set', success=True)

    return jsonify({'success': True, 'message': 'Master password set successfully'})


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate with master password"""
    if not db.has_master_password():
        return jsonify({'error': 'Master password not set'}), 400

    ip_address = get_client_ip()

    # Check if account is locked
    if is_account_locked():
        db.log_event('login_failed', ip_address, 'Account locked due to too many failed attempts', success=False)
        return jsonify({'error': 'Account locked due to too many failed attempts. Please try again later.'}), 429

    # Check rate limit
    if not check_rate_limit(ip_address):
        db.log_event('rate_limit_exceeded', ip_address, 'Too many login attempts', success=False)
        # Lock the account
        db.set_lockout(minutes=LOCKOUT_DURATION_MINUTES)
        db.log_event('account_locked_rate_limit', ip_address, f'Account locked for {LOCKOUT_DURATION_MINUTES} minutes', success=False)
        return jsonify({'error': f'Too many login attempts. Account locked for {LOCKOUT_DURATION_MINUTES} minutes.'}), 429

    data = request.json
    master_password = data.get('master_password')

    if not master_password:
        return jsonify({'error': 'Master password required'}), 400

    # Record the attempt
    db.record_rate_limit_attempt(ip_address, 'login')

    # Verify master password
    master_data = db.get_master_password()
    if not crypto.verify_master_password(master_password, master_data['password_hash']):
        db.increment_failed_attempts()
        db.log_event('login_failed', ip_address, 'Invalid master password', success=False)
        return jsonify({'error': 'Invalid master password'}), 401

    # Successful login - reset failed attempts
    db.reset_failed_attempts()

    # Set session
    session['authenticated'] = True
    session['salt'] = master_data['salt']
    session.permanent = True

    # Log successful login
    db.log_event('login_success', ip_address, 'User logged in successfully', success=True)

    return jsonify({'success': True, 'message': 'Login successful'})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout user"""
    ip_address = get_client_ip()
    db.log_event('logout', ip_address, 'User logged out', success=True)
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})


# Category endpoints
@app.route('/api/categories', methods=['GET'])
@login_required
def get_categories():
    """Get all categories"""
    categories = db.get_categories()
    return jsonify(categories)


@app.route('/api/categories', methods=['POST'])
@login_required
def add_category():
    """Add a new category"""
    data = request.json
    name = data.get('name')
    color = data.get('color', '#3B82F6')
    ip_address = get_client_ip()

    if not name:
        return jsonify({'error': 'Category name required'}), 400

    try:
        category_id = db.add_category(name, color)
        db.log_event('category_added', ip_address, f'Category added: {name}', success=True)
        return jsonify({'success': True, 'id': category_id})
    except Exception as e:
        db.log_event('category_add_failed', ip_address, f'Failed to add category: {str(e)}', success=False)
        return jsonify({'error': str(e)}), 400


@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@login_required
def delete_category(category_id):
    """Delete a category"""
    ip_address = get_client_ip()

    if db.delete_category(category_id):
        db.log_event('category_deleted', ip_address, f'Category deleted: {category_id}', success=True)
        return jsonify({'success': True})

    db.log_event('category_delete_failed', ip_address, f'Failed to delete category: {category_id}', success=False)
    return jsonify({'error': 'Category not found'}), 404


# Password endpoints
@app.route('/api/passwords', methods=['GET'])
@login_required
def get_passwords():
    """Get all passwords (encrypted)"""
    category_id = request.args.get('category_id', type=int)
    search_query = request.args.get('search')

    if search_query:
        passwords = db.search_passwords(search_query)
    else:
        passwords = db.get_all_passwords(category_id)

    # Remove encrypted_password from list view for security
    for pwd in passwords:
        pwd.pop('encrypted_password', None)

    return jsonify(passwords)


@app.route('/api/passwords/<int:password_id>', methods=['GET'])
@login_required
def get_password(password_id):
    """Get a specific password and decrypt it"""
    password_entry = db.get_password(password_id)

    if not password_entry:
        return jsonify({'error': 'Password not found'}), 404

    # Decrypt the password
    master_data = db.get_master_password()
    decrypted = crypto.decrypt_password(
        password_entry['encrypted_password'],
        request.json.get('master_password', ''),
        master_data['salt']
    )

    if decrypted is None:
        return jsonify({'error': 'Failed to decrypt password'}), 500

    password_entry['password'] = decrypted
    password_entry.pop('encrypted_password', None)

    return jsonify(password_entry)


@app.route('/api/passwords/decrypt/<int:password_id>', methods=['POST'])
@login_required
def decrypt_password(password_id):
    """Decrypt a specific password"""
    password_entry = db.get_password(password_id)
    ip_address = get_client_ip()

    if not password_entry:
        return jsonify({'error': 'Password not found'}), 404

    # Decrypt the password using session salt
    salt = session.get('salt')
    if not salt:
        return jsonify({'error': 'Session expired'}), 401

    data = request.json
    master_password = data.get('master_password', '')

    # Verify master password before decrypting
    master_data = db.get_master_password()
    if not crypto.verify_master_password(master_password, master_data['password_hash']):
        db.log_event('password_decrypt_failed', ip_address, f'Invalid master password for password {password_id}', success=False)
        return jsonify({'error': 'Invalid master password'}), 401

    decrypted = crypto.decrypt_password(
        password_entry['encrypted_password'],
        master_password,
        salt
    )

    if decrypted is None:
        db.log_event('password_decrypt_failed', ip_address, f'Failed to decrypt password {password_id}', success=False)
        return jsonify({'error': 'Failed to decrypt password'}), 500

    db.log_event('password_decrypted', ip_address, f'Password decrypted: {password_entry["title"]}', success=True)
    return jsonify({'password': decrypted})


@app.route('/api/passwords', methods=['POST'])
@login_required
def add_password():
    """Add a new password"""
    data = request.json
    ip_address = get_client_ip()

    title = data.get('title')
    password = data.get('password')
    master_password = data.get('master_password')
    username = data.get('username')
    url = data.get('url')
    notes = data.get('notes')
    category_id = data.get('category_id')

    if not title or not password or not master_password:
        return jsonify({'error': 'Title, password, and master password required'}), 400

    # Verify master password
    master_data = db.get_master_password()
    if not crypto.verify_master_password(master_password, master_data['password_hash']):
        db.log_event('password_add_failed', ip_address, 'Invalid master password', success=False)
        return jsonify({'error': 'Invalid master password'}), 401

    # Encrypt password
    encrypted_password = crypto.encrypt_password(password, master_password, master_data['salt'])

    # Save to database (username, url, notes are encrypted in database layer)
    password_id = db.add_password(
        title=title,
        encrypted_password=encrypted_password,
        username=username,
        url=url,
        notes=notes,
        category_id=category_id
    )

    db.log_event('password_added', ip_address, f'Password added: {title}', success=True)
    return jsonify({'success': True, 'id': password_id})


@app.route('/api/passwords/<int:password_id>', methods=['PUT'])
@login_required
def update_password(password_id):
    """Update a password"""
    data = request.json
    ip_address = get_client_ip()

    title = data.get('title')
    password = data.get('password')
    master_password = data.get('master_password')
    username = data.get('username')
    url = data.get('url')
    notes = data.get('notes')
    category_id = data.get('category_id')

    # Verify master password if provided
    if master_password:
        master_data = db.get_master_password()
        if not crypto.verify_master_password(master_password, master_data['password_hash']):
            db.log_event('password_update_failed', ip_address, f'Invalid master password for password {password_id}', success=False)
            return jsonify({'error': 'Invalid master password'}), 401

        # Encrypt new password if provided
        encrypted_password = None
        if password:
            encrypted_password = crypto.encrypt_password(password, master_password, master_data['salt'])
    else:
        encrypted_password = None

    # Update in database
    success = db.update_password(
        password_id=password_id,
        title=title,
        username=username,
        encrypted_password=encrypted_password,
        url=url,
        notes=notes,
        category_id=category_id
    )

    if success:
        db.log_event('password_updated', ip_address, f'Password updated: {password_id}', success=True)
        return jsonify({'success': True})

    db.log_event('password_update_failed', ip_address, f'Failed to update password: {password_id}', success=False)
    return jsonify({'error': 'Password not found'}), 404


@app.route('/api/passwords/<int:password_id>', methods=['DELETE'])
@login_required
def delete_password(password_id):
    """Delete a password"""
    ip_address = get_client_ip()

    if db.delete_password(password_id):
        db.log_event('password_deleted', ip_address, f'Password deleted: {password_id}', success=True)
        return jsonify({'success': True})

    db.log_event('password_delete_failed', ip_address, f'Failed to delete password: {password_id}', success=False)
    return jsonify({'error': 'Password not found'}), 404


# Password generator endpoint
@app.route('/api/generate-password', methods=['POST'])
@login_required
def generate_password():
    """Generate a random password"""
    data = request.json or {}

    length = data.get('length', 16)
    use_uppercase = data.get('use_uppercase', True)
    use_lowercase = data.get('use_lowercase', True)
    use_digits = data.get('use_digits', True)
    use_symbols = data.get('use_symbols', True)

    password = pw_gen.generate(
        length=length,
        use_uppercase=use_uppercase,
        use_lowercase=use_lowercase,
        use_digits=use_digits,
        use_symbols=use_symbols
    )

    return jsonify({'password': password})


@app.route('/api/generate-passphrase', methods=['POST'])
@login_required
def generate_passphrase():
    """Generate a passphrase"""
    data = request.json or {}

    word_count = data.get('word_count', 4)
    separator = data.get('separator', '-')

    passphrase = pw_gen.generate_passphrase(word_count=word_count, separator=separator)

    return jsonify({'passphrase': passphrase})


# Security audit endpoint
@app.route('/api/security/audit-log', methods=['GET'])
@login_required
def get_audit_log():
    """Get audit log entries"""
    limit = request.args.get('limit', 100, type=int)
    event_type = request.args.get('event_type')

    logs = db.get_audit_logs(limit=limit, event_type=event_type)
    return jsonify(logs)


# Maintenance endpoint
@app.route('/api/maintenance/cleanup', methods=['POST'])
@login_required
def cleanup_old_data():
    """Clean up old rate limit records"""
    ip_address = get_client_ip()
    db.clear_old_rate_limits(hours=24)
    db.log_event('maintenance', ip_address, 'Cleaned up old rate limit records', success=True)
    return jsonify({'success': True, 'message': 'Cleanup completed'})


if __name__ == '__main__':
    # Create .env file if it doesn't exist
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write(f"SECRET_KEY={os.urandom(24).hex()}\n")
            f.write("FLASK_ENV=production\n")
            f.write("HOST=127.0.0.1\n")  # Changed to localhost for nginx proxy
            f.write("PORT=5000\n")
            f.write("DATABASE_PATH=locknest.db\n")
            f.write("SESSION_TIMEOUT=30\n")
        os.chmod('.env', 0o600)

    print(f"Starting LockNest Password Manager with Enhanced Security...")
    print(f"Access the application at: http://{app.config['HOST']}:{app.config['PORT']}")
    print(f"Security Features Enabled:")
    print(f"  - Database field encryption (AES-256-GCM)")
    print(f"  - Rate limiting ({MAX_LOGIN_ATTEMPTS} attempts per {RATE_LIMIT_WINDOW_MINUTES} minutes)")
    print(f"  - Account lockout ({LOCKOUT_DURATION_MINUTES} minutes)")
    print(f"  - Audit logging")
    print(f"  - Security headers")

    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=False
    )
