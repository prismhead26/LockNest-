from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
from datetime import timedelta
import os

from config import Config
from database import Database
from crypto import CryptoManager
from password_generator import PasswordGenerator

app = Flask(__name__)
app.config.from_object(Config)

# Initialize components
db = Database(app.config['DATABASE_PATH'])
crypto = CryptoManager()
pw_gen = PasswordGenerator()

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
    return jsonify({
        'has_master_password': has_master,
        'is_authenticated': is_authenticated
    })

@app.route('/api/auth/setup', methods=['POST'])
def setup_master_password():
    """Set up the initial master password"""
    if db.has_master_password():
        return jsonify({'error': 'Master password already set'}), 400

    data = request.json
    master_password = data.get('master_password')

    if not master_password or len(master_password) < 8:
        return jsonify({'error': 'Master password must be at least 8 characters'}), 400

    # Hash and store master password
    password_hash, salt = crypto.hash_master_password(master_password)
    db.set_master_password(password_hash, salt)

    # Authenticate the user
    session['authenticated'] = True
    session['salt'] = salt
    session.permanent = True

    return jsonify({'success': True, 'message': 'Master password set successfully'})

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate with master password"""
    if not db.has_master_password():
        return jsonify({'error': 'Master password not set'}), 400

    data = request.json
    master_password = data.get('master_password')

    if not master_password:
        return jsonify({'error': 'Master password required'}), 400

    # Verify master password
    master_data = db.get_master_password()
    if not crypto.verify_master_password(master_password, master_data['password_hash']):
        return jsonify({'error': 'Invalid master password'}), 401

    # Set session
    session['authenticated'] = True
    session['salt'] = master_data['salt']
    session.permanent = True

    return jsonify({'success': True, 'message': 'Login successful'})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout user"""
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

    if not name:
        return jsonify({'error': 'Category name required'}), 400

    try:
        category_id = db.add_category(name, color)
        return jsonify({'success': True, 'id': category_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@login_required
def delete_category(category_id):
    """Delete a category"""
    if db.delete_category(category_id):
        return jsonify({'success': True})
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

    if not password_entry:
        return jsonify({'error': 'Password not found'}), 404

    # Decrypt the password using session salt
    salt = session.get('salt')
    if not salt:
        return jsonify({'error': 'Session expired'}), 401

    data = request.json
    master_password = data.get('master_password', '')

    decrypted = crypto.decrypt_password(
        password_entry['encrypted_password'],
        master_password,
        salt
    )

    if decrypted is None:
        return jsonify({'error': 'Failed to decrypt password'}), 500

    return jsonify({'password': decrypted})

@app.route('/api/passwords', methods=['POST'])
@login_required
def add_password():
    """Add a new password"""
    data = request.json

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
        return jsonify({'error': 'Invalid master password'}), 401

    # Encrypt password
    encrypted_password = crypto.encrypt_password(password, master_password, master_data['salt'])

    # Save to database
    password_id = db.add_password(
        title=title,
        encrypted_password=encrypted_password,
        username=username,
        url=url,
        notes=notes,
        category_id=category_id
    )

    return jsonify({'success': True, 'id': password_id})

@app.route('/api/passwords/<int:password_id>', methods=['PUT'])
@login_required
def update_password(password_id):
    """Update a password"""
    data = request.json

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
        return jsonify({'success': True})
    return jsonify({'error': 'Password not found'}), 404

@app.route('/api/passwords/<int:password_id>', methods=['DELETE'])
@login_required
def delete_password(password_id):
    """Delete a password"""
    if db.delete_password(password_id):
        return jsonify({'success': True})
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

if __name__ == '__main__':
    # Create .env file if it doesn't exist
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write(f"SECRET_KEY={os.urandom(24).hex()}\n")
            f.write("FLASK_ENV=production\n")
            f.write("HOST=0.0.0.0\n")
            f.write("PORT=5000\n")
            f.write("DATABASE_PATH=locknest.db\n")
            f.write("SESSION_TIMEOUT=30\n")

    print(f"Starting LockNest Password Manager...")
    print(f"Access the application at: http://{app.config['HOST']}:{app.config['PORT']}")
    print(f"On your local network, use your Pi's IP address instead of {app.config['HOST']}")

    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=False
    )
