import sqlite3
from contextlib import contextmanager
from datetime import datetime
import json

class Database:
    """Database manager for LockNest password manager with enhanced security"""

    def __init__(self, db_path, crypto_manager=None):
        self.db_path = db_path
        self.crypto = crypto_manager
        self.init_database()

    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def init_database(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Master password table (stores hashed master password and salt)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS master_password (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')

            # Categories table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    color TEXT DEFAULT '#3B82F6',
                    created_at TEXT NOT NULL
                )
            ''')

            # Passwords table (stores encrypted passwords)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    username TEXT,
                    encrypted_password TEXT NOT NULL,
                    url TEXT,
                    notes TEXT,
                    category_id INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE SET NULL
                )
            ''')

            # Audit log table for security events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    details TEXT,
                    success INTEGER DEFAULT 1
                )
            ''')

            # Rate limiting table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rate_limits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    attempt_time TEXT NOT NULL,
                    event_type TEXT NOT NULL
                )
            ''')

            # Create index for audit log queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log(timestamp DESC)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_event_type
                ON audit_log(event_type)
            ''')

            # Create index for rate limiting
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_rate_limits_ip
                ON rate_limits(ip_address, attempt_time)
            ''')

            # Create default categories
            default_categories = [
                ('Personal', '#3B82F6'),
                ('Work', '#10B981'),
                ('Finance', '#F59E0B'),
                ('Social Media', '#8B5CF6'),
                ('Email', '#EF4444'),
                ('Other', '#6B7280')
            ]

            for name, color in default_categories:
                cursor.execute('''
                    INSERT OR IGNORE INTO categories (name, color, created_at)
                    VALUES (?, ?, ?)
                ''', (name, color, datetime.utcnow().isoformat()))

    # Audit Logging Methods
    def log_event(self, event_type, ip_address=None, details=None, success=True):
        """Log a security event"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log (timestamp, event_type, ip_address, details, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.utcnow().isoformat(), event_type, ip_address, details, 1 if success else 0))

    def get_audit_logs(self, limit=100, event_type=None):
        """Get audit logs with optional filtering"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if event_type:
                cursor.execute('''
                    SELECT * FROM audit_log
                    WHERE event_type = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (event_type, limit))
            else:
                cursor.execute('''
                    SELECT * FROM audit_log
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # Rate Limiting Methods
    def record_rate_limit_attempt(self, ip_address, event_type='login'):
        """Record a rate-limited event attempt"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO rate_limits (ip_address, attempt_time, event_type)
                VALUES (?, ?, ?)
            ''', (ip_address, datetime.utcnow().isoformat(), event_type))

    def get_recent_attempts(self, ip_address, minutes=15, event_type='login'):
        """Get recent attempts for rate limiting"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) as count FROM rate_limits
                WHERE ip_address = ?
                AND event_type = ?
                AND datetime(attempt_time) > datetime('now', ? || ' minutes')
            ''', (ip_address, event_type, -minutes))
            result = cursor.fetchone()
            return result['count'] if result else 0

    def clear_old_rate_limits(self, hours=24):
        """Clean up old rate limit records"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM rate_limits
                WHERE datetime(attempt_time) < datetime('now', ? || ' hours')
            ''', (-hours,))

    # Master Password Methods
    def set_master_password(self, password_hash, salt):
        """Set or update master password"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()

            cursor.execute('SELECT id FROM master_password WHERE id = 1')
            if cursor.fetchone():
                cursor.execute('''
                    UPDATE master_password
                    SET password_hash = ?, salt = ?, updated_at = ?, failed_attempts = 0, locked_until = NULL
                    WHERE id = 1
                ''', (password_hash, salt, now))
            else:
                cursor.execute('''
                    INSERT INTO master_password (id, password_hash, salt, failed_attempts, created_at, updated_at)
                    VALUES (1, ?, ?, 0, ?, ?)
                ''', (password_hash, salt, now, now))

    def get_master_password(self):
        """Get master password hash and salt"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash, salt, failed_attempts, locked_until FROM master_password WHERE id = 1')
            row = cursor.fetchone()
            return dict(row) if row else None

    def has_master_password(self):
        """Check if master password is set"""
        return self.get_master_password() is not None

    def increment_failed_attempts(self):
        """Increment failed login attempts"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE master_password
                SET failed_attempts = failed_attempts + 1
                WHERE id = 1
            ''')

    def reset_failed_attempts(self):
        """Reset failed login attempts"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE master_password
                SET failed_attempts = 0
                WHERE id = 1
            ''')

    def set_lockout(self, minutes=30):
        """Set account lockout"""
        from datetime import timedelta
        lockout_until = (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE master_password
                SET locked_until = ?
                WHERE id = 1
            ''', (lockout_until,))

    def clear_lockout(self):
        """Clear account lockout"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE master_password
                SET locked_until = NULL, failed_attempts = 0
                WHERE id = 1
            ''')

    def is_locked_out(self):
        """Check if account is currently locked out"""
        master_data = self.get_master_password()
        if not master_data or not master_data.get('locked_until'):
            return False

        locked_until = datetime.fromisoformat(master_data['locked_until'])
        return datetime.utcnow() < locked_until

    # Category Methods
    def get_categories(self):
        """Get all categories"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM categories ORDER BY name')
            return [dict(row) for row in cursor.fetchall()]

    def add_category(self, name, color='#3B82F6'):
        """Add a new category"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO categories (name, color, created_at)
                VALUES (?, ?, ?)
            ''', (name, color, datetime.utcnow().isoformat()))
            return cursor.lastrowid

    def delete_category(self, category_id):
        """Delete a category"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM categories WHERE id = ?', (category_id,))
            return cursor.rowcount > 0

    # Password Methods
    def add_password(self, title, encrypted_password, username=None, url=None, notes=None, category_id=None):
        """Add a new password entry with field encryption"""
        # Encrypt sensitive fields if crypto manager is available
        encrypted_username = self.crypto.encrypt_field(username) if self.crypto and username else username
        encrypted_url = self.crypto.encrypt_field(url) if self.crypto and url else url
        encrypted_notes = self.crypto.encrypt_field(notes) if self.crypto and notes else notes

        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            cursor.execute('''
                INSERT INTO passwords (title, username, encrypted_password, url, notes, category_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (title, encrypted_username, encrypted_password, encrypted_url, encrypted_notes, category_id, now, now))
            return cursor.lastrowid

    def get_password(self, password_id):
        """Get a specific password entry with field decryption"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT p.*, c.name as category_name, c.color as category_color
                FROM passwords p
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE p.id = ?
            ''', (password_id,))
            row = cursor.fetchone()
            if not row:
                return None

            result = dict(row)

            # Decrypt sensitive fields if crypto manager is available
            if self.crypto:
                result['username'] = self.crypto.decrypt_field(result['username'])
                result['url'] = self.crypto.decrypt_field(result['url'])
                result['notes'] = self.crypto.decrypt_field(result['notes'])

            return result

    def get_all_passwords(self, category_id=None):
        """Get all password entries, optionally filtered by category"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if category_id:
                cursor.execute('''
                    SELECT p.*, c.name as category_name, c.color as category_color
                    FROM passwords p
                    LEFT JOIN categories c ON p.category_id = c.id
                    WHERE p.category_id = ?
                    ORDER BY p.title
                ''', (category_id,))
            else:
                cursor.execute('''
                    SELECT p.*, c.name as category_name, c.color as category_color
                    FROM passwords p
                    LEFT JOIN categories c ON p.category_id = c.id
                    ORDER BY p.title
                ''')

            results = [dict(row) for row in cursor.fetchall()]

            # Decrypt sensitive fields if crypto manager is available
            if self.crypto:
                for result in results:
                    result['username'] = self.crypto.decrypt_field(result['username'])
                    result['url'] = self.crypto.decrypt_field(result['url'])
                    result['notes'] = self.crypto.decrypt_field(result['notes'])

            return results

    def update_password(self, password_id, title=None, username=None, encrypted_password=None,
                       url=None, notes=None, category_id=None):
        """Update a password entry with field encryption"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Get current values
            current = self.get_password(password_id)
            if not current:
                return False

            # Use current values if new ones not provided
            title = title if title is not None else current['title']

            # Encrypt new values if provided, otherwise keep current
            if username is not None:
                username = self.crypto.encrypt_field(username) if self.crypto else username
            else:
                # Re-encrypt current value to maintain encryption
                username = self.crypto.encrypt_field(current['username']) if self.crypto and current['username'] else current['username']

            if url is not None:
                url = self.crypto.encrypt_field(url) if self.crypto else url
            else:
                url = self.crypto.encrypt_field(current['url']) if self.crypto and current['url'] else current['url']

            if notes is not None:
                notes = self.crypto.encrypt_field(notes) if self.crypto else notes
            else:
                notes = self.crypto.encrypt_field(current['notes']) if self.crypto and current['notes'] else current['notes']

            encrypted_password = encrypted_password if encrypted_password is not None else current['encrypted_password']
            category_id = category_id if category_id is not None else current['category_id']

            cursor.execute('''
                UPDATE passwords
                SET title = ?, username = ?, encrypted_password = ?, url = ?, notes = ?,
                    category_id = ?, updated_at = ?
                WHERE id = ?
            ''', (title, username, encrypted_password, url, notes, category_id,
                  datetime.utcnow().isoformat(), password_id))
            return cursor.rowcount > 0

    def delete_password(self, password_id):
        """Delete a password entry"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
            return cursor.rowcount > 0

    def search_passwords(self, query):
        """Search passwords by title"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            search_term = f'%{query}%'
            # Only search by title since username/URL are encrypted
            cursor.execute('''
                SELECT p.*, c.name as category_name, c.color as category_color
                FROM passwords p
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE p.title LIKE ?
                ORDER BY p.title
            ''', (search_term,))

            results = [dict(row) for row in cursor.fetchall()]

            # Decrypt sensitive fields if crypto manager is available
            if self.crypto:
                for result in results:
                    result['username'] = self.crypto.decrypt_field(result['username'])
                    result['url'] = self.crypto.decrypt_field(result['url'])
                    result['notes'] = self.crypto.decrypt_field(result['notes'])

            return results
