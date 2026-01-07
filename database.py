import sqlite3
from contextlib import contextmanager
from datetime import datetime
import json

class Database:
    """Database manager for LockNest password manager"""

    def __init__(self, db_path):
        self.db_path = db_path
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
                    SET password_hash = ?, salt = ?, updated_at = ?
                    WHERE id = 1
                ''', (password_hash, salt, now))
            else:
                cursor.execute('''
                    INSERT INTO master_password (id, password_hash, salt, created_at, updated_at)
                    VALUES (1, ?, ?, ?, ?)
                ''', (password_hash, salt, now, now))

    def get_master_password(self):
        """Get master password hash and salt"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash, salt FROM master_password WHERE id = 1')
            row = cursor.fetchone()
            return dict(row) if row else None

    def has_master_password(self):
        """Check if master password is set"""
        return self.get_master_password() is not None

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
        """Add a new password entry"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            cursor.execute('''
                INSERT INTO passwords (title, username, encrypted_password, url, notes, category_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (title, username, encrypted_password, url, notes, category_id, now, now))
            return cursor.lastrowid

    def get_password(self, password_id):
        """Get a specific password entry"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT p.*, c.name as category_name, c.color as category_color
                FROM passwords p
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE p.id = ?
            ''', (password_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

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
            return [dict(row) for row in cursor.fetchall()]

    def update_password(self, password_id, title=None, username=None, encrypted_password=None,
                       url=None, notes=None, category_id=None):
        """Update a password entry"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Get current values
            current = self.get_password(password_id)
            if not current:
                return False

            # Use current values if new ones not provided
            title = title if title is not None else current['title']
            username = username if username is not None else current['username']
            encrypted_password = encrypted_password if encrypted_password is not None else current['encrypted_password']
            url = url if url is not None else current['url']
            notes = notes if notes is not None else current['notes']
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
        """Search passwords by title, username, or URL"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            search_term = f'%{query}%'
            cursor.execute('''
                SELECT p.*, c.name as category_name, c.color as category_color
                FROM passwords p
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE p.title LIKE ? OR p.username LIKE ? OR p.url LIKE ?
                ORDER BY p.title
            ''', (search_term, search_term, search_term))
            return [dict(row) for row in cursor.fetchall()]
