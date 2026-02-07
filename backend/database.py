"""
Database operations for user authentication
"""
import sqlite3
import bcrypt
from datetime import datetime
import json
import os

# Database file in backend folder
DB_PATH = os.path.join(os.path.dirname(__file__), 'phishguard.db')

def init_db():
    """Initialize database with user and scan history tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked_until TIMESTAMP
        )
    ''')
    
    # Scan history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_level TEXT NOT NULL,
            features_json TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_email ON users(email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_user ON scan_history(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_history(scanned_at)')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

class User:
    """User authentication operations"""
    
    @staticmethod
    def create(username, email, password):
        """Create new user"""
        try:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
            ''', (username, email, password_hash))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return {'id': user_id, 'username': username, 'email': email}
        
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                raise ValueError("Username already exists")
            elif 'email' in str(e):
                raise ValueError("Email already registered")
            else:
                raise ValueError("Registration failed")
    
    @staticmethod
    def verify_password(email, password):
        """Verify login credentials"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, email, password_hash, failed_login_attempts, account_locked_until
            FROM users WHERE email = ?
        ''', (email,))
        
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return None
        
        user_id, username, email, password_hash, failed_attempts, locked_until = result
        
        # Check account lock
        if locked_until:
            locked_until_dt = datetime.fromisoformat(locked_until)
            if datetime.utcnow() < locked_until_dt:
                conn.close()
                raise ValueError("Account temporarily locked due to multiple failed login attempts")
        
        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), password_hash):
            cursor.execute('''
                UPDATE users 
                SET last_login = CURRENT_TIMESTAMP, 
                    failed_login_attempts = 0,
                    account_locked_until = NULL
                WHERE id = ?
            ''', (user_id,))
            conn.commit()
            conn.close()
            
            return {'id': user_id, 'username': username, 'email': email}
        else:
            failed_attempts += 1
            
            if failed_attempts >= 5:
                from datetime import timedelta
                lock_until = datetime.utcnow() + timedelta(minutes=15)
                cursor.execute('''
                    UPDATE users 
                    SET failed_login_attempts = ?,
                        account_locked_until = ?
                    WHERE id = ?
                ''', (failed_attempts, lock_until.isoformat(), user_id))
            else:
                cursor.execute('''
                    UPDATE users 
                    SET failed_login_attempts = ?
                    WHERE id = ?
                ''', (failed_attempts, user_id))
            
            conn.commit()
            conn.close()
            return None
    
    @staticmethod
    def get_by_id(user_id):
        """Get user by ID"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, email FROM users WHERE id = ? AND is_active = 1', (user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {'id': result[0], 'username': result[1], 'email': result[2]}
        return None

class ScanHistory:
    """Scan history operations"""
    
    @staticmethod
    def add_scan(user_id, url, prediction, confidence, risk_level, features=None):
        """Save scan to history"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        features_json = json.dumps(features) if features else None
        
        cursor.execute('''
            INSERT INTO scan_history (user_id, url, prediction, confidence, risk_level, features_json)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, url, prediction, confidence, risk_level, features_json))
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_user_history(user_id, limit=50):
        """Get user scan history"""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, url, prediction, confidence, risk_level, scanned_at
            FROM scan_history
            WHERE user_id = ?
            ORDER BY scanned_at DESC
            LIMIT ?
        ''', (user_id, limit))
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    @staticmethod
    def get_user_stats(user_id):
        """Get user statistics"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total_scans,
                SUM(CASE WHEN prediction = 'Phishing' THEN 1 ELSE 0 END) as phishing_detected,
                SUM(CASE WHEN prediction = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_detected,
                SUM(CASE WHEN prediction = 'Legitimate' THEN 1 ELSE 0 END) as legitimate_scans
            FROM scan_history
            WHERE user_id = ?
        ''', (user_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        return {
            'total_scans': result[0] or 0,
            'phishing_detected': result[1] or 0,
            'suspicious_detected': result[2] or 0,
            'legitimate_scans': result[3] or 0
        }