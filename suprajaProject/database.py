import sqlite3

def initialize_db():
    conn = sqlite3.connect('file_encryption_tool.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        smtp_username TEXT,
        smtp_password TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS guest_access (
        system_id TEXT UNIQUE,
        access_count INTEGER
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        file_path TEXT,
        encrypted INTEGER,
        file_id TEXT,
        key TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')

    conn.commit()
    conn.close()

def get_file_path(file_id):
    conn = sqlite3.connect('file_encryption_tool.db')
    cursor = conn.cursor()

    cursor.execute('''
    SELECT file_path FROM files WHERE file_id=?
    ''', (file_id,))
    record = cursor.fetchone()
    conn.close()
    return record[0] if record else None
