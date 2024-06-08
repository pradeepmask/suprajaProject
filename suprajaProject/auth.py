import sqlite3
import hashlib
from tkinter import messagebox

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def signup_user(username, password, smtp_username, smtp_password):
    conn = sqlite3.connect('file_encryption_tool.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''
        INSERT INTO users (username, password, smtp_username, smtp_password) 
        VALUES (?, ?, ?, ?)
        ''', (username, hash_password(password), smtp_username, smtp_password))
        conn.commit()
        messagebox.showinfo("Info", "User registered successfully.")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists.")
    finally:
        conn.close()

def login_user(username, password):
    conn = sqlite3.connect('file_encryption_tool.db')
    cursor = conn.cursor()

    cursor.execute('''
    SELECT * FROM users WHERE username=? AND password=?
    ''', (username, hash_password(password)))

    user = cursor.fetchone()
    conn.close()
    return user

def guest_access(system_id):
    conn = sqlite3.connect('file_encryption_tool.db')
    cursor = conn.cursor()

    cursor.execute('''
    SELECT access_count FROM guest_access WHERE system_id=?
    ''', (system_id,))
    record = cursor.fetchone()

    if record:
        access_count = record[0]
        if access_count < 4:
            cursor.execute('''
            UPDATE guest_access SET access_count = access_count + 1 WHERE system_id=?
            ''', (system_id,))
            conn.commit()
            conn.close()
            return True
        else:
            conn.close()
            return False
    else:
        cursor.execute('''
        INSERT INTO guest_access (system_id, access_count) VALUES (?, 1)
        ''', (system_id,))
        conn.commit()
        conn.close()
        return True

def get_smtp_credentials(username):
    conn = sqlite3.connect('file_encryption_tool.db')
    cursor = conn.cursor()

    cursor.execute('''
    SELECT smtp_username, smtp_password FROM users WHERE username=?
    ''', (username,))
    credentials = cursor.fetchone()
    conn.close()
    return credentials
