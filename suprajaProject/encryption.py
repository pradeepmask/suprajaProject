import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.fernet import Fernet
from tkinter import messagebox

def generate_key():
    return Fernet.generate_key()

def encrypt_file(filepath, key):
    fernet = Fernet(key)
    try:
        with open(filepath, 'rb') as file:
            data = file.read()
        encrypted_data = fernet.encrypt(data)
        with open(filepath, 'wb') as file:
            file.write(encrypted_data)
        messagebox.showinfo("Info", "File encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

def decrypt_file(filepath, key):
    fernet = Fernet(key)
    try:
        with open(filepath, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(filepath, 'wb') as file:
            file.write(decrypted_data)
        messagebox.showinfo("Info", "File decrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def send_key(sender_email, receiver_email, key, file_id):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "developermask140@gmail.com"
    smtp_password = "gmikylkvtqjxmnrx"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = 'Encryption Key for File'

    message = f'The key for the encrypted file with ID "{file_id}" is:\n{key}'

    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        messagebox.showinfo("Info", "Key sent via email successfully.")
    except smtplib.SMTPAuthenticationError:
        messagebox.showerror("Error", "Failed to authenticate. Check SMTP credentials.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email: {str(e)}")
