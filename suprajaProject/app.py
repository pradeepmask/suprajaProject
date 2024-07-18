import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from ttkthemes import ThemedStyle
from database import initialize_db, get_file_path
from auth import signup_user, login_user, guest_access
from encryption import generate_key, encrypt_file, decrypt_file, send_key
import os
import uuid
import sqlite3
import hashlib


def get_system_id():
    return hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()


def show_frame(frame):
    frame.tkraise()


def browse_file(entry_widget):
    filepath = filedialog.askopenfilename(filetypes=[("All Files", ".")])
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, filepath)


def store_file_info(filepath, key, file_id):
    conn = sqlite3.connect('file_encryption_tool.db')
    cursor = conn.cursor()

    cursor.execute('''
    INSERT INTO files (user_id, file_path, encrypted, file_id, key) 
    VALUES (?, ?, ?, ?, ?)
    ''', (None, filepath, 1, file_id, key))
    conn.commit()
    conn.close()


def encrypt_and_send(filepath, receiver_email,password):
    if not filepath:
        messagebox.showerror("Error", "Please select a file to encrypt.")
        return
    if not receiver_email:
        messagebox.showerror("Error", "Please enter the receiver email.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter the password.")
        return
    key = generate_key(password)
    file_id = str(uuid.uuid4())
    encrypt_file(filepath, key)
    send_key("developermask140@gmail.com", receiver_email, password, file_id)
    store_file_info(filepath, key.decode(), file_id)
    messagebox.showinfo("Success", "File encrypted and key sent successfully!")
    refresh_page()


def show_file(file_id, key):
    if not file_id:
        messagebox.showerror("Error", "Please enter the file ID.")
        return
    if not key:
        messagebox.showerror("Error", "Please enter the decryption key.")
        return

    filepath = get_file_path(file_id)
    if not filepath:
        messagebox.showerror("Error", "Invalid file ID.")
        return

    try:
        decrypt_file(filepath, key.encode())
        os.startfile(filepath)
        decrypted_file_label.config(text=f"Decrypted File: {filepath}")
        decrypted_key_label.config(text=f"Decryption Key: {key}")
        download_button.config(state="normal", command=lambda: download_file(filepath))
        messagebox.showinfo("Success", "File decrypted successfully!")
    except FileNotFoundError:
        messagebox.showerror("Error", "File not found.")
    except Exception as e:
        messagebox.showerror("Error", str(e))
    refresh_page()


def download_file(filepath):
    download_path = filedialog.asksaveasfilename(defaultextension=os.path.splitext(filepath)[1],
                                                 filetypes=[("All Files", ".*")])
    if download_path:
        try:
            with open(filepath, 'rb') as src_file:
                with open(download_path, 'wb') as dst_file:
                    dst_file.write(src_file.read())
            messagebox.showinfo("Success", f"File downloaded to {download_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


def refresh_page():
    # Reset encryption fields
    filepath_entry_enc.delete(0, tk.END)
    receiver_email_entry_enc.delete(0, tk.END)

    # Reset decryption fields
    file_id_entry_dec.delete(0, tk.END)
    key_entry_dec.delete(0, tk.END)

    # Reset decrypted file labels
    decrypted_file_label.config(text="")
    decrypted_key_label.config(text="")

    # Disable the download button
    download_button.config(state="disabled")


def run_app():
    global filepath_entry_enc, receiver_email_entry_enc
    global file_id_entry_dec, key_entry_dec
    global decrypted_file_label, decrypted_key_label
    global download_button

    root = tk.Tk()
    root.title("File Encryption Tool")
    root.geometry("800x600")

    style = ThemedStyle(root)
    style.set_theme("arc")

    container = ttk.Frame(root)
    container.pack(fill="both", expand=True)
    container.grid_rowconfigure(0, weight=1)
    container.grid_columnconfigure(0, weight=1)

    landing_frame = ttk.Frame(container)
    landing_frame.grid(row=0, column=0, sticky="nsew")

    encrypt_frame = ttk.Frame(container)
    encrypt_frame.grid(row=0, column=0, sticky="nsew")

    decrypt_frame = ttk.Frame(container)
    decrypt_frame.grid(row=0, column=0, sticky="nsew")

    frames = {
        "Landing": landing_frame,
        "Encrypt": encrypt_frame,
        "Decrypt": decrypt_frame,
    }

    for frame in frames.values():
        frame.grid(row=0, column=0, sticky="nsew")

    def on_show_file():
        file_id = file_id_entry_dec.get()
        key = key_entry_dec.get()
        if not file_id:
            messagebox.showerror("Error", "Please enter the file ID.")
            return
        if not key:
            messagebox.showerror("Error", "Please enter the decryption key.")
            return

        filepath = get_file_path(file_id)
        if not filepath:
            messagebox.showerror("Error", "Invalid file ID.")
            return

        try:
            decrypt_file(filepath, key.encode())
            decrypted_file_label.config(text=f"Decrypted File: {filepath}")
            decrypted_key_label.config(text=f"Decryption Key: {key}")
            download_button.config(state="normal", command=lambda: download_file(filepath))
        except FileNotFoundError:
            messagebox.showerror("Error", "File not found.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # Landing Frame UI
    ttk.Label(landing_frame, text="File Encryption Tool", font=("Helvetica", 16)).pack(pady=20)

    upload_box = ttk.LabelFrame(landing_frame, text="Encrypt and Send", padding=(10, 5))
    upload_box.pack(pady=10, fill="x", padx=20)

    ttk.Label(upload_box, text="Upload File:").grid(row=0, column=0, pady=10, padx=10)
    filepath_entry_enc = ttk.Entry(upload_box, width=40)
    filepath_entry_enc.grid(row=0, column=1, pady=5)
    ttk.Button(upload_box, text="Browse", command=lambda: browse_file(filepath_entry_enc)).grid(row=0, column=2,
                                                                                                pady=10, padx=10)

    ttk.Label(upload_box, text="Receiver Email:").grid(row=1, column=0, pady=10, padx=10)
    receiver_email_entry_enc = ttk.Entry(upload_box, width=40)
    receiver_email_entry_enc.grid(row=1, column=1, pady=5)

    ttk.Label(upload_box, text="Password:").grid(row=2, column=0, pady=10, padx=10)
    password_entry_enc = ttk.Entry(upload_box, width=40)
    password_entry_enc.grid(row=2, column=1, pady=5)

    ttk.Button(upload_box, text="Encrypt and Send Key",
               command=lambda: encrypt_and_send(filepath_entry_enc.get(), receiver_email_entry_enc.get(),password_entry_enc.get())).grid(row=2,
                                                                                                                column=4,
                                                                                                                columnspan=3,
                                                                                                                pady=20)

    receive_box = ttk.LabelFrame(landing_frame, text="Decrypt and Receive", padding=(10, 5))
    receive_box.pack(pady=10, fill="x", padx=20)

    ttk.Label(receive_box, text="File ID:").grid(row=0, column=0, pady=10, padx=10)
    file_id_entry_dec = ttk.Entry(receive_box, width=40)
    file_id_entry_dec.grid(row=0, column=1, pady=5)

    ttk.Label(receive_box, text="Decryption Key:").grid(row=1, column=0, pady=10, padx=10)
    key_entry_dec = ttk.Entry(receive_box, width=40)
    key_entry_dec.grid(row=1, column=1, pady=5)

    ttk.Button(receive_box, text="Show File", command=on_show_file).grid(row=2, column=0, columnspan=3, pady=20)

    decrypted_file_label = ttk.Label(landing_frame, text="", font=("Helvetica", 12))
    decrypted_file_label.pack(pady=10)

    decrypted_key_label = ttk.Label(landing_frame, text="", font=("Helvetica", 12))
    decrypted_key_label.pack(pady=10)

    download_button = ttk.Button(landing_frame, text="Download File", state="disabled")
    download_button.pack(pady=20)

    ttk.Button(landing_frame, text="Exit", command=root.destroy).pack(pady=20)

    initialize_db()
    show_frame(landing_frame)

    root.mainloop()


if __name__ == "__main__":
    run_app()
