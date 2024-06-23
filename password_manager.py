import tkinter as tk
from tkinter import messagebox, filedialog
import sqlite3
import hashlib
from cryptography.fernet import Fernet
import random
import string
import re
import csv
import pyotp
import time
from PIL import Image, ImageTk
import qrcode
import os

# File to store the encryption key
KEY_FILE = "encryption_key.key"

def generate_key():
    return Fernet.generate_key()

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

# Load or generate encryption key
key = load_key()
cipher_suite = Fernet(key)

# Inactivity timeout in seconds (e.g., 5 minutes)
INACTIVITY_TIMEOUT = 300

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.user_id = None
        self.master_password = None
        self.totp = None
        self.inactivity_timer = None

        self.create_db()
        self.show_login_screen()
        self.last_activity_time = time.time()
        self.auto_lock()

    def reset_inactivity_timer(self, event=None):
        self.last_activity_time = time.time()

    def auto_lock(self):
        if time.time() - self.last_activity_time > INACTIVITY_TIMEOUT:
            self.lock_application()
        self.root.after(1000, self.auto_lock)

    def lock_application(self):
        self.root.withdraw()
        self.show_login_screen()

    def create_db(self):
        self.conn = sqlite3.connect("passwords.db")
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                master_password TEXT NOT NULL,
                totp_secret TEXT NOT NULL
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                category TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        self.conn.commit()

    def encrypt_password(self, password):
        return cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self, password):
        return cipher_suite.decrypt(password.encode()).decode()

    def show_login_screen(self):
        self.root.withdraw()
        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Login")
        self.login_window.bind("<Any-KeyPress>", self.reset_inactivity_timer)

        self.label_username = tk.Label(self.login_window, text="Username:")
        self.label_username.grid(row=0, column=0, padx=10, pady=10)
        self.entry_username = tk.Entry(self.login_window, width=30)
        self.entry_username.grid(row=0, column=1, padx=10, pady=10)

        self.label_password = tk.Label(self.login_window, text="Master Password:")
        self.label_password.grid(row=1, column=0, padx=10, pady=10)
        self.entry_password = tk.Entry(self.login_window, show='*', width=30)
        self.entry_password.grid(row=1, column=1, padx=10, pady=10)

        self.login_button = tk.Button(self.login_window, text="Login", command=self.login_user)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=10)

        self.register_button = tk.Button(self.login_window, text="Register", command=self.show_register_screen)
        self.register_button.grid(row=3, column=0, columnspan=2, pady=10)

    def show_register_screen(self):
        self.login_window.withdraw()
        self.register_window = tk.Toplevel(self.root)
        self.register_window.title("Register")
        self.register_window.bind("<Any-KeyPress>", self.reset_inactivity_timer)

        self.label_new_username = tk.Label(self.register_window, text="Username:")
        self.label_new_username.grid(row=0, column=0, padx=10, pady=10)
        self.entry_new_username = tk.Entry(self.register_window, width=30)
        self.entry_new_username.grid(row=0, column=1, padx=10, pady=10)

        self.label_new_password = tk.Label(self.register_window, text="Master Password:")
        self.label_new_password.grid(row=1, column=0, padx=10, pady=10)
        self.entry_new_password = tk.Entry(self.register_window, show='*', width=30)
        self.entry_new_password.grid(row=1, column=1, padx=10, pady=10)

        self.register_new_button = tk.Button(self.register_window, text="Register", command=self.register_user)
        self.register_new_button.grid(row=2, column=0, columnspan=2, pady=10)

        self.back_to_login_button = tk.Button(self.register_window, text="Back to Login", command=self.back_to_login)
        self.back_to_login_button.grid(row=3, column=0, columnspan=2, pady=10)

    def back_to_login(self):
        self.register_window.destroy()
        self.login_window.deiconify()

    def register_user(self):
        username = self.entry_new_username.get()
        password = self.entry_new_password.get()
        if username and password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            totp_secret = pyotp.random_base32()
            try:
                self.cursor.execute("INSERT INTO users (username, master_password, totp_secret) VALUES (?, ?, ?)", (username, hashed_password, totp_secret))
                self.conn.commit()
                self.totp = pyotp.TOTP(totp_secret)
                self.show_totp_qr(username)
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username already exists.")
        else:
            messagebox.showerror("Error", "All fields are required!")

    def show_totp_qr(self, username):
        self.qr_window = tk.Toplevel(self.root)
        self.qr_window.title("Two-Factor Authentication Setup")
        self.qr_window.bind("<Any-KeyPress>", self.reset_inactivity_timer)

        self.label_qr = tk.Label(self.qr_window, text="Scan the QR code with your 2FA app:")
        self.label_qr.grid(row=0, column=0, padx=10, pady=10, columnspan=2)

        self.qr_label = tk.Label(self.qr_window)
        self.qr_label.grid(row=1, column=0, padx=10, pady=10, columnspan=2)
        self.qr_code = pyotp.totp.TOTP(self.totp.secret).provisioning_uri(name=username, issuer_name="PasswordManager")

        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(self.qr_code)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        img.save("totp_qr.png")
        self.qr_code_image = ImageTk.PhotoImage(Image.open("totp_qr.png"))
        self.qr_label.config(image=self.qr_code_image)

        self.label_totp_code = tk.Label(self.qr_window, text="Enter TOTP Code:")
        self.label_totp_code.grid(row=2, column=0, padx=10, pady=10)
        self.entry_totp_code = tk.Entry(self.qr_window, width=30)
        self.entry_totp_code.grid(row=2, column=1, padx=10, pady=10)

        self.button_verify_totp = tk.Button(self.qr_window, text="Verify", command=self.verify_totp)
        self.button_verify_totp.grid(row=3, column=0, columnspan=2, pady=10)

    def verify_totp(self):
        code = self.entry_totp_code.get()
        if self.totp.verify(code):
            self.qr_window.destroy()
            messagebox.showinfo("Success", "User registered and 2FA setup successfully!")
            self.register_window.destroy()
            self.login_window.deiconify()
        else:
            messagebox.showerror("Error", "Invalid TOTP code.")

    def login_user(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute("SELECT id, totp_secret FROM users WHERE username = ? AND master_password = ?", (username, hashed_password))
        result = self.cursor.fetchone()
        if result:
            self.user_id = result[0]
            self.master_password = hashed_password
            self.totp = pyotp.TOTP(result[1])
            self.login_window.destroy()
            self.show_2fa_setup()
        else:
            messagebox.showerror("Error", "Invalid username or password.")

    def show_2fa_setup(self):
        self.totp_window = tk.Toplevel(self.root)
        self.totp_window.title("Two-Factor Authentication")
        self.totp_window.bind("<Any-KeyPress>", self.reset_inactivity_timer)

        self.label_totp_code = tk.Label(self.totp_window, text="Enter TOTP Code:")
        self.label_totp_code.grid(row=0, column=0, padx=10, pady=10)
        self.entry_totp_code = tk.Entry(self.totp_window, width=30)
        self.entry_totp_code.grid(row=0, column=1, padx=10, pady=10)

        self.button_verify_totp = tk.Button(self.totp_window, text="Verify", command=self.verify_totp_login)
        self.button_verify_totp.grid(row=1, column=0, columnspan=2, pady=10)

    def verify_totp_login(self):
        code = self.entry_totp_code.get()
        if self.totp.verify(code):
            self.totp_window.destroy()
            self.root.deiconify()
            self.build_main_interface()
        else:
            messagebox.showerror("Error", "Invalid TOTP code.")

    def build_main_interface(self):
        self.root.bind("<Any-KeyPress>", self.reset_inactivity_timer)

        self.sidebar = tk.Listbox(self.root, width=30)
        self.sidebar.grid(row=0, column=0, rowspan=15, padx=10, pady=10, sticky='ns')
        self.sidebar.bind('<<ListboxSelect>>', self.on_website_select)

        self.load_saved_websites()

        self.label_website = tk.Label(self.root, text="Website:")
        self.label_website.grid(row=0, column=1, padx=10, pady=10)
        self.entry_website = tk.Entry(self.root, width=30)
        self.entry_website.grid(row=0, column=2, padx=10, pady=10)

        self.label_username = tk.Label(self.root, text="Username:")
        self.label_username.grid(row=1, column=1, padx=10, pady=10)
        self.entry_username = tk.Entry(self.root, width=30)
        self.entry_username.grid(row=1, column=2, padx=10, pady=10)

        self.label_password = tk.Label(self.root, text="Password:")
        self.label_password.grid(row=2, column=1, padx=10, pady=10)
        self.entry_password = tk.Entry(self.root, show='*', width=30)
        self.entry_password.grid(row=2, column=2, padx=10, pady=10)

        self.show_password_var = tk.IntVar()
        self.show_password_check = tk.Checkbutton(self.root, text="Show Password", variable=self.show_password_var, command=self.toggle_password_visibility)
        self.show_password_check.grid(row=2, column=3, padx=10, pady=10)

        self.strength_label = tk.Label(self.root, text="Strength: ")
        self.strength_label.grid(row=3, column=1, columnspan=2, pady=10)

        self.generate_button = tk.Button(self.root, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=4, column=1, columnspan=3, pady=10)

        self.add_button = tk.Button(self.root, text="Add Password", command=self.add_password)
        self.add_button.grid(row=5, column=1, columnspan=3, pady=10)

        self.label_category = tk.Label(self.root, text="Category:")
        self.label_category.grid(row=6, column=1, padx=10, pady=10)
        self.entry_category = tk.Entry(self.root, width=30)
        self.entry_category.grid(row=6, column=2, padx=10, pady=10)

        self.label_retrieve = tk.Label(self.root, text="Website to retrieve:")
        self.label_retrieve.grid(row=7, column=1, padx=10, pady=10)
        self.entry_retrieve = tk.Entry(self.root, width=30)
        self.entry_retrieve.grid(row=7, column=2, padx=10, pady=10)

        self.retrieve_button = tk.Button(self.root, text="Retrieve Password", command=self.retrieve_password)
        self.retrieve_button.grid(row=8, column=1, columnspan=3, pady=10)

        self.label_delete = tk.Label(self.root, text="Website to delete:")
        self.label_delete.grid(row=9, column=1, padx=10, pady=10)
        self.entry_delete = tk.Entry(self.root, width=30)
        self.entry_delete.grid(row=9, column=2, padx=10, pady=10)

        self.delete_button = tk.Button(self.root, text="Delete Password", command=self.delete_password)
        self.delete_button.grid(row=10, column=1, columnspan=3, pady=10)

        self.label_search = tk.Label(self.root, text="Search:")
        self.label_search.grid(row=11, column=1, padx=10, pady=10)
        self.entry_search = tk.Entry(self.root, width=30)
        self.entry_search.grid(row=11, column=2, padx=10, pady=10)

        self.search_button = tk.Button(self.root, text="Search", command=self.search_passwords)
        self.search_button.grid(row=12, column=1, columnspan=3, pady=10)

        self.export_button = tk.Button(self.root, text="Export Passwords", command=self.export_passwords)
        self.export_button.grid(row=13, column=1, columnspan=2, pady=10)

        self.import_button = tk.Button(self.root, text="Import Passwords", command=self.import_passwords)
        self.import_button.grid(row=13, column=2, columnspan=2, pady=10)

        self.dark_mode_var = tk.IntVar()
        self.dark_mode_check = tk.Checkbutton(self.root, text="Dark Mode", variable=self.dark_mode_var, command=self.toggle_dark_mode)
        self.dark_mode_check.grid(row=14, column=1, columnspan=3, pady=10)

        self.entry_password.bind("<KeyRelease>", self.check_password_strength)

    def load_saved_websites(self):
        self.sidebar.delete(0, tk.END)
        self.cursor.execute("SELECT website FROM passwords WHERE user_id = ?", (self.user_id,))
        websites = self.cursor.fetchall()
        for website in websites:
            self.sidebar.insert(tk.END, website[0])

    def on_website_select(self, event):
        selected_index = self.sidebar.curselection()
        if selected_index:
            selected_website = self.sidebar.get(selected_index)
            self.cursor.execute("SELECT username, password, category FROM passwords WHERE user_id = ? AND website = ?", (self.user_id, selected_website))
            result = self.cursor.fetchone()
            if result:
                username, encrypted_password, category = result
                password = self.decrypt_password(encrypted_password)
                self.entry_website.delete(0, tk.END)
                self.entry_website.insert(0, selected_website)
                self.entry_username.delete(0, tk.END)
                self.entry_username.insert(0, username)
                self.entry_password.delete(0, tk.END)
                self.entry_password.insert(0, password)
                self.entry_category.delete(0, tk.END)
                self.entry_category.insert(0, category)

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.entry_password.config(show='')
        else:
            self.entry_password.config(show='*')

    def generate_password(self):
        length = 12
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(length))
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, password)
        self.check_password_strength()

    def add_password(self):
        website = self.entry_website.get()
        username = self.entry_username.get()
        password = self.encrypt_password(self.entry_password.get())
        category = self.entry_category.get()

        if website and username and password and category:
            self.cursor.execute("INSERT INTO passwords (user_id, website, username, password, category) VALUES (?, ?, ?, ?, ?)",
                                (self.user_id, website, username, password, category))
            self.conn.commit()
            messagebox.showinfo("Success", "Password added successfully!")
            self.load_saved_websites()
            self.entry_website.delete(0, tk.END)
            self.entry_username.delete(0, tk.END)
            self.entry_password.delete(0, tk.END)
            self.entry_category.delete(0, tk.END)
            self.strength_label.config(text="Strength: ")
        else:
            messagebox.showerror("Error", "All fields are required!")

    def retrieve_password(self):
        website = self.entry_retrieve.get()
        if website:
            self.cursor.execute("SELECT username, password, category FROM passwords WHERE user_id = ? AND website = ?", (self.user_id, website))
            result = self.cursor.fetchone()
            if result:
                username, encrypted_password, category = result
                password = self.decrypt_password(encrypted_password)
                messagebox.showinfo("Password Retrieved", f"Website: {website}\nUsername: {username}\nPassword: {password}\nCategory: {category}")
            else:
                messagebox.showerror("Error", "No password found for the given website.")
            self.entry_retrieve.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Please enter a website to retrieve the password.")

    def delete_password(self):
        website = self.entry_delete.get()
        if website:
            self.cursor.execute("DELETE FROM passwords WHERE user_id = ? AND website = ?", (self.user_id, website))
            self.conn.commit()
            if self.cursor.rowcount > 0:
                messagebox.showinfo("Success", "Password deleted successfully!")
                self.load_saved_websites()
            else:
                messagebox.showerror("Error", "No password found for the given website.")
            self.entry_delete.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Please enter a website to delete the password.")

    def check_password_strength(self, event=None):
        password = self.entry_password.get()
        strength = self.evaluate_password_strength(password)
        self.strength_label.config(text=f"Strength: {strength}")

    def evaluate_password_strength(self, password):
        length = len(password)
        lower = re.search("[a-z]", password)
        upper = re.search("[A-Z]", password)
        digit = re.search("[0-9]", password)
        special = re.search("[@#$%^&+=]", password)

        if length >= 12 and lower and upper and digit and special:
            return "Strong"
        elif length >= 8 and (lower or upper) and digit:
            return "Medium"
        else:
            return "Weak"

    def search_passwords(self):
        search_term = self.entry_search.get()
        if search_term:
            self.cursor.execute("SELECT website, username, password, category FROM passwords WHERE user_id = ? AND (website LIKE ? OR username LIKE ? OR category LIKE ?)", 
                                (self.user_id, '%' + search_term + '%', '%' + search_term + '%', '%' + search_term + '%'))
            results = self.cursor.fetchall()
            if results:
                result_text = "\n".join([f"Website: {website}, Username: {username}, Password: {self.decrypt_password(password)}, Category: {category}" for website, username, password, category in results])
                messagebox.showinfo("Search Results", result_text)
            else:
                messagebox.showinfo("Search Results", "No matching records found.")
        else:
            messagebox.showerror("Error", "Please enter a search term.")

    def export_passwords(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            self.cursor.execute("SELECT website, username, password, category FROM passwords WHERE user_id = ?", (self.user_id,))
            records = self.cursor.fetchall()
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Website", "Username", "Password", "Category"])
                for record in records:
                    writer.writerow([record[0], record[1], self.decrypt_password(record[2]), record[3]])
            messagebox.showinfo("Export Success", f"Passwords exported successfully to {file_path}")

    def import_passwords(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, mode='r') as file:
                reader = csv.reader(file)
                next(reader)  # Skip header row
                for row in reader:
                    if len(row) == 4:
                        website, username, password, category = row
                        encrypted_password = self.encrypt_password(password)
                        self.cursor.execute("INSERT INTO passwords (user_id, website, username, password, category) VALUES (?, ?, ?, ?, ?)",
                                            (self.user_id, website, username, encrypted_password, category))
                self.conn.commit()
            self.load_saved_websites()
            messagebox.showinfo("Import Success", f"Passwords imported successfully from {file_path}")

    def toggle_dark_mode(self):
        if self.dark_mode_var.get():
            self.root.config(bg='black')
            for widget in self.root.winfo_children():
                widget.config(bg='black', fg='white')
        else:
            self.root.config(bg='white')
            for widget in self.root.winfo_children():
                widget.config(bg='white', fg='black')

def main():
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()

if __name__ == "__main__":
    main()
