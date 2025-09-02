import tkinter as tk
from tkinter import messagebox, simpledialog, Frame, Label, Entry, Button
import subprocess
import os
import logging
import hashlib
import configparser
import random
import string
import sqlite3
import smtplib
from email.message import EmailMessage
import ctypes
import sys
import time

# Attempt to import OpenCV, but allow the app to run without it.
# To install: pip install opencv-python pandas
try:
    import cv2
    import pandas as pd # Used for the timestamp in the filename
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False

# --- ADMIN & SYSTEM FUNCTIONS ---
def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# --- CONFIGURATION SETUP ---
def create_default_config():
    """Creates a default config.ini file if it doesn't exist."""
    if not os.path.exists('config.ini'):
        config = configparser.ConfigParser()
        config['SECURITY'] = {
            'MaxLoginAttempts': '3'
        }
        config['EMAIL'] = {
            'SMTPServer': 'smtp.gmail.com',
            'Port': '587',
            'YourEmail': 'your_email@gmail.com',
            'YourPassword': 'your_app_password' # IMPORTANT: Use a Gmail App Password
        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        logging.info("Created default config.ini file.")

# --- LOGGER SETUP ---
logging.basicConfig(filename='usb_security.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(username)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# --- USER & DATABASE MANAGEMENT (SQLite) ---
DB_FILE = 'users.db'
CURRENT_USER = "SYSTEM" # Default user for initial logs

def get_logger_with_user():
    """Creates a logger adapter to include the current username in logs."""
    return logging.LoggerAdapter(logging.getLogger(), {'username': CURRENT_USER})

def hash_password(password, salt=None):
    """Hashes a password with a salt. Generates a new salt if one isn't provided."""
    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + pwd_hash

def verify_password(stored_password_hex, provided_password):
    """Verifies a provided password against a stored salted hash."""
    try:
        stored_password = bytes.fromhex(stored_password_hex)
        salt = stored_password[:16]
        stored_hash = stored_password[16:]
        provided_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return stored_hash == provided_hash
    except (ValueError, TypeError):
        return False

def initialize_database():
    """Initializes the SQLite database and creates the users table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            email TEXT
        )
    ''')
    
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        default_password = "admin"
        hashed_password = hash_password(default_password).hex()
        cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                       ('admin', hashed_password, 'admin@example.com'))
        conn.commit()
        get_logger_with_user().info(f"Database created. Default user 'admin' with password '{default_password}' was created.")
    
    conn.close()

def get_user(username):
    """Retrieves a user's data from the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password, email FROM users WHERE username=?", (username,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data:
        return {"password": user_data[0], "email": user_data[1]}
    return None

def update_user_password(username, new_password):
    """Securely updates a user's password in the database."""
    hashed_password = hash_password(new_password).hex()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed_password, username))
    conn.commit()
    conn.close()
    get_logger_with_user().info(f"Successfully updated password for user '{username}'.")
    return True

def update_user_email(username, new_email):
    """Updates a user's email in the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET email=? WHERE username=?", (new_email, username))
    conn.commit()
    conn.close()
    get_logger_with_user().info(f"Successfully updated email for user '{username}' to '{new_email}'.")
    return True


# --- Email and Webcam Features ---

def send_email(recipient_email, subject, body):
    """Sends an email using credentials from config.ini."""
    logger = get_logger_with_user()
    logger.info(f"Attempting to send email to {recipient_email}.")
    
    try:
        config = configparser.ConfigParser()
        config.read('config.ini')
        smtp_server = config['EMAIL']['SMTPServer']
        port = int(config['EMAIL']['Port'])
        sender_email = config['EMAIL']['YourEmail']
        password = config['EMAIL']['YourPassword']

        if 'your_email' in sender_email or 'your_app_password' in password:
            messagebox.showwarning("Email Not Configured", "Please configure your sender email address and App Password in config.ini to send emails.")
            logger.warning("Email sending skipped: email not configured in config.ini.")
            return

        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = recipient_email

        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls()
            server.login(sender_email, password)
            server.send_message(msg)
        logger.info("Email sent successfully.")
        messagebox.showinfo("Success", "Email sent successfully!")

    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        messagebox.showerror("Email Error", f"Failed to send email: {e}\nCheck your config.ini settings and ensure you are using a valid 'App Password'.")

def capture_intruder_video():
    """Records a 5-second video from the webcam with improved error handling."""
    logger = get_logger_with_user()
    logger.critical("INTRUDER ALERT: Maximum login attempts exceeded. Starting video capture.")

    if not OPENCV_AVAILABLE:
        logger.error("Intruder capture failed: OpenCV (cv2) library not installed.")
        messagebox.showerror("Intruder Alert!", "Maximum login attempts exceeded. Video capture requires 'opencv-python' to be installed.")
        return

    cap = None
    out = None
    try:
        cap = cv2.VideoCapture(0)
        time.sleep(0.5)

        if not cap.isOpened():
            logger.error("Could not open webcam. It might be in use or disconnected.")
            messagebox.showerror("Webcam Error", "Could not access the webcam.")
            return

        if not os.path.exists('intruder_videos'):
            os.makedirs('intruder_videos')
            logger.info("Created 'intruder_videos' directory.")
        
        filename = f"intruder_videos/intruder_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.avi"
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        frame_width = int(cap.get(3))
        frame_height = int(cap.get(4))
        out = cv2.VideoWriter(filename, fourcc, 20.0, (frame_width, frame_height))

        start_time = time.time()
        frames_written = 0
        logger.info(f"Recording 5-second video to {filename}")
        
        while (time.time() - start_time) < 5:
            ret, frame = cap.read()
            if ret:
                out.write(frame)
                frames_written += 1
            else:
                logger.warning("Could not read frame from webcam during recording.")
                break
        
        if frames_written > 0:
            logger.info(f"Successfully wrote {frames_written} frames to video.")
            messagebox.showwarning("Intruder Alert", f"Unauthorized access attempt recorded. Video saved to:\n{filename}")
        else:
            logger.error("Failed to write any frames to the video file.")
            messagebox.showerror("Capture Error", "Failed to record video. Please check the webcam.")

    except Exception as e:
        logger.error(f"An unexpected error occurred during video capture: {e}")
        messagebox.showerror("Webcam Error", f"An error occurred while capturing video: {e}")
    finally:
        if cap is not None and cap.isOpened():
            cap.release()
        if out is not None:
            out.release()
        cv2.destroyAllWindows()


# --- CORE APPLICATION LOGIC ---

class USBControlApp:
    def __init__(self, root):
        self.root = root
        self.login_attempts = 0
        
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.max_login_attempts = self.config.getint('SECURITY', 'MaxLoginAttempts', fallback=3)

        self.create_login_window()

    def create_login_window(self):
        self.clear_window()
        self.root.title("Login - USB Security")
        self.root.geometry("500x350")
        self.root.configure(bg="#808080")
        
        frame = Frame(self.root, bg="#808080")
        frame.pack(fill="both", expand=True, pady=20)

        Label(frame, text="Admin Login", font=("Arial", 24, "bold"), bg="#808080", fg="white").pack(pady=10)
        
        Label(frame, text="Username:", font=("Arial", 12), bg="#808080", fg="white").pack(pady=(10,0))
        self.username_entry = Entry(frame, width=30, font=("Arial", 12))
        self.username_entry.pack(pady=5)
        
        Label(frame, text="Password:", font=("Arial", 12), bg="#808080", fg="white").pack(pady=(10,0))
        self.password_entry = Entry(frame, show="*", width=30, font=("Arial", 12))
        self.password_entry.pack(pady=5)
        
        Button(frame, text="Login", command=self.handle_login, bg="#4A90E2", fg="white", font=("Arial", 12, "bold"), relief="raised", borderwidth=2, width=15).pack(pady=20)
        
        self.username_entry.focus_set()

    def handle_login(self):
        global CURRENT_USER
        username = self.username_entry.get()
        password = self.password_entry.get()
        CURRENT_USER = username or "GUEST"
        logger = get_logger_with_user()

        user_data = get_user(username)
        
        if user_data and verify_password(user_data['password'], password):
            logger.info("Login successful.")
            self.login_attempts = 0
            self.create_main_window()
        else:
            logger.warning(f"Failed login attempt for user '{username}'.")
            self.login_attempts += 1
            if self.login_attempts >= self.max_login_attempts:
                capture_intruder_video()
                self.root.destroy()
            else:
                messagebox.showerror("Login Failed", f"Invalid credentials. You have {self.max_login_attempts - self.login_attempts} attempts remaining.")

    def create_main_window(self):
        self.clear_window()
        self.root.title("USB Physical Security Control Panel")
        self.root.geometry("600x650") 
        self.root.configure(bg="#808080")

        main_frame = Frame(self.root, bg="#808080")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        Label(main_frame, text=f"Welcome, {CURRENT_USER}!", font=("Arial", 18, "bold"), bg="#808080", fg="white").pack(pady=10)

        # --- CHANGE 1: Create the status label but leave it empty for now ---
        self.status_label = Label(main_frame, text="", font=("Arial", 16, "bold"), bg="#808080")
        self.status_label.pack(pady=(5, 20))

        btn_style = {"font": ("Arial", 12, "bold"), "fg": "white", "width": 25, "pady": 10, "relief": "raised", "borderwidth": 3}
        
        Button(main_frame, text="Disable USB Ports", bg="red", **btn_style, command=self.disable_usb).pack(pady=8)
        Button(main_frame, text="Enable USB Ports", bg="green", **btn_style, command=self.enable_usb).pack(pady=8)
        Button(main_frame, text="View Status", bg="blue", **btn_style, command=self.update_status_display).pack(pady=8)
        Button(main_frame, text="Generate & Email Password", bg="orange", **btn_style, command=self.generate_and_email_password).pack(pady=8)
        Button(main_frame, text="Change User Email", bg="#5D3FD3", **btn_style, command=self.change_user_email).pack(pady=8)
        Button(main_frame, text="Project Info", bg="#00008B", **btn_style, command=self.show_project_info).pack(pady=8)
        Button(main_frame, text="Logout", font=("Arial", 10, "bold"), bg="#A9A9A9", fg="black", width=15, command=self.logout).pack(side="bottom", pady=20)
        
        # --- CHANGE 2: Remove the automatic status update on login ---
        # self.update_status_display() # This line has been commented out
    
    def change_user_email(self):
        """GUI handler to change a user's email address."""
        logger = get_logger_with_user()
        target_username = simpledialog.askstring("Input", "Enter the username to update:", parent=self.root)
        if not target_username:
            return

        user_data = get_user(target_username)
        if not user_data:
            messagebox.showerror("Error", f"User '{target_username}' not found in the database.")
            return

        new_email = simpledialog.askstring("Input", f"Enter the new email for {target_username}:", parent=self.root)
        if not new_email or '@' not in new_email:
            messagebox.showwarning("Invalid Email", "Please enter a valid email address.")
            return

        if update_user_email(target_username, new_email):
            messagebox.showinfo("Success", f"Email for '{target_username}' has been updated successfully.")
        else:
            messagebox.showerror("Database Error", "Failed to update the email in the database.")

    def logout(self):
        global CURRENT_USER
        logger = get_logger_with_user()
        logger.info("User logged out.")
        CURRENT_USER = "SYSTEM"
        self.login_attempts = 0
        self.create_login_window()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def check_usb_status(self):
        try:
            command = r'reg query HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR /v Start'
            result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, text=True)
            if "0x3" in result: return "Enabled"
            if "0x4" in result: return "Disabled"
            return "Unknown"
        except (subprocess.CalledProcessError, FileNotFoundError):
            return "Permission Denied"

    def update_status_display(self):
        """This function is now ONLY called when the 'View Status' button is clicked."""
        status = self.check_usb_status()
        get_logger_with_user().info(f"Status check performed. Result: {status}")
        self.status_label.config(text=f"Current Status: {status}")
        color = {"Enabled": "#00FF00", "Disabled": "red", "Permission Denied": "orange"}.get(status, "yellow")
        self.status_label.config(fg=color)

    def change_usb_state(self, enable=True):
        state_code = 3 if enable else 4
        action = "enable" if enable else "disable"
        command = f'reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d {state_code} /f'
        logger = get_logger_with_user()
        
        try:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            if result.returncode == 0:
                message = f"USB Ports {action.capitalize()}d Successfully"
                logger.info(message)
                messagebox.showinfo("Success", message)
            else:
                raise subprocess.CalledProcessError(result.returncode, command, output=result.stdout, stderr=result.stderr)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to {action} USB ports. Admin rights required. Error: {e.stderr}")
            messagebox.showerror("Administrator Error", f"Failed to {action} ports. Please ensure this application is run with Administrator privileges.")
        finally:
            # --- CHANGE 3: Also update the display after enabling/disabling ---
            self.update_status_display()

    def disable_usb(self):
        self.change_usb_state(enable=False)

    def enable_usb(self):
        self.change_usb_state(enable=True)

    def generate_and_email_password(self):
        logger = get_logger_with_user()
        target_username = simpledialog.askstring("Input", "Enter username to reset password for:", parent=self.root)
        
        if not target_username:
            return

        user_data = get_user(target_username)
        if not user_data:
            messagebox.showerror("Error", f"User '{target_username}' not found in the database.")
            return

        recipient_email = user_data.get('email')
        if not recipient_email or '@' not in recipient_email:
            messagebox.showerror("Error", "User does not have a valid email address configured.")
            return
            
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        
        if update_user_password(target_username, new_password):
            subject = "Your New Temporary Password"
            body = f"Hello {target_username},\n\nYour new temporary password is: {new_password}\n\nPlease use this to log in."
            
            logger.info(f"Generated new password for {target_username}. Attempting to email.")
            send_email(recipient_email, subject, body)
        else:
             messagebox.showerror("Database Error", f"Failed to update password for {target_username} in the database.")


    def show_project_info(self):
        get_logger_with_user().info("Project Info viewed.")
        messagebox.showinfo("Project Info", "This application was developed by Sal Krishna and Praneeth Nanda for a Cyber Security Internship.")


if __name__ == "__main__":
    if is_admin():
        create_default_config()
        initialize_database()
        
        logger = get_logger_with_user()
        logger.info("Application started with admin rights.")

        root = tk.Tk()
        app = USBControlApp(root)
        root.mainloop()
        
        logger.info("Application closed.")
    else:
        root = tk.Tk()
        root.withdraw() 
        messagebox.showerror("Administrator Privileges Required", 
                             "This application requires administrator privileges to function.\n\n"
                             "Please start the application by right-clicking the 'run.bat' file and choosing 'Run as administrator'.")
        sys.exit(1)

