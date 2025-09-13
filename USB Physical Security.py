import tkinter as tk
from tkinter import messagebox, simpledialog, Frame, Label, Entry, Button, Toplevel
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
import tempfile
import webbrowser

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
            'YourEmail': 'k.v.c23kb1a3037@gmail.com',
            'YourPassword': 'tyim nwey xgml vtae' # IMPORTANT: Use a Gmail App Password
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


# --- PROJECT INFO FUNCTIONALITY ---
def show_project_info():
    """Displays project information in a web browser."""
    html_code = """
<!DOCTYPE html>
<html>
<head>
    <title>Project Information</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
    body {
        font-family: Arial, sans-serif;
        margin: 0;
        padding: 0;
        background-color: #f2f2f2;
    }

    .container {
        max-width: 800px;
        margin: 0 auto;
        padding: 50px 20px;
        background-color: #fff;
        box-shadow: 0 0 10px rgba(0, 0, 0, 0.2);
        border-radius: 8px;
    }

    h1 {
        color: #2c3e50;
        text-align: center;
        margin-bottom: 30px;
    }

    h2 {
        color: #3498db;
        border-bottom: 2px solid #3498db;
        padding-bottom: 10px;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 20px;
    }

    th, td {
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #ddd;
    }

    th {
        background-color: #f2f2f2;
    }
    </style>
</head>
<body>
    <div class="container">
        <h1>Project Information</h1>
        
        <p>This project was developed by <strong>K.Venkata Chaitanya,D.Harshanth Reddy,Tejaswi,Princy,Rajeswari</strong> as part of a <strong>Cyber Security Internship</strong>. This project is designed to <strong>Secure the Organizations in Real World from Cyber Frauds performed by Hackers</strong>.</p>
        
        <h2>Project Details</h2>
        <table>
            <tr>
                <th>Project Details</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Project Name</td>
                <td>USB Physical Security</td>
            </tr>
            <tr>
                <td>Project Description</td>
                <td>Implementing Physical Security Policy on USB Ports in Organization for Physical Security</td>
            </tr>
            <tr>
                <td>Project Start Date</td>
                <td>08-Aug-2025</td>
            </tr>
            <tr>
                <td>Project End Date</td>
                <td>07-Sep-2025</td>
            </tr>
            <tr>
                <td>Project Status</td>
                <td>Completed</td>
            </tr>
        </table>
        
        <h2>Developer Details</h2>
        <table>
            <tr>
                <th>Name</th>
                <th>Employee ID</th>
                <th>Email</th>
            </tr>
              <tr>
                <td>K.Venkata Chaitanya</td>
                <td>ST#IS#8052</td>
                <td>23kb1a3037@nbkrist.org</td>
            </tr>
            <tr>
                <td>D.Harshanth Reddy</td>
                <td>ST#IS#8107</td>
                <td>23kb1a3021@nbkrist.org</td>
            </tr>
            <tr>
                <td>Tejaswi</td>
                <td>ST#IS#8056</td>
                <td>tejaswi@gmail.com</td>
            </tr>
            <tr>
                <td>Princy</td>
                <td>ST#IS#8051</td>
                <td>23kb1a3014@nbkrist.org</td>
            </tr>
            <tr>
                <td>Rajeswari</td>
                <td>ST#IS#8079</td>
                <td>rajeswari@gmail.com</td>
            </tr>
        
        </table>
        
        <h2>Company Details</h2>
        <table>
            <tr>
                <th>Company</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Name</td>
                <td>Supraja Technologies</td>
            </tr>
             <tr>
                <td>Email</td>
                <td>contact@suprajatechnologies.com</td>
            </tr>
        </table>
    </div>
</body>
</html>
"""
    
    # Save the HTML content to a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html') as temp_file:
        temp_file.write(html_code)
        temp_file_path = temp_file.name

    # Open the temporary HTML file in the default web browser
    webbrowser.open('file://' + os.path.realpath(temp_file_path))
    get_logger_with_user().info("Project Info viewed.")


# --- CORE APPLICATION LOGIC ---

class USBControlApp:
    def __init__(self, root):
        self.root = root
        self.login_attempts = 0
        
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.max_login_attempts = self.config.getint('SECURITY', 'MaxLoginAttempts', fallback=3)

        # Modern color scheme
        self.bg_color = "#2c3e50"  # Dark blue-gray
        self.accent_color = "#3498db"  # Bright blue
        self.button_color = "#2980b9"  # Slightly darker blue
        self.hover_color = "#1abc9c"  # Teal for hover effects
        self.text_color = "#ecf0f1"  # Light gray text
        self.error_color = "#e74c3c"  # Red for errors
        self.success_color = "#2ecc71"  # Green for success
        
        self.create_login_window()

    def create_login_window(self):
        self.clear_window()
        self.root.title("Login - USB Security")
        self.root.geometry("600x500")
        self.root.configure(bg=self.bg_color)
        
        # Create a stylish frame
        frame = Frame(self.root, bg=self.bg_color, padx=30, pady=30)
        frame.pack(fill="both", expand=True)
        
        # Title with modern styling
        title_label = Label(frame, text="USB Security Control", font=("Arial", 28, "bold"), 
                           bg=self.bg_color, fg=self.text_color)
        title_label.pack(pady=(20, 40))
        
        # Subtitle
        subtitle_label = Label(frame, text="Admin Login Required", font=("Arial", 14), 
                              bg=self.bg_color, fg=self.accent_color)
        subtitle_label.pack(pady=(0, 30))
        
        # Username field
        Label(frame, text="Username:", font=("Arial", 12), bg=self.bg_color, fg=self.text_color).pack(pady=(10,5))
        self.username_entry = Entry(frame, width=30, font=("Arial", 12), bg="#34495e", fg=self.text_color, 
                                   insertbackground=self.text_color, relief="flat")
        self.username_entry.pack(pady=5, ipady=8)
        
        # Password field
        Label(frame, text="Password:", font=("Arial", 12), bg=self.bg_color, fg=self.text_color).pack(pady=(20,5))
        self.password_entry = Entry(frame, show="*", width=30, font=("Arial", 12), bg="#34495e", 
                                   fg=self.text_color, insertbackground=self.text_color, relief="flat")
        self.password_entry.pack(pady=5, ipady=8)
        
        # Login button with hover effect
        login_btn = Button(frame, text="Login", command=self.handle_login, 
                          bg=self.button_color, fg=self.text_color, 
                          font=("Arial", 14, "bold"), relief="flat", 
                          width=20, pady=12, cursor="hand2")
        login_btn.pack(pady=30)
        
        # Bind hover effects
        login_btn.bind("<Enter>", lambda e: login_btn.config(bg=self.hover_color))
        login_btn.bind("<Leave>", lambda e: login_btn.config(bg=self.button_color))
        
        # Footer
        footer_label = Label(frame, text="© 2025 Supraja Technologies - Cyber Security Internship", 
                            font=("Arial", 9), bg=self.bg_color, fg="#7f8c8d")
        footer_label.pack(side="bottom", pady=10)
        
        self.username_entry.focus_set()
        self.password_entry.bind('<Return>', lambda event: self.handle_login())

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
        self.root.geometry("800x700") 
        self.root.configure(bg=self.bg_color)

        # Header frame
        header_frame = Frame(self.root, bg=self.bg_color)
        header_frame.pack(fill="x", pady=(20, 10))
        
        # Welcome message
        welcome_label = Label(header_frame, text=f"Welcome, {CURRENT_USER}!", 
                             font=("Arial", 20, "bold"), bg=self.bg_color, fg=self.text_color)
        welcome_label.pack(pady=10)
        
        # Status label
        self.status_label = Label(header_frame, text="Status: Not Checked", 
                                 font=("Arial", 14), bg=self.bg_color, fg=self.accent_color)
        self.status_label.pack(pady=5)
        
        # Main content frame
        main_frame = Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill="both", expand=True, padx=40, pady=20)
        
        # Button styling
        btn_style = {
            "font": ("Arial", 12, "bold"), 
            "fg": self.text_color, 
            "width": 25, 
            "pady": 12, 
            "relief": "flat", 
            "borderwidth": 0,
            "cursor": "hand2"
        }
        
        # Button grid
        buttons = [
            ("Disable USB Ports", self.disable_usb, "#e74c3c"),
            ("Enable USB Ports", self.enable_usb, "#2ecc71"),
            ("View Status", self.update_status_display, "#3498db"),
            ("Generate & Email Password", self.generate_and_email_password, "#f39c12"),
            ("Change User Email", self.change_user_email, "#9b59b6"),
            ("Project Info", self.show_project_info, "#1abc9c"),
        ]
        
        for i, (text, command, color) in enumerate(buttons):
            btn = Button(main_frame, text=text, command=command, bg=color, **btn_style)
            btn.grid(row=i//2, column=i%2, padx=10, pady=10, sticky="nsew")
            # Bind hover effects
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=self.hover_color))
            btn.bind("<Leave>", lambda e, b=btn, c=color: b.config(bg=c))
        
        # Configure grid weights
        for i in range(2):
            main_frame.columnconfigure(i, weight=1)
        for i in range(3):
            main_frame.rowconfigure(i, weight=1)
        
        # Logout button
        logout_btn = Button(self.root, text="Logout", font=("Arial", 10, "bold"), 
                           bg="#7f8c8d", fg=self.text_color, width=15, 
                           command=self.logout, cursor="hand2", relief="flat")
        logout_btn.pack(side="bottom", pady=20)
        logout_btn.bind("<Enter>", lambda e: logout_btn.config(bg="#95a5a6"))
        logout_btn.bind("<Leave>", lambda e: logout_btn.config(bg="#7f8c8d"))
    
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
        self.status_label.config(text=f"Status: {status}")
        color = {"Enabled": self.success_color, "Disabled": self.error_color, "Permission Denied": "#f39c12"}.get(status, "#f39c12")
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
            # Update the display after enabling/disabling
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
        show_project_info()


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
