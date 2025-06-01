import sys
import os
import ctypes
import subprocess
import tkinter as tk
import pyotp
import threading
import time
import pythoncom
import win32com.client
import win32gui
import win32con
import atexit
from tkinter import filedialog
from tkinter import simpledialog, messagebox
import string
import random

# -------------------- Auto-Elevation --------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if not is_admin():
    print("Script is not running as administrator. Attempting to relaunch with elevated privileges...")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit(0)

# -------------------- Configuration --------------------
# TOTP secret — generate your own secure secret for production!
SECRET = 'JBSWY3DPEHPK3PXP'  

# Path to your encrypted VHD file (created via Disk Management)
VHD_PATH = r"D:\TimeCrypt\vault.vhd"

# DiskCryptor password set during encryption (store securely!)
MOUNT_PASSWORD = ""

# Full path to DiskCryptor console tool (dccon.exe); ensure it matches your installation
DCON_PATH = r"C:\Program Files\dcrypt"

# The drive letter where the mounted VHD will appear (e.g., Z:)
MOUNT_DRIVE_LETTER = ""

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VHD_MAP_PATH = os.path.join(SCRIPT_DIR, "vhd_map.txt")

# -------------------- VHD Mount/Unmount --------------------
def attach_vhd():
    # Use PowerShell to mount the VHD file
    try:
        print(f"Attaching VHD: {VHD_PATH}")
        subprocess.check_call([
            "powershell", "-Command",
            f"Mount-DiskImage -ImagePath '{VHD_PATH}'"
        ])
        print("VHD attached successfully.")
    except Exception as e:
        print(f"Error attaching VHD: {e}")

def unmount_vhd():
    try:
        os.chdir(DCON_PATH)
        print(f"Current working directory: {os.getcwd()}")
        command = ["dccon.exe", "-unmount", MOUNT_DRIVE_LETTER]
        subprocess.call(command)
        print("VHD unmounted successfully.")

        # Detach the VHD from Windows (no -Force)
        subprocess.call([
            "powershell", "-Command",
            f"Dismount-DiskImage -ImagePath '{VHD_PATH}'"
        ])
        print("VHD detached (ejected) successfully.")
    except Exception as e:
        print(f"Error unmounting or detaching VHD: {e}")

atexit.register(unmount_vhd)

# -------------------- VHD Mapping --------------------
def get_password_from_map(vhd_path, drive_letter, map_file=VHD_MAP_PATH):
    try:
        with open(map_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or "," not in line:
                    continue
                parts = line.split(",", 2)
                if len(parts) < 3:
                    continue
                path, letter, password = parts
                if (os.path.normcase(path.strip()) == os.path.normcase(vhd_path.strip())
                    and letter.strip().upper() == drive_letter.strip().upper()):
                    return password.strip()
    except Exception as e:
        print(f"Error reading VHD map for password: {e}")
    return None

def get_drive_letter_from_map(vhd_path, map_file=VHD_MAP_PATH):
    try:
        with open(map_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or "," not in line:
                    continue
                parts = line.split(",", 2)
                if len(parts) < 3:
                    continue
                path, letter, _ = parts
                if os.path.normcase(path.strip()) == os.path.normcase(vhd_path.strip()):
                    return letter.strip()
    except Exception as e:
        print(f"Error reading VHD map: {e}")
    return None

def save_vhd_mapping(vhd_path, drive_letter, password, map_file=VHD_MAP_PATH):
    # Read all lines except the one matching vhd_path
    lines = []
    found = False
    if os.path.exists(map_file):
        with open(map_file, "r") as f:
            for line in f:
                parts = line.strip().split(",", 2)
                if len(parts) < 3:
                    continue
                path, _, _ = parts
                if os.path.normcase(path.strip()) == os.path.normcase(vhd_path.strip()):
                    found = True
                    continue  # Skip old entry
                lines.append(line.rstrip())
    # Add the new/updated entry
    lines.append(f"{vhd_path},{drive_letter},{password}")
    # Write back to file
    with open(map_file, "w") as f:
        for line in lines:
            f.write(line + "\n")
    if found:
        print(f"Updated mapping: {vhd_path},{drive_letter},{password}")
    else:
        print(f"Saved mapping: {vhd_path},{drive_letter},{password}")

def remove_vhd_mapping(vhd_path, map_file=VHD_MAP_PATH):
    if not os.path.exists(map_file):
        return
    lines = []
    removed = False
    with open(map_file, "r") as f:
        for line in f:
            parts = line.strip().split(",", 2)
            if len(parts) < 3:
                continue
            path, _, _ = parts
            if os.path.normcase(path.strip()) == os.path.normcase(vhd_path.strip()):
                removed = True
                continue  # Skip this entry
            lines.append(line.rstrip())
    with open(map_file, "w") as f:
        for line in lines:
            f.write(line + "\n")
    if removed:
        print(f"Removed mapping for: {vhd_path}")

def generate_random_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

# -------------------- Tkinter GUI Logic --------------------
def pick_vhd_file():
    vhd_path = filedialog.askopenfilename(
        title="Select VHD File",
        filetypes=[("VHD files", "*.vhd *.vhdx"), ("All files", "*.*")]
    )
    return vhd_path

def pick_vhd_and_detect_drive():
    global VHD_PATH, MOUNT_DRIVE_LETTER
    vhd_path = pick_vhd_file()
    if not vhd_path:
        print("No VHD selected.")
        return

    drive_letter = get_drive_letter_from_map(vhd_path)
    if drive_letter:
        MOUNT_DRIVE_LETTER = drive_letter
        print(f"Found drive letter from map: {MOUNT_DRIVE_LETTER}")
    else:
        print("Drive letter not found in map. Please update vhd_map.txt.")
    VHD_PATH = vhd_path
    print(f"VHD_PATH set to: {VHD_PATH}")

def authenticate_and_mount():
    global MOUNT_PASSWORD
    totp = pyotp.TOTP(SECRET)
    entered_code = code_entry.get().strip()
    
    if totp.verify(entered_code):
        result_label.config(text="Authentication successful!")
        MOUNT_PASSWORD = get_password_from_map(VHD_PATH, MOUNT_DRIVE_LETTER)
        if not MOUNT_PASSWORD:
            result_label.config(text="Password not found for this VHD and drive letter!")
            return
        attach_vhd()
        try:
            os.chdir(DCON_PATH)
            mount_cmd = ["dccon.exe", "-mount", MOUNT_DRIVE_LETTER, "-p", MOUNT_PASSWORD]
            subprocess.call(mount_cmd)
            result_label.config(text="VHD mounted and unlocked!")
            # After successful mount/unlock:
            threading.Thread(target=monitor_explorer_and_unmount, args=(MOUNT_DRIVE_LETTER,), daemon=True).start()
        except Exception as e:
            result_label.config(text=f"Error mounting VHD: {e}")
    else:
        result_label.config(text="Invalid code. Try again.")

def authenticate_and_permanently_decrypt():
    global MOUNT_PASSWORD
    totp = pyotp.TOTP(SECRET)
    entered_code = code_entry.get().strip()

    if totp.verify(entered_code):
        result_label.config(text="Authentication successful!")
        MOUNT_PASSWORD = get_password_from_map(VHD_PATH, MOUNT_DRIVE_LETTER)
        if not MOUNT_PASSWORD:
            result_label.config(text="Password not found for this VHD and drive letter!")
            return
        attach_vhd()
        try:
            os.chdir(DCON_PATH)
            mount_cmd = ["dccon.exe", "-mount", MOUNT_DRIVE_LETTER, "-p", MOUNT_PASSWORD]
            subprocess.call(mount_cmd)
            result_label.config(text="VHD mounted. Now decrypting (removing encryption)...")
            decrypt_cmd = ["dccon.exe", "-decrypt", MOUNT_DRIVE_LETTER, "-p", MOUNT_PASSWORD]
            subprocess.call(decrypt_cmd)
            result_label.config(text="VHD has been decrypted (encryption removed)!")
            remove_vhd_mapping(VHD_PATH)
            close_explorer_for_drive(MOUNT_DRIVE_LETTER)  # <-- Add this line
            time.sleep(1)  # Give Explorer a moment to close
        except Exception as e:
            result_label.config(text=f"Error during decryption: {e}")
        finally:
            unmount_vhd()
    else:
        result_label.config(text="Invalid code. Try again.")

def encrypt_and_register_existing_vhd():
    vhd_path = filedialog.askopenfilename(
        title="Select VHD File",
        filetypes=[("VHD files", "*.vhd *.vhdx"), ("All files", "*.*")]
    )
    if not vhd_path:
        print("No VHD selected.")
        return
    already_registered = False
    if os.path.exists(VHD_MAP_PATH):
        with open(VHD_MAP_PATH, "r") as f:
            for line in f:
                parts = line.strip().split(",", 2)
                if len(parts) < 3:
                    continue
                path, _, _ = parts
                if os.path.normcase(path.strip()) == os.path.normcase(vhd_path.strip()):
                    already_registered = True
                    break
    if already_registered:
        messagebox.showerror("Already Encrypted", "This VHD is already encrypted and registered!")
        return
    try:
        print(f"Attaching VHD: {vhd_path}")
        subprocess.check_call([
            "powershell", "-Command",
            f"Mount-DiskImage -ImagePath '{vhd_path}'"
        ])
        print("VHD attached successfully.")
    except Exception as e:
        print(f"Error attaching VHD (it may already be attached): {e}")
    try:
        result = subprocess.check_output([
            "powershell", "-Command",
            f"(Get-DiskImage -ImagePath '{vhd_path}' | Get-Disk | Get-Partition | Get-Volume).DriveLetter"
        ], universal_newlines=True)
        drive_letters = [line.strip() for line in result.splitlines() if line.strip()]
        if not drive_letters:
            messagebox.showerror("Error", "Could not detect drive letter for this VHD. Make sure it is mounted.")
            return
        drive_letter = drive_letters[0] + ":"
        print(f"Detected drive letter: {drive_letter}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not detect drive letter: {e}")
        return
    # Before showing the password dialog
    root.attributes('-topmost', True)
    password = simpledialog.askstring(
        "DiskCryptor Password",
        "Enter a password for encryption (leave blank for random):",
        parent=root
    )
    root.attributes('-topmost', False)
    if not password:
        password = generate_random_password()
        messagebox.showinfo("Generated Password", f"Generated password: {password}")
    try:
        os.chdir(DCON_PATH)
        subprocess.check_call([
            "dccon.exe", "-encrypt", drive_letter, "-p", password
        ])
        print("VHD encrypted with DiskCryptor.")
    except Exception as e:
        messagebox.showerror("Error", f"Error encrypting VHD: {e}")
        return
    save_vhd_mapping(vhd_path, drive_letter, password)
    messagebox.showinfo("Success", f"VHD encrypted and registered!\n\nPath: {vhd_path}\nDrive: {drive_letter}\nPassword: {password}")

    # Unmount after encrypting
    unmount_vhd()


def monitor_explorer_and_unmount(drive_letter):
    import time
    import win32gui

    def is_explorer_open_for_drive():
        found = False
        def enum_handler(hwnd, ctx):
            nonlocal found
            if win32gui.IsWindowVisible(hwnd):
                title = win32gui.GetWindowText(hwnd).upper()
                # Match "E:\", "E:", "LABEL (E:)", "FOLDER - E:\", etc.
                drive = drive_letter.upper().replace(":", "")
                if (
                    f"{drive}:\\" in title or
                    f"{drive}:" in title or
                    f"({drive}:)" in title or
                    title.endswith(f"{drive}:") or
                    title.endswith(f"{drive}:\\")
                ):
                    found = True
        win32gui.EnumWindows(enum_handler, None)
        return found

    # Wait up to 30 seconds for at least one Explorer window to open for the drive
    for _ in range(30):
        if is_explorer_open_for_drive():
            break
        time.sleep(1)

    # Now wait until all Explorer windows for the drive are closed
    while True:
        if not is_explorer_open_for_drive():
            break
        time.sleep(1)
    unmount_vhd()

def close_explorer_for_drive(drive_letter):
    import win32gui
    import win32con

    drive = drive_letter.upper().replace(":", "")
    def enum_handler(hwnd, ctx):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd).upper()
            if (
                f"{drive}:\\" in title or
                f"{drive}:" in title or
                f"({drive}:)" in title or
                title.endswith(f"{drive}:") or
                title.endswith(f"{drive}:\\")
            ):
                win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
    win32gui.EnumWindows(enum_handler, None)

# -------------------- Tkinter GUI Setup --------------------
root = tk.Tk()
root.title("TimeCrypt Authentication")

frame = tk.Frame(root, padx=20, pady=20)
frame.pack()

tk.Label(frame, text="Enter TOTP Code:").grid(row=0, column=0, pady=5)
code_entry = tk.Entry(frame)
code_entry.grid(row=0, column=1, pady=5)

tk.Button(frame, text="Authenticate", command=authenticate_and_mount).grid(row=1, column=0, columnspan=2, pady=5)
tk.Button(frame, text="Pick VHD and Detect Drive", command=pick_vhd_and_detect_drive).grid(row=2, column=0, columnspan=2, pady=5)
tk.Button(frame, text="Encrypt & Register Existing VHD", command=encrypt_and_register_existing_vhd).grid(row=5, column=0, columnspan=2, pady=5)
tk.Button(frame, text="Authenticate & Remove Encryption", command=authenticate_and_permanently_decrypt).grid(row=7, column=0, columnspan=2, pady=5)

result_label = tk.Label(frame, text="")
result_label.grid(row=3, column=0, columnspan=2)

root.mainloop()



