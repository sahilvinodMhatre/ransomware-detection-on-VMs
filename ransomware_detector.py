import os
import json
import platform
from datetime import datetime
import logging
import getpass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

class RansomwareDetector:
    def __init__(self, malicious_ext_file, custom_folders_file, log_file):
        self.malicious_extensions = self.load_malicious_extensions(malicious_ext_file)
        self.custom_folders = self.load_custom_folders(custom_folders_file)
        self.log_file = log_file
        self.logged_files = self.load_logged_files()
        self.is_windows = platform.system() == "Windows"
    
    def load_malicious_extensions(self, malicious_ext_file):
        """Load malicious extensions from a text file."""
        try:
            with open(malicious_ext_file, 'r') as f:
                extensions = [ext.strip().lower() for ext in f.readlines()]
                logging.info(f"Loaded {len(extensions)} malicious extensions")
                return extensions
        except FileNotFoundError:
            logging.error(f"Malicious extensions file not found: {malicious_ext_file}")
            return []
    
    def load_custom_folders(self, custom_folders_file):
        """Load custom folders from a JSON file."""
        try:
            with open(custom_folders_file, 'r') as f:
                folders = json.load(f)
                logging.info(f"Loaded custom folders: {len(folders.get('windows', []))} Windows folders, "
                             f"{len(folders.get('linux', []))} Linux folders")
                return folders
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"Error loading custom folders file: {e}")
            return {"windows": [], "linux": []}

    def load_logged_files(self):
        """Load previously logged files to avoid duplicates."""
        logged_files = set()
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    for line in f:
                        # Extract file path from log entry
                        if line.strip():
                            # File paths may contain spaces, so we need to parse carefully
                            # Format is: file_path YYYY-MM-DD HH:MM:SS TIMEZONE
                            parts = line.strip().split()
                            if len(parts) >= 3:  # At minimum we need path and timestamp parts
                                # Get everything before the timestamp (which starts with a digit)
                                path_parts = []
                                for part in parts:
                                    if part[0].isdigit() and len(part) == 10 and part[4] == '-':  # Looks like YYYY-MM-DD
                                        break
                                    path_parts.append(part)
                                
                                if path_parts:
                                    file_path = " ".join(path_parts)
                                    logged_files.add(file_path)
                logging.info(f"Loaded {len(logged_files)} previously logged files")
        except Exception as e:
            logging.error(f"Error loading log file: {e}")
        return logged_files
    
    def log_encrypted_file(self, file_path):
        """Log a newly found encrypted file with timestamp."""
        if file_path in self.logged_files:
            return False
        
        # Get current time with timezone information
      
        import time
        
        # Get current time
        current_time = datetime.now()
        
        # Get timezone name or offset
        try:
            # Try to get the timezone name directly (works on some systems)
            timezone_name = time.tzname[0] if time.daylight == 0 else time.tzname[1]
            if not timezone_name or timezone_name == "UTC":
                # If not available, fall back to offset
                offset = time.timezone / -3600  # Convert seconds to hours and flip sign
                timezone_name = f"{'+' if offset >= 0 else ''}{int(offset):02d}00"
        except (AttributeError, IndexError):
            # If timezone name not available, use offset
            offset = time.timezone / -3600  # Convert seconds to hours and flip sign
            timezone_name = f"{'+' if offset >= 0 else ''}{int(offset):02d}00"
            
        timestamp = f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} {timezone_name}"
        
        log_entry = f"{file_path} {timestamp}\n"
        try:
            # Ensure the directory exists
            log_dir = os.path.dirname(os.path.abspath(self.log_file))
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                
            # Write to the log file
            with open(self.log_file, 'a+') as f:
                f.write(log_entry)
                
            logging.info(f"Added encrypted file to log: {file_path}")
            self.logged_files.add(file_path)
            return True
        except Exception as e:
            logging.error(f"Error writing to log file: {e}")
            return False
    
    def scan_directory(self, directory):
        """Scan a directory recursively for files with malicious extensions."""
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_extension = os.path.splitext(file)[1].lower()
                    
                    if file_extension.lstrip('.') in self.malicious_extensions:
                        if self.log_encrypted_file(file_path):
                            logging.warning(f"Potentially encrypted file found: {file_path}")
        except Exception as e:
            logging.error(f"Error scanning directory {directory}: {e}")
    
    def get_all_system_users(self):
        """Get a list of all users on the system."""
        users = []
        try:
            if self.is_windows:
                # Get all users in Windows by looking in the Users directory
                if os.path.exists('C:\\Users'):
                    users = [d for d in os.listdir('C:\\Users') if os.path.isdir(os.path.join('C:\\Users', d))]
                    # Filter out system users like 'Default', 'Public', 'All Users'
                    users = [user for user in users if user.lower() not in ('default', 'public', 'all users', 'default user')]
            else:
                # Get all users in Linux by reading /etc/passwd
                import pwd
                users = [entry.pw_name for entry in pwd.getpwall() if entry.pw_uid >= 1000 and entry.pw_shell != '/usr/sbin/nologin']
            
            logging.info(f"Found {len(users)} user accounts on the system")
        except Exception as e:
            logging.error(f"Error getting system users: {e}")
        
        return users
    
    def get_important_system_directories(self):
        """Get important system directories to scan based on OS."""
        import getpass
        current_username = getpass.getuser()
        important_dirs = []
        
        # Get all system users
        all_users = self.get_all_system_users()
        
        if self.is_windows:
            # Add important directories for all users
            for username in all_users:
                user_dir = os.path.join("C:\\", "Users", username)
                if os.path.exists(user_dir):
                    important_dirs.extend([
                        os.path.join(user_dir, "Documents"),
                        os.path.join(user_dir, "Desktop"),
                        os.path.join(user_dir, "Downloads"),
                        os.path.join(user_dir, "Pictures"),
                        os.path.join(user_dir, "OneDrive")
                    ])
            
            # Add Public and current user directories separately to ensure they're included
            important_dirs.extend([
                os.path.join("C:\\", "Users", current_username, "Documents"),
                os.path.join("C:\\", "Users", current_username, "Desktop"),
                os.path.join("C:\\", "Users", current_username, "Downloads"),
                os.path.join("C:\\", "Users", current_username, "Pictures"),
                os.path.join("C:\\", "Users", current_username, "Music"),
                os.path.join("C:\\", "Users", current_username, "Videos"),
                os.path.join("C:\\", "Users", current_username, "OneDrive"),
                os.path.join("C:\\", "Users", "Public", "Documents"),
                os.path.join("C:\\", "Users", current_username, "AppData", "Local", "Temp"),
            ])
            
            # Add mounted drives
            for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    important_dirs.append(drive)
        else:
            # Add Linux directories for all users
            for username in all_users:
                user_home = os.path.join("/home", username)
                if os.path.exists(user_home):
                    important_dirs.extend([
                        user_home,
                        os.path.join(user_home, "Documents"),
                        os.path.join(user_home, "Desktop"),
                        os.path.join(user_home, "Downloads"),
                        os.path.join(user_home, "Pictures"),
                        os.path.join(user_home, "Music"),
                        os.path.join(user_home, "Vidoes")
                    ])
            
            # Add system directories
            important_dirs.extend([
                os.path.join("/home", current_username),
                "/etc",
                "/var/www",
                "/var/log",
                "/opt",
                "/tmp",
                "/root"       
            ])
        
        # Remove duplicates while preserving order
        important_dirs = list(dict.fromkeys(important_dirs))
        return important_dirs
    
    def scan_all_directories(self):
        """Scan all configured directories based on the OS."""
        folders_to_scan = []
        
        # Add user-configured folders based on the current OS
        if self.is_windows:
            folders_to_scan.extend(self.custom_folders.get('windows', []))
        else:
            folders_to_scan.extend(self.custom_folders.get('linux', []))
        
        # Add important system directories
        folders_to_scan.extend(self.get_important_system_directories())
        
        # Remove duplicates
        folders_to_scan = list(dict.fromkeys(folders_to_scan))
            
        # Scan each folder
        for folder in folders_to_scan:
            if os.path.exists(folder) and os.path.isdir(folder):
                logging.info(f"Scanning directory: {folder}")
                self.scan_directory(folder)
            else:
                logging.warning(f"Directory does not exist or is not accessible: {folder}")



def main():
    """Main function to run the ransomware detector."""
    import argparse
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Detect files potentially encrypted by ransomware.')
    
    # Set default log file path based on operating system
    if os.name == 'nt':  # Windows
        default_log_path = r'C:\ProgramData\Ransomeware-Detector\enc-files.log'
    else:  # Linux/Unix
        default_log_path = '/var/log/enc-files.log'
    
    parser.add_argument('-l', '--log', default=default_log_path,
                        help=f'Path to the log file (default: {default_log_path})')
    args = parser.parse_args()
    
    # Default file paths
    malicious_ext_file = "malicious_extensions.txt"
    custom_folders_file = "custom_folders.json"
    log_file = args.log
    
    # Ensure log directory exists
    log_dir = os.path.dirname(log_file)
    try:
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            logging.info(f"Created log directory: {log_dir}")
    except Exception as e:
        logging.error(f"Failed to create log directory: {e}")
        return
        
    # Force create log file to ensure it exists
    try:
        with open(log_file, 'a') as f:
            pass
        logging.info(f"Log file ready: {log_file}")
    except Exception as e:
        logging.error(f"Failed to access log file: {e}")
        return
    
    # Check if files exist, create with default values if they don't
    if not os.path.exists(malicious_ext_file):
        logging.warning(f"{malicious_ext_file} not found, creating with default values...")
        with open(malicious_ext_file, 'w') as f:
            default_extensions = [
                "crypted", "encrypted", "enc", "locked", "crypto", "lol", 
                "crypt", "cryptolocker", "cryptowall", "locky", "cerber", 
                "ransomware", "pay", "decrypt", "ryuk", "wallet", "dharma",
                "zzzzz", "wncry", "wcry", "teslacrypt"
            ]
            f.write('\n'.join(default_extensions))
    
    if not os.path.exists(custom_folders_file):
        logging.warning(f"{custom_folders_file} not found, creating with default values...")
        
        # Get current username for path construction
        username = getpass.getuser()
        
        # Create default folders with dynamic username
        default_folders = {
            "windows": [
                f"C:\\Users\\{username}\\Documents",
                f"C:\\Users\\{username}\\Pictures",
                f"C:\\Users\\{username}\\Desktop",
                f"C:\\Users\\{username}\\Downloads",
                "C:\\Users\\Public\\Documents",
                "C:\\Users\\Public\\Pictures",
                "C:\\Users\\Public\\Desktop"
            ],
            "linux": [
                f"/home/{username}/Documents",
                f"/home/{username}/Pictures",
                f"/home/{username}/Desktop",
                f"/home/{username}/Downloads",
                "/opt/data",
                "/var/www/html",
                "/usr/local/share/data"
            ]
        }
        with open(custom_folders_file, 'w') as f:
            json.dump(default_folders, f, indent=4)
    
    # Create detector instance and run scan
    detector = RansomwareDetector(malicious_ext_file, custom_folders_file, log_file)
    detector.scan_all_directories()
    
    # Verify if log file was created and contains entries
    try:
        with open(log_file, 'r') as f:
            log_content = f.read()
            if log_content.strip():
                logging.info(f"Log file created with {len(log_content.strip().split(chr(10)))} entries")
            else:
                logging.warning("Log file is empty. No encrypted files detected.")
    except Exception as e:
        logging.error(f"Error reading log file: {e}")
    
    logging.info("Scan completed.")

if __name__ == "__main__":
    main()  