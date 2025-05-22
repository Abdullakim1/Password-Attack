"""
Login system for password analyzer.
Handles user registration, authentication, and account management.
"""

import hashlib
import secrets
import sys
from getpass import getpass
from colorama import Fore, Style

from ..database import DatabaseManager

class LoginSystem:
    """Manages user authentication and account operations."""
    
    def __init__(self):
        """Initialize the login system with database connection."""
        self.db_manager = DatabaseManager()
        if not self.test_connection():
            print(f"{Fore.RED}Error: Could not connect to MySQL database!{Style.RESET_ALL}")
            print("Please ensure:")
            print("1. MySQL server is running")
            print("2. Database credentials are correct in db_config")
            print("3. The 'security' database exists")
            print("\nMySQL Connection Details:")
            print(f"Host: {self.db_manager.db_config['host']}")
            print(f"User: {self.db_manager.db_config['user']}")
            print(f"Database: {self.db_manager.db_config['database']}")
            sys.exit(1)
        self.init_database()

    def test_connection(self):
        """Test database connectivity."""
        try:
            conn = self.db_manager.get_connection()
            conn.close()
            return True
        except Exception:
            return False

    def init_database(self):
        """Initialize database and create tables if not exists."""
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username VARCHAR(255) PRIMARY KEY,
                    unsalted_hash VARCHAR(64),
                    salted_hash VARCHAR(64),
                    salt VARCHAR(64),
                    failed_attempts INT DEFAULT 0,
                    locked BOOLEAN DEFAULT FALSE
                )
            ''')
            
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"{Fore.RED}Failed to initialize database: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
            
    def generate_salt(self):
        """
        Generate a random salt for password hashing.
        
        Returns:
            str: A random hexadecimal salt
        """
        return secrets.token_hex(16)  # 16 bytes = 128 bits
        
    def hash_with_salt(self, password, salt):
        """
        Create a salted SHA-256 hash of the password.
        
        Args:
            password: The password to hash
            salt: The salt to use
            
        Returns:
            str: The salted hash
        """
        salted = password + salt
        return hashlib.sha256(salted.encode()).hexdigest()

    def execute_db_operation(self, operation_func):
        """
        Execute a database operation with error handling.
        
        Args:
            operation_func: Function that takes a connection and performs operations
            
        Returns:
            Any: Result of the operation or None if error
        """
        try:
            conn = self.db_manager.get_connection()
            result = operation_func(conn)
            conn.close()
            return result
        except Exception as err:
            print(f"{Fore.RED}Database error: {str(err)}{Style.RESET_ALL}")
            return None

    def load_credentials(self, username):
        """
        Load user credentials from database.
        
        Args:
            username: Username to load credentials for
            
        Returns:
            dict: User credentials or None if not found
        """
        def operation(conn):
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            cursor.close()
            return user
        return self.execute_db_operation(operation)

    def save_credentials(self, username, unsalted_hash, salted_hash, salt, failed_attempts=0, locked=False):
        """
        Save or update user credentials in database.
        
        Args:
            username: Username to save
            unsalted_hash: Unsalted password hash
            salted_hash: Salted password hash
            salt: Salt used for hashing
            failed_attempts: Number of failed login attempts
            locked: Whether the account is locked
            
        Returns:
            bool: True if successful, False otherwise
        """
        def operation(conn):
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, unsalted_hash, salted_hash, salt, failed_attempts, locked)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    unsalted_hash = VALUES(unsalted_hash),
                    salted_hash = VALUES(salted_hash),
                    salt = VALUES(salt),
                    failed_attempts = VALUES(failed_attempts),
                    locked = VALUES(locked)
            ''', (username, unsalted_hash, salted_hash, salt, failed_attempts, locked))
            conn.commit()
            cursor.close()
            return True
        return self.execute_db_operation(operation)
        
    def update_login_attempt(self, username, failed_attempts, locked):
        """
        Update failed attempts and lock status.
        
        Args:
            username: Username to update
            failed_attempts: Number of failed login attempts
            locked: Whether the account is locked
            
        Returns:
            bool: True if successful, False otherwise
        """
        def operation(conn):
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET failed_attempts = %s, locked = %s
                WHERE username = %s
            ''', (failed_attempts, locked, username))
            conn.commit()
            cursor.close()
            return True
        return self.execute_db_operation(operation)

    def hash_password(self, password):
        """
        Create SHA-256 hash of a password.
        
        Args:
            password: Password to hash
            
        Returns:
            str: SHA-256 hash of the password
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def register(self):
        """
        Register a new user.
        
        Returns:
            bool: True if registration successful, False otherwise
        """
        print(f"\n{Fore.CYAN}=== User Registration ==={Style.RESET_ALL}")
        username = input("Enter username: ").strip()
        
        if self.load_credentials(username):
            print(f"{Fore.RED}Username already exists!{Style.RESET_ALL}")
            return False
        
        password = getpass("Enter password: ")
        confirm_password = getpass("Confirm password: ")
        
        if password != confirm_password:
            print(f"{Fore.RED}Passwords don't match!{Style.RESET_ALL}")
            return False
        
        salt = self.generate_salt()
        unsalted_hash = self.hash_password(password)
        salted_hash = self.hash_with_salt(password, salt)
        self.save_credentials(username, unsalted_hash, salted_hash, salt)
        
        print(f"{Fore.GREEN}Registration successful!{Style.RESET_ALL}")
        return True

    def login(self):
        """
        Attempt to log in a user.
        
        Returns:
            bool: True if login successful, False otherwise
        """
        print(f"\n{Fore.CYAN}=== User Login ==={Style.RESET_ALL}")
        username = input("Enter username: ").strip()
        password = getpass("Enter password: ")

        user_data = self.load_credentials(username)
        if not user_data:
            print(f"{Fore.RED}Username not found!{Style.RESET_ALL}")
            return False

        if user_data['locked']:
            print(f"{Fore.RED}Account is locked due to too many failed attempts!{Style.RESET_ALL}")
            return False

        salted_hash = self.hash_with_salt(password, user_data['salt'])
        if salted_hash == user_data['salted_hash']:
            print(f"{Fore.GREEN}Login successful!{Style.RESET_ALL}")
            self.update_login_attempt(username, 0, False)
            return True
        else:
            failed_attempts = user_data['failed_attempts'] + 1
            locked = failed_attempts >= 3
            self.update_login_attempt(username, failed_attempts, locked)
            
            if locked:
                print(f"{Fore.RED}Too many failed attempts. Account locked!{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid password! Attempts remaining: {3 - failed_attempts}{Style.RESET_ALL}")
            return False

    def reset_account(self, username):
        """
        Reset account lock and failed attempts.
        
        Args:
            username: Username to reset
            
        Returns:
            bool: True if reset successful, False otherwise
        """
        if self.load_credentials(username):
            self.update_login_attempt(username, 0, False)
            print(f"{Fore.GREEN}Account '{username}' has been reset.{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}Username not found!{Style.RESET_ALL}")
            return False


def main():
    """Main entry point for the login system."""
    login_system = LoginSystem()
    
    while True:
        print(f"\n{Fore.CYAN}=== Security Demo System ==={Style.RESET_ALL}")
        print("1. Register")
        print("2. Login")
        print("3. Reset Account")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '1':
            login_system.register()
        elif choice == '2':
            login_system.login()
        elif choice == '3':
            username = input("Enter username to reset: ")
            login_system.reset_account(username)
        elif choice == '4':
            break
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
