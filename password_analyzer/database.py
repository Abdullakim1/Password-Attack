"""
Database module for password analyzer.
Handles all database operations including connections and queries.
"""

import os
import mysql.connector
from colorama import Fore, Style

class DatabaseManager:
    
    def __init__(self):
        self.db_config = {
            'host': 'localhost',
            'user': 'luxury_user',
            'password': 'luxury123',
            'database': 'security'
        }
    
    def get_connection(self):
        
        try:
            return mysql.connector.connect(**self.db_config)
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Database connection error: {err}{Style.RESET_ALL}")
            return None
    
    def get_users(self):
        
        conn = self.get_connection()
        if not conn:
            return []

        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users')
        users = [row[0] for row in cursor.fetchall()]
        
        cursor.close()
        conn.close()
        
        return users
    
    def get_user_hash(self, username, use_salt=False):
        
        conn = self.get_connection()
        if not conn:
            return None, None

        cursor = conn.cursor()
        
        if use_salt:
            cursor.execute('SELECT salted_hash, salt FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            hash_value = result[0] if result else None
            salt = result[1] if result else None
        else:
            cursor.execute('SELECT unsalted_hash FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            hash_value = result[0] if result else None
            salt = None
        
        cursor.close()
        conn.close()
        
        return hash_value, salt
