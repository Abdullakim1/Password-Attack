"""
Wordlist module for password analyzer.
Handles downloading, loading, and managing password wordlists.
"""

import os
import requests
from colorama import Fore, Style

class WordlistManager:
    
    def __init__(self, wordlists_dir='wordlists'):
        
        self.wordlists_dir = wordlists_dir
        
        if not os.path.exists(self.wordlists_dir):
            os.makedirs(self.wordlists_dir)
    
    def download_wordlists(self):
        
        print(f"\n{Fore.YELLOW}Downloading password lists...{Style.RESET_ALL}")
        
        wordlists = {
            'rockyou-10k.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-10.txt',
            'common-passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt',
            'leaked-passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/000webhost.txt',
            'wifi-passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt',
            'twitter-passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/twitter-banned.txt'
        }
        
        success = False
        for filename, url in wordlists.items():
            filepath = os.path.join(self.wordlists_dir, filename)
            if not os.path.exists(filepath):
                try:
                    print(f"Downloading {filename}...")
                    response = requests.get(url)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(response.text)
                    print(f"{Fore.GREEN}Successfully downloaded {filename}{Style.RESET_ALL}")
                    success = True
                except Exception as e:
                    print(f"{Fore.RED}Failed to download {filename}: {str(e)}{Style.RESET_ALL}")
        
        return success
    
    def load_wordlists(self):
        
        passwords = set()
        
        for filename in os.listdir(self.wordlists_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(self.wordlists_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        passwords.update(line.strip() for line in f if line.strip())
                except Exception as e:
                    print(f"{Fore.RED}Error reading {filename}: {str(e)}{Style.RESET_ALL}")
        
        return list(passwords)
    
    def get_base_words(self):
       
        return [
            "pass", "pwd", "admin", "user", "login", "test", "demo", 
            "guest", "root", "dev", "system", "web", "app", "api"
        ]
    
    def generate_username_variations(self, username):
        
        variations = [username.lower(), username]
        
        if len(username) > 3:
            variations.extend([username[:4], username[:3]])
            
            leetspeak = {
                'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'
            }
            
            leet_name = username.lower()
            for char, replacement in leetspeak.items():
                if char in leet_name:
                    variations.append(leet_name.replace(char, replacement))
        
        return variations
