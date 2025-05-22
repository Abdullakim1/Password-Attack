"""
Rainbow table attack module for password analyzer.
Implements rainbow table-based password cracking.
"""

import time
import hashlib
import string
import itertools
from colorama import Fore, Style
from ..base import PasswordAttack

class RainbowTableAttack(PasswordAttack):
    """Implements rainbow table-based password cracking."""
    
    def __init__(self, hash_verifier):
        """
        Initialize the rainbow table attack.
        
        Args:
            hash_verifier: Object that verifies if a password matches a hash
        """
        super().__init__(hash_verifier)
    
    def execute(self, target_hash, **kwargs):
        """
        Execute the rainbow table attack.
        
        Args:
            target_hash: The hash to crack
            **kwargs: Additional parameters (not used)
            
        Returns:
            tuple: (success, password, attempts, elapsed_time)
        """
        print(f"\n{Fore.CYAN}Starting rainbow table attack...{Style.RESET_ALL}")
        print("This will use pre-computed hashes to crack the password")
        
        using_salt = self.hash_verifier.using_salt
        current_salt = self.hash_verifier.current_salt
        
        if using_salt:
            print(f"\n{Fore.YELLOW}Note: This hash is salted. Let's see why rainbow tables don't work...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Salt used: {current_salt}{Style.RESET_ALL}")
            
        start_time = time.time()
        
        rainbow_table = self.generate_rainbow_table(3)
        total_attempts = len(rainbow_table)
        
        if using_salt:
            print(f"\n{Fore.CYAN}Trying each password with the salt...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}This means computing {total_attempts:,} new hashes!{Style.RESET_ALL}")
            
            attempts = 0
            for password in rainbow_table.values():
                attempts += 1
                if attempts % 100000 == 0:
                    elapsed = time.time() - start_time
                    rate = int(attempts/elapsed) if elapsed > 0 else 0
                    print(f"{Fore.CYAN}Progress: {attempts:,}/{total_attempts:,} hashes tried ({rate:,}/sec){Style.RESET_ALL}", end='\r')
                    
                salted = password + current_salt
                hash_value = hashlib.sha256(salted.encode()).hexdigest()
                
                if hash_value == target_hash:
                    end_time = time.time()
                    print(f"\n\n{Fore.GREEN}Password found!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Password: {password}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Hashes computed: {attempts:,}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Time taken: {end_time - start_time:.1f} seconds{Style.RESET_ALL}")
                    print(f"\n{Fore.YELLOW}Why was this slower?{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}1. Rainbow table was useless - couldn't look up salted hash{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}2. Had to compute new hash for each password + salt combination{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}3. This is why salting defeats rainbow table attacks!{Style.RESET_ALL}")
                    return True
        else:
            if target_hash in rainbow_table:
                password = rainbow_table[target_hash]
                end_time = time.time()
                print(f"\n{Fore.GREEN}Password found in rainbow table!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Password: {password}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Time for lookup: {end_time - start_time:.6f} seconds{Style.RESET_ALL}")
                print(f"\n{Fore.YELLOW}Notice how fast this was - just a simple lookup!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}This is why we need salting to prevent rainbow table attacks{Style.RESET_ALL}")
                return True
        
        end_time = time.time()
        print(f"\n{Fore.RED}Password not found after trying {total_attempts:,} hashes{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Time taken: {end_time - start_time:.1f} seconds{Style.RESET_ALL}")
        return False
    
    def generate_rainbow_table(self, max_length=3):
        """
        Generate a rainbow table of password hashes.
        
        Args:
            max_length: Maximum password length to include
            
        Returns:
            dict: Dictionary mapping hashes to passwords
        """
        rainbow_table = {}
        chars = string.ascii_lowercase + string.digits + string.ascii_uppercase + string.punctuation
        total = 0
        
        print(f"{Fore.CYAN}Generating rainbow table...{Style.RESET_ALL}")
        start_time = time.time()
        
        for length in range(1, max_length + 1):
            for password in itertools.product(chars, repeat=length):
                password = ''.join(password)
                hash_value = hashlib.sha256(password.encode()).hexdigest()
                rainbow_table[hash_value] = password
                total += 1
                
                if total % 100000 == 0:
                    print(f"Generated {total:,} hashes...", end='\r')
        
        end_time = time.time()
        print(f"\n{Fore.GREEN}Rainbow table generated with {total:,} password hashes{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Time taken: {end_time - start_time:.1f} seconds{Style.RESET_ALL}")
        return rainbow_table
