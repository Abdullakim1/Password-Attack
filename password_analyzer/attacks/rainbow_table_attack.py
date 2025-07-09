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
    
    def __init__(self, hash_verifier):
        super().__init__(hash_verifier)
    
    def execute(self, target_hash, **kwargs):
        print(f"\n{Fore.CYAN}Starting rainbow table attack...{Style.RESET_ALL}")
        print("This will use pre-computed hashes to crack the password")
        
        using_salt = self.hash_verifier.using_salt
        current_salt = self.hash_verifier.current_salt
        
        if using_salt:
            print(f"{Fore.YELLOW}Salt used: {current_salt}{Style.RESET_ALL}")
            
        start_time = time.time()
        
        # Generate a small rainbow table for demonstration purposes
        # Note: A real-world rainbow table for any practical length is enormous.
        rainbow_table = self.generate_rainbow_table(4) # Generate table for passwords up to 4 chars
        total_table_entries = len(rainbow_table) 

        if using_salt:
            print(f"\n{Fore.CYAN}Trying each password from the table with the salt...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}This means computing {total_table_entries:,} new hashes! Please be patient...{Style.RESET_ALL}")
            
            attempts_made_salted = 0
            try:
                # When using salt, rainbow table becomes a glorified wordlist, as each entry needs to be re-hashed with the specific salt.
                for password_candidate in rainbow_table.values():
                    attempts_made_salted += 1
                    if attempts_made_salted % 200000 == 0:
                        elapsed = time.time() - start_time
                        rate = int(attempts_made_salted/elapsed) if elapsed > 0 else 0
                        print(f"{Fore.CYAN}Progress: {attempts_made_salted:,}/{total_table_entries:,} hashes tried ({rate:,}/sec){Style.RESET_ALL}", end='\r')
                        
                    salted = password_candidate + current_salt
                    hash_value_computed = hashlib.sha256(salted.encode()).hexdigest()
                    
                    if hash_value_computed == target_hash:
                        # Password found with salt: Use the base class's success reporting method
                        return self.print_success_stats(password_candidate, attempts_made_salted, start_time)
            except KeyboardInterrupt:
                # Handle user interruption for salted attack
                return self.print_interrupt_stats(attempts_made_salted, start_time)
            
            # If the loop finishes without finding the password (salted hash)
            return self.print_failure_stats(attempts_made_salted, start_time)
            
        else: # Not using salt, direct lookup in the pre-computed table
            attempts_for_lookup = 1 # A direct lookup is conceptually 1 attempt
            try:
                if target_hash in rainbow_table:
                    password_found = rainbow_table[target_hash]
                    # Password found unsalted: Use the base class's success reporting method
                    return self.print_success_stats(password_found, attempts_for_lookup, start_time)
                else:
                    # Password not found in unsalted table
                    return self.print_failure_stats(attempts_for_lookup, start_time)
            except KeyboardInterrupt:
                # Handle user interruption for unsalted lookup
                return self.print_interrupt_stats(attempts_for_lookup, start_time)

    def generate_rainbow_table(self, max_length=4):
        rainbow_table = {}
        chars = string.ascii_lowercase
        total = 0
        
        print(f"{Fore.CYAN}Generating a (lowercase only) rainbow table for passwords up to {max_length} characters...{Style.RESET_ALL}")
        start_time = time.time()
        
        for length in range(1, max_length + 1):
            for password in itertools.product(chars, repeat=length):
                password = ''.join(password)
                hash_value = hashlib.sha256(password.encode()).hexdigest()
                rainbow_table[hash_value] = password
                total += 1
        
        end_time = time.time()
        print(f"\n{Fore.GREEN}Rainbow table generated with {total:,} password hashes.{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Time taken: {end_time:.1f} seconds{Style.RESET_ALL}")
        return rainbow_table