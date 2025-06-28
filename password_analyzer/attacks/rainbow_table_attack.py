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
        
        rainbow_table = self.generate_rainbow_table(4) 
        total_attempts = len(rainbow_table)
        
        if using_salt:
            print(f"\n{Fore.CYAN}Trying each password with the salt...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}This means computing {total_attempts:,} new hashes! Please be patient...{Style.RESET_ALL}")
            
            attempts = 0
            for password in rainbow_table.values():
                attempts += 1
                if attempts % 200000 == 0:
                    elapsed = time.time() - start_time
                    rate = int(attempts/elapsed) if elapsed > 0 else 0
                    print(f"{Fore.CYAN}Progress: {attempts:,}/{total_attempts:,} hashes tried ({rate:,}/sec){Style.RESET_ALL}", end='\r')
                    
                salted = password + current_salt
                hash_value = hashlib.sha256(salted.encode()).hexdigest()
                
                if hash_value == target_hash:
                    self.print_salted_success_stats(password, attempts, start_time)
                    return True
        else:
            if target_hash in rainbow_table:
                password = rainbow_table[target_hash]
                lookup_time = time.time() - start_time 
                self.print_unsalted_success_stats(password, lookup_time)
                return True
        
        self.print_failure_stats(total_attempts, start_time)
        return False

    def print_unsalted_success_stats(self, password, time_taken):
        print(f"\n\n{Fore.GREEN}Password found instantly in rainbow table!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Password: {password}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Time for lookup: {time_taken:.6f} seconds{Style.RESET_ALL}")

    def print_salted_success_stats(self, password, attempts, start_time):
        end_time = time.time()
        print(f"\n\n{Fore.GREEN}Password found!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Password: {password}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Hashes computed: {attempts:,}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Time taken: {end_time:.1f} seconds{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}2. We had to compute a new hash for each password + salt combination.{Style.RESET_ALL}")

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