"""
Base module containing abstract base classes and common functionality.
"""

import hashlib
import time
from abc import ABC, abstractmethod
from colorama import Fore, Style

class PasswordAttack(ABC):
    
    def __init__(self, hash_verifier):
        self.hash_verifier = hash_verifier
        
    @abstractmethod
    def execute(self, target_hash, **kwargs):
        pass
    
    def print_interrupt_stats(self, attempts, start_time):
        elapsed = time.time() - start_time
        rate = attempts / elapsed if elapsed > 0 else 0
        print(f"\n\n{Fore.YELLOW}Attack stopped by user")
        print(f"Attempts made: {attempts:,}")
        print(f"Time elapsed: {elapsed:.1f} seconds")
        print(f"Rate: {rate:.0f} passwords/second{Style.RESET_ALL}")
        return False, None, attempts, elapsed
    
    def print_failure_stats(self, attempts, start_time):
        elapsed = time.time() - start_time
        rate = attempts / elapsed if elapsed > 0 else 0
        print(f"\n\n{Fore.RED}Password not found after {attempts:,} attempts")
        print(f"Time taken: {elapsed:.1f} seconds")
        print(f"Rate: {rate:.0f} passwords/second{Style.RESET_ALL}")
        return False, None, attempts, elapsed
    
    def print_success_stats(self, password, attempts, start_time):
        elapsed = time.time() - start_time
        rate = attempts / elapsed if elapsed > 0 else 0
        print(f"\n\n{Fore.GREEN}Password cracked!")
        print(f"Password: {password}")
        print(f"Attempts: {attempts:,}")
        print(f"Time taken: {elapsed:.1f} seconds")
        print(f"Rate: {rate:.0f} passwords/second{Style.RESET_ALL}")
        return True, password, attempts, elapsed
    
    def print_progress(self, attempts, total, current, start_time, bar_width=40):
        elapsed = time.time() - start_time
        rate = attempts / elapsed if elapsed > 0 else 0
        progress = (attempts / total) if total > 0 else 0
        filled_length = int(bar_width * progress)
        bar = '=' * filled_length + '-' * (bar_width - filled_length)
        
        print(f"\r{Fore.CYAN}Progress: [{bar}] {progress*100:4.1f}%  "
              f"({attempts:,}/{total:,})  "
              f"Rate: {rate:,.0f}/sec  "
              f"Testing: {current}{Style.RESET_ALL}", end="", flush=True)


class HashVerifier:
    
    def __init__(self, using_salt=False, current_salt=None):
        
        self.using_salt = using_salt
        self.current_salt = current_salt
    
    def verify(self, password, target_hash):
        
        if self.using_salt:
            salted = password + self.current_salt
            return hashlib.sha256(salted.encode()).hexdigest() == target_hash
        else:
            return hashlib.sha256(password.encode()).hexdigest() == target_hash
