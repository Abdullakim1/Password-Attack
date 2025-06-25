"""
Brute force attack module for password analyzer.
Implements exhaustive password cracking by trying all possible combinations.
"""

import time
import string
import itertools
from colorama import Fore, Style
from ..base import PasswordAttack

class BruteForceAttack(PasswordAttack):
    """Implements brute force password cracking."""
    
    def __init__(self, hash_verifier):
        """
        Initialize the brute force attack.
        
        Args:
            hash_verifier: Object that verifies if a password matches a hash
        """
        super().__init__(hash_verifier)
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.numbers = string.digits
        self.symbols = string.punctuation
    
    def execute(self, target_hash, **kwargs):
        """
        Execute the brute force attack.
        
        Args:
            target_hash: The hash to crack
            **kwargs: Additional parameters (not used)
            
        Returns:
            tuple: (success, password, attempts, elapsed_time)
        """
        print(f"\n{Fore.YELLOW}Starting brute force attack...{Style.RESET_ALL}")
        print("This will try every possible combination of characters")
        
        print("\nWhich characters should we try?")
        print("1. Just lowercase (a-z)")
        print("2. Lowercase + numbers")
        print("3. Lowercase + uppercase + numbers")
        print("4. All characters (lowercase, uppercase, numbers, symbols)")
        
        choice = input("Enter choice (1-4): ")
        charset = ""
        if choice == '1':
            charset = self.lowercase
            print("Using lowercase letters only")
        elif choice == '2':
            charset = self.lowercase + self.numbers
            print("Using lowercase letters and numbers")
        elif choice == '3':
            charset = self.lowercase + self.uppercase + self.numbers
            print("Using letters and numbers")
        else:
            charset = self.lowercase + self.uppercase + self.numbers + self.symbols
            print("Using all possible characters")

        max_length = int(input("\nMaximum password length to try (1-8): "))
        max_length = min(max(1, max_length), 8)  
        
        start_time = time.time()
        attempts = 0
        
        print(f"\n{Fore.CYAN}Starting attack with {len(charset)} possible characters{Style.RESET_ALL}")
        print(f"Character set: {charset}")
        
        try:
            for length in range(1, max_length + 1):
                print(f"\n{Fore.YELLOW}Trying {length}-character passwords...{Style.RESET_ALL}")
                total_combinations = len(charset) ** length
                print(f"Total combinations for {length} chars: {total_combinations:,}")
                
                for guess in itertools.product(charset, repeat=length):
                    password = ''.join(guess)
                    attempts += 1
                    
                    if attempts % 5000 == 0:
                        elapsed = time.time() - start_time
                        rate = attempts / elapsed if elapsed > 0 else 0
                        print(f"\r{Fore.CYAN}Progress: {attempts:,} attempts, Current: {password}, "
                              f"Time: {elapsed:.1f}s, Rate: {rate:.0f} tries/sec{Style.RESET_ALL}", 
                              end="", flush=True)
                    
                    if self.hash_verifier.verify(password, target_hash):
                        return self.print_success_stats(password, attempts, start_time)

        except KeyboardInterrupt:
            return self.print_interrupt_stats(attempts, start_time)
        
        return self.print_failure_stats(attempts, start_time)
