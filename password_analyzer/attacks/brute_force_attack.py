import time
import string
import itertools
from colorama import Fore, Style
from ..base import PasswordAttack

class BruteForceAttack(PasswordAttack):
    
    def __init__(self, hash_verifier):
        
        super().__init__(hash_verifier)
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.numbers = string.digits
        self.symbols = string.punctuation
    
    def execute(self, target_hash, min_length=1, max_length=8, 
                use_lowercase=True, use_uppercase=False, use_digits=False, 
                use_symbols=False, max_time=60, **kwargs):
        
        print(f"\n{Fore.YELLOW}Starting brute force attack...{Style.RESET_ALL}")
        print("This will try every possible combination of characters")
        
        charset = ""
        if use_lowercase:
            charset += self.lowercase
        if use_uppercase:
            charset += self.uppercase
        if use_digits:
            charset += self.numbers
        if use_symbols:
            charset += self.symbols

        if not charset:
            print(f"{Fore.RED}No character set selected. Aborting brute force attack.{Style.RESET_ALL}")
            return False, None, 0, 0

        max_length = min(max(1, max_length), 10)  # Max length from HTML is 10
        min_length = min(max(1, min_length), max_length) # Ensures min_length <= max_length
        
        start_time = time.time()
        attempts = 0
        
        print(f"\n{Fore.CYAN}Starting attack with {len(charset)} possible characters{Style.RESET_ALL}")
        print(f"Character set: {charset}")
        print(f"Length range: {min_length}-{max_length}")
        print(f"Maximum attack time: {max_time} seconds")
        
        try:
            for length in range(min_length, max_length + 1):
                if time.time() - start_time > max_time:
                    print(f"{Fore.YELLOW}Maximum time limit ({max_time}s) reached. Stopping attack.{Style.RESET_ALL}")
                    return self.print_interrupt_stats(attempts, start_time)

                print(f"\n{Fore.YELLOW}Trying {length}-character passwords...{Style.RESET_ALL}")
                total_combinations = len(charset) ** length
                print(f"Total combinations for {length} chars: {total_combinations:,}")
                
                for guess in itertools.product(charset, repeat=length):
                    if time.time() - start_time > max_time:
                        print(f"{Fore.YELLOW}Maximum time limit ({max_time}s) reached. Stopping attack.{Style.RESET_ALL}")
                        return self.print_interrupt_stats(attempts, start_time)

                    password = ''.join(guess)
                    attempts += 1
                    
                    if attempts % 50000 == 0:
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