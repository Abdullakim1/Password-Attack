"""
Mask attack module for password analyzer.
Implements mask-based password cracking using pattern templates.
"""

import time
import string
import itertools
from colorama import Fore, Style
from ..base import PasswordAttack

class MaskAttack(PasswordAttack):
    
    def __init__(self, hash_verifier):
        
        super().__init__(hash_verifier)
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.numbers = string.digits
        self.symbols = string.punctuation
    
    def execute(self, target_hash, **kwargs):
        
        print(f"\n{Fore.YELLOW}Starting mask attack...{Style.RESET_ALL}")

        masks = [
            ("4 lowercase & 2 digits at the end", "?l?l?l?l?d?d"),
            ("3 lowercase & 3 digits at the end", "?l?l?l?d?d?d"),
            ("1 uppercase 3 lowercase 2 digits at the end", "?u?l?l?l?d?d"),
            ("4 lowercase & symbol and digit at the end", "?l?l?l?l?s?d"),
            ("6 digits", "?d?d?d?d?d?d"),
            ("3 combination(w) 2 digits & symbol at the end", "?w?w?w?d?d?s")
        ]

        print("\nAvailable Mask Patterns:")
        for idx, (desc, _) in enumerate(masks, start=1):
            print(f"{idx}. {desc}")

        selection = input("Choose a mask number (1-6): ").strip()

        try:
            selected_index = int(selection) - 1
            if not 0 <= selected_index < len(masks):
                raise ValueError
        except ValueError:
            print(f"{Fore.RED}Invalid selection. Aborting mask attack.{Style.RESET_ALL}")
            return False, None, 0, 0

        desc, mask = masks[selected_index]
        print(f"\n{Fore.CYAN}Selected pattern: {desc}")
        print(f"Mask pattern: {mask}{Style.RESET_ALL}")

        start_time = time.time()
        attempts = 0

        combinations = self._generate_from_mask(mask)
        mask_total = len(combinations)
        print(f"Combinations for this mask: {mask_total:,}")

        try:
            for password in combinations:
                attempts += 1
                if attempts % 50000 == 0:
                    elapsed = time.time() - start_time
                    rate = attempts / elapsed if elapsed > 0 else 0
                    print(f"{Fore.CYAN}Progress: {attempts:,}, Current: {password}, "
                        f"Time: {elapsed:.1f}s, Rate: {rate:.0f} tries/sec{Style.RESET_ALL}"
                        )

                if self.hash_verifier.verify(password, target_hash):
                    elapsed = time.time() - start_time
                    print(f"\n\n{Fore.GREEN}Password cracked!")
                    print(f"Password: {password}")
                    print(f"Using mask: {mask}")
                    print(f"Attempts: {attempts:,}")
                    print(f"Time taken: {elapsed:.1f} seconds")
                    print(f"Rate: {attempts/elapsed:.0f} passwords/second{Style.RESET_ALL}")
                    return True, password, attempts, elapsed

        except KeyboardInterrupt:
            return self.print_interrupt_stats(attempts, start_time)

        return self.print_failure_stats(attempts, start_time)
    
    def _generate_from_mask(self, mask):
        
        charset_map = {
            '?l': self.lowercase,
            '?u': self.uppercase,
            '?d': self.numbers,
            '?s': self.symbols,
            '?w': self.lowercase + self.uppercase + self.numbers
        }

        positions = []
        for i in range(0, len(mask), 2):
            char_type = mask[i:i+2]
            if char_type in charset_map:
                positions.append(charset_map[char_type])

        all_combinations = []
        for combo in itertools.product(*positions):
            all_combinations.append(''.join(combo))

        return all_combinations
