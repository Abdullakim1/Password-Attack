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
    
    def execute(self, target_hash, mask_pattern_choice=None, custom_mask=None, **kwargs):
        
        print(f"\n{Fore.YELLOW}Starting mask attack...{Style.RESET_ALL}")

        masks_map = {
            "?l?l?l?l": ("4 lowercase letters", "?l?l?l?l"),
            "?u?l?l?l": ("1 upper + 3 lower", "?u?l?l?l"),
            "?l?l?l?d": ("3 letters + 1 digit", "?l?l?l?d"),
            "?l?l?d?d": ("2 letters + 2 digits", "?l?l?d?d"),
            "?u?l?l?d?d": ("1 upper + 2 lower + 2 digits", "?u?l?l?d?d"),
            "?d?d?d?d?d?d": ("6 digits", "?d?d?d?d?d?d"),
            "?w?w?w?d?d?s": ("3 combination(w) 2 digits & symbol at the end", "?w?w?w?d?d?s"),
            "common": ("Common passwords", "?c")
        }

        mask = None
        desc = "Custom mask"

        if mask_pattern_choice == 'custom' and custom_mask:
            mask = custom_mask
        elif mask_pattern_choice in masks_map:
            desc, mask = masks_map[mask_pattern_choice]
        
        if not mask:
            print(f"{Fore.RED}No valid mask pattern selected. Aborting mask attack.{Style.RESET_ALL}")
            return False, None, 0, 0

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
                    print(f"\r{Fore.CYAN}Progress: {attempts:,}, Current: {password}, "
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

        tokens = []
        i = 0
        while i < len(mask):
            if mask[i] == '?':
                tokens.append(mask[i:i+2])
                i += 2
            else:
                tokens.append(mask[i])
                i += 1

        positions = []
        for token in tokens:
            if token in charset_map:
                positions.append(charset_map[token])
            elif len(token) == 1:
                positions.append(token)
            else:
                print(f"{Fore.RED}Warning: Unknown mask token '{token}'. Skipping.{Style.RESET_ALL}")
                return []
        
        all_combinations = []
        for combo in itertools.product(*positions):
            all_combinations.append(''.join(combo))

        return all_combinations