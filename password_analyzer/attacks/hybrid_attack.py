"""
Hybrid attack module for password analyzer.
Implements hybrid password cracking by combining words with patterns.
"""

import time
from colorama import Fore, Style
from ..base import PasswordAttack
from ..wordlist import WordlistManager

class HybridAttack(PasswordAttack):
    """Implements hybrid password cracking (word + pattern combinations)."""
    
    def __init__(self, hash_verifier):
        """
        Initialize the hybrid attack.
        
        Args:
            hash_verifier: Object that verifies if a password matches a hash
        """
        super().__init__(hash_verifier)
        self.wordlist_manager = WordlistManager()
    
    def execute(self, target_hash, **kwargs):
        """
        Execute the hybrid attack.
        
        Args:
            target_hash: The hash to crack
            **kwargs: Additional parameters
                username: Optional username to generate variations from
            
        Returns:
            tuple: (success, password, attempts, elapsed_time)
        """
        username = kwargs.get('username')
        
        print(f"\n{Fore.YELLOW}Starting hybrid attack (word + pattern combinations)...{Style.RESET_ALL}")

        base_words = self.wordlist_manager.get_base_words()
        
        # Add username to base words if provided
        if username:
            base_words.extend(self.wordlist_manager.generate_username_variations(username))

        number_patterns = [
            "###",      # Three digits
            "####",     # Four digits
            "#@#",      # Digit, letter, digit
            "@##",      # Letter, two digits
            "##@",      # Two digits, letter
            "@#@"       # Letter, digit, letter
        ]

        symbol_patterns = [
            "_#", "#_",     # Underscore and digit
            "@#", "#@",     # Letter and digit
            "!#", "#!",     # Exclamation and digit
            "$#", "#$"      # Dollar and digit
        ]

        start_time = time.time()
        attempts = 0
        bar_width = 40
        
        # Calculate estimated total attempts
        year_attempts = len(base_words) * 5  # 2020-2024 = 5 years
        
        # For number patterns: calculate based on actual loop structure
        number_attempts = 0
        for pattern in number_patterns:
            digit_count = pattern.count('#')
            iterations = min(10 ** digit_count, 1000)
            
            if '@' in pattern:
                # Pattern has @ symbols - multiply by 26 for letter substitutions
                number_attempts += len(base_words) * iterations * 26 * 3
            else:
                # Pattern has no @ symbols - just the base iterations
                number_attempts += len(base_words) * iterations * 3
        
        symbol_attempts = len(base_words) * len(symbol_patterns) * 100 * 3
        
        estimated_total = year_attempts + number_attempts + symbol_attempts
        
        print(f"Estimated attempts breakdown:")
        print(f"  Year attempts: {year_attempts:,}")
        print(f"  Number attempts: {number_attempts:,}")  
        print(f"  Symbol attempts: {symbol_attempts:,}")
        print(f"  Total estimated: {estimated_total:,}")

        try:
            last_print_time = 0
        
            # Year-based passwords
            for word in base_words:
                for year in range(2020, 2025):
                    attempts += 1
                    password = f"{word}{year}"
                    
                    current_time = time.time()
                    if current_time - last_print_time >= 0.1:
                        self.print_progress(attempts, estimated_total, password, start_time, bar_width)
                        last_print_time = current_time
                    
                    if self.hash_verifier.verify(password, target_hash):
                        return self.print_success_stats(password, attempts, start_time)
            
                # Number pattern passwords
                for pattern in number_patterns:
                    max_num = 10 ** pattern.count('#')
                    for i in range(min(max_num, 1000)):
                    
                        attempt = pattern
                        for digit in str(i).zfill(pattern.count('#')):
                            attempt = attempt.replace('#', digit, 1)
                        
                        if '@' in pattern:
                            # Pattern contains @ - substitute each letter
                            for letter in 'abcdefghijklmnopqrstuvwxyz':
                                temp = attempt.replace('@', letter)
                            
                                passwords = [
                                    f"{word}{temp}",    
                                    f"{temp}{word}",    
                                    f"{word}_{temp}"    
                                ]
                            
                                current_time = time.time()
                                if current_time - last_print_time >= 0.1:
                                    self.print_progress(attempts, estimated_total, word+temp, start_time, bar_width)
                                    last_print_time = current_time
                            
                                for password in passwords:
                                    attempts += 1
                                    if self.hash_verifier.verify(password, target_hash):
                                        return self.print_success_stats(password, attempts, start_time)
                        else:
                            # Pattern has no @ - use attempt directly
                            passwords = [
                                f"{word}{attempt}",    
                                f"{attempt}{word}",    
                                f"{word}_{attempt}"    
                            ]
                        
                            current_time = time.time()
                            if current_time - last_print_time >= 0.1:
                                self.print_progress(attempts, estimated_total, word+attempt, start_time, bar_width)
                                last_print_time = current_time
                        
                            for password in passwords:
                                attempts += 1
                                if self.hash_verifier.verify(password, target_hash):
                                    return self.print_success_stats(password, attempts, start_time)
            
                # Symbol pattern passwords
                for pattern in symbol_patterns:
                    for i in range(100):
                        attempt = pattern.replace('#', str(i).zfill(2))
                        
                        passwords = [
                            f"{word}{attempt}",
                            f"{attempt}{word}",
                            f"{word}{attempt}{word[:2]}"
                        ]
                        
                        current_time = time.time()
                        if current_time - last_print_time >= 0.1:
                            self.print_progress(attempts, estimated_total, word+attempt, start_time, bar_width)
                            last_print_time = current_time
                        
                        for password in passwords:
                            attempts += 1
                            if self.hash_verifier.verify(password, target_hash):
                                return self.print_success_stats(password, attempts, start_time)
        
        except KeyboardInterrupt:
            return self.print_interrupt_stats(attempts, start_time)
            
        return self.print_failure_stats(attempts, start_time)
