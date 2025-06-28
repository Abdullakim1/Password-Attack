"""
Dictionary attack module for password analyzer.
Implements dictionary-based password cracking.
"""

import time
from colorama import Fore, Style
from ..base import PasswordAttack
from ..wordlist import WordlistManager

class DictionaryAttack(PasswordAttack):
    
    def __init__(self, hash_verifier):
        
        super().__init__(hash_verifier)
        self.wordlist_manager = WordlistManager()
    
    def execute(self, target_hash, **kwargs):
        
        print(f"\n{Fore.YELLOW}Starting enhanced dictionary attack...{Style.RESET_ALL}")
        
        self.wordlist_manager.download_wordlists()
        
        print("\nLoading password lists...")
        passwords = self.wordlist_manager.load_wordlists()
        print(f"Loaded {len(passwords):,} unique passwords")
        
        start_time = time.time()
        attempts = 0
        total = len(passwords)
        bar_width = 40
        
        print(f"\n{Fore.CYAN}Starting attack with {total:,} passwords to try{Style.RESET_ALL}")
        
        try:
            last_print_time = 0
            for password in passwords:
                attempts += 1
                
                current_time = time.time()
                if current_time - last_print_time >= 0.1:
                    self.print_progress(attempts, total, password, start_time, bar_width)
                    last_print_time = current_time
                
                if self.hash_verifier.verify(password, target_hash):
                    return self.print_success_stats(password, attempts, start_time)
        
        except KeyboardInterrupt:
            return self.print_interrupt_stats(attempts, start_time)
            
        return self.print_failure_stats(attempts, start_time)
