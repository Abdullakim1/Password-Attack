"""
Controller module for password analyzer.
Coordinates the different components of the password analyzer.
"""

from colorama import Fore, Style
from .base import HashVerifier
from .database import DatabaseManager
from .attacks.dictionary_attack import DictionaryAttack
from .attacks.brute_force_attack import BruteForceAttack
from .attacks.hybrid_attack import HybridAttack
from .attacks.mask_attack import MaskAttack
from .attacks.rule_based_attack import RuleBasedAttack
from .attacks.rainbow_table_attack import RainbowTableAttack

class PasswordCrackingController:
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.hash_verifier = HashVerifier()
    
    def load_target(self):
        
        users = self.db_manager.get_users()
        
        if not users:
            print(f"{Fore.RED}No accounts found in database{Style.RESET_ALL}")
            return None, None
            
        print(f"\n{Fore.CYAN}Available accounts:{Style.RESET_ALL}")
        for username in users:
            print(f"- {username}")
            
        username = input(f"{Fore.YELLOW}\nEnter username to crack: {Style.RESET_ALL}")
        
        print("\nSelect hash type to crack:")
        print("1. Unsalted hash")
        print("2. Salted hash")
        choice = input("Enter choice (1-2): ")
        
        use_salt = (choice == '2')
        
        hash_value, salt = self.db_manager.get_user_hash(username, use_salt)
        
        if not hash_value:
            print(f"{Fore.RED}Username not found or hash not available!{Style.RESET_ALL}")
            return None, None
        
        self.hash_verifier.using_salt = use_salt
        self.hash_verifier.current_salt = salt
        
        return username, hash_value
    
    def run_dictionary_attack(self, target_hash):
        
        attack = DictionaryAttack(self.hash_verifier)
        return attack.execute(target_hash)
    
    def run_brute_force_attack(self, target_hash):
        
        attack = BruteForceAttack(self.hash_verifier)
        return attack.execute(target_hash)
    
    def run_hybrid_attack(self, target_hash, username=None):
        
        attack = HybridAttack(self.hash_verifier)
        return attack.execute(target_hash, username=username)
    
    def run_mask_attack(self, target_hash):
        
        attack = MaskAttack(self.hash_verifier)
        return attack.execute(target_hash)
    
    def run_rule_based_attack(self, target_hash):
        
        attack = RuleBasedAttack(self.hash_verifier)
        return attack.execute(target_hash)
    
    def run_rainbow_table_attack(self, target_hash):
        
        attack = RainbowTableAttack(self.hash_verifier)
        return attack.execute(target_hash)
