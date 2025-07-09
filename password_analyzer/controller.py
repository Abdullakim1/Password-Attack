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
from .strength_analyzer import PasswordStrengthAnalyzer
from .reporting import ResultsReporter
from .benchmark import PerformanceBenchmark

class PasswordCrackingController:
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.hash_verifier = HashVerifier()
        self.strength_analyzer = PasswordStrengthAnalyzer()
        self.reporter = ResultsReporter()
        self.benchmark = PerformanceBenchmark()
    
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

        self.last_target_salted = use_salt

        return username, hash_value
    
    def run_dictionary_attack(self, target_hash, **kwargs):
        
        attack = DictionaryAttack(self.hash_verifier)
        return attack.execute(target_hash, **kwargs)
    
    def run_brute_force_attack(self, target_hash, **kwargs):
        
        attack = BruteForceAttack(self.hash_verifier)
        return attack.execute(target_hash, **kwargs)
    
    def run_hybrid_attack(self, target_hash, username=None, **kwargs):
        
        attack = HybridAttack(self.hash_verifier)
        return attack.execute(target_hash, username=username, **kwargs)
    
    def run_mask_attack(self, target_hash, **kwargs):
        
        attack = MaskAttack(self.hash_verifier)
        return attack.execute(target_hash, **kwargs)
    
    def run_rule_based_attack(self, target_hash, **kwargs):
        
        attack = RuleBasedAttack(self.hash_verifier)
        return attack.execute(target_hash, **kwargs)
    
    def run_rainbow_table_attack(self, target_hash, **kwargs):
        
        attack = RainbowTableAttack(self.hash_verifier)
        return attack.execute(target_hash, **kwargs)
    
    def analyze_password_strength(self, password):
        """Analyze password strength before cracking"""
        return self.strength_analyzer.analyze_password(password)
    
    def save_attack_result(self, attack_type, username, target_hash, success, password, attempts, elapsed, use_salt=False):
        """Save attack results to file"""
        rate = attempts / elapsed if elapsed > 0 else 0
        result = self.reporter.create_attack_result(
            attack_type, username, target_hash, success, password, attempts, elapsed, rate, use_salt
        )
        return self.reporter.save_result(result)
    
    def run_benchmark(self):
        """Run performance benchmark"""
        return self.benchmark.run_comprehensive_benchmark()
    
    def get_previous_results(self):
        """Get previous analysis results"""
        return self.reporter.load_previous_results()