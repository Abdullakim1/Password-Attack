"""
Performance benchmarking module.
Benchmarks different attack methods and generates performance reports.
"""

import time
import hashlib
import statistics
import logging
from colorama import Fore, Style
from .base import HashVerifier
from .attacks.dictionary_attack import DictionaryAttack
from .attacks.brute_force_attack import BruteForceAttack
from .attacks.hybrid_attack import HybridAttack
from .attacks.mask_attack import MaskAttack
from .attacks.rule_based_attack import RuleBasedAttack
from .attacks.rainbow_table_attack import RainbowTableAttack

class PerformanceBenchmark:
    
    def __init__(self, target_password=None):
        self.target_password = target_password
        self.test_passwords = [target_password] if target_password else []
        self.benchmark_results = []
    
    def create_test_hashes(self):
        """Create test hashes for benchmarking"""
        test_hashes = {}
        
        for password in self.test_passwords:
            # Unsalted hash
            hash_unsalted = hashlib.sha256(password.encode()).hexdigest()
            
            # Salted hash
            salt = "test_salt_123"
            salted = password + salt
            hash_salted = hashlib.sha256(salted.encode()).hexdigest()
            
            test_hashes[password] = {
                'unsalted': hash_unsalted,
                'salted': hash_salted,
                'salt': salt
            }
        
        return test_hashes
    
    def benchmark_dictionary_attack(self, target_password, max_attempts=10000):
        """Benchmark dictionary attack performance"""
        print(f"\n{Fore.YELLOW}Benchmarking dictionary attack...{Style.RESET_ALL}")
        
        # Create hash verifier
        hash_verifier = HashVerifier()
        target_hash = hashlib.sha256(target_password.encode()).hexdigest()
        
        # Create attack instance
        attack = DictionaryAttack(hash_verifier)
        
        start_time = time.time()
        success, found_password, attempts, elapsed = attack.execute(target_hash)
        
        result = {
            'test_type': 'dictionary_attack',
            'target_password': target_password,
            'success': success,
            'found_password': found_password,
            'attempts': attempts,
            'elapsed_time': elapsed,
            'rate_per_second': attempts / elapsed if elapsed > 0 else 0
        }
        
        return result
    
    def benchmark_brute_force_attack(self, target_password, max_length=6, max_time=None):
        """Benchmark brute force attack performance with max time"""
        print(f"\n{Fore.YELLOW}Benchmarking brute force attack...{Style.RESET_ALL}")
        
        # Removed the condition: if len(target_password) > max_length:
        # The brute force attack will now only be limited by max_time.
        
        hash_verifier = HashVerifier()
        target_hash = hashlib.sha256(target_password.encode()).hexdigest()
        
        # Pass max_time to the BruteForceAttack constructor
        attack = BruteForceAttack(hash_verifier, max_time=max_time)
        
        start_time = time.time()
        success, found_password, attempts, elapsed = attack.execute(target_hash, max_time=max_time) # Pass max_time to execute
        
        result = {
            'test_type': 'brute_force_attack',
            'target_password': target_password,
            'success': success,
            'found_password': found_password,
            'attempts': attempts,
            'elapsed_time': elapsed,
            'rate_per_second': attempts / elapsed if elapsed > 0 else 0
        }
        
        return result
    
    def benchmark_hybrid_attack(self, target_password):
        """Benchmark hybrid attack performance"""
        print(f"\n{Fore.YELLOW}Benchmarking hybrid attack...{Style.RESET_ALL}")
        
        hash_verifier = HashVerifier()
        target_hash = hashlib.sha256(target_password.encode()).hexdigest()
        
        attack = HybridAttack(hash_verifier)
        
        start_time = time.time()
        success, found_password, attempts, elapsed = attack.execute(target_hash)
        
        result = {
            'test_type': 'hybrid_attack',
            'target_password': target_password,
            'success': success,
            'found_password': found_password,
            'attempts': attempts,
            'elapsed_time': elapsed,
            'rate_per_second': attempts / elapsed if elapsed > 0 else 0
        }
        
        return result

    def benchmark_mask_attack(self, target_password, mask_pattern_choice="?l?l?l?l"):
        """Benchmark mask attack performance."""
        print(f"\n{Fore.YELLOW}Benchmarking mask attack...{Style.RESET_ALL}")
        
        hash_verifier = HashVerifier()
        target_hash = hashlib.sha256(target_password.encode()).hexdigest()
        
        attack = MaskAttack(hash_verifier)
        
        start_time = time.time()
        success, found_password, attempts, elapsed = attack.execute(
            target_hash, mask_pattern_choice=mask_pattern_choice
        )
        
        result = {
            'test_type': 'mask_attack',
            'target_password': target_password,
            'success': success,
            'found_password': found_password,
            'attempts': attempts,
            'elapsed_time': elapsed,
            'rate_per_second': attempts / elapsed if elapsed > 0 else 0
        }
        
        return result

    def benchmark_rule_based_attack(self, target_password):
        """Benchmark rule-based attack performance."""
        print(f"\n{Fore.YELLOW}Benchmarking rule-based attack...{Style.RESET_ALL}")
        
        hash_verifier = HashVerifier()
        target_hash = hashlib.sha256(target_password.encode()).hexdigest()
        
        attack = RuleBasedAttack(hash_verifier)
        
        start_time = time.time()
        success, found_password, attempts, elapsed = attack.execute(target_hash)
        
        result = {
            'test_type': 'rule_based_attack',
            'target_password': target_password,
            'success': success,
            'found_password': found_password,
            'attempts': attempts,
            'elapsed_time': elapsed,
            'rate_per_second': attempts / elapsed if elapsed > 0 else 0
        }
        
        return result

    def benchmark_rainbow_table_attack(self, target_password):
        """Benchmark rainbow table attack performance."""
        print(f"\n{Fore.YELLOW}Benchmarking rainbow table attack...{Style.RESET_ALL}")
        
        hash_verifier = HashVerifier()
        target_hash = hashlib.sha256(target_password.encode()).hexdigest()
        
        attack = RainbowTableAttack(hash_verifier)
        
        start_time = time.time()
        success, found_password, attempts, elapsed = attack.execute(target_hash)
        
        result = {
            'test_type': 'rainbow_table_attack',
            'target_password': target_password,
            'success': success,
            'found_password': found_password,
            'attempts': attempts,
            'elapsed_time': elapsed,
            'rate_per_second': attempts / elapsed if elapsed > 0 else 0
        }
        
        return result

    def run_comprehensive_benchmark(self):
        """Run comprehensive benchmark of all attack methods"""
        print(f"\n{Fore.CYAN}=== Comprehensive Performance Benchmark ==={Style.RESET_ALL}")
        
        results = []
        
        # Test passwords with different attacks
        for password in self.test_passwords:
            print(f"\n{Fore.BLUE}Testing password: {password}{Style.RESET_ALL}")
            
            # Dictionary attack
            try:
                dict_result = self.benchmark_dictionary_attack(password)
                if dict_result:
                    results.append(dict_result)
            except Exception as e:
                print(f"{Fore.RED}Dictionary attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Dictionary attack failed for {password}: {e}")
            
            # Brute force attack
            try:
                # Pass max_time from the web interface if available, otherwise use a default
                # The max_time here should ideally come from the form submission in benchmark.html
                # For this example, let's assume a default if not explicitly passed.
                # In a real scenario, this would be passed from the web_interface.py's run_benchmark function.
                bf_result = self.benchmark_brute_force_attack(password, max_time=self.max_time_per_test if hasattr(self, 'max_time_per_test') else 60)
                if bf_result:
                    results.append(bf_result)
            except Exception as e:
                print(f"{Fore.RED}Brute force attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Brute force attack failed for {password}: {e}")
            
            # Hybrid attack
            try:
                hybrid_result = self.benchmark_hybrid_attack(password)
                if hybrid_result:
                    results.append(hybrid_result)
            except Exception as e:
                print(f"{Fore.RED}Hybrid attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Hybrid attack failed for {password}: {e}")
            
            # Add Mask attack
            try:
                mask_result = self.benchmark_mask_attack(password)
                if mask_result:
                    results.append(mask_result)
            except Exception as e:
                print(f"{Fore.RED}Mask attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Mask attack failed for {password}: {e}")

            # Add Rule-Based attack
            try:
                rule_based_result = self.benchmark_rule_based_attack(password)
                if rule_based_result:
                    results.append(rule_based_result)
            except Exception as e:
                print(f"{Fore.RED}Rule-based attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Rule-based attack failed for {password}: {e}")

            # Add Rainbow Table attack
            try:
                rainbow_table_result = self.benchmark_rainbow_table_attack(password)
                if rainbow_table_result:
                    results.append(rainbow_table_result)
            except Exception as e:
                print(f"{Fore.RED}Rainbow Table attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Rainbow Table attack failed for {password}: {e}")
        
        return results
    
    def generate_benchmark_report(self, results):
        """Generate detailed benchmark report"""
        print(f"\n{Fore.CYAN}=== Benchmark Report ==={Style.RESET_ALL}")
        
        if not results:
            print(f"{Fore.RED}No benchmark results to report{Style.RESET_ALL}")
            return {
                'timestamp': time.time(),
                'results': [],
                'summary': {},
                'error': 'No results to report'
            }
        
        try:
            # Group results by test type
            grouped = {}
            for result in results:
                test_type = result.get('test_type', 'unknown')
                if test_type not in grouped:
                    grouped[test_type] = []
                grouped[test_type].append(result)
            
            # Generate report for each test type
            for test_type, test_results in grouped.items():
                print(f"\n{Fore.YELLOW}{test_type.upper()} RESULTS:{Style.RESET_ALL}")
                
                if test_type == 'hash_verification':
                    for result in test_results:
                        rate = result.get('rate_per_second', 0)
                        print(f"  Rate: {rate:,.0f} hashes/second")
                
                else:
                    rates = [r.get('rate_per_second', 0) for r in test_results if r.get('rate_per_second', 0) > 0]
                    times = [r.get('elapsed_time', 0) for r in test_results if 'elapsed_time' in r]
                    successes = [r for r in test_results if r.get('success', False)]
                    
                    print(f"  Tests run: {len(test_results)}")
                    print(f"  Successful cracks: {len(successes)}")
                    
                    if rates:
                        print(f"  Average rate: {statistics.mean(rates):,.0f} attempts/second")
                        print(f"  Max rate: {max(rates):,.0f} attempts/second")
                        print(f"  Min rate: {min(rates):,.0f} attempts/second")
                    
                    if times:
                        print(f"  Average time: {statistics.mean(times):.2f} seconds")
            
            return {
                'timestamp': time.time(),
                'results': results,
                'summary': grouped
            }
            
        except Exception as e:
            print(f"{Fore.RED}Error generating report: {e}{Style.RESET_ALL}")
            return {
                'timestamp': time.time(),
                'results': results,
                'summary': {},
                'error': str(e)
            }