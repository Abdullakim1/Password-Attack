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
        test_hashes = {}
        
        for password in self.test_passwords:
            hash_unsalted = hashlib.sha256(password.encode()).hexdigest()
            
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
        print(f"\n{Fore.YELLOW}Benchmarking dictionary attack...{Style.RESET_ALL}")
        
        hash_verifier = HashVerifier()
        target_hash = hashlib.sha256(target_password.encode()).hexdigest()
        
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
        print(f"\n{Fore.YELLOW}Benchmarking brute force attack...{Style.RESET_ALL}")
        
        hash_verifier = HashVerifier()
        target_hash = hashlib.sha256(target_password.encode()).hexdigest()
        
        attack = BruteForceAttack(hash_verifier, max_time=max_time)
        
        start_time = time.time()
        success, found_password, attempts, elapsed = attack.execute(target_hash, max_time=max_time)
        
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
        print(f"\n{Fore.CYAN}=== Comprehensive Performance Benchmark ==={Style.RESET_ALL}")
        
        results = []
        
        for password in self.test_passwords:
            print(f"\n{Fore.BLUE}Testing password: {password}{Style.RESET_ALL}")
            
            try:
                dict_result = self.benchmark_dictionary_attack(password)
                if dict_result:
                    results.append(dict_result)
            except Exception as e:
                print(f"{Fore.RED}Dictionary attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Dictionary attack failed for {password}: {e}")
            
            try:
                bf_result = self.benchmark_brute_force_attack(password, max_time=self.max_time_per_test if hasattr(self, 'max_time_per_test') else 60)
                if bf_result:
                    results.append(bf_result)
            except Exception as e:
                print(f"{Fore.RED}Brute force attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Brute force attack failed for {password}: {e}")
            
            try:
                hybrid_result = self.benchmark_hybrid_attack(password)
                if hybrid_result:
                    results.append(hybrid_result)
            except Exception as e:
                print(f"{Fore.RED}Hybrid attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Hybrid attack failed for {password}: {e}")
            
            try:
                mask_result = self.benchmark_mask_attack(password)
                if mask_result:
                    results.append(mask_result)
            except Exception as e:
                print(f"{Fore.RED}Mask attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Mask attack failed for {password}: {e}")

            try:
                rule_based_result = self.benchmark_rule_based_attack(password)
                if rule_based_result:
                    results.append(rule_based_result)
            except Exception as e:
                print(f"{Fore.RED}Rule-based attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Rule-based attack failed for {password}: {e}")

            try:
                rainbow_table_result = self.benchmark_rainbow_table_attack(password)
                if rainbow_table_result:
                    results.append(rainbow_table_result)
            except Exception as e:
                print(f"{Fore.RED}Rainbow Table attack failed: {e}{Style.RESET_ALL}")
                logging.error(f"Rainbow Table attack failed for {password}: {e}")
        
        return results
    
    def generate_benchmark_report(self, results):
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
            grouped = {}
            for result in results:
                test_type = result.get('test_type', 'unknown')
                if test_type not in grouped:
                    grouped[test_type] = []
                grouped[test_type].append(result)
            
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