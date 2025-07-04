
"""
Performance benchmarking module.
Benchmarks different attack methods and generates performance reports.
"""

import time
import hashlib
import statistics
from colorama import Fore, Style
from .base import HashVerifier
from .attacks.dictionary_attack import DictionaryAttack
from .attacks.brute_force_attack import BruteForceAttack
from .attacks.hybrid_attack import HybridAttack

class PerformanceBenchmark:
    
    def __init__(self):
        self.test_passwords = [
            "123456",
            "password",
            "hello123",
            "admin2024",
            "Test123!",
            "MyPassword1",
            "SecurePass123",
            "ComplexPassword1!"
        ]
        
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
    
    def benchmark_hash_verification(self, iterations=100000):
        """Benchmark hash verification performance"""
        print(f"\n{Fore.YELLOW}Benchmarking hash verification...{Style.RESET_ALL}")
        
        hash_verifier = HashVerifier()
        test_password = "testpassword"
        test_hash = hashlib.sha256(test_password.encode()).hexdigest()
        
        start_time = time.time()
        
        for _ in range(iterations):
            hash_verifier.verify(test_password, test_hash)
        
        elapsed = time.time() - start_time
        rate = iterations / elapsed
        
        result = {
            'test_type': 'hash_verification',
            'iterations': iterations,
            'elapsed_time': elapsed,
            'rate_per_second': rate
        }
        
        print(f"Hash verification rate: {rate:,.0f} hashes/second")
        return result
    
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
    
    def benchmark_brute_force_attack(self, target_password, charset_size=36, max_length=6):
        """Benchmark brute force attack performance"""
        print(f"\n{Fore.YELLOW}Benchmarking brute force attack...{Style.RESET_ALL}")
        
        if len(target_password) > max_length:
            print(f"{Fore.RED}Password too long for benchmark (max {max_length} chars){Style.RESET_ALL}")
            return None
        
        hash_verifier = HashVerifier()
        target_hash = hashlib.sha256(target_password.encode()).hexdigest()
        
        attack = BruteForceAttack(hash_verifier)
        
        start_time = time.time()
        success, found_password, attempts, elapsed = attack.execute(target_hash)
        
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
    
    def run_comprehensive_benchmark(self):
        """Run comprehensive benchmark of all attack methods"""
        print(f"\n{Fore.CYAN}=== Comprehensive Performance Benchmark ==={Style.RESET_ALL}")
        
        results = []
        
        # Hash verification benchmark
        hash_result = self.benchmark_hash_verification()
        results.append(hash_result)
        
        # Test simple passwords with different attacks
        simple_passwords = ["123456", "password", "admin"]
        
        for password in simple_passwords:
            print(f"\n{Fore.BLUE}Testing password: {password}{Style.RESET_ALL}")
            
            # Dictionary attack
            try:
                dict_result = self.benchmark_dictionary_attack(password)
                if dict_result:
                    results.append(dict_result)
            except Exception as e:
                print(f"{Fore.RED}Dictionary attack failed: {e}{Style.RESET_ALL}")
            
            # Brute force for very short passwords only
            if len(password) <= 4:
                try:
                    bf_result = self.benchmark_brute_force_attack(password)
                    if bf_result:
                        results.append(bf_result)
                except Exception as e:
                    print(f"{Fore.RED}Brute force attack failed: {e}{Style.RESET_ALL}")
        
        return results
    
    def generate_benchmark_report(self, results):
        """Generate detailed benchmark report"""
        print(f"\n{Fore.CYAN}=== Benchmark Report ==={Style.RESET_ALL}")
        
        if not results:
            print(f"{Fore.RED}No benchmark results to report{Style.RESET_ALL}")
            return
        
        # Group results by test type
        grouped = {}
        for result in results:
            test_type = result['test_type']
            if test_type not in grouped:
                grouped[test_type] = []
            grouped[test_type].append(result)
        
        # Generate report for each test type
        for test_type, test_results in grouped.items():
            print(f"\n{Fore.YELLOW}{test_type.upper()} RESULTS:{Style.RESET_ALL}")
            
            if test_type == 'hash_verification':
                for result in test_results:
                    print(f"  Rate: {result['rate_per_second']:,.0f} hashes/second")
            
            else:
                rates = [r['rate_per_second'] for r in test_results if r['rate_per_second'] > 0]
                times = [r['elapsed_time'] for r in test_results]
                successes = [r for r in test_results if r['success']]
                
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
