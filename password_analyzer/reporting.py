
"""
Results reporting and export module.
Handles saving cracking results to various formats.
"""

import json
import csv
import datetime
import os
from colorama import Fore, Style

class ResultsReporter:
    
    def __init__(self):
        self.results_dir = "results"
        self.ensure_results_dir()
    
    def ensure_results_dir(self):
        """Create results directory if it doesn't exist"""
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
    
    def save_result(self, result_data, format_type="json"):
        """Save cracking result to file"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type.lower() == "json":
            filename = f"{self.results_dir}/crack_result_{timestamp}.json"
            self.save_to_json(result_data, filename)
        elif format_type.lower() == "csv":
            filename = f"{self.results_dir}/crack_result_{timestamp}.csv"
            self.save_to_csv(result_data, filename)
        else:
            print(f"{Fore.RED}Unsupported format: {format_type}{Style.RESET_ALL}")
            return None
        
        return filename
    
    def save_to_json(self, data, filename):
        """Save data to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"{Fore.GREEN}Results saved to: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error saving JSON: {e}{Style.RESET_ALL}")
    
    def save_to_csv(self, data, filename):
        """Save data to CSV file"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                if isinstance(data, list) and len(data) > 0:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)
                else:
                    writer = csv.DictWriter(f, fieldnames=data.keys())
                    writer.writeheader()
                    writer.writerow(data)
            print(f"{Fore.GREEN}Results saved to: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error saving CSV: {e}{Style.RESET_ALL}")
    
    def create_attack_result(self, attack_type, username, target_hash, success, 
                           password, attempts, elapsed_time, rate, salt_used=False):
        """Create standardized attack result dictionary"""
        return {
            'timestamp': datetime.datetime.now().isoformat(),
            'attack_type': attack_type,
            'username': username,
            'target_hash': target_hash,
            'success': success,
            'password_found': password,
            'attempts': attempts,
            'elapsed_time_seconds': elapsed_time,
            'rate_per_second': rate,
            'salt_used': salt_used
        }
    
    def save_benchmark_results(self, benchmark_data):
        """Save benchmark results to file"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.results_dir}/benchmark_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(benchmark_data, f, indent=2, ensure_ascii=False)
            print(f"{Fore.GREEN}Benchmark results saved to: {filename}{Style.RESET_ALL}")
            return filename
        except Exception as e:
            print(f"{Fore.RED}Error saving benchmark: {e}{Style.RESET_ALL}")
            return None
    
    def load_previous_results(self):
        """Load and display previous results"""
        if not os.path.exists(self.results_dir):
            print(f"{Fore.YELLOW}No previous results found{Style.RESET_ALL}")
            return []
        
        results = []
        for filename in os.listdir(self.results_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.results_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        results.append({'filename': filename, 'data': data})
                except Exception as e:
                    print(f"{Fore.RED}Error loading {filename}: {e}{Style.RESET_ALL}")
        
        return results
    
    def display_results_summary(self, results):
        """Display summary of previous results"""
        if not results:
            print(f"{Fore.YELLOW}No results to display{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}=== Previous Results Summary ==={Style.RESET_ALL}")
        for result in results:
            data = result['data']
            if isinstance(data, list):
                print(f"File: {result['filename']} - {len(data)} entries")
            else:
                print(f"File: {result['filename']}")
                if 'attack_type' in data:
                    print(f"  Attack: {data['attack_type']}")
                    print(f"  Success: {data['success']}")
                    print(f"  Time: {data.get('elapsed_time_seconds', 'N/A')}s")
