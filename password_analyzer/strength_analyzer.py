
"""
Password strength analysis module.
Analyzes password strength using entropy calculation and pattern detection.
"""

import re
import math
from colorama import Fore, Style

class PasswordStrengthAnalyzer:
    
    def __init__(self):
        self.common_patterns = [
            r'password',
            r'123456',
            r'qwerty',
            r'admin',
            r'welcome',
            r'letmein',
            r'monkey',
            r'dragon',
            r'master',
            r'shadow'
        ]
        
        self.pattern_descriptions = {
            'sequential_numbers': r'\d{3,}',
            'sequential_letters': r'[a-zA-Z]{3,}',
            'repeated_chars': r'(.)\1{2,}',
            'keyboard_pattern': r'(qwerty|asdf|zxcv|123|abc)',
            'common_substitutions': r'[@4aA][sS5$][df][gh]',
            'year_pattern': r'(19|20)\d{2}',
            'simple_leet': r'[4@][sS5$][eE3][tT7]'
        }
    
    def calculate_entropy(self, password):
        if not password:
            return 0
        
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    def detect_patterns(self, password):
        detected = []
        
        for pattern_name, pattern in self.pattern_descriptions.items():
            if re.search(pattern, password.lower()):
                detected.append(pattern_name)
        
        for common in self.common_patterns:
            if common in password.lower():
                detected.append(f"contains_common_word: {common}")
        
        return detected
    
    def calculate_crack_time_estimate(self, password, attacks_per_second=1000000):
        entropy = self.calculate_entropy(password)
        combinations = 2 ** entropy
        
        average_attempts = combinations / 2
        
        seconds = average_attempts / attacks_per_second
        
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.1f} years"
    
    def get_strength_rating(self, password):
        entropy = self.calculate_entropy(password)
        patterns = self.detect_patterns(password)
        
        if entropy < 28:
            rating = "Very Weak"
            color = Fore.RED
        elif entropy < 36:
            rating = "Weak"
            color = Fore.YELLOW
        elif entropy < 60:
            rating = "Fair"
            color = Fore.BLUE
        elif entropy < 128:
            rating = "Strong"
            color = Fore.GREEN
        else:
            rating = "Very Strong"
            color = Fore.CYAN
        
        if patterns:
            if rating == "Very Strong":
                rating = "Strong"
            elif rating == "Strong":
                rating = "Fair"
            elif rating == "Fair":
                rating = "Weak"
        
        return rating, color
    
    def analyze_password(self, password):
        entropy = self.calculate_entropy(password)
        patterns = self.detect_patterns(password)
        crack_time = self.calculate_crack_time_estimate(password)
        rating, color = self.get_strength_rating(password)
        
        analysis = {
            'password': password,
            'length': len(password),
            'entropy': entropy,
            'patterns': patterns,
            'crack_time_estimate': crack_time,
            'strength_rating': rating,
            'color': color
        }
        
        return analysis
    
    def print_analysis(self, analysis):
        print(f"\n{Fore.CYAN}=== Password Strength Analysis ==={Style.RESET_ALL}")
        print(f"Password: {analysis['password']}")
        print(f"Length: {analysis['length']} characters")
        print(f"Entropy: {analysis['entropy']:.2f} bits")
        print(f"Estimated crack time: {analysis['crack_time_estimate']}")
        print(f"Strength Rating: {analysis['color']}{analysis['strength_rating']}{Style.RESET_ALL}")
        
        if analysis['patterns']:
            print(f"\n{Fore.YELLOW}Detected Patterns:{Style.RESET_ALL}")
            for pattern in analysis['patterns']:
                print(f"  - {pattern}")
        
        print(f"\n{Fore.GREEN}Recommendations:{Style.RESET_ALL}")
        if analysis['length'] < 12:
            print("  - Use at least 12 characters")
        if not re.search(r'[a-z]', analysis['password']):
            print("  - Include lowercase letters")
        if not re.search(r'[A-Z]', analysis['password']):
            print("  - Include uppercase letters")
        if not re.search(r'[0-9]', analysis['password']):
            print("  - Include numbers")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', analysis['password']):
            print("  - Include special characters")
        if analysis['patterns']:
            print("  - Avoid common patterns and dictionary words")
