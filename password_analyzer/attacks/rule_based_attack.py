"""
Rule-based attack module for password analyzer.
Implements rule-based password cracking using word transformations.
"""

import time
from colorama import Fore, Style
from ..base import PasswordAttack

class RuleBasedAttack(PasswordAttack):
    """Implements rule-based password cracking using word transformations."""
    
    def __init__(self, hash_verifier):
        """
        Initialize the rule-based attack.
        
        Args:
            hash_verifier: Object that verifies if a password matches a hash
        """
        super().__init__(hash_verifier)
    
    def execute(self, target_hash, **kwargs):
        """
        Execute the rule-based attack.
        
        Args:
            target_hash: The hash to crack
            **kwargs: Additional parameters (not used)
            
        Returns:
            tuple: (success, password, attempts, elapsed_time)
        """
        print(f"\n{Fore.YELLOW}Starting rule-based attack (word transformations)...{Style.RESET_ALL}")
    
        base_words = [
            "password", "welcome", "admin", "login", "secret", "secure",
            "system", "root", "user", "guest", "test", "demo", "temp", "dev",
            "manager", "super", "master", "control", "access", "server",
            "john", "mike", "david", "james", "peter", "paul", "mary", "sarah",
            "web", "app", "api", "cloud", "data", "code", "dev", "test",
            "admin", "root", "sys", "net", "db", "sql", "ftp", "ssh",
            "hello", "world", "main", "home", "work", "office", "company",
            "service", "support", "help", "info", "mail", "web", "site"
        ]
        
        basic_rules = [
            lambda w: w.upper(),                        
            lambda w: w.lower(),                        
            lambda w: w.capitalize(),                   
            lambda w: w.title(),                        
            lambda w: w[::-1],                          
            lambda w: w + w[::-1],                      
            lambda w: w[::2] + w[1::2],                
            lambda w: w + w,                            
            lambda w: w * 2,                            
            lambda w: w * 3                             
        ]
        
        case_rules = [
            lambda w: ''.join(c.swapcase() for c in w), 
            lambda w: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(w)),  
            lambda w: ''.join(c.upper() if i % 3 == 0 else c.lower() for i, c in enumerate(w)),  
            lambda w: ''.join(c.upper() + c.lower() for c in w), 
            lambda w: w.upper() + w.lower(),            
            lambda w: w + w.upper(),                    
            lambda w: w.lower() + w.capitalize(),       
            lambda w: w.capitalize() + w.lower()        
        ]
        
        leet_maps = [
            {'a':'@', 'e':'3', 'i':'1', 'o':'0', 's':'$', 't':'7'},
            {'a':'4', 'b':'8', 'e':'3', 'g':'9', 'i':'1', 'o':'0', 's':'$', 't':'7'},
            {'a':'@', 'e':'€', 'i':'¡', 'o':'°', 's':'§'},
            {'a':'@', 'e':'3', 'i':'!', 'o':'0', 's':'$'},
            {'a':'@', 'b':'8', 'e':'3', 'g':'6', 'i':'1', 'l':'|', 'o':'0', 's':'5', 't':'7'},
            {'a':'4', 'e':'3', 'i':'1', 'o':'0', 's':'5', 't':'7'},
            {'a':'@', 'e':'3', 'i':'!', 'o':'0', 's':'$', 't':'7', 'b':'8', 'g':'9'},
            {'a':'4', 'e':'3', 'i':'1', 'o':'0', 's':'5', 'b':'8', 'l':'1', 'z':'2'}
        ]
        
        pattern_rules = [
            lambda w: ''.join(c*2 for c in w),          
            lambda w: ''.join(c + c.upper() for c in w),
            lambda w: ''.join(c + '.' for c in w[:-1]) + w[-1], 
            lambda w: '.'.join(w),                      
            lambda w: '-'.join(w),                      
            lambda w: '_'.join(w),                      
            lambda w: '*'.join(w),                      
            lambda w: '#'.join(w),                      
            lambda w: '@'.join(w),                      
            lambda w: '$'.join(w)                       
        ]
        
        number_patterns = [
            "", "123", "1234", "12345", "123456",
            "111", "222", "333", "444", "555",
            "666", "777", "888", "999", "000",
            "!@#", "!@#$", "!@#$%", "!@#$%^",
            "321", "4321", "54321", "654321"
        ]
        
        years = [str(year) for year in range(2020, 2026)]
        dates = ["0101", "1234", "2468", "1111", "0000"]

        start_time = time.time()
        attempts = 0
        combinations = []

        print("\nApplying advanced transformation rules...")
        for word in base_words:
            combinations.append(word)
            
            for rule in basic_rules:
                try:
                    transformed = rule(word)
                    if transformed and transformed != word:
                        combinations.append(transformed)
                except Exception:
                    continue
            
            for rule in case_rules:
                try:
                    transformed = rule(word)
                    if transformed and transformed != word:
                        combinations.append(transformed)
                        for i in range(1000):  
                            combinations.append(f"{transformed}{i:03d}")
                            combinations.append(f"{i:03d}{transformed}")
                        for year in years:
                            combinations.append(f"{transformed}{year}")
                        for date in dates:
                            combinations.append(f"{transformed}{date}")
                except Exception:
                    continue
            
            for leet_map in leet_maps:
                transformed = word
                for k, v in leet_map.items():
                    transformed = transformed.replace(k, v)
                if transformed != word:
                    combinations.append(transformed)
                    for pattern in number_patterns:
                        combinations.append(transformed + pattern)
                        combinations.append(pattern + transformed)
                    for year in years:
                        combinations.append(f"{transformed}{year}")
                        combinations.append(f"{year}{transformed}")
                    for date in dates:
                        combinations.append(f"{transformed}{date}")
                        combinations.append(f"{date}{transformed}")
            
            for rule in pattern_rules:
                try:
                    transformed = rule(word)
                    if transformed and transformed != word:
                        combinations.append(transformed)
                        for special in ['!', '@', '#', '$', '*', '&', '~', '^']:
                            combinations.append(transformed + special)
                            combinations.append(special + transformed)
                            for i in range(100):
                                combinations.append(f"{transformed}{special}{i:02d}")
                except Exception:
                    continue
            
            for basic_rule in basic_rules:
                for leet_map in leet_maps:
                    try:
                        transformed = basic_rule(word)
                        for k, v in leet_map.items():
                            transformed = transformed.replace(k, v)
                        if transformed != word:
                            combinations.append(transformed)
                            for pattern in number_patterns:
                                combinations.append(f"{transformed}{pattern}")
                                combinations.append(f"{pattern}{transformed}")
                            for year in years:
                                combinations.append(f"{transformed}{year}")
                                combinations.append(f"{year}{transformed}")
                            for special in ['!', '@', '#', '$', '*', '&', '~', '^']:
                                for i in range(100):
                                    combinations.append(f"{transformed}{special}{i:02d}")
                                    combinations.append(f"{i:02d}{special}{transformed}")
                    except Exception:
                        continue

        combinations = sorted(set(combinations), key=len)
        total = len(combinations)
        print(f"\n{Fore.CYAN}Generated {total:,} sophisticated word transformations{Style.RESET_ALL}\n")

        try:
            for password in combinations:
                attempts += 1
                if attempts % 1000 == 0:
                    elapsed = time.time() - start_time
                    print(f"{Fore.CYAN}Progress: {attempts:,}/{total:,}, Current: {password}, "
                      f"Time: {elapsed:.1f}s {Style.RESET_ALL}")

                if self.hash_verifier.verify(password, target_hash):
                    return self.print_success_stats(password, attempts, start_time)

        except KeyboardInterrupt:
            return self.print_interrupt_stats(attempts, start_time)
            
        return self.print_failure_stats(attempts, start_time)
