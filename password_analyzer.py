import hashlib
import time
import string
import itertools
import mysql.connector
import os
from colorama import Fore, Style, init
import requests

init()

class PasswordCracker:
    def __init__(self):
        self.db_config = {
            'host': 'localhost',
            'user': 'luxury_user',
            'password': 'luxury123',
            'database': 'security'
        }
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.numbers = string.digits
        self.using_salt = False
        self.current_salt = None
        self.symbols = string.punctuation
        self.wordlists_dir = 'wordlists'
        
        if not os.path.exists(self.wordlists_dir):
            os.makedirs(self.wordlists_dir)
        

    def get_db_connection(self):
        """Create and return a database connection."""
        try:
            return mysql.connector.connect(**self.db_config)
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Database connection error: {err}{Style.RESET_ALL}")
            return None

    
    def download_wordlists(self):
        """Download common password lists from the internet."""
        print(f"\n{Fore.YELLOW}Downloading password lists...{Style.RESET_ALL}")
        
        wordlists = {
            'rockyou-10k.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-10.txt',
            'common-passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt',
            'leaked-passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/000webhost.txt',
            'wifi-passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt',
            'twitter-passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/twitter-banned.txt'
        }
        
        for filename, url in wordlists.items():
            filepath = os.path.join(self.wordlists_dir, filename)
            if not os.path.exists(filepath):
                try:
                    print(f"Downloading {filename}...")
                    response = requests.get(url)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(response.text)
                    print(f"{Fore.GREEN}Successfully downloaded {filename}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Failed to download {filename}: {str(e)}{Style.RESET_ALL}")

    def load_wordlists(self):
        """Load all downloaded password lists."""
        passwords = set()
        
        for filename in os.listdir(self.wordlists_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(self.wordlists_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        passwords.update(line.strip() for line in f if line.strip())
                except Exception as e:
                    print(f"{Fore.RED}Error reading {filename}: {str(e)}{Style.RESET_ALL}")
        
        return list(passwords)

    def load_target(self):
        """Load the target account to crack from database."""
        conn = self.get_db_connection()
        if not conn:
            return None, None

        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users')
        users = [row[0] for row in cursor.fetchall()]
        
        if not users:
            print(f"{Fore.RED}No accounts found in database{Style.RESET_ALL}")
            cursor.close()
            conn.close()
            return None, None
            
        print(f"\n{Fore.CYAN}Available accounts:{Style.RESET_ALL}")
        for username in users:
            print(f"- {username}")
            
        username = input(f"{Fore.YELLOW}\nEnter username to crack: {Style.RESET_ALL}")
        
        print("\nSelect hash type to crack:")
        print("1. Unsalted hash")
        print("2. Salted hash")
        choice = input("Enter choice (1-2): ")
        
        if choice == '1':
            cursor.execute('SELECT unsalted_hash FROM users WHERE username = %s', (username,))
            self.using_salt = False
        else:
            cursor.execute('SELECT salted_hash, salt FROM users WHERE username = %s', (username,))
            self.using_salt = True
            
        result = cursor.fetchone()
        
        if result and self.using_salt:
            self.current_salt = result[1]  
            return username, result[0]  
        
        cursor.close()
        conn.close()
        
        if not result:
            print(f"{Fore.RED}Username not found!{Style.RESET_ALL}")
            return None, None
            
        return username, result[0]

    def try_password(self, password, target_hash):
        """Check if a password matches the target hash."""
        if self.using_salt:
            salted = password + self.current_salt
            return hashlib.sha256(salted.encode()).hexdigest() == target_hash
        else:
            return hashlib.sha256(password.encode()).hexdigest() == target_hash

    def brute_force_attack(self, target_hash):
        """Real brute force attack trying character combinations."""
        print(f"\n{Fore.YELLOW}Starting brute force attack...{Style.RESET_ALL}")
        print("This will try every possible combination of characters")
        
        print("\nWhich characters should we try?")
        print("1. Just lowercase (a-z)")
        print("2. Lowercase + numbers")
        print("3. Lowercase + uppercase + numbers")
        print("4. All characters (lowercase, uppercase, numbers, symbols)")
        
        choice = input("Enter choice (1-4): ")
        charset = ""
        if choice == '1':
            charset = self.lowercase
            print("Using lowercase letters only")
        elif choice == '2':
            charset = self.lowercase + self.numbers
            print("Using lowercase letters and numbers")
        elif choice == '3':
            charset = self.lowercase + self.uppercase + self.numbers
            print("Using letters and numbers")
        else:
            charset = self.lowercase + self.uppercase + self.numbers + self.symbols
            print("Using all possible characters")

        max_length = int(input("\nMaximum password length to try (1-8): "))
        max_length = min(max(1, max_length), 8)  
        
        start_time = time.time()
        attempts = 0
        
        print(f"\n{Fore.CYAN}Starting attack with {len(charset)} possible characters{Style.RESET_ALL}")
        print(f"Character set: {charset}")
        
        try:
            for length in range(1, max_length + 1):
                print(f"\n{Fore.YELLOW}Trying {length}-character passwords...{Style.RESET_ALL}")
                total_combinations = len(charset) ** length
                print(f"Total combinations for {length} chars: {total_combinations:,}")
                
                for guess in itertools.product(charset, repeat=length):
                    password = ''.join(guess)
                    attempts += 1
                    
                    if attempts % 5000 == 0:
                        elapsed = time.time() - start_time
                        rate = attempts / elapsed if elapsed > 0 else 0
                        print(f"\r{Fore.CYAN}Progress: {attempts:,} attempts, Current: {password}, "
                              f"Time: {elapsed:.1f}s, Rate: {rate:.0f} tries/sec{Style.RESET_ALL}", 
                              end="", flush=True)
                    
                    if self.try_password(password, target_hash):
                        elapsed = time.time() - start_time
                        print(f"\n\n{Fore.GREEN}Password cracked!")
                        print(f"Password: {password}")
                        print(f"Attempts: {attempts:,}")
                        print(f"Time taken: {elapsed:.1f} seconds")
                        print(f"Rate: {rate:.0f} passwords/second{Style.RESET_ALL}")
                        return True, password, attempts, elapsed

        except KeyboardInterrupt:
            elapsed = time.time() - start_time
            rate = attempts / elapsed if elapsed > 0 else 0
            print(f"\n\n{Fore.YELLOW}Attack stopped by user")
            print(f"Attempts made: {attempts:,}")
            print(f"Time elapsed: {elapsed:.1f} seconds")
            print(f"Rate: {rate:.0f} passwords/second{Style.RESET_ALL}")
            return False, None, attempts, elapsed
        
        elapsed = time.time() - start_time
        rate = attempts / elapsed if elapsed > 0 else 0
        print(f"\n\n{Fore.RED}Password not found after {attempts:,} attempts")
        print(f"Time taken: {elapsed:.1f} seconds")
        print(f"Rate: {rate:.0f} passwords/second{Style.RESET_ALL}")
        return False, None, attempts, elapsed

    def dictionary_attack(self, target_hash):
        """Enhanced dictionary attack using real-world password lists."""
        print(f"\n{Fore.YELLOW}Starting enhanced dictionary attack...{Style.RESET_ALL}")
        
        self.download_wordlists()
        
        print("\nLoading password lists...")
        passwords = self.load_wordlists()
        print(f"Loaded {len(passwords):,} unique passwords")
        
        
        start_time = time.time()
        attempts = 0
        total = len(passwords)
        bar_width = 40  # 40 characters wide
        
        print(f"\n{Fore.CYAN}Starting attack with {total:,} passwords to try{Style.RESET_ALL}")
        
        try:
            last_print_time = 0
            for password in passwords:
                attempts += 1
                
                current_time = time.time()
                if current_time - last_print_time >= 0.1:
                    elapsed = current_time - start_time
                    rate = attempts / elapsed if elapsed > 0 else 0
                    progress = (attempts / total)
                    filled_length = int(bar_width * progress)
                    bar = '=' * filled_length + '-' * (bar_width - filled_length)
                    
                    print(f"{Fore.CYAN}Progress: [{bar}] {progress*100:4.1f}%  "
                          f"({attempts:,}/{total:,})  "
                          f"Rate: {rate:,.0f}/sec  "
                          f"Testing: {password}{Style.RESET_ALL}")
                    last_print_time = current_time
                
                if self.try_password(password, target_hash):
                    elapsed = time.time() - start_time
                    print(f"\n\n{Fore.GREEN}Password cracked!")
                    print(f"Password: {password}")
                    print(f"Found in wordlist")
                    print(f"Attempts: {attempts:,}")
                    print(f"Time taken: {elapsed:.1f} seconds")
                    print(f"Rate: {attempts/elapsed:,.0f} passwords/second{Style.RESET_ALL}")
                    return True, password, attempts, elapsed
        
        except KeyboardInterrupt:
            self._print_interrupt_stats(attempts, start_time)
            return False, None, attempts, time.time() - start_time
            
        self._print_failure_stats(attempts, start_time)
        return False, None, attempts, time.time() - start_time

    def hybrid_attack(self, target_hash, username=None):
        """Hybrid attack combining words with number/symbol patterns.
        This attack focuses on combining base words with numerical and symbol patterns,
        such as: admin123, pass@2024, test_123, etc."""
        print(f"\n{Fore.YELLOW}Starting hybrid attack (word + pattern combinations)...{Style.RESET_ALL}")

        base_words = [
        "pass", "pwd", "admin", "user", "login", "test", "demo", 
        "guest", "root", "dev", "system", "web", "app", "api"
        ]
        
        # Add username to base words if provided
        if username:
            base_words.extend([username.lower(), username])
            # Also add common variations
            if len(username) > 3:
                base_words.extend([username[:4], username[:3]])

        number_patterns = [
        "###",      
        "####",     
        "#@#",      
        "@##",      
        "##@",      
        "@#@"       
        ]

        symbol_patterns = [
        "_#", "#_",     
        "@#", "#@",     
        "!#", "#!",     
        "$#", "#$"      
        ]

        start_time = time.time()
        attempts = 0
        bar_width = 40
        
        # Calculate estimated total BEFORE the loops start
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
        
        print(f"Debug - Estimated breakdown:")
        print(f"  Year attempts: {year_attempts:,}")
        print(f"  Number attempts: {number_attempts:,}")  
        print(f"  Symbol attempts: {symbol_attempts:,}")
        print(f"  Total estimated: {estimated_total:,}")

        try:
            last_print_time = 0
        
            for word in base_words:
                # Year-based passwords
                for year in range(2020, 2025):
                    attempts += 1
                    password = f"{word}{year}"
                    
                    current_time = time.time()
                    if current_time - last_print_time >= 0.1:
                        self._print_progress(attempts, estimated_total, password, start_time, bar_width)
                        last_print_time = current_time
                    
                    if self.try_password(password, target_hash):
                        return self._print_success_stats(password, attempts, start_time)
            
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
                                    self._print_progress(attempts, estimated_total, word+temp, start_time, bar_width)
                                    last_print_time = current_time
                            
                                for password in passwords:
                                    attempts += 1
                                    if self.try_password(password, target_hash):
                                        return self._print_success_stats(password, attempts, start_time)
                        else:
                            # Pattern has no @ - use attempt directly
                            passwords = [
                                f"{word}{attempt}",    
                                f"{attempt}{word}",    
                                f"{word}_{attempt}"    
                            ]
                        
                            current_time = time.time()
                            if current_time - last_print_time >= 0.1:
                                self._print_progress(attempts, estimated_total, word+attempt, start_time, bar_width)
                                last_print_time = current_time
                        
                            for password in passwords:
                                attempts += 1
                                if self.try_password(password, target_hash):
                                    return self._print_success_stats(password, attempts, start_time)
            
                # Symbol pattern passwords
                for pattern in symbol_patterns:
                    for i in range(100):
                    
                        attempt = pattern.replace('#', str(i).zfill(2))
                    
                        passwords = [
                            f"{word}{attempt}",    
                            f"{attempt}{word}",    
                            f"{word}{attempt}{word}"  
                        ]
                    
                        current_time = time.time()
                        if current_time - last_print_time >= 0.1:
                            self._print_progress(attempts, estimated_total, word+attempt, start_time, bar_width)
                            last_print_time = current_time
                    
                        for password in passwords:
                            attempts += 1
                            if self.try_password(password, target_hash):
                                return self._print_success_stats(password, attempts, start_time)

        except KeyboardInterrupt:
            self._print_interrupt_stats(attempts, start_time)
            return False, None, attempts, time.time() - start_time

        self._print_failure_stats(attempts, start_time)
        return False, None, attempts, time.time() - start_time
    def rule_based_attack(self, target_hash):
        """Rule-based attack applying sophisticated password transformation rules.
        This attack focuses on word mutations and transformations like:
        - Case changes (upper, lower, alternate)
        - Character substitutions (leetspeak)
        - String manipulations (reverse, duplicate)
        - Advanced patterns (alternating case, character doubling)"""
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

                if self.try_password(password, target_hash):
                    return self._print_success_stats(password, attempts, start_time)

        except KeyboardInterrupt:
            self._print_interrupt_stats(attempts, start_time)
            return False, None, attempts, time.time() - start_time

        self._print_failure_stats(attempts, start_time)
        return False, None, attempts, time.time() - start_time

    def mask_attack(self, target_hash):
        """Mask attack using a selected password pattern."""
        print(f"\n{Fore.YELLOW}Starting mask attack...{Style.RESET_ALL}")

        masks = [
            ("4 lowercase & 2 digits at the end", "?l?l?l?l?d?d"),
            ("3 lowercase & 3 digits at the end", "?l?l?l?d?d?d"),
            ("1 uppercase 3 lowercase 2 digits at the end", "?u?l?l?l?d?d"),
            ("4 lowercase & symbol and digit at the end", "?l?l?l?l?s?d"),
            ("6 digits", "?d?d?d?d?d?d"),
            ("3 combination(w) 2 digits & symbol at the end", "?w?w?w?d?d?s")
        ]

        print("\nAvailable Mask Patterns:")
        for idx, (desc, _) in enumerate(masks, start=1):
            print(f"{idx}. {desc}")

        selection = input("Choose a mask number (1-6): ").strip()

        try:
            selected_index = int(selection) - 1
            if not 0 <= selected_index < len(masks):
                raise ValueError
        except ValueError:
            print(f"{Fore.RED}Invalid selection. Aborting mask attack.{Style.RESET_ALL}")
            return False, None, 0, 0

        desc, mask = masks[selected_index]
        print(f"\n{Fore.CYAN}Selected pattern: {desc}")
        print(f"Mask pattern: {mask}{Style.RESET_ALL}")

        start_time = time.time()
        attempts = 0

        combinations = self._generate_from_mask(mask)
        mask_total = len(combinations)
        print(f"Combinations for this mask: {mask_total:,}")

        try:
            for password in combinations:
                attempts += 1
                if attempts % 50000 == 0:
                    elapsed = time.time() - start_time
                    rate = attempts / elapsed if elapsed > 0 else 0
                    print(f"{Fore.CYAN}Progress: {attempts:,}, Current: {password}, "
                        f"Time: {elapsed:.1f}s, Rate: {rate:.0f} tries/sec{Style.RESET_ALL}"
                        )

                if self.try_password(password, target_hash):
                    elapsed = time.time() - start_time
                    print(f"\n\n{Fore.GREEN}Password cracked!")
                    print(f"Password: {password}")
                    print(f"Using mask: {mask}")
                    print(f"Attempts: {attempts:,}")
                    print(f"Time taken: {elapsed:.1f} seconds")
                    print(f"Rate: {attempts/elapsed:.0f} passwords/second{Style.RESET_ALL}")
                    return True, password, attempts, elapsed

        except KeyboardInterrupt:
            self._print_interrupt_stats(attempts, start_time)
            return False, None, attempts, time.time() - start_time

        self._print_failure_stats(attempts, start_time)
        return False, None, attempts, time.time() - start_time
    
    def _generate_from_mask(self, mask):
        charset_map = {
            '?l': self.lowercase,
            '?u': self.uppercase,
            '?d': self.numbers,
            '?s': self.symbols,
            '?w': self.lowercase + self.uppercase + self.numbers
        }

        positions = []
        for i in range(0, len(mask), 2):
            char_type = mask[i:i+2]
            if char_type in charset_map:
                positions.append(charset_map[char_type])

        all_combinations = []
        for length in range(1, len(positions) + 1):
            for pos_subset in itertools.combinations(positions, length):
                all_combinations.extend([''.join(chars) for chars in itertools.product(*pos_subset)])

        return all_combinations

    def _print_interrupt_stats(self, attempts, start_time):
        """Print statistics when attack is interrupted."""
        elapsed = time.time() - start_time
        rate = attempts / elapsed if elapsed > 0 else 0
        print(f"\n\n{Fore.YELLOW}Attack stopped by user")
        print(f"Attempts made: {attempts:,}")
        print(f"Time elapsed: {elapsed:.1f} seconds")
        print(f"Rate: {rate:.0f} passwords/second{Style.RESET_ALL}")

    def _print_failure_stats(self, attempts, start_time):
        """Print statistics when attack fails to find password."""
        elapsed = time.time() - start_time
        rate = attempts / elapsed if elapsed > 0 else 0
        print(f"\n\n{Fore.RED}Password not found")
        print(f"Attempts: {attempts:,}")
        print(f"Time taken: {elapsed:.1f} seconds")
        print(f"Rate: {rate:.0f} passwords/second{Style.RESET_ALL}")

    def _print_success_stats(self, password, attempts, start_time):
        """Print statistics when password is found and return success."""
        elapsed = time.time() - start_time
        print(f"\n\n{Fore.GREEN}Password cracked!")
        print(f"Password: {password}")
        print(f"Attempts: {attempts:,}")
        print(f"Time taken: {elapsed:.1f} seconds")
        print(f"Rate: {attempts/elapsed:.0f} passwords/second{Style.RESET_ALL}")
        return True, password, attempts, elapsed

    def _print_progress(self, attempts, total, current, start_time, bar_width):
        """Print progress bar with current status."""
        elapsed = time.time() - start_time
        rate = attempts / elapsed if elapsed > 0 else 0
        progress = min(1.0, attempts / total)
        filled_length = int(bar_width * progress)
        bar = '=' * filled_length + '-' * (bar_width - filled_length)
        
        print(f"{Fore.CYAN}Progress: [{bar}] {progress*100:4.1f}%  "
              f"Attempts: {attempts:,}  "
              f"Rate: {rate:,.0f}/sec  "
              f"Testing: {current}{Style.RESET_ALL}")

    def _generate_username_variations(self, username):
        """Generate common variations of the username."""
        variations = set()
        variations.add(username)
        variations.add(username.lower())
        variations.add(username.upper())
        variations.add(username.capitalize())
        
        years = list(range(2000, 2025)) + [123, 1234, 12345]
        for year in years:
            variations.add(f"{username}{year}")
            variations.add(f"{year}{username}")
        
        for affix in ["123", "!", "@", "#", "1234", "12345", "123456", 
                     "pass", "pwd", "password", "admin", "user"]:
            variations.add(f"{username}{affix}")
            variations.add(f"{affix}{username}")
            
        subs = username.lower()
        subs = subs.replace('a', '@')
        subs = subs.replace('e', '3')
        subs = subs.replace('i', '1')
        subs = subs.replace('o', '0')
        subs = subs.replace('s', '$')
        variations.add(subs)
        
        return list(variations)

    def _generate_number_patterns(self):
        """Generate common number patterns."""
        patterns = set()
        for i in range(1000):
            patterns.add(str(i))
            patterns.add(f"{i:03d}")
            patterns.add(f"{i:04d}")
        
        for year in range(1960, 2025):
            patterns.add(str(year))
        
        patterns.update([
            "123456", "12345", "111111", "000000", "11111",
            "55555", "77777", "88888", "99999", "12321",
            "123123", "456456", "654321", "112233", "445566"
        ])
        return list(patterns)

    def generate_rainbow_table(self, max_length=3):
        """Generate a rainbow table of password hashes."""
        rainbow_table = {}
        chars = self.lowercase + self.uppercase + self.numbers + self.symbols
        total = 0
        
        print(f"{Fore.CYAN}Generating rainbow table...{Style.RESET_ALL}")
        start_time = time.time()
        
        for length in range(1, max_length + 1):
            for password in itertools.product(chars, repeat=length):
                password = ''.join(password)
                hash_value = hashlib.sha256(password.encode()).hexdigest()
                rainbow_table[hash_value] = password
                total += 1
                
                if total % 100000 == 0:
                    print(f"Generated {total:,} hashes...", end='\r')
        
        end_time = time.time()
        print(f"\n{Fore.GREEN}Rainbow table generated with {total:,} password hashes{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Time taken: {end_time - start_time:.1f} seconds{Style.RESET_ALL}")
        return rainbow_table

    def rainbow_table_attack(self, target_hash):
        """Try to crack password using pre-computed rainbow table."""
        print(f"\n{Fore.CYAN}Starting rainbow table attack...{Style.RESET_ALL}")
        print("This will use pre-computed hashes to crack the password")
        
        if self.using_salt:
            print(f"\n{Fore.YELLOW}Note: This hash is salted. Let's see why rainbow tables don't work...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Salt used: {self.current_salt}{Style.RESET_ALL}")
            
        start_time = time.time()
        
        rainbow_table = self.generate_rainbow_table(3)
        total_attempts = len(rainbow_table)
        
        if self.using_salt:
            print(f"\n{Fore.CYAN}Trying each password with the salt...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}This means computing {total_attempts:,} new hashes!{Style.RESET_ALL}")
            
            attempts = 0
            for password in rainbow_table.values():
                attempts += 1
                if attempts % 100000 == 0:
                    elapsed = time.time() - start_time
                    rate = int(attempts/elapsed) if elapsed > 0 else 0
                    print(f"{Fore.CYAN}Progress: {attempts:,}/{total_attempts:,} hashes tried ({rate:,}/sec){Style.RESET_ALL}", end='\r')
                    
                salted = password + self.current_salt
                hash_value = hashlib.sha256(salted.encode()).hexdigest()
                
                if hash_value == target_hash:
                    end_time = time.time()
                    print(f"\n\n{Fore.GREEN}Password found!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Password: {password}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Hashes computed: {attempts:,}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Time taken: {end_time - start_time:.1f} seconds{Style.RESET_ALL}")
                    print(f"\n{Fore.YELLOW}Why was this slower?{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}1. Rainbow table was useless - couldn't look up salted hash{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}2. Had to compute new hash for each password + salt combination{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}3. This is why salting defeats rainbow table attacks!{Style.RESET_ALL}")
                    return True
        else:
            if target_hash in rainbow_table:
                password = rainbow_table[target_hash]
                end_time = time.time()
                print(f"\n{Fore.GREEN}Password found in rainbow table!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Password: {password}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Time for lookup: {end_time - start_time:.6f} seconds{Style.RESET_ALL}")
                print(f"\n{Fore.YELLOW}Notice how fast this was - just a simple lookup!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}This is why we need salting to prevent rainbow table attacks{Style.RESET_ALL}")
                return True
        
        end_time = time.time()
        print(f"\n{Fore.RED}Password not found after trying {total_attempts:,} hashes{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Time taken: {end_time - start_time:.1f} seconds{Style.RESET_ALL}")
        return False


def main():
    cracker = PasswordCracker()
    
    print(f"{Fore.BLUE}=== Real Password Cracker ==={Style.RESET_ALL}")
    print("This tool demonstrates how real password cracking works\n")
    
    while True:
        print("Attack Methods:")
        print("1. Dictionary Attack (tries common passwords and patterns)")
        print("2. Brute Force Attack (tries every possible combination)")
        print("3. Hybrid Attack (combines words with patterns)")
        print("4. Mask Attack (uses password structure patterns)")
        print("5. Rule-Based Attack (applies transformation rules)")
        print("6. Rainbow Table Attack (pre-computed hash tables)")
        print("7. Quit")
        
        choice = input(f"{Fore.YELLOW}\nChoose attack method (1-7): {Style.RESET_ALL}")
        
        if choice in ['1', '2', '3', '4', '5', '6']:
            username, target_hash = cracker.load_target()
            
            if not username or not target_hash:
                continue
                
            print(f"\nTarget: {username}")
            print(f"Hash: {target_hash}")
            
            if choice == '1':
                cracker.dictionary_attack(target_hash)
            elif choice == '2':
                cracker.brute_force_attack(target_hash)
            elif choice == '3':
                cracker.hybrid_attack(target_hash)
            elif choice == '4':
                cracker.mask_attack(target_hash)
            elif choice == '5':
                cracker.rule_based_attack(target_hash)
            elif choice == '6':
                cracker.rainbow_table_attack(target_hash)
                
        elif choice == '7':
            break

if __name__ == "__main__":
    main()
