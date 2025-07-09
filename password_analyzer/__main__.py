
"""
Password Analyzer - Main Entry Point
This module serves as the entry point for the password analyzer application.
"""

from colorama import Fore, Style, init
from .controller import PasswordCrackingController
from .login.login_system import LoginSystem

init()  

def password_cracker_menu():
    controller = PasswordCrackingController()
    
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
        print("7. Analyze Password Strength (check before cracking)")
        print("8. View Previous Results")
        print("9. Run Performance Benchmark")
        print("10. Start Web Interface")
        print("11. Return to Main Menu")
        
        choice = input(f"{Fore.YELLOW}\nChoose attack method (1-11): {Style.RESET_ALL}")
        
        if choice in ['1', '2', '3', '4', '5', '6']:
            username, target_hash = controller.load_target()
            
            if not username or not target_hash:
                continue
                
            print(f"\nTarget: {username}")
            print(f"Hash: {target_hash}")

            if choice == '1':
                controller.run_dictionary_attack(target_hash)
            elif choice == '2':
                controller.run_brute_force_attack(target_hash)
            elif choice == '3':
                controller.run_hybrid_attack(target_hash, username)
            elif choice == '4':
                controller.run_mask_attack(target_hash)
            elif choice == '5':
                controller.run_rule_based_attack(target_hash)
            elif choice == '6':
                controller.run_rainbow_table_attack(target_hash)
                
        elif choice == '7':
            password = input(f"{Fore.YELLOW}Enter password to analyze: {Style.RESET_ALL}")
            if password:
                analysis = controller.analyze_password_strength(password)
                controller.strength_analyzer.print_analysis(analysis)
                
        elif choice == '8':
            results = controller.get_previous_results()
            controller.reporter.display_results_summary(results)
            
        elif choice == '9':
            print(f"{Fore.YELLOW}Running performance benchmark...{Style.RESET_ALL}")
            results = controller.run_benchmark()
            report = controller.benchmark.generate_benchmark_report(results)
            filename = controller.reporter.save_benchmark_results(report)
            print(f"{Fore.GREEN}Benchmark completed and saved to {filename}{Style.RESET_ALL}")
            
        elif choice == '10':
            print(f"{Fore.CYAN}Starting web interface...{Style.RESET_ALL}")
            print(f"Access the web interface at: http://localhost:5000")
            from .web_interface import run_web_interface
            run_web_interface()
            
        elif choice == '11':
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

def login_system_menu():
    login_system = LoginSystem()
    
    while True:
        print(f"\n{Fore.CYAN}=== Security Demo System ==={Style.RESET_ALL}")
        print("1. Register")
        print("2. Login")
        print("3. Reset Account")
        print("4. Return to Main Menu")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '1':
            login_system.register()
        elif choice == '2':
            login_system.login()
        elif choice == '3':
            username = input("Enter username to reset: ")
            login_system.reset_account(username)
        elif choice == '4':
            return
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")

def main():
    print(f"{Fore.CYAN}Starting Password Security Analyzer Web Interface...{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Access the web interface at: http://localhost:5000{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}All features are available through the web interface!{Style.RESET_ALL}")
    
    from .web_interface import run_web_interface
    run_web_interface()

if __name__ == "__main__":
    main()
