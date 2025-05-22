#!/usr/bin/env python3
"""
Password Analyzer - Main Entry Point
This module serves as the entry point for the password analyzer application.
"""

from colorama import Fore, Style, init
from .controller import PasswordCrackingController
from .login.login_system import LoginSystem

init()  

def password_cracker_menu():
    """Run the password cracker menu."""
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
        print("7. Return to Main Menu")
        
        choice = input(f"{Fore.YELLOW}\nChoose attack method (1-7): {Style.RESET_ALL}")
        
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
            return

def login_system_menu():
    """Run the login system menu."""
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
    """Main entry point for the password analyzer application."""
    while True:
        print(f"\n{Fore.BLUE}=== Password Security System ==={Style.RESET_ALL}")
        print("1. Password Cracker")
        print("2. Login System")
        print("3. Exit")
        
        choice = input(f"{Fore.YELLOW}\nChoose system (1-3): {Style.RESET_ALL}")
        
        if choice == '1':
            password_cracker_menu()
        elif choice == '2':
            login_system_menu()
        elif choice == '3':
            print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
