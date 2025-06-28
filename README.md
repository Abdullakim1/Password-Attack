# Password Security Analysis Tool

This project provides a comprehensive demonstration of password security concepts through two main components:
1. A secure login system with salted password hashing
2. A password analyzer demonstrating various password cracking techniques

## Components

### 1. Login System (`login_system.py`)
- Secure user registration and login
- SHA-256 password hashing with salt
- Account lockout after 3 failed attempts
- MySQL database integration
- Account reset functionality

### 2. Password Analyzer (`password_analyzer.py`)
Demonstrates various password cracking techniques:
- Dictionary Attack using real-world password lists
- Brute Force Attack with character combinations
- Hybrid Attack combining words with patterns
- Mask Attack using password structure patterns
- Rule-Based Attack with password transformations
- Rainbow Table Attack with pre-computed hashes

## Setup

1. Configure MySQL database:
```bash
# Database configuration in both files:
host: localhost
user: luxury_user
password: luxury123
database: security
```
2. Command to see the database:
```bash
mysql -u luxury_user -p
``` 

3. Run the login system:
```bash
python -m password_analyzer
```

## Security Features

- Salted password hashing to prevent rainbow table attacks
- Account lockout mechanism to prevent brute force
- Secure password storage in MySQL database
- Real-time password cracking statistics
- Automatic download of common password lists

## Educational Purpose

This tool is for educational purposes only to demonstrate:
- How password hashing and salting work
- Why strong passwords are important
- The effectiveness of different password cracking techniques
- Best practices for password security
- Real-world attack vectors and defenses

## Technical Implementation

- Uses SHA-256 for password hashing
- Implements both unsalted and salted hash comparisons
- Colorama for enhanced CLI interface
- Progress tracking for cracking attempts
- Performance metrics and statistics
- MySQL for secure credential storage