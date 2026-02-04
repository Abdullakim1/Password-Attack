# 🔐 Password Cracking Tool

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![MySQL](https://img.shields.io/badge/Database-MySQL-orange.svg)
![Security](https://img.shields.io/badge/Focus-Cybersecurity-red.svg)

A comprehensive cybersecurity simulation tool designed to demonstrate the efficacy of various password cracking vectors against different hashing implementations. This project juxtaposes a secure, salted login system against a multi-vector password analysis engine.

## ⚡ Demo

> *Note: This simulation runs in a controlled environment for educational analysis.*

![Password Attack Demo](media/demo.gif)
*(If the GIF doesn't load, please check the `media/` folder)*

## 📂 Project Architecture

This tool is split into two distinct modules representing **Defense** (Blue Team) and **Offense** (Red Team):

### 1. The Defense: Secure Login System (`login_system.py`)
A production-grade authentication module implementing industry best practices:
* **Cryptographic Hashing:** Uses SHA-256 with unique per-user salts to neutralize Rainbow Table attacks.
* **Brute Force Mitigation:** Implements an exponential backoff and account lockout mechanism (3 failed attempts).
* **Persistence:** Securely stores credentials in a MySQL database.

### 2. The Offense: Attack Vectors (`password_analyzer.py`)
A benchmarking tool that simulates real-world attack strategies:
* **Dictionary Attack:** Utilizes standard wordlists (e.g., `rockyou.txt` subsets).
* **Brute Force:** Exhaustive key search for short/simple passwords.
* **Hybrid Attack:** Combines dictionary words with common suffix patterns (e.g., "password123").
* **Mask Attack:** Targets specific structural patterns (e.g., Upper-Lower-Digit-Digit).
* **Rainbow Table Attack:** Demonstrates the speed of pre-computed hash lookup vs. dynamic hashing.

---

## 🛠️ Setup & Installation

### Prerequisites
* Python 3.8+
* MySQL Server
* `pip` package manager

### 1. Database Configuration
Access your MySQL instance and set up the environment:

```sql
CREATE DATABASE security;
CREATE USER 'luxury_user'@'localhost' IDENTIFIED BY 'luxury123';
GRANT ALL PRIVILEGES ON security.* TO 'luxury_user'@'localhost';
FLUSH PRIVILEGES;

```
---
2. Install DependenciesBashpip install mysql-connector-python colorama
3. UsageStep 1: Initialize the SystemFirst, run the login system to register a user. This populates the database with a salted hash.Bashpython login_system.py
Step 2: Run the AnalyzerLaunch the attack simulation to test the strength of the stored passwords.Bashpython password_analyzer.py
📊 Technical Implementation DetailsThe core of this project compares the computational cost of attacking Unsalted MD5/SHA vs Salted SHA-256.FeatureImplementationPurposeHashing AlgorithmSHA-256Demonstrates collision resistance standard.Saltingos.urandom(32)Prevents pre-computation attacks.DatabaseMySQL ConnectorSimulates real-world backend latency.UIColoramaProvides real-time visual feedback on attack progress.Code StructureBash├── login_system.py       # Authentication & Registration logic
├── password_analyzer.py  # Attack simulation engine
├── wordlists/           # Directory for dictionary files
│   └── common_pass.txt
├── media/               # Demo assets
│   └── demo.gif
└── README.md
⚠️ Ethical DisclaimerThis tool is strictly for educational purposes and security analysis.It is designed to help developers understand the importance of secure password storage and the mechanics of common vulnerabilities. Do not use this tool against systems you do not own or have explicit permission to test.Developed by Abdullakim Zamirbek uulu
### 💡 Quick Tip for the GIF
Since you want to look like a "serious student," don't just record the whole screen.
1.  Open your terminal.
2.  Resize it so it looks neat.
3.  Run the attack script.
4.  Record **only the terminal window**.
5.  If the attack takes too long, speed up the GIF to 1.5x or 2x speed so the viewer doesn't get bored waiting for the "Success" message.
