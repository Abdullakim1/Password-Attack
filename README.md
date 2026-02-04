# 🔐 Password Security Analysis Tool

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
