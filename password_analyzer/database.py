"""
Database module for password analyzer.
Handles all database operations including connections and queries.
"""

import os
import mysql.connector
from colorama import Fore, Style

class DatabaseManager:
    
    def __init__(self):
        self.db_config = {
            'host': 'localhost',
            'user': 'luxury_user',
            'password': 'luxury123',
            'database': 'security'
        }
    
    def insert_crack_result(self, result_data):
        conn = self.get_connection()
        if not conn:
            return False

        cursor = conn.cursor()
        try:
            sql = """
            INSERT INTO crack_results (
                timestamp, attack_type, username, target_hash, success,
                password_found, attempts, elapsed_time_seconds, rate_per_second, salt_used
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            values = (
                result_data['timestamp'],
                result_data['attack_type'],
                result_data['username'],
                result_data['target_hash'],
                result_data['success'],
                result_data['password_found'],
                result_data['attempts'],
                result_data['elapsed_time_seconds'],
                result_data['rate_per_second'],
                result_data['salt_used']
            )
            cursor.execute(sql, values)
            conn.commit()
            print(f"{Fore.GREEN}Crack result for {result_data['username']} inserted successfully.{Style.RESET_ALL}")
            return True
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Error inserting crack result: {err}{Style.RESET_ALL}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            conn.close()

    def insert_benchmark_data(self, benchmark_data):
        conn = self.get_connection()
        if not conn:
            return False

        cursor = conn.cursor()
        try:
            sql_benchmark = "INSERT INTO benchmarks (timestamp) VALUES (FROM_UNIXTIME(%s))"
            cursor.execute(sql_benchmark, (benchmark_data['timestamp'],))
            benchmark_id = cursor.lastrowid

            sql_results = """
            INSERT INTO benchmark_results (
                benchmark_id, test_type, iterations, elapsed_time, rate_per_second,
                target_password, success, found_password, attempts
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            for result in benchmark_data['results']:
                values = (
                    benchmark_id,
                    result['test_type'],
                    result.get('iterations'),
                    result['elapsed_time'],
                    result['rate_per_second'],
                    result.get('target_password'),
                    result.get('success'),
                    result.get('found_password'),
                    result.get('attempts')
                )
                cursor.execute(sql_results, values)

            conn.commit()
            print(f"{Fore.GREEN}Benchmark data inserted successfully with ID: {benchmark_id}.{Style.RESET_ALL}")
            return True
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Error inserting benchmark data: {err}{Style.RESET_ALL}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            conn.close()
    
    def get_connection(self):
        
        try:
            return mysql.connector.connect(**self.db_config)
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Database connection error: {err}{Style.RESET_ALL}")
            return None
    
    def fetch_crack_results(self):
        conn = self.get_connection()
        if not conn:
            return []
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM crack_results ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            return rows if rows else []
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Error fetching crack results: {err}{Style.RESET_ALL}")
            return []
        finally:
            cursor.close()
            conn.close()

    def fetch_crack_result_by_id(self, result_id):
        conn = self.get_connection()
        if not conn:
            return None
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM crack_results WHERE id=%s", (result_id,))
            return cursor.fetchone()
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Error fetching crack result: {err}{Style.RESET_ALL}")
            return None
        finally:
            cursor.close()
            conn.close()

    def fetch_benchmark_report_by_id(self, bench_id):
        conn = self.get_connection()
        if not conn:
            return None
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT timestamp FROM benchmarks WHERE id=%s", (bench_id,))
            bench = cursor.fetchone()
            if not bench:
                return None
            cursor.execute("SELECT * FROM benchmark_results WHERE benchmark_id=%s", (bench_id,))
            results = cursor.fetchall()
            return {
                'timestamp': bench['timestamp'].timestamp() if hasattr(bench['timestamp'], 'timestamp') else bench['timestamp'],
                'results': results,
            }
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Error fetching benchmark report: {err}{Style.RESET_ALL}")
            return None
        finally:
            cursor.close()
            conn.close()

    def fetch_benchmark_reports(self):
        conn = self.get_connection()
        if not conn:
            return []
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id, timestamp FROM benchmarks ORDER BY timestamp DESC")
            benchmarks = cursor.fetchall()
            reports = []
            for bench in benchmarks:
                bench_id = bench['id']
                cursor.execute("SELECT * FROM benchmark_results WHERE benchmark_id=%s", (bench_id,))
                results = cursor.fetchall()
                report = {
                    'timestamp': bench['timestamp'].timestamp() if hasattr(bench['timestamp'], 'timestamp') else bench['timestamp'],
                    'results': results,
                }
                reports.append({'filename': f'database_benchmark_{bench_id}', 'data': report})
            return reports
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Error fetching benchmark reports: {err}{Style.RESET_ALL}")
            return []
        finally:
            cursor.close()
            conn.close()

    def get_users(self):
        
        conn = self.get_connection()
        if not conn:
            return []

        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users')
        users = [row[0] for row in cursor.fetchall()]
        
        cursor.close()
        conn.close()
        
        return users
    
    def get_user_hash(self, username, use_salt=False):
        
        conn = self.get_connection()
        if not conn:
            return None, None

        cursor = conn.cursor()
        
        if use_salt:
            cursor.execute('SELECT salted_hash, salt FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            hash_value = result[0] if result else None
            salt = result[1] if result else None
        else:
            cursor.execute('SELECT unsalted_hash FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            hash_value = result[0] if result else None
            salt = None
        
        cursor.close()
        conn.close()
        
        return hash_value, salt

    def delete_crack_result(self, result_id):
        conn = self.get_connection()
        if not conn:
            return False
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM crack_results WHERE id = %s", (result_id,))
            conn.commit()
            print(f"{Fore.GREEN}Crack result with ID {result_id} deleted successfully.{Style.RESET_ALL}")
            return True
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Error deleting crack result: {err}{Style.RESET_ALL}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            conn.close()

    def delete_benchmark_report(self, benchmark_id):
        conn = self.get_connection()
        if not conn:
            return False
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM benchmark_results WHERE benchmark_id = %s", (benchmark_id,))
            cursor.execute("DELETE FROM benchmarks WHERE id = %s", (benchmark_id,))
            conn.commit()
            print(f"{Fore.GREEN}Benchmark report with ID {benchmark_id} and its results deleted successfully.{Style.RESET_ALL}")
            return True
        except mysql.connector.Error as err:
            print(f"{Fore.RED}Error deleting benchmark report: {err}{Style.RESET_ALL}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            conn.close()