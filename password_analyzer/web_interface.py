"""
Web interface for password analyzer using Flask.
Provides a user-friendly web interface for all password analysis features.
"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
import os
import json
from .controller import PasswordCrackingController
from .strength_analyzer import PasswordStrengthAnalyzer
from .reporting import ResultsReporter
from .benchmark import PerformanceBenchmark

app = Flask(__name__, template_folder='templates', static_folder='static')

controller = PasswordCrackingController()
strength_analyzer = PasswordStrengthAnalyzer()
reporter = ResultsReporter()
benchmark = PerformanceBenchmark()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'}), 400
    
    from .login.login_system import LoginSystem
    login_system = LoginSystem()
    
    user_data = login_system.load_credentials(username)
    if not user_data:
        return jsonify({'success': False, 'message': 'Username not found!'}), 404
    
    if user_data['locked']:
        return jsonify({'success': False, 'message': 'Account is locked due to too many failed attempts!'}), 403
    
    salted_hash = login_system.hash_with_salt(password, user_data['salt'])
    if salted_hash == user_data['salted_hash']:
        login_system.update_login_attempt(username, 0, False)
        return jsonify({'success': True, 'message': f'Login successful! Welcome {username}'})
    else:
        failed_attempts = user_data['failed_attempts'] + 1
        locked = failed_attempts >= 3
        login_system.update_login_attempt(username, failed_attempts, locked)
        
        if locked:
            return jsonify({'success': False, 'message': 'Too many failed attempts. Account locked!'}), 403
        else:
            return jsonify({'success': False, 'message': f'Invalid password! Attempts remaining: {3 - failed_attempts}'}), 401

@app.route('/api/register', methods=['POST'])
def api_register():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'}), 400
    
    from .login.login_system import LoginSystem
    login_system = LoginSystem()
    
    if login_system.load_credentials(username):
        return jsonify({'success': False, 'message': 'Username already exists!'}), 409
    
    salt = login_system.generate_salt()
    unsalted_hash = login_system.hash_password(password)
    salted_hash = login_system.hash_with_salt(password, salt)
    
    if login_system.save_credentials(username, unsalted_hash, salted_hash, salt):
        return jsonify({'success': True, 'message': f'Registration successful! User {username} created.'})
    else:
        return jsonify({'success': False, 'message': 'Registration failed. Please try again.'}), 500

@app.route('/api/reset', methods=['POST'])
def api_reset():
    username = request.form.get('username', '').strip()
    
    if not username:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    
    from .login.login_system import LoginSystem
    login_system = LoginSystem()
    
    if login_system.load_credentials(username):
        login_system.update_login_attempt(username, 0, False)
        return jsonify({'success': True, 'message': f'Account {username} has been reset successfully.'})
    else:
        return jsonify({'success': False, 'message': 'Username not found!'}), 404

@app.route('/analyze', methods=['GET', 'POST'])
def analyze_password():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password:
            analysis = strength_analyzer.analyze_password(password)
            return render_template('analysis_result.html', analysis=analysis)
        else:
            return render_template('analyze.html', error="Please enter a password")
    
    return render_template('analyze.html')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    analysis = strength_analyzer.analyze_password(password)
    analysis.pop('color', None)
    
    return jsonify(analysis)

@app.route('/crack')
def crack_password():
    users = controller.db_manager.get_users()
    return render_template('crack.html', users=users)

@app.route('/crack/execute', methods=['POST'])
def execute_crack():
    attack_type = request.form.get('attack_type')
    username = request.form.get('username')
    use_salt = request.form.get('use_salt') == 'on'
    
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    
    hash_value, salt = controller.db_manager.get_user_hash(username, use_salt)
    
    if not hash_value:
        return jsonify({'error': 'User not found or hash not available'}), 404
    
    controller.hash_verifier.using_salt = use_salt
    controller.hash_verifier.current_salt = salt
    
    attack_params = {}
    if attack_type == 'brute_force':
        attack_params['min_length'] = int(request.form.get('min_length', 1))
        attack_params['max_length'] = int(request.form.get('max_length', 4))
        attack_params['use_lowercase'] = request.form.get('use_lowercase') == 'on'
        attack_params['use_uppercase'] = request.form.get('use_uppercase') == 'on'
        attack_params['use_digits'] = request.form.get('use_digits') == 'on'
        attack_params['use_symbols'] = request.form.get('use_symbols') == 'on'
        attack_params['max_time'] = int(request.form.get('max_time', 60))
    elif attack_type == 'mask':
        mask_pattern_choice = request.form.get('mask_pattern')
        attack_params['mask_pattern_choice'] = mask_pattern_choice
        if mask_pattern_choice == 'custom':
            attack_params['custom_mask'] = request.form.get('custom_mask')
    elif attack_type == 'dictionary':
        pass


    try:
        if attack_type == 'dictionary':
            success, password, attempts, elapsed = controller.run_dictionary_attack(hash_value, **attack_params)
        elif attack_type == 'brute_force':
            success, password, attempts, elapsed = controller.run_brute_force_attack(hash_value, **attack_params)
        elif attack_type == 'hybrid':
            success, password, attempts, elapsed = controller.run_hybrid_attack(hash_value, username=username, **attack_params)
        elif attack_type == 'mask':
            success, password, attempts, elapsed = controller.run_mask_attack(hash_value, **attack_params)
        elif attack_type == 'rule_based':
            success, password, attempts, elapsed = controller.run_rule_based_attack(hash_value, **attack_params)
        elif attack_type == 'rainbow_table':
            success, password, attempts, elapsed = controller.run_rainbow_table_attack(hash_value, **attack_params)
        else:
            return jsonify({'error': 'Invalid attack type'}), 400
        
        result = reporter.create_attack_result(
            attack_type, username, hash_value, success, password, 
            attempts, elapsed, attempts/elapsed if elapsed > 0 else 0, use_salt
        )
        
        filename = reporter.save_result(result)
        
        return jsonify({
            'success': success,
            'password': password,
            'attempts': attempts,
            'elapsed': elapsed,
            'rate': attempts/elapsed if elapsed > 0 else 0,
            'saved_to': filename
        })
        
    except Exception as e:
        app.logger.error(f"Crack execution error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/benchmark')
def benchmark_page():
    return render_template('benchmark.html')

@app.route('/benchmark/run', methods=['POST'])
def run_benchmark():
    try:
        test_passwords_text = request.form.get('test_passwords', 'password\\n123456\\nadmin\\ntest')
        test_passwords = [pwd.strip() for pwd in test_passwords_text.split('\\n') if pwd.strip()]
        
        max_time = int(request.form.get('max_time', 30))
        
        benchmark_instance = PerformanceBenchmark()
        benchmark_instance.test_passwords = test_passwords
        
        results = benchmark_instance.run_comprehensive_benchmark()
        if not results:
            return jsonify({'error': 'No benchmark results generated'}), 500
            
        report = benchmark.generate_benchmark_report(results)
        if not report:
            return jsonify({'error': 'Failed to generate benchmark report'}), 500
        
        filename = reporter.save_benchmark_results(report)
        if not filename:
            return jsonify({'error': 'Failed to save benchmark results'}), 500
        
        formatted_results = {}
        for result in results:
            test_type = result.get('test_type', 'unknown')
            if test_type not in formatted_results:
                formatted_results[test_type] = {
                    'tests': [],
                    'success_rate': 0,
                    'avg_time': 0,
                    'avg_attempts': 0
                }
            formatted_results[test_type]['tests'].append(result)
        
        for test_type, data in formatted_results.items():
            tests = data['tests']
            if tests:
                successful = [t for t in tests if t.get('success', False)]
                data['success_rate'] = len(successful) / len(tests) if tests else 0
                data['avg_time'] = sum(t.get('elapsed_time', 0) for t in tests) / len(tests)
                data['avg_attempts'] = sum(t.get('attempts', 0) for t in tests) / len(tests)
        
        return jsonify({
            'success': True,
            'results': formatted_results,
            'raw_results': results,
            'report': report,
            'saved_to': filename
        })
        
    except Exception as e:
        app.logger.error(f"Benchmark error: {str(e)}")
        return jsonify({'error': f'Benchmark failed: {str(e)}'}), 500

@app.route('/results')
def results_page():
    previous_results = reporter.load_previous_results()
    attack_results = []
    benchmark_files = []
    
    for result in previous_results:
        data = result['data']
        filename = result['filename']
        
        if filename.startswith(('benchmark_', 'database_benchmark_')):
            benchmark_files.append({'filename': filename, 'data': data})
        elif isinstance(data, dict) and 'attack_type' in data:
            data['filename'] = filename
            attack_results.append(data)
    
    return render_template('results.html', results=attack_results, benchmarks=benchmark_files)

@app.route('/results/delete/<record_type>/<record_id>', methods=['POST'])
def delete_result(record_type, record_id):
    try:
        if record_type == 'crack_result':
            success = controller.db_manager.delete_crack_result(record_id)
            if success:
                return jsonify({'success': True, 'message': 'Crack result deleted successfully.'})
            else:
                return jsonify({'success': False, 'message': 'Failed to delete crack result.'}), 500
        elif record_type == 'benchmark_report':
            success = controller.db_manager.delete_benchmark_report(record_id)
            if success:
                return jsonify({'success': True, 'message': 'Benchmark report deleted successfully.'})
            else:
                return jsonify({'success': False, 'message': 'Failed to delete benchmark report.'}), 500
        else:
            return jsonify({'success': False, 'message': 'Invalid record type.'}), 400
    except Exception as e:
        app.logger.error(f"Error deleting record: {str(e)}")
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500


@app.route('/download/<filename>')
def download_result(filename):
    if filename.startswith('database_crack_'):
        result_id = filename.split('_')[-1]
        row = controller.db_manager.fetch_crack_result_by_id(result_id)
        if not row:
            return f"Database record not found", 404
        temp_path = f"/tmp/{filename}.json"
        with open(temp_path, 'w') as f:
            json.dump(row, f, indent=2, default=str)
        return send_file(temp_path, as_attachment=True)
    if filename.startswith('database_benchmark_'):
        bench_id = filename.split('_')[-1]
        report = controller.db_manager.fetch_benchmark_report_by_id(bench_id)
        if not report:
            return f"Database record not found", 404
        temp_path = f"/tmp/{filename}.json"
        with open(temp_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        return send_file(temp_path, as_attachment=True)
    filepath = os.path.abspath(os.path.join(reporter.results_dir, filename))
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return f"File not found: {filename}", 404

def run_web_interface():
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == '__main__':
    run_web_interface()