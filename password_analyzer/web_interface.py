
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

# Initialize components
controller = PasswordCrackingController()
strength_analyzer = PasswordStrengthAnalyzer()
reporter = ResultsReporter()
benchmark = PerformanceBenchmark()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/analyze', methods=['GET', 'POST'])
def analyze_password():
    """Password strength analysis page"""
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
    """API endpoint for password analysis"""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    
    analysis = strength_analyzer.analyze_password(password)
    # Remove color codes for JSON response
    analysis.pop('color', None)
    
    return jsonify(analysis)

@app.route('/crack')
def crack_password():
    """Password cracking interface"""
    users = controller.db_manager.get_users()
    return render_template('crack.html', users=users)

@app.route('/crack/execute', methods=['POST'])
def execute_crack():
    """Execute password cracking attack"""
    attack_type = request.form.get('attack_type')
    username = request.form.get('username')
    use_salt = request.form.get('use_salt') == 'on'
    
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    
    # Get target hash
    hash_value, salt = controller.db_manager.get_user_hash(username, use_salt)
    
    if not hash_value:
        return jsonify({'error': 'User not found or hash not available'}), 404
    
    # Configure hash verifier
    controller.hash_verifier.using_salt = use_salt
    controller.hash_verifier.current_salt = salt
    
    # Execute attack
    try:
        if attack_type == 'dictionary':
            success, password, attempts, elapsed = controller.run_dictionary_attack(hash_value)
        elif attack_type == 'brute_force':
            success, password, attempts, elapsed = controller.run_brute_force_attack(hash_value)
        elif attack_type == 'hybrid':
            success, password, attempts, elapsed = controller.run_hybrid_attack(hash_value, username)
        elif attack_type == 'mask':
            success, password, attempts, elapsed = controller.run_mask_attack(hash_value)
        elif attack_type == 'rule_based':
            success, password, attempts, elapsed = controller.run_rule_based_attack(hash_value)
        elif attack_type == 'rainbow_table':
            success, password, attempts, elapsed = controller.run_rainbow_table_attack(hash_value)
        else:
            return jsonify({'error': 'Invalid attack type'}), 400
        
        # Create result
        result = reporter.create_attack_result(
            attack_type, username, hash_value, success, password, 
            attempts, elapsed, attempts/elapsed if elapsed > 0 else 0, use_salt
        )
        
        # Save result
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
        return jsonify({'error': str(e)}), 500

@app.route('/benchmark')
def benchmark_page():
    """Benchmark page"""
    return render_template('benchmark.html')

@app.route('/benchmark/run', methods=['POST'])
def run_benchmark():
    """Run performance benchmark"""
    try:
        results = benchmark.run_comprehensive_benchmark()
        report = benchmark.generate_benchmark_report(results)
        
        # Save benchmark results
        filename = reporter.save_benchmark_results(report)
        
        return jsonify({
            'success': True,
            'results': results,
            'report': report,
            'saved_to': filename
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/results')
def results_page():
    """Results and reports page"""
    previous_results = reporter.load_previous_results()
    return render_template('results.html', results=previous_results)

@app.route('/download/<filename>')
def download_result(filename):
    """Download result file"""
    filepath = os.path.join(reporter.results_dir, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return "File not found", 404

def run_web_interface():
    """Run the web interface"""
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == '__main__':
    run_web_interface()
