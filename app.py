import os
import json
from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for, flash
from functools import wraps
import database
import ml_engine

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Initialize SQLite tables and populate mock seed records on boot
database.init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            # If it's an API request, return 401
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized', 'redirect': '/login'}), 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('home'))
        
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if database.verify_user(username, password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('home'))
        else:
            error = "Invalid username or password"
            
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/api/analyze/text', methods=['POST'])
@login_required
def api_analyze_text():
    data = request.get_json() or {}
    text = data.get('text', '').strip()
    model_name = data.get('model', 'Logistic Regression')
    
    if not text:
        return jsonify({'error': 'Empty input text'}), 400
        
    # Process text input
    result = ml_engine.analyze_text(text, model_name)
    
    # Log details to SQLite database
    # Red flags are list of dicts, convert to list of names for database storage
    flag_names = [f['name'] for f in result['red_flags']]
    database.add_scan(
        scan_type='text',
        input_content=text,
        risk_score=result['risk_score'],
        threat_level=result['threat_level'],
        category=result['category'],
        flags=flag_names
    )
    
    return jsonify(result)

@app.route('/api/analyze/url', methods=['POST'])
@login_required
def api_analyze_url():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'Empty URL input'}), 400
        
    # Process URL input
    result = ml_engine.analyze_url(url)
    
    # Log details to SQLite database
    # Indicators are list of dicts, convert to list of names for DB
    indicator_names = [ind['name'] for ind in result['indicators']]
    database.add_scan(
        scan_type='url',
        input_content=url,
        risk_score=result['risk_score'],
        threat_level=result['threat_level'],
        category=result['verdict'] + ' URL',
        flags=indicator_names
    )
    
    return jsonify(result)

@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def api_dashboard_stats():
    try:
        stats = database.get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
@login_required
def api_history():
    query = request.args.get('query', '')
    category = request.args.get('category', '')
    risk_level = request.args.get('risk_level', '')
    limit = request.args.get('limit', 50, type=int)
    
    try:
        scans = database.get_scans(query, category, risk_level, limit)
        return jsonify(scans)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ml/metrics', methods=['GET'])
@login_required
def api_ml_metrics():
    metrics_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model_metrics.json')
    
    # Ensure models have been trained and metrics exist
    if not os.path.exists(metrics_path):
        ml_engine.ensure_models_trained()
        
    try:
        with open(metrics_path, 'r') as f:
            metrics = json.load(f)
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Determine port
    port = int(os.environ.get('PORT', 5000))
    print(f"AEGIS Digital Threat System starting on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=True)
