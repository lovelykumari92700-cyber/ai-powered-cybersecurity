import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            input_content TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            threat_level TEXT NOT NULL,
            category TEXT NOT NULL,
            flags TEXT, -- JSON string representing identified flags
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Check if there is any data. If not, add some seed data for standard SaaS dashboard feel
    cursor.execute("SELECT COUNT(*) FROM scans")
    if cursor.fetchone()[0] == 0:
        seed_data = [
            # type, content, score, level, category, flags
            ('text', 'Urgent Alert: Your bank account has been locked. Verify immediately at http://fake-alert-bank.com', 95, 'Critical Risk', 'Banking Scam', json.dumps(['Urgent language', 'Suspicious links', 'Bank detail requests'])),
            ('text', 'Congratulations! You have won a free iPhone 15. Claim here http://win-now.net', 85, 'High Risk', 'Prize Scam', json.dumps(['Prize-winning claims', 'Suspicious links', 'Limited-time pressure tactics'])),
            ('url', 'http://netflix-billing-update.com/login', 98, 'Critical Risk', 'Phishing Scam', json.dumps(['URL shorteners', 'Special characters', 'Obfuscation patterns'])),
            ('text', 'Hey are we still meeting today at 5 PM for coffee?', 0, 'Safe', 'Safe', json.dumps([])),
            ('text', 'Make $5000 a day working from home! No experience required. Apply now at http://easy-job-scam.org', 90, 'High Risk', 'Job Scam', json.dumps(['Unrealistic salary offers', 'Investment promises', 'Suspicious links'])),
            ('url', 'https://www.google.com', 0, 'Safe', 'Safe', json.dumps([])),
            ('text', 'OTP request: Use 882912 to authorize transfer of $450. If you did not make this request, call support.', 80, 'High Risk', 'OTP Scam', json.dumps(['OTP requests', 'Urgent language'])),
            ('text', 'Invest $100 and get $10,000 back in 24 hours guaranteed! High yields guaranteed. DM us.', 92, 'Critical Risk', 'Investment Scam', json.dumps(['Investment promises', 'Prize-winning claims', 'Limited-time pressure tactics'])),
        ]
        cursor.executemany('''
            INSERT INTO scans (scan_type, input_content, risk_score, threat_level, category, flags)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', seed_data)
        
    conn.commit()
    conn.close()

def add_scan(scan_type, input_content, risk_score, threat_level, category, flags):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (scan_type, input_content, risk_score, threat_level, category, flags)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (scan_type, input_content, risk_score, threat_level, category, json.dumps(flags)))
    conn.commit()
    conn.close()

def get_scans(query=None, category=None, risk_level=None, limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    sql = "SELECT * FROM scans WHERE 1=1"
    params = []
    
    if query:
        sql += " AND input_content LIKE ?"
        params.append(f'%{query}%')
    
    if category:
        sql += " AND category = ?"
        params.append(category)
        
    if risk_level:
        sql += " AND threat_level = ?"
        params.append(risk_level)
        
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    
    result = []
    for r in rows:
        result.append({
            'id': r['id'],
            'scan_type': r['scan_type'],
            'input_content': r['input_content'],
            'risk_score': r['risk_score'],
            'threat_level': r['threat_level'],
            'category': r['category'],
            'flags': json.loads(r['flags']) if r['flags'] else [],
            'timestamp': r['timestamp']
        })
    conn.close()
    return result

def get_dashboard_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    stats = {}
    
    # Total Scans
    cursor.execute("SELECT COUNT(*) FROM scans")
    stats['total_scans'] = cursor.fetchone()[0]
    
    # Scans by Type
    cursor.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type")
    stats['scans_by_type'] = dict(cursor.fetchall())
    
    # Scans by Threat Level
    cursor.execute("SELECT threat_level, COUNT(*) FROM scans GROUP BY threat_level")
    stats['scans_by_threat'] = dict(cursor.fetchall())
    
    # Scans by Category (Distribution)
    cursor.execute("SELECT category, COUNT(*) FROM scans GROUP BY category")
    stats['scans_by_category'] = dict(cursor.fetchall())
    
    # Average Risk Score
    cursor.execute("SELECT AVG(risk_score) FROM scans")
    avg_score = cursor.fetchone()[0]
    stats['avg_risk_score'] = round(avg_score, 1) if avg_score else 0.0
    
    # High/Critical threat count
    cursor.execute("SELECT COUNT(*) FROM scans WHERE threat_level IN ('High Risk', 'Critical Risk')")
    stats['high_threats_count'] = cursor.fetchone()[0]
    
    # Safe count
    cursor.execute("SELECT COUNT(*) FROM scans WHERE threat_level = 'Safe'")
    stats['safe_count'] = cursor.fetchone()[0]
    
    conn.close()
    return stats
