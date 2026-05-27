import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'threat_model.db')

def get_db():
    """Get SQLite database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()

    # DFD Components table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dfd_components (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            component_type TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Threats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component_id INTEGER,
            category TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            dread_score REAL,
            mitigation TEXT,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (component_id) REFERENCES dfd_components(id)
        )
    ''')

    # CVE Data table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id INTEGER,
            cve_id TEXT,
            description TEXT,
            cvss_score REAL,
            severity TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (threat_id) REFERENCES threats(id)
        )
    ''')

    # Reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            summary TEXT,
            threats_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
    print("[✓] Database initialized successfully.")

def save_threat(component_id, category, name, description, severity, dread_score, mitigation):
    """Save a threat to the database."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO threats (component_id, category, name, description, severity, dread_score, mitigation)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (component_id, category, name, description, severity, dread_score, mitigation))
    threat_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return threat_id

def get_all_threats():
    """Retrieve all threats from the database."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM threats ORDER BY dread_score DESC')
    threats = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return threats

def save_component(name, component_type, description=''):
    """Save a DFD component to the database."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO dfd_components (name, component_type, description)
        VALUES (?, ?, ?)
    ''', (name, component_type, description))
    component_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return component_id

def get_all_components():
    """Retrieve all DFD components."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM dfd_components')
    components = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return components

def save_report(title, summary, threats):
    """Save a threat modeling report."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO reports (title, summary, threats_json)
        VALUES (?, ?, ?)
    ''', (title, summary, json.dumps(threats)))
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id

def get_all_reports():
    """Retrieve all reports."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reports ORDER BY created_at DESC')
    reports = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return reports
