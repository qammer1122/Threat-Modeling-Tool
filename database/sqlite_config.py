import sqlite3

def connect_to_sqlite(db_path='threat_modeling.db'):
    conn = sqlite3.connect(db_path)
    return conn
