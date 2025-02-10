import sqlite3
import os

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'system_metrics.db')

def create_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics (
            timestamp TEXT,
            cpu REAL,
            memory REAL,
            disk REAL,
            network REAL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            log TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print(f"Database and tables were created successfully '{DATABASE_PATH}'")

if __name__ == '__main__':
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    create_database()
