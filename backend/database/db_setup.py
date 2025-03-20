import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "fingerprints.db")

def setup_database():
    """Creates the OS fingerprint database if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS os_fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT,
            ttl INT,
            window_size INT,
            os_guess TEXT
        )
    ''')
    conn.commit()
    conn.close()

if __name__ == "__main__":
    setup_database()
    print("[+] Database setup complete.")
