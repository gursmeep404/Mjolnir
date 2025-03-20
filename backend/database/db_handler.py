import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "fingerprints.db")

def store_fingerprint(host, ttl, window_size, os_guess):
    """Stores OS fingerprint details in the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO os_fingerprints (host, ttl, window_size, os_guess) VALUES (?, ?, ?, ?)",
        (host, ttl, window_size, os_guess)
    )
    conn.commit()
    conn.close()

def get_fingerprints():
    """Retrieves all stored OS fingerprints."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM os_fingerprints")
    records = cursor.fetchall()
    conn.close()
    return records
