import sqlite3

DB_PATH = "database/results.db"

def setup_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ttl INTEGER,
            window_size INTEGER,
            os_guess TEXT,
            firewall_status TEXT,
            icmp_responses TEXT,
            tcp_open TEXT,
            tcp_closed TEXT,
            tcp_filtered TEXT,
            udp_open TEXT,
            udp_closed TEXT,
            udp_filtered TEXT
        )
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    setup_database()
