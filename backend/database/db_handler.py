import sqlite3
import json

DB_PATH = "database/fingerprints.db"

def store_scan_results(host, ttl, window_size, os_guess, firewall_status, icmp_responses, 
                       tcp_open, tcp_closed, tcp_filtered, udp_open, udp_closed, udp_filtered):
    """Stores all scan results in the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_results (host, ttl, window_size, os_guess, firewall_status, icmp_responses, 
                                  tcp_open, tcp_closed, tcp_filtered, udp_open, udp_closed, udp_filtered)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (host, ttl, window_size, os_guess, firewall_status, 
          json.dumps(icmp_responses), json.dumps(tcp_open), json.dumps(tcp_closed), json.dumps(tcp_filtered),
          json.dumps(udp_open), json.dumps(udp_closed), json.dumps(udp_filtered)))

    conn.commit()
    conn.close()

def get_scan_results():
    """Retrieves all stored scan results."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT host, scan_time, ttl, window_size, os_guess, firewall_status, icmp_responses, 
               tcp_open, tcp_closed, tcp_filtered, udp_open, udp_closed, udp_filtered 
        FROM scan_results ORDER BY scan_time DESC
    """)

    records = cursor.fetchall()
    conn.close()

    scan_data = []
    for row in records:
        scan_data.append({
            "host": row[0],
            "scan_time": row[1],
            "ttl": row[2],
            "window_size": row[3],
            "os_guess": row[4],
            "firewall_status": row[5],
            "icmp_responses": json.loads(row[6]) if row[6] else [],
            "tcp_open": json.loads(row[7]) if row[7] else [],
            "tcp_closed": json.loads(row[8]) if row[8] else [],
            "tcp_filtered": json.loads(row[9]) if row[9] else [],
            "udp_open": json.loads(row[10]) if row[10] else [],
            "udp_closed": json.loads(row[11]) if row[11] else [],
            "udp_filtered": json.loads(row[12]) if row[12] else [],
        })

    return scan_data
