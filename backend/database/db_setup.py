import sqlite3

DB_PATH = "results.db"

def setup_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Table to store unique hosts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            host_id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT UNIQUE,
            last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

     # Table to store ARP scan results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS arp_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            scanned_ip TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
    """)

      # Table for TCP scan results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tcp_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tcp_open TEXT,
            tcp_closed TEXT,
            tcp_filtered TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts (host_id) ON DELETE CASCADE
        )
    """
    )


    # Table for UDP scan results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS udp_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            udp_open TEXT,
            udp_closed TEXT,
            udp_filtered TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts (host_id) ON DELETE CASCADE
        )
    """
    )


    # Table for ICMP scan results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS icmp_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            icmp_responses TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts (host_id) ON DELETE CASCADE
        )
    """
    )

  
    # Table for OS detection results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS os_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ttl INTEGER,
            window_size INTEGER,
            os_guess TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts (host_id) ON DELETE CASCADE
        )
    """
    )


    # Table to store firewall detection results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS firewall_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            tcp_syn_responses TEXT,
            icmp_response TEXT,
            port_443_response TEXT,
            conclusion TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
    """)

    
    # Table to store packet summary
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            packet_summary TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts (host_id) ON DELETE CASCADE
        )
    """)


    # Table to store services
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS service_results (
            host_id INTEGER,
            port INTEGER,
            service TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts (host_id) ON DELETE CASCADE
        )
    """)



    conn.commit()
    conn.close()

if __name__ == "__main__":
    setup_database()
