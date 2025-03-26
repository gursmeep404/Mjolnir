import sqlite3
import json
from datetime import datetime

DB_PATH = "database/results.db"

# Utility function to get or insert host and return host_id
def get_or_create_host(host):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    host = str(host)  
    # print(f"DEBUG: Checking if host '{host}' exists in database.")

    cursor.execute("SELECT host_id FROM hosts WHERE host = ?", (host,))
    row = cursor.fetchone()

    if row:
        host_id = row[0]
        # print(f"DEBUG: Found existing host '{host}' with host_id {host_id}. Updating last_scanned.")
        cursor.execute("UPDATE hosts SET last_scanned = CURRENT_TIMESTAMP WHERE host_id = ?", (host_id,))
    else:
        # print(f"DEBUG: Host '{host}' not found. Inserting new record.")
        cursor.execute("INSERT INTO hosts (host) VALUES (?)", (host,))
        conn.commit() 
        
        cursor.execute("SELECT host_id FROM hosts WHERE host = ?", (host,))
        row = cursor.fetchone()
        host_id = row[0]
        # print(f"DEBUG: Inserted new host '{host}' with host_id {host_id}.")

    conn.commit()
    conn.close()
    return host_id


# Function to store ARP scan results
def store_arp_results(host, scanned_ips):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for ip in scanned_ips:
        cursor.execute("INSERT INTO arp_results (host_id, scanned_ip) VALUES (?, ?)", (host, ip))

    conn.commit()
    conn.close()


# Function to store TCP scan results
def store_tcp_results(host, open_ports, closed_ports, filtered_ports):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO tcp_results (host_id, tcp_open, tcp_closed, tcp_filtered)
        VALUES (?, ?, ?, ?)
    """, (host, json.dumps(open_ports), json.dumps(closed_ports), json.dumps(filtered_ports)))

    conn.commit()
    conn.close()


# Function to store UDP scan results
def store_udp_results(host, open_ports, closed_ports, filtered_ports):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO udp_results (host_id, udp_open, udp_closed, udp_filtered)
        VALUES (?, ?, ?, ?)
    """, (host, json.dumps(open_ports), json.dumps(closed_ports), json.dumps(filtered_ports)))

    conn.commit()
    conn.close()


# Function to store ICMP scan results
def store_icmp_results(host, responses):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO icmp_results (host_id, icmp_responses)
        VALUES (?, ?)
    """, (host, json.dumps(responses)))

    conn.commit()
    conn.close()


# Function to store OS detection results
def store_os_results(host, ttl, window_size, os_guess):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO os_results (host_id, ttl, window_size, os_guess)
        VALUES (?, ?, ?, ?)
    """, (host, ttl, window_size, os_guess))

    conn.commit()
    conn.close()


# Function to store Firewall detection results
def store_firewall_results(host, tcp_syn_responses, icmp_response, port_443_response, conclusion):
    def serialize_response(response):
        """ Convert Scapy response to JSON-safe format """
        return response.summary() if response else None  

    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Convert responses to JSON-safe format
    serialized_tcp_syn = [serialize_response(resp) for resp in tcp_syn_responses]
    serialized_icmp = serialize_response(icmp_response)
    serialized_port_443 = serialize_response(port_443_response)

    cursor.execute("""
        INSERT INTO firewall_results (host_id, tcp_syn_responses, icmp_response, port_443_response, conclusion)
        VALUES (?, ?, ?, ?, ?)
    """, (
        host, 
        json.dumps(serialized_tcp_syn), 
        json.dumps(serialized_icmp), 
        json.dumps(serialized_port_443), 
        conclusion
    ))


# Function to retrieve scan results for a specific host
def get_scan_results(host):
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    results = {"host": host, "scan_results": {}}

    # Fetch ARP results
    cursor.execute("SELECT scanned_ip, scan_time FROM arp_results WHERE host_id = ?", (host,))
    results["scan_results"]["arp"] = cursor.fetchall()

    # Fetch TCP results
    cursor.execute("SELECT tcp_open, tcp_closed, tcp_filtered, scan_time FROM tcp_results WHERE host_id = ?", (host,))
    results["scan_results"]["tcp"] = cursor.fetchall()

    # Fetch UDP results
    cursor.execute("SELECT udp_open, udp_closed, udp_filtered, scan_time FROM udp_results WHERE host_id = ?", (host,))
    results["scan_results"]["udp"] = cursor.fetchall()

    # Fetch ICMP results
    cursor.execute("SELECT icmp_responses, scan_time FROM icmp_results WHERE host_id = ?", (host,))
    results["scan_results"]["icmp"] = cursor.fetchall()

    # Fetch OS results
    cursor.execute("SELECT ttl, window_size, os_guess, scan_time FROM os_results WHERE host_id = ?", (host,))
    results["scan_results"]["os"] = cursor.fetchall()

    # Fetch Firewall results
    cursor.execute("SELECT tcp_syn_responses, icmp_response, port_443_response, conclusion, scan_time FROM firewall_results WHERE host_id = ?", (host,))
    results["scan_results"]["firewall"] = cursor.fetchall()

    conn.close()
    return results

# Store packet summary
def store_packet_summary(host_id, packet_summary):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO packets (host_id, packet_summary) 
        VALUES (?, ?)
    """, (host_id, packet_summary))
    conn.commit()
    conn.close()

# delete old packet summary
def clear_old_packets(host_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='packets';")
    if cursor.fetchone(): 
        cursor.execute("DELETE FROM packets WHERE host_id = ?", (host_id,))
        conn.commit()

    conn.close()

    import sqlite3

def get_results(table_name):
    """Fetch all data from a given table."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # To return dict-like rows
    cursor = conn.cursor()

    query = f"SELECT * FROM {table_name}"
    cursor.execute(query)
    results = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return results

def get_hosts():
    """Fetch all hosts with their last scanned timestamp."""
    return get_results("hosts")

def get_arp_results():
    """Fetch ARP scan results."""
    return get_results("arp_results")

def get_tcp_results():
    """Fetch TCP scan results."""
    return get_results("tcp_results")

def get_udp_results():
    """Fetch UDP scan results."""
    return get_results("udp_results")

def get_icmp_results():
    """Fetch ICMP scan results."""
    return get_results("icmp_results")

def get_os_results():
    """Fetch OS detection results."""
    return get_results("os_results")

def get_firewall_results():
    """Fetch firewall detection results."""
    return get_results("firewall_results")

def get_packets():
    """Fetch network packet summary."""
    return get_results("packets")

