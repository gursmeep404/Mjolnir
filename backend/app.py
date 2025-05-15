from flask import Flask, jsonify, request
from flask_cors import CORS
import sys
import os
import subprocess
import threading
import json
import httpx
from dotenv import load_dotenv

load_dotenv()


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db_handler import get_results, ip_exists 

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}})



# Utility to safely fetch results, with optional IP filter
def safe_get_results(category):
    try:
        ip = request.args.get("ip")  # Optional IP query param
        data = get_results(category, ip)
        if not data:
            return jsonify({"error": f"No data found for {category} with IP {ip}"}), 404
        return jsonify(data)
    except Exception as e:
        print(f"Error fetching {category}: {e}")  
        return jsonify({"error": "Internal Server Error"}), 500


# API endpoints for each result category
@app.route("/api/hosts")
def get_hosts():
    return safe_get_results("hosts")

@app.route("/api/arp_results")
def get_arp_results():
    return safe_get_results("arp_results")

@app.route("/api/tcp_results")
def get_tcp_results():
    return safe_get_results("tcp_results")

@app.route("/api/udp_results")
def get_udp_results():
    return safe_get_results("udp_results")

@app.route("/api/icmp_results")
def get_icmp_results():
    return safe_get_results("icmp_results")

@app.route("/api/os_results")
def get_os_results():
    return safe_get_results("os_results")

@app.route("/api/firewall_results")
def get_firewall_results():
    return safe_get_results("firewall_results")

@app.route("/api/packets")
def get_packets():
    return safe_get_results("packets")

@app.route("/api/service_results")
def get_service_results():
    return safe_get_results("service_results")


def run_scanner(ip):
    try:
        # Full absolute path to Python interpreter (verified from your system)
        python_path = r"C:\Users\HP\AppData\Local\Programs\Python\Python312\python.exe"

        # Absolute path to the scanner script
        script_path = os.path.join(os.path.dirname(__file__), 'scanners', 'network_scanner.py')

        subprocess.run([python_path, script_path, ip], check=True)
        print(f"[+] Scanner completed for {ip}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Scanner failed for {ip}: {e}")



@app.route("/api/scan", methods=["POST"])
def scan_ip():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP address not provided"}), 400

    print(f"[+] Received IP to scan: {ip}")

    ip_check = ip_exists(ip)
    if ip_check["exists"]:
        print(f"[+] IP {ip} already exists in database.")
        return jsonify({"host_id": ip_check["host_id"]})

    # If IP not in database, run scanner in a background thread
    print(f"[~] IP {ip} not found in database. Starting scan.")
    threading.Thread(target=run_scanner, args=(ip,)).start()

    # Return a "scanning" status and no host_id until scan is complete
    return jsonify({"status": "scanning"})

NVD_API_KEY = os.getenv("NVD_API_KEY")

PORT_KEYWORD_MAP = {
    "20": "ftp",               # FTP Data
    "21": "ftp",               # FTP Control
    "22": "ssh",               # Secure Shell
    "23": "telnet",            # Telnet
    "25": "smtp",              # Simple Mail Transfer Protocol
    "53": "dns",               # Domain Name System
    "67": "dhcp",              # DHCP Server
    "68": "dhcp",              # DHCP Client
    "69": "tftp",              # Trivial FTP
    "80": "http",              # HyperText Transfer Protocol
    "110": "pop3",             # Post Office Protocol v3
    "111": "rpcbind",          # RPC Bind
    "123": "ntp",              # Network Time Protocol
    "135": "rpc",              # MS RPC
    "137": "netbios",          # NetBIOS Name Service
    "138": "netbios",          # NetBIOS Datagram
    "139": "netbios",          # NetBIOS Session
    "143": "imap",             # Internet Message Access Protocol
    "161": "snmp",             # SNMP
    "162": "snmptrap",         # SNMP Trap
    "179": "bgp",              # Border Gateway Protocol
    "389": "ldap",             # Lightweight Directory Access Protocol
    "443": "https",            # Secure HTTP
    "445": "smb",              # Server Message Block (Windows)
    "500": "isakmp",           # Internet Security Association and Key Management Protocol (IPsec VPN)
    "512": "exec",             # Remote Process Execution
    "513": "login",            # Remote Login
    "514": "shell",            # Remote Shell
    "515": "printer",          # LPD - Line Printer Daemon
    "520": "rip",              # Routing Information Protocol
    "554": "rtsp",             # Real Time Streaming Protocol
    "587": "smtp",             # SMTP Secure (Submission)
    "631": "ipp",              # Internet Printing Protocol
    "636": "ldaps",            # LDAP over SSL
    "993": "imaps",            # IMAP over SSL
    "995": "pop3s",            # POP3 over SSL
    "1433": "mssql",           # Microsoft SQL Server
    "1521": "oracle",          # Oracle DB
    "1723": "pptp",            # Point-to-Point Tunneling Protocol
    "2049": "nfs",             # Network File System
    "3306": "mysql",           # MySQL
    "3389": "rdp",             # Remote Desktop Protocol
    "5432": "postgresql",      # PostgreSQL
    "5900": "vnc",             # Virtual Network Computing
    "6000": "x11",             # X Window System
    "8080": "http-proxy",      # HTTP Alternate / Proxy
    "8443": "https-alt",       # HTTPS Alternate
}


def get_cve_for_keyword(keyword):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 10,
        "startIndex": 0
    }

    headers = {
        "apiKey": NVD_API_KEY
    }

    try:
        response = httpx.get(base_url, params=params, headers=headers)
        print(f"🔗 NVD URL: {response.url}")
        print("Response status:", response.status_code)
        print("Response headers:", response.headers)
        print("Response content:", response.text)

        response.raise_for_status()

        cves = response.json().get("vulnerabilities", [])
        return [
            {
                "id": cve["cve"]["id"],
                "summary": cve["cve"]["descriptions"][0]["value"]
            }
            for cve in cves
        ]
    except httpx.HTTPStatusError as e:
        print(f"❌ NVD API error {response.status_code} for '{keyword}': {response.text}")
    except Exception as e:
        print(f"❌ NVD API general error for '{keyword}': {e}")

    return []

@app.route('/api/generate_report', methods=['POST'])
def generate_report():
    data = request.get_json()
    keywords = set()

    # Extract ports and map to service names
    for entry in data.get("tcpResults", []):
        for key in ["tcp_open", "tcp_filtered"]:
            raw_ports = entry.get(key, "[]")
            try:
                port_list = json.loads(raw_ports) if isinstance(raw_ports, str) else raw_ports
                for port in port_list:
                    port_str = str(port)
                    mapped_keyword = PORT_KEYWORD_MAP.get(port_str, port_str)
                    keywords.add(mapped_keyword)
            except Exception as e:
                print(f"⚠️ Failed to parse ports from '{key}': {e}")

    # Extract OS guess words
    for entry in data.get("osResults", []):
        guess = entry.get("os_guess", "")
        for word in guess.split():
            if word.isalpha():
                keywords.add(word)

    print("📌 Keywords for CVE search:", keywords)

    # Filter and query CVEs
    all_cves = []
    for keyword in keywords:
        # if keyword.lower() in {"windows", "linux", "os", "unknown"}:
        #     print(f"⚠️ Skipping generic keyword '{keyword}'")
        #     continue

        print(f"🔍 Querying CVEs for keyword: {keyword}")
        cves = get_cve_for_keyword(keyword)
        all_cves.extend(cves)

    return jsonify({"cves": all_cves})
