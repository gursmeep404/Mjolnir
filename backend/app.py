from flask import Flask, jsonify, request
from flask_cors import CORS
import sys
import os
import subprocess
import threading

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db_handler import get_results, ip_exists 

app = Flask(__name__)
CORS(app) 


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
