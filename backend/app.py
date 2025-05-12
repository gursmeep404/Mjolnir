from flask import Flask, jsonify, request
from flask_cors import CORS
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db_handler import get_results, get_or_create_host  # Added get_or_create_host import

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


# ✅ New route to receive IP from frontend
@app.route("/api/scan", methods=["POST"])
def scan_ip():
    try:
        data = request.get_json()
        ip = data.get("ip")
        if not ip:
            return jsonify({"error": "IP address not provided"}), 400

        print(f"Received IP to scan: {ip}")

        # Store or retrieve host ID (insert if new)
        host_id = get_or_create_host(ip)

        # You can trigger your scanning logic here (e.g., Nmap, Scapy, etc.)
        # For now, just acknowledging receipt
        return jsonify({"message": f"Scan initiated for {ip}", "host_id": host_id})
    except Exception as e:
        print(f"Scan error: {e}")
        return jsonify({"error": "Internal Server Error"}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
