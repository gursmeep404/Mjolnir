from flask import Flask, jsonify
from flask_cors import CORS
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db_handler import get_results

app = Flask(__name__)
CORS(app) 

def safe_get_results(category):
    try:
        data = get_results(category)
        if data is None:
            return jsonify({"error": f"No data found for {category}"}), 404
        return jsonify(data)
    except Exception as e:
        print(f"Error fetching {category}: {e}")  
        return jsonify({"error": "Internal Server Error"}), 500

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

if __name__ == "__main__":
    app.run(debug=True, port=5000)
