from flask import Flask, jsonify, request
from flask_cors import CORS
import sys
import os

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db_handler import get_scan_results

@app.route('/scan_results', methods=['GET'])
def scan_results():
    host = request.args.get('host')  # Get 'host' from URL query
    if not host:
        return jsonify({"error": "Host parameter is missing"}), 400

    results = get_scan_results(host)  # Call your function
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)  # Make sure it's running on port 5000