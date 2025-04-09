from flask import Blueprint, jsonify

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/logs", methods=["GET"])
def logs():
    return jsonify([
        {"timestamp": "2025-04-09 10:00", "ip": "192.168.1.4", "type": "ddos"},
        {"timestamp": "2025-04-09 10:05", "ip": "192.168.1.10", "type": "normal"}
    ])
