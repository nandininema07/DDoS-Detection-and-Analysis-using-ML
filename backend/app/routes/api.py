from flask import Blueprint, request, jsonify
from datetime import datetime
import joblib
import pandas as pd
import os

api_bp = Blueprint("api", __name__)

# Load model and scaler
model = joblib.load("app/ml/model.pkl")
scaler = joblib.load("app/ml/scaler.pkl")

# In-memory logs and user info (mock database)
logs = []
blacklist = set()

@api_bp.route("/api/signup", methods=["POST"])
def signup():
    data = request.json
    # Store user in DB (mock response)
    return jsonify({"message": "User signed up successfully"}), 201

@api_bp.route("/api/login", methods=["POST"])
def login():
    data = request.json
    return jsonify({"token": "mock-jwt-token"})

@api_bp.route("/api/detect", methods=["POST"])
def detect():
    try:
        input_data = request.json
        df = pd.DataFrame([input_data])
        X = scaler.transform(df)
        pred = model.predict(X)[0]
        confidence = model.predict_proba(X)[0].max()

        log = {
            "ip": input_data.get("Src IP", "unknown"),
            "datetime": datetime.now().isoformat(),
            "status": "DDoS" if pred == 1 else "Safe",
            "confidence": float(confidence),
            "details": input_data
        }

        logs.append(log)
        if pred == 1:
            blacklist.add(log["ip"])

        return jsonify({
            "result": log["status"].lower(),
            "confidence": round(confidence, 4),
            "ip": log["ip"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route("/api/logs", methods=["GET"])
def get_logs():
    return jsonify(logs[::-1])  # latest first

@api_bp.route("/api/blacklist", methods=["GET"])
def get_blacklist():
    flagged = [log for log in logs if log["ip"] in blacklist]
    return jsonify(flagged[::-1])

@api_bp.route("/api/logs/<ip>", methods=["GET"])
def log_details(ip):
    details = [log for log in logs if log["ip"] == ip]
    return jsonify(details)

@api_bp.route("/api/notifications", methods=["GET"])
def get_notifications():
    notif = [
        {
            "action": log["status"],
            "ip": log["ip"],
            "datetime": log["datetime"],
            "reason": f"Detected with {round(log['confidence']*100, 2)}% confidence",
            "mail_sent": True,
            "call_status": "Success"
        } for log in logs if log["status"] != "Safe"
    ]
    return jsonify(notif[::-1])

@api_bp.route("/api/profile", methods=["GET"])
def get_profile():
    return jsonify({
        "username": "Nandini",
        "email": "nandini@example.com",
        "phone": "9876543210"
    })

@api_bp.route("/api/settings", methods=["POST"])
def update_settings():
    data = request.json
    return jsonify({"message": "Settings updated successfully"})