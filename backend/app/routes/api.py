# app/routes/api.py
from flask import Blueprint, request, jsonify
from datetime import datetime
import joblib
import pandas as pd
import os
import uuid
from app.models import db, User, Log, Setting
from app.services.ddos_detection import DDoSDetector  # Import DDoSDetector

api_bp = Blueprint("api", __name__)

# Load model and scaler
model = joblib.load("app/ml/model.pkl")
scaler = joblib.load("app/ml/scaler.pkl")

# Initialize DDoSDetector
ddos_detector = DDoSDetector(threshold=100, time_window=60)  # Example threshold and time window

@api_bp.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.json
        if User.query.filter_by(email=data["email"]).first():
            return jsonify({"error": "Email already exists"}), 409

        api_key = str(uuid.uuid4())
        new_user = User(
            username=data["username"],
            email=data["email"],
            phone=data.get("phone"),
            password=data["password"],  # In production, hash passwords!
            api_key=api_key
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User signed up successfully", "api_key": api_key}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data["email"]).first()
    if user and user.password == data["password"]:
        return jsonify({"token": user.api_key, "user": user.username})
    return jsonify({"error": "Invalid credentials"}), 401

@api_bp.route("/api/detect", methods=["POST"])
def detect():
    api_key = request.headers.get("Authorization")
    if not api_key or not api_key.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid API key"}), 401

    api_key = api_key.split("Bearer ")[-1].strip()
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        input_data = request.json
        print(f"Received input data: {input_data}")  # Debug: print the incoming data

        # Ensure 'Src IP' exists in the input and capture the IP address
        ip_address = input_data.get("Src IP", "unknown")

        # Remove 'Src IP' from input data since the model doesn't need it
        input_data.pop("Src IP", None)

        # Prepare the data as per the model's needs
        df = pd.DataFrame([input_data])

        # Check for any missing features that the model expects
        feature_columns = [
            "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
            "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
            "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
            "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
            "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
            "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
            "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s",
            "Bwd Packets/s", "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
            "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
            "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
            "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
            "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
            "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
            "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
            "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max",
            "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
        ]
        
        missing_features = [col for col in feature_columns if col not in input_data]
        if missing_features:
            return jsonify({"error": f"Missing features: {', '.join(missing_features)}"}), 400

        # Ensure that all columns are present
        df = df[feature_columns]  # Ensure the dataframe contains only the necessary columns

        # Perform scaling (if needed)
        X = scaler.transform(df)

        # Predict using the model
        pred = model.predict(X)[0]
        confidence = model.predict_proba(X)[0].max()

        # DDoS detection logic
        status = "DDoS" if pred == 1 else "Safe"

        # Log the result
        log = Log(
            ip=ip_address,  # Ensure that the IP address is correctly captured
            status=status,
            confidence=float(confidence),
            details=str(input_data),
            user_id=user.id
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({
            "result": status.lower(),
            "confidence": round(confidence, 4),
            "ip": ip_address  # Ensure the IP is included in the response
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/logs", methods=["GET"])
def get_logs():
    api_key = request.headers.get("Authorization")
    if not api_key or not api_key.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid API key"}), 401

    api_key = api_key.split("Bearer ")[-1].strip()
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    all_logs = Log.query.filter_by(user_id=user.id).order_by(Log.datetime.desc()).all()
    return jsonify([{
        "ip": log.ip,
        "datetime": log.datetime.isoformat(),
        "status": log.status,
        "confidence": log.confidence,
        "details": log.details
    } for log in all_logs])

@api_bp.route("/api/blacklist", methods=["GET"])
def get_blacklist():
    api_key = request.headers.get("Authorization")
    if not api_key or not api_key.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid API key"}), 401

    api_key = api_key.split("Bearer ")[-1].strip()
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    flagged = Log.query.filter(Log.user_id == user.id, Log.status != "Safe").order_by(Log.datetime.desc()).all()
    return jsonify([{
        "ip": log.ip,
        "datetime": log.datetime.isoformat(),
        "status": log.status,
        "action": "Blocked" if log.status == "DDoS" else "Flagged"
    } for log in flagged])

# Other routes remain the same


@api_bp.route("/api/logs/<ip>", methods=["GET"])
def log_details(ip):
    api_key = request.headers.get("Authorization")
    if not api_key or not api_key.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid API key"}), 401

    api_key = api_key.split("Bearer ")[-1].strip()
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    details = Log.query.filter_by(user_id=user.id, ip=ip).order_by(Log.datetime.desc()).all()
    return jsonify([
        {
            "ip": log.ip,
            "datetime": log.datetime.isoformat(),
            "status": log.status,
            "confidence": log.confidence,
            "details": log.details
        } for log in details
    ])

@api_bp.route("/api/notifications", methods=["GET"])
def get_notifications():
    api_key = request.headers.get("Authorization")
    if not api_key or not api_key.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid API key"}), 401

    api_key = api_key.split("Bearer ")[-1].strip()
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    notif_logs = Log.query.filter(Log.user_id == user.id, Log.status != "Safe").order_by(Log.datetime.desc()).all()
    return jsonify([
        {
            "action": log.status,
            "ip": log.ip,
            "datetime": log.datetime.isoformat(),
            "reason": f"Detected with {round(log.confidence * 100, 2)}% confidence",
            "mail_sent": True,
            "call_status": "Success"
        } for log in notif_logs
    ])

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
    setting = Setting.query.filter_by(user_id=data["user_id"]).first()
    if not setting:
        setting = Setting(user_id=data["user_id"])
        db.session.add(setting)

    setting.website_url = data.get("website_url")
    setting.alert_email = data.get("alert_email")
    setting.alert_phone = data.get("alert_phone")
    setting.email_alerts = data.get("email_alerts", True)
    setting.call_alerts = data.get("call_alerts", False)

    db.session.commit()
    return jsonify({"message": "Settings updated successfully"})

@api_bp.route("/api/sample_logs", methods=["GET"])
def sample_logs():
    return jsonify([
        {
            "ip": "192.168.0.101",
            "datetime": "2025-04-10T14:30:00",
            "status": "DDoS",
            "confidence": 0.96,
            "details": "Simulated TCP SYN flood from IP"
        },
        {
            "ip": "10.0.0.45",
            "datetime": "2025-04-10T14:45:00",
            "status": "Safe",
            "confidence": 0.85,
            "details": "Normal user activity"
        },
        {
            "ip": "192.168.0.202",
            "datetime": "2025-04-10T15:00:00",
            "status": "DDoS",
            "confidence": 0.91,
            "details": "UDP amplification attempt"
        }
    ])

import json

@api_bp.route("/api/chatbot", methods=["POST"])
def chatbot():
    user_input = request.json.get("message", "").lower()

    with open("chatbot_responses.json") as f:
        responses = json.load(f)

    for key, value in responses["faq"].items():
        if key in user_input:
            return jsonify({"response": value})

    return jsonify({"response": responses.get("fallback")})

