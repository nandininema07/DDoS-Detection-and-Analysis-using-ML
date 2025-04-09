# app/routes/api.py
from flask import Blueprint, request, jsonify
from datetime import datetime
import joblib
import pandas as pd
import os
import uuid
from app.models import db, User, Log, Setting

api_bp = Blueprint("api", __name__)

# Load model and scaler
model = joblib.load("app/ml/model.pkl")
scaler = joblib.load("app/ml/scaler.pkl")

@api_bp.route("/api/signup", methods=["POST"])
def signup():
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
        df = pd.DataFrame([input_data])
        X = scaler.transform(df)
        pred = model.predict(X)[0]
        confidence = model.predict_proba(X)[0].max()

        status = "DDoS" if pred == 1 else "Safe"
        ip = input_data.get("Src IP", "unknown")

        log = Log(
            ip=ip,
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
            "ip": ip
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
    return jsonify([
        {
            "ip": log.ip,
            "datetime": log.datetime.isoformat(),
            "status": log.status,
            "confidence": log.confidence,
            "details": log.details
        } for log in all_logs
    ])

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
    return jsonify([
        {
            "ip": log.ip,
            "datetime": log.datetime.isoformat(),
            "status": log.status,
            "action": "Blocked" if log.status == "DDoS" else "Flagged"
        } for log in flagged
    ])

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
