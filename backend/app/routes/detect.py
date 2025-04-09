from flask import Blueprint, request, jsonify
from app.ml.predict import predict_ddos

detect_bp = Blueprint("detect", __name__)

@detect_bp.route("/detect", methods=["POST"])
def detect():
    data = request.get_json()
    result = predict_ddos(data)
    return jsonify({
        "result": "ddos" if result == 1 else "normal",
        "ip": data.get("Src IP")
    })
