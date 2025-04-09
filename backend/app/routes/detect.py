from flask import Blueprint, request, jsonify
from app.ml.predict import predict_ddos

# ✅ Define the blueprint BEFORE using it
detect_bp = Blueprint("detect", __name__)

@detect_bp.route("/detect", methods=["POST"])
def detect():
    try:
        data = request.get_json()
        result = predict_ddos(data)
        return jsonify({
            "result": "ddos" if result["label"] == 1 else "normal",
            "confidence": result["confidence"],
            "ip": data.get("Src IP", "unknown")
        })
    except Exception as e:
        print("❌ Prediction Error:", e)
        return jsonify({"error": str(e)}), 500
