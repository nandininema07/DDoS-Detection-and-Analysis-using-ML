from flask import Blueprint, request, jsonify
from app.ml.predict import predict_ddos
from twilio.rest import Client

detect_bp = Blueprint("detect", __name__)

# Optional: Replace with environment variables or config
TWILIO_ACCOUNT_SID = "your_account_sid"
TWILIO_AUTH_TOKEN = "your_auth_token"
TWILIO_PHONE = "+15184131143"  # your Twilio number
ADMIN_PHONE = "+919372523295"  # destination for calls
ADMIN_EMAIL = "nandini.semstack2327@gmail.com"  # destination for emails (currently printed)

def send_alerts(ip, confidence):
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

    # Call alert
    call = client.calls.create(
        twiml=f'<Response><Say>Alert. DDoS attack detected from IP {ip} with {int(confidence * 100)} percent confidence.</Say></Response>',
        to=ADMIN_PHONE,
        from_=TWILIO_PHONE
    )

    # Print email placeholder
    print(f"[EMAIL ALERT] DDoS detected from {ip} with confidence {confidence:.2f}. Email sent to {ADMIN_EMAIL}.")

@detect_bp.route("/api/detect", methods=["POST"])
def detect():
    try:
        data = request.get_json()
        result = predict_ddos(data)
        label = result["label"]
        confidence = result["confidence"]
        ip = data.get("Src IP", "unknown")

        if label == 1:  # If DDoS
            send_alerts(ip, confidence)

        return jsonify({
            "result": "ddos" if label == 1 else "normal",
            "confidence": confidence,
            "ip": ip
        })

    except Exception as e:
        print("❌ Prediction Error:", e)
        return jsonify({"error": str(e)}), 500
