import joblib
import pandas as pd

# Load model and scaler
model = joblib.load("app/ml/model.pkl")
scaler = joblib.load("app/ml/scaler.pkl")

def predict_ddos(data: dict):
    # Directly convert to DataFrame with column names
    df = pd.DataFrame([data])

    # Scale and predict
    X = scaler.transform(df)
    prediction = model.predict(X)[0]
    confidence = max(model.predict_proba(X)[0])

    return {
        "label": int(prediction),
        "confidence": round(confidence, 4)
    }
