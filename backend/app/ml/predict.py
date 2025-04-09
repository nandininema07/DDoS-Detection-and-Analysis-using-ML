import joblib
import pandas as pd

model = joblib.load("app/ml/model.pkl")
scaler = joblib.load("app/ml/scaler.pkl")

def predict_ddos(features: dict):
    df = pd.DataFrame([features])
    X = scaler.transform(df)
    prediction = model.predict(X)
    return int(prediction[0])
