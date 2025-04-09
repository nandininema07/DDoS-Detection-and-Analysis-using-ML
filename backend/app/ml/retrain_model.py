import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import os

# Load and clean the dataset
df = pd.read_csv("data/DDos.csv")
df.columns = df.columns.str.strip()
df.dropna(inplace=True)
df["Label"] = df["Label"].map({"BENIGN": 0, "DDoS": 1})

# Use all columns except 'Label' for training
X = df.drop(columns=["Label"])
y = df["Label"]

# Train scaler
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train model
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X_scaled, y)

# Ensure output directory exists
os.makedirs("app/ml", exist_ok=True)

# Save scaler and model
joblib.dump(scaler, os.path.join("app", "ml", "scaler.pkl"))
joblib.dump(model, os.path.join("app", "ml", "model.pkl"))

print("✅ Model and scaler saved with the SAME 78 feature set.")
