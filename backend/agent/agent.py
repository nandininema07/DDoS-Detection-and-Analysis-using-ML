import subprocess
import pandas as pd
import time
import requests
import os

API_ENDPOINT = "http://localhost:5000/api/detect"
API_KEY = "b9f246d7-eb21-4add-8772-6096c3181a88"

CSV_PATH = "../CICFlowMeter/CICFlowMeter-master/output.csv"

def run_cicflowmeter():
    print("[*] Starting CICFlowMeter...")
    subprocess.run(["cmd", "/c", "agent\\run_cicflowmeter.bat"], shell=True)

def send_flows_to_api():
    if not os.path.exists(CSV_PATH):
        print("[!] Flow file not found.")
        return

    df = pd.read_csv(CSV_PATH)
    print(f"[*] Read {len(df)} flows.")

    for _, row in df.iterrows():
        flow = row.to_dict()
        headers = {"Authorization": f"Bearer {API_KEY}"}
        try:
            response = requests.post(API_ENDPOINT, json=flow, headers=headers)
            print("[+] Response:", response.status_code, response.text)
        except Exception as e:
            print("[!] Failed to send:", str(e))

if __name__ == "__main__":
    run_cicflowmeter()
    print("[*] Waiting 10 seconds for flows to finish...")
    time.sleep(10)
    send_flows_to_api()
