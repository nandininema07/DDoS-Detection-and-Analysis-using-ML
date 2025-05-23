import requests

url = "http://localhost:5000/api/detect"

sample_input = {
    "Src IP": "192.168.1.1",
    "Destination Port": 80,
    "Flow Duration": 100000,
    "Total Fwd Packets": 12,
    "Total Backward Packets": 6,
    "Total Length of Fwd Packets": 1400,
    "Total Length of Bwd Packets": 800,
    "Fwd Packet Length Max": 120,
    "Fwd Packet Length Min": 40,
    "Fwd Packet Length Mean": 80,
    "Fwd Packet Length Std": 10,
    "Bwd Packet Length Max": 100,
    "Bwd Packet Length Min": 30,
    "Bwd Packet Length Mean": 65,
    "Bwd Packet Length Std": 8,
    "Flow Bytes/s": 20000,
    "Flow Packets/s": 150,
    "Flow IAT Mean": 100,
    "Flow IAT Std": 25,
    "Flow IAT Max": 500,
    "Flow IAT Min": 5,
    "Fwd IAT Total": 20000,
    "Fwd IAT Mean": 1000,
    "Fwd IAT Std": 50,
    "Fwd IAT Max": 1200,
    "Fwd IAT Min": 10,
    "Bwd IAT Total": 15000,
    "Bwd IAT Mean": 750,
    "Bwd IAT Std": 40,
    "Bwd IAT Max": 1000,
    "Bwd IAT Min": 8,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 80,
    "Bwd Header Length": 60,
    "Fwd Packets/s": 60,
    "Bwd Packets/s": 30,
    "Min Packet Length": 20,
    "Max Packet Length": 150,
    "Packet Length Mean": 85,
    "Packet Length Std": 15,
    "Packet Length Variance": 225,
    "FIN Flag Count": 0,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 8,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 1,
    "Average Packet Size": 80,
    "Avg Fwd Segment Size": 90,
    "Avg Bwd Segment Size": 70,
    "Fwd Header Length.1": 80,
    "Fwd Avg Bytes/Bulk": 0,
    "Fwd Avg Packets/Bulk": 0,
    "Fwd Avg Bulk Rate": 0,
    "Bwd Avg Bytes/Bulk": 0,
    "Bwd Avg Packets/Bulk": 0,
    "Bwd Avg Bulk Rate": 0,
    "Subflow Fwd Packets": 12,
    "Subflow Fwd Bytes": 1400,
    "Subflow Bwd Packets": 6,
    "Subflow Bwd Bytes": 800,
    "Init_Win_bytes_forward": 8192,
    "Init_Win_bytes_backward": 8192,
    "act_data_pkt_fwd": 10,
    "min_seg_size_forward": 20,
    "Active Mean": 100,
    "Active Std": 10,
    "Active Max": 120,
    "Active Min": 80,
    "Idle Mean": 0,
    "Idle Std": 0,
    "Idle Max": 0,
    "Idle Min": 0
}

response = requests.post(url, json=sample_input)
print("Status Code:", response.status_code)
print("Response:", response.text)
