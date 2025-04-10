import time
from collections import defaultdict

class DDoSDetector:
    def __init__(self, threshold=100, time_window=60):
        self.threshold = threshold  # Max requests allowed per time_window
        self.time_window = time_window  # Time window in seconds
        self.request_counts = defaultdict(int)  # To count requests per IP
        self.time_stamps = defaultdict(list)  # To track time of requests per IP

    def detect(self, ip_address):
        current_time = time.time()

        # Remove timestamps older than time_window
        self.time_stamps[ip_address] = [
            ts for ts in self.time_stamps[ip_address] if current_time - ts < self.time_window
        ]
        
        # Add the current timestamp
        self.time_stamps[ip_address].append(current_time)
        
        # Count the number of requests in the time window
        request_count = len(self.time_stamps[ip_address])
        
        if request_count > self.threshold:
            return True  # DDoS detected (too many requests from the same IP)
        
        return False  # No DDoS detected
