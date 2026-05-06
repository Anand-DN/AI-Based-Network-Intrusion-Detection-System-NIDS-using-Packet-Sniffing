from datetime import datetime
import csv
import os

LOG_FILE = "data/logs.csv"
os.makedirs("data", exist_ok=True)

def log_alert(alert_type, severity, src_ip, dst_ip, protocol, details, timestamp=None):
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = {
        "timestamp": timestamp,
        "type": alert_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "details": details
    }
    
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=alert.keys())
        if f.tell() == 0:
            writer.writeheader()
        writer.writerow(alert)
    
    return alert