from flask import Flask, render_template, jsonify, request, Response
from sniffer.packet_sniffer import start_sniffing, get_alerts, get_stats, reset_alerts, stop_sniffing
import threading
import base64
import time

app = Flask(__name__)
sniffing_thread = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/favicon.ico")
def favicon():
    return Response(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🛡️</text></svg>',
        mimetype="image/svg+xml"
    )

@app.route("/api/status")
def status():
    from sniffer.packet_sniffer import _sniffer
    is_active = sniffing_thread is not None and sniffing_thread.is_alive()
    return jsonify({"active": is_active, "stats": get_stats()})

@app.route("/api/alerts")
def alerts():
    return jsonify(get_alerts())

@app.route("/api/start", methods=["POST"])
def start():
    global sniffing_thread
    if sniffing_thread is None or not sniffing_thread.is_alive():
        stop_sniffing()
        sniffing_thread = threading.Thread(target=run_sniffer)
        sniffing_thread.daemon = True
        sniffing_thread.start()
        time.sleep(0.5)
    return jsonify({"status": "started"})

@app.route("/api/stop", methods=["POST"])
def stop():
    stop_sniffing()
    global sniffing_thread
    sniffing_thread = None
    return jsonify({"status": "stopped"})

@app.route("/api/reset", methods=["POST"])
def reset():
    reset_alerts()
    return jsonify({"status": "reset"})

@app.route("/api/test", methods=["POST"])
def test():
    import config
    from sniffer.packet_sniffer import _sniffer
    if _sniffer:
        alert1 = _sniffer._create_alert("ML Anomaly", "MEDIUM", "Traffic Pattern", "Network", "IP", "Anomalous packet rate deviating from normal baseline", 0.87)
        alert2 = _sniffer._create_alert("Blocked IP", "CRITICAL", config.BLOCKED_IPS[0] if config.BLOCKED_IPS else "1.2.3.4", "192.168.1.1", "TCP", "IP in blocklist", 1.0)
        _sniffer.alerts.append(alert1)
        _sniffer.alerts.append(alert2)
    return jsonify({"status": "tested"})

@app.route("/api/export", methods=["GET"])
def export():
    from sniffer.packet_sniffer import get_alerts
    alerts = get_alerts()
    import csv
    import io
    output = io.StringIO()
    if alerts:
        writer = csv.DictWriter(output, fieldnames=alerts[0].keys())
        writer.writeheader()
        writer.writerows(alerts)
    output.seek(0)
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=alerts.csv"})

def run_sniffer():
    try:
        start_sniffing(count=0)
    except Exception as e:
        print(f"Sniffer error: {e}")

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("="*50)
    print("NIDS Dashboard: http://localhost:5000")
    print("NOTE: Run as Administrator for packet capture!")
    print("="*50)
    app.run(debug=False, host="0.0.0.0", port=port, threaded=True)