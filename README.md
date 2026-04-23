# AI Based Network Intrusion Detection System (NIDS)

A real-time network intrusion detection system with live dashboard and ML-based anomaly detection.

## Features

- **Real-time Packet Capture** - Monitors network traffic using Scapy
- **Attack Detection**:
  - SYN Flood Detection
  - Port Scan Detection  
  - Blocked IP Detection
  - ML Anomaly Detection with confidence scores
- **Live Dashboard** - Traffic graphs, alerts, and statistics
- **Theme Toggle** - Dark/Light mode
- **Export** - Export alerts to CSV

## Tech Stack

- **Backend**: Python, Flask, Scapy
- **Frontend**: HTML, CSS, JavaScript, Chart.js

## Installation

```bash
git clone <your-repo-url>
cd NIDS
pip install -r requirements.txt
```

## Usage

Run as Administrator:

```bash
python app.py
```

Open http://localhost:5000

## Requirements

- Python 3.8+
- Npcap (Windows) - Download from https://nmap.org/npcap/

## Deployment

Deploy to Render:
1. Push to GitHub
2. Create Web Service on render.com
3. Connect GitHub repo
4. Build Command: `pip install -r requirements.txt`
5. Start Command: `python app.py`

## License

MIT
