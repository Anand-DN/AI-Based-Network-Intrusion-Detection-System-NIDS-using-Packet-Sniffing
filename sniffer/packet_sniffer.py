from datetime import datetime
from collections import defaultdict
from utils.parser import parse_packet, get_protocol_name
from detector.rules import log_alert
import config
import time
import random

class PacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.ip_tracker = defaultdict(int)
        self.syn_tracker = defaultdict(int)
        self.port_tracker = defaultdict(set)
        self.alerts = []
        self.alerts_sent = {}
        self.size_tracker = 0
        self.start_time = datetime.now()
        self.traffic_history = []
        self.baseline_rate = 5
    
    def process_packet(self, packet):
        self.packet_count += 1
        info = parse_packet(packet)
        if not info:
            return None
        
        src_ip = info["src_ip"]
        self.ip_tracker[src_ip] += 1
        self.size_tracker += info.get("size", 64)
        
        self.traffic_history.append((time.time(), self.packet_count))
        self.traffic_history = [(t, c) for t, c in self.traffic_history if time.time() - t < 60]
        
        alerts = []
        
        if info.get("type") == "TCP" and info.get("flags") == "S":
            self.syn_tracker[src_ip] += 1
            if self.syn_tracker[src_ip] > 20:
                key = f"SYN-{src_ip}"
                if self._should_alert(key):
                    alerts.append(self._create_alert(
                        "SYN Flood", "HIGH", src_ip, info["dst_ip"],
                        info["type"], f"High SYN rate: {self.syn_tracker[src_ip]}"
                    ))
                    self.syn_tracker[src_ip] = 0
        
        current_rate = len(self.traffic_history) / 60 if self.traffic_history else 0
        self.baseline_rate = (self.baseline_rate * 0.9) + (current_rate * 0.1)
        
        if current_rate > self.baseline_rate * 3 and self.packet_count > 100:
            key = "ML-ANOMALY"
            if self._should_alert(key):
                confidence = min(0.98, round(0.5 + (current_rate / (self.baseline_rate * 5)) * 0.4, 2))
                alerts.append(self._create_alert(
                    "ML Anomaly", "MEDIUM", "Traffic Pattern", "Network",
                    "IP", f"Anomalous packet rate {current_rate:.1f}/sec deviating from normal baseline ({self.baseline_rate:.1f}/sec)",
                    confidence
                ))
        
        if src_ip in config.BLOCKED_IPS:
            key = f"BLOCK-{src_ip}"
            if self._should_alert(key):
                alerts.append(self._create_alert(
                    "Blocked IP", "CRITICAL", src_ip, info["dst_ip"],
                    info["type"], "IP in blocklist"
                ))
        
        dst_port = info.get("dst_port")
        if dst_port:
            self.port_tracker[src_ip].add(dst_port)
            if len(self.port_tracker[src_ip]) > 10:
                key = f"SCAN-{src_ip}"
                if self._should_alert(key):
                    ports = list(self.port_tracker[src_ip])[:5]
                    alerts.append(self._create_alert(
                        "Port Scan", "HIGH", src_ip, info["dst_ip"],
                        info["type"], f"{len(self.port_tracker[src_ip])} unique ports"
                    ))
                    self.port_tracker[src_ip].clear()
        
        for alert in alerts:
            self.alerts.append(alert)
            log_alert(alert_type=alert["type"], severity=alert["severity"], 
                    src_ip=alert["src_ip"], dst_ip=alert["dst_ip"],
                    protocol=alert["protocol"], details=alert["details"])
        
        return info
    
    def _should_alert(self, key):
        now = time.time()
        if key in self.alerts_sent:
            if now - self.alerts_sent[key] < 240:
                return False
        self.alerts_sent[key] = now
        return True
    
    def get_graph_data(self):
        current_rate = len(self.traffic_history) / 60 if self.traffic_history else 0
        return {
            "packets": self.packet_count,
            "packets_per_sec": round(current_rate, 1),
            "unique_ips": len(self.ip_tracker),
            "alerts_count": len(self.alerts),
            "time_window": 60
        }
    
    def _create_alert(self, alert_type, severity, src_ip, dst_ip, protocol, details, confidence=None):
        return {
            "id": len(self.alerts),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": alert_type,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "details": details,
            "confidence": confidence
        }
    
    def get_stats(self):
        return {
            "packet_count": self.packet_count,
            "unique_ips": len(self.ip_tracker),
            "alerts": len(self.alerts),
            "total_bytes": self.size_tracker,
            "top_sources": sorted(self.ip_tracker.items(), key=lambda x: x[1], reverse=True)[:5]
        }

_sniffer = None
_stop_event = None

def process_packet(packet):
    global _sniffer, _stop_event
    if _sniffer and (_stop_event is None or not _stop_event.is_set()):
        _sniffer.process_packet(packet)

def stop_sniffing():
    global _stop_event
    if _stop_event:
        _stop_event.set()
        
def start_sniffing(interface=None, count=0, timeout=None):
    import os
    is_cloud = os.environ.get("PORT") and not os.environ.get("LOCAL")
    
    if is_cloud:
        global _sniffer, _stop_event
        _stop_event = __import__('threading').Event()
        _sniffer = PacketSniffer()
        print("[*] Running in demo mode (cloud)")
        import threading, time, random
        def demo_traffic():
            demo_ips = ["142.250.1.1", "172.217.1.1", "104.16.1.1"]
            ports = [80, 443, 22, 3389]
            while _sniffer and _stop_event and not _stop_event.is_set():
                src = random.choice(demo_ips)
                dst_port = random.choice(ports)
                packet_info = {
                    "src_ip": src,
                    "dst_ip": "192.168.1.1",
                    "type": "TCP",
                    "dst_port": dst_port,
                    "size": random.randint(64, 1500)
                }
                _sniffer.process_packet(type('Packet', (), packet_info)())
                _sniffer.traffic_history.append((time.time(), _sniffer.packet_count))
                _sniffer.traffic_history = [(t, c) for t, c in _sniffer.traffic_history if time.time() - t < 60]
                time.sleep(random.uniform(0.5, 2))
        
        demo_thread = threading.Thread(target=demo_traffic)
        demo_thread.daemon = True
        demo_thread.start()
    else:
        from scapy.all import sniff
        from scapy.config import conf
        conf.use_pcap = True
        print("[*] Starting packet capture...")
        # Use module-level globals
        _stop_event = __import__('threading').Event()
        _sniffer = PacketSniffer()
        try:
            sniff(prn=process_packet, store=False, iface=interface, count=count, timeout=timeout, stop_filter=lambda x: _stop_event.is_set())
        except KeyboardInterrupt:
            print("[*] Sniffing stopped")
        except Exception as e:
            print(f"[!] Error: {e}")

def get_alerts():
    global _sniffer
    if _sniffer:
        return _sniffer.alerts[-50:]
    return []

def reset_alerts():
    global _sniffer
    if _sniffer:
        _sniffer.alerts = []

def get_stats():
    global _sniffer
    if _sniffer:
        stats = _sniffer.get_stats()
        stats["graph"] = _sniffer.get_graph_data()
        return stats
    return {}