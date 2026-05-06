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
        self.protocol_counts = defaultdict(int)
        self.protocol_history = defaultdict(list)
        self.ml_initialized = False
        self.packet_count_for_retrain = 0

    def _init_ml(self):
        if not self.ml_initialized:
            try:
                from ml import anomaly_detector, ip_scorer, dns_resolver, trainer
                self.anomaly_detector = anomaly_detector
                self.ip_scorer = ip_scorer
                self.dns_resolver = dns_resolver
                self.trainer = trainer
                trainer.load_model()
                self.ml_initialized = True
            except Exception as e:
                print(f"[ML] Init failed: {e}")
                self.ml_initialized = False

    def process_packet(self, packet):
        self._init_ml()
        self.packet_count += 1
        info = parse_packet(packet)
        if not info:
            return None

        src_ip = info["src_ip"]
        self.ip_tracker[src_ip] += 1
        self.size_tracker += info.get("size", 64)

        protocol = info.get("type", "OTHER")
        self.protocol_counts[protocol] += 1

        self.traffic_history.append((time.time(), self.packet_count))
        self.traffic_history = [(t, c) for t, c in self.traffic_history if time.time() - t < 60]

        self.protocol_history[protocol].append((time.time(), self.protocol_counts[protocol]))
        for proto in self.protocol_history:
            self.protocol_history[proto] = [(t, c) for t, c in self.protocol_history[proto] if time.time() - t < 60]

        if self.ml_initialized:
            features = self.anomaly_detector.extract_features(info)
            self.anomaly_detector.add_sample(features)
            anomaly_score = self.anomaly_detector.predict(features)
            self.ip_scorer.update(info)
            self.dns_resolver.resolve(src_ip)
            self.dns_resolver.resolve(info.get("dst_ip", ""))

            if anomaly_score > config.ML_ANOMALY_THRESHOLD:
                key = f"ML-{src_ip}"
                if self._should_alert(key):
                    self.alerts.append(self._create_alert(
                        "ML Anomaly", "HIGH", src_ip, info.get("dst_ip", "N/A"),
                        protocol, f"Anomaly score: {anomaly_score:.2f}", anomaly_score
                    ))

            if len(self.anomaly_detector.feature_buffer) >= config.ML_TRAIN_BUFFER_SIZE:
                if not self.anomaly_detector.is_trained:
                    self.trainer.train()
                elif self.packet_count_for_retrain >= config.ML_RETRAIN_INTERVAL:
                    self.trainer.train()
                    self.packet_count_for_retrain = 0

        self.packet_count_for_retrain += 1

        alerts = []

        if info.get("type") == "TCP" and info.get("flags") == "S":
            self.syn_tracker[src_ip] += 1
            if self.syn_tracker[src_ip] > config.THRESHOLD_SYN_RATE:
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
            key = "STAT-ANOMALY"
            if self._should_alert(key):
                confidence = min(0.98, round(0.5 + (current_rate / (self.baseline_rate * 5)) * 0.4, 2))
                alerts.append(self._create_alert(
                    "Statistical Anomaly", "MEDIUM", "Traffic Pattern", "Network",
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

        protocol_pattern = {}
        for proto in ['TCP', 'UDP', 'ICMP']:
            history = self.protocol_history.get(proto, [])
            if history:
                rate = len(history) / 60
                protocol_pattern[proto] = round(rate, 1)

        return {
            "packets": self.packet_count,
            "packets_per_sec": round(current_rate, 1),
            "unique_ips": len(self.ip_tracker),
            "alerts_count": len(self.alerts),
            "time_window": 60,
            "protocol_pattern": protocol_pattern
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
        protocol_dist = {
            "TCP": self.protocol_counts.get("TCP", 0),
            "UDP": self.protocol_counts.get("UDP", 0),
            "ICMP": self.protocol_counts.get("ICMP", 0),
            "OTHER": self.protocol_counts.get("OTHER", 0)
        }
        return {
            "packet_count": self.packet_count,
            "unique_ips": len(self.ip_tracker),
            "alerts": len(self.alerts),
            "total_bytes": self.size_tracker,
            "top_sources": sorted(self.ip_tracker.items(), key=lambda x: x[1], reverse=True)[:5],
            "protocol_distribution": protocol_dist
        }

    def get_ml_data(self):
        if not self.ml_initialized:
            return {"error": "ML not initialized"}
        return {
            "anomaly_scores": self.anomaly_detector.get_recent_scores(),
            "anomaly_status": self.anomaly_detector.get_status(),
            "ip_scores": self.ip_scorer.get_all_scores(),
            "dns_cache": self.dns_resolver.get_stats()
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
                from scapy.layers.inet import IP, TCP
                from scapy.packet import Raw
                while _sniffer and _stop_event and not _stop_event.is_set():
                    src = random.choice(demo_ips)
                    dst_port = random.choice(ports)
                    pkt = IP(src=src, dst="192.168.1.1")/TCP(dport=dst_port)/Raw(load="X" * random.randint(20, 100))
                    _sniffer.process_packet(pkt)
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
        alerts = _sniffer.alerts[-50:]
        if _sniffer.ml_initialized:
            dns = _sniffer.dns_resolver
            for alert in alerts:
                src = alert.get("src_ip", "")
                dst = alert.get("dst_ip", "")
                if src and src not in ["Traffic Pattern", "Network"]:
                    dns.resolve(src)
                if dst and dst not in ["Traffic Pattern", "Network"]:
                    dns.resolve(dst)
                src_resolved = dns.get(src)
                dst_resolved = dns.get(dst)
                if src_resolved != src:
                    alert["src_ip_display"] = f"{src_resolved} ({src})"
                if dst_resolved != dst:
                    alert["dst_ip_display"] = f"{dst_resolved} ({dst})"
        return alerts
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

def get_ml_data():
    global _sniffer
    if _sniffer:
        return _sniffer.get_ml_data()
    return {}

def train_ml():
    global _sniffer
    if _sniffer and _sniffer.ml_initialized:
        return _sniffer.trainer.train()
    return {"success": False, "message": "ML not available"}

def reset_ml():
    global _sniffer
    if _sniffer and _sniffer.ml_initialized:
        _sniffer.trainer.reset()
        _sniffer.ip_scorer.reset()
        _sniffer.dns_resolver.clear()
        return {"success": True, "message": "ML reset"}
    return {"success": False, "message": "ML not available"}
