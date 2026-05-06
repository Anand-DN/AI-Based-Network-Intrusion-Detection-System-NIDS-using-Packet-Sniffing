import time
import math
from collections import defaultdict, deque

class IPScorer:
    def __init__(self, window=60):
        self.window = window
        self.ip_data = {}
        self.thresholds = {"safe": 20, "suspicious": 40, "threat": 70}

    def _get_ip(self, src_ip):
        if src_ip not in self.ip_data:
            self.ip_data[src_ip] = {
                "packets": deque(maxlen=5000),
                "ports": set(),
                "protocols": defaultdict(int),
                "syn_count": 0,
                "total_size": 0,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "has_payload": 0,
                "total_packets": 0
            }
        return self.ip_data[src_ip]

    def update(self, packet_info):
        src_ip = packet_info.get("src_ip", "")
        if not src_ip:
            return
        now = time.time()
        ip = self._get_ip(src_ip)
        ip["packets"].append(now)
        ip["last_seen"] = now
        ip["total_packets"] += 1
        dst_port = packet_info.get("dst_port")
        if dst_port:
            ip["ports"].add(dst_port)
        proto = packet_info.get("type", "OTHER")
        ip["protocols"][proto] += 1
        if packet_info.get("flags") == "S":
            ip["syn_count"] += 1
        ip["total_size"] += packet_info.get("size", 64)
        if packet_info.get("payload_size", 0) > 0:
            ip["has_payload"] += 1
        self._cleanup_expired()

    def get_score(self, ip):
        if ip not in self.ip_data:
            return {"ip": ip, "score": 0, "level": "Safe", "color": "var(--text-secondary)", "details": {}}
        d = self.ip_data[ip]
        now = time.time()
        recent_packets = [t for t in d["packets"] if now - t < self.window]
        pps = len(recent_packets) / self.window
        unique_ports = len(d["ports"])
        syn_ratio = d["syn_count"] / max(d["total_packets"], 1)
        avg_size = d["total_size"] / max(d["total_packets"], 1)
        payload_ratio = d["has_payload"] / max(d["total_packets"], 1)
        duration = now - d["first_seen"]
        port_diversity = unique_ports / max(min(d["total_packets"], 100), 1)
        proto_count = len([p for p in d["protocols"] if d["protocols"][p] > 0])
        score = 0
        score += min(pps * 2, 25)
        score += min(unique_ports * 2, 25)
        score += syn_ratio * 20
        score += (1 - payload_ratio) * 10
        if avg_size < 100:
            score += 10
        if duration < 30 and d["total_packets"] > 50:
            score += 10
        score += port_diversity * 10
        score = min(max(score, 0), 100)
        level, color = self._get_level(score)
        return {
            "ip": ip,
            "score": round(score, 1),
            "level": level,
            "color": color,
            "details": {
                "packets_per_sec": round(pps, 1),
                "unique_ports": unique_ports,
                "syn_ratio": round(syn_ratio, 2),
                "total_packets": d["total_packets"],
                "avg_size": round(avg_size, 0),
                "duration": round(duration, 0)
            }
        }

    def _get_level(self, score):
        if score >= self.thresholds["threat"]:
            return "Critical", "var(--danger)"
        elif score >= self.thresholds["suspicious"]:
            return "Threat", "var(--warning)"
        elif score >= self.thresholds["safe"]:
            return "Suspicious", "var(--primary)"
        else:
            return "Safe", "var(--text-secondary)"

    def _cleanup_expired(self):
        now = time.time()
        expired = []
        for ip, d in self.ip_data.items():
            if now - d["last_seen"] > self.window * 3:
                expired.append(ip)
        for ip in expired:
            del self.ip_data[ip]

    def get_all_scores(self):
        self._cleanup_expired()
        scores = [self.get_score(ip) for ip in self.ip_data]
        scores.sort(key=lambda x: x["score"], reverse=True)
        return scores

    def get_critical_ips(self):
        return [s for s in self.get_all_scores() if s["score"] >= self.thresholds["threat"]]

    def reset(self):
        self.ip_data = {}
