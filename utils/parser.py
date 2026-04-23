from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

def parse_packet(packet):
    if not packet.haslayer(IP):
        return None
    
    info = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "ttl": packet[IP].ttl,
        "size": len(packet)
    }
    
    if packet.haslayer(TCP):
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
        info["flags"] = packet[TCP].flags
        info["type"] = "TCP"
    elif packet.haslayer(UDP):
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport
        info["type"] = "UDP"
    elif packet.haslayer(ICMP):
        info["type"] = "ICMP"
    else:
        info["type"] = "OTHER"
    
    if packet.haslayer(Raw):
        info["payload_size"] = len(packet[Raw].load)
    
    return info

def get_protocol_name(proto):
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"Proto-{proto}")