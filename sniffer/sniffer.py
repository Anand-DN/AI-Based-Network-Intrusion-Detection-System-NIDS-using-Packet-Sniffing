from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        print(f"\n📦 Packet Captured")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")

        if packet.haslayer(TCP):
            print("Protocol Type: TCP")
        elif packet.haslayer(UDP):
            print("Protocol Type: UDP")
        else:
            print("Protocol Type: Other")

# Start sniffing
print("🚀 Starting packet capture... Press CTRL+C to stop")
sniff(prn=process_packet, store=False)