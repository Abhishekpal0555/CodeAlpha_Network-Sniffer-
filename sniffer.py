from scapy.all import sniff, IP, TCP, UDP

# Function to process each captured packet
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}")

        # Check if the packet has a TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP, Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")

        # Check if the packet has a UDP layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP, Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

# Start sniffing packets
print("Starting the network sniffer...")
sniff(prn=packet_callback, count=10)  # Change count to capture more packets
