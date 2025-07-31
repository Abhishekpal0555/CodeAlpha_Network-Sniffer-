from scapy.all import *
from scapy.layers.http import HTTPRequest
from datetime import datetime

# Color formatting
class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def packet_handler(packet):
    """Process each packet with colored output"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Ethernet Layer
    if packet.haslayer(Ether):
        print(f"\n{bcolors.BLUE}[{timestamp}] MAC: {packet[Ether].src} → {packet[Ether].dst}{bcolors.END}")
    
    # IP Layer
    if packet.haslayer(IP):
        print(f"{bcolors.GREEN}[{timestamp}] IP: {packet[IP].src} → {packet[IP].dst}{bcolors.END}")
        
        # TCP Layer
        if packet.haslayer(TCP):
            print(f"{bcolors.YELLOW}[{timestamp}] TCP: Port {packet[TCP].sport} → {packet[TCP].dport}{bcolors.END}")
            
            # HTTP Layer
            if packet[TCP].dport == 80 and packet.haslayer(HTTPRequest):
                http = packet[HTTPRequest]
                print(f"{bcolors.RED}[{timestamp}] HTTP: {http.Host.decode()}{http.Path.decode()}{bcolors.END}")

# Main execution
if __name__ == "__main__":
    print(f"{bcolors.HEADER}=== Network Sniffer (20 packets) ==={bcolors.END}")
    print(f"{bcolors.CYAN}Press Ctrl+C to stop early{bcolors.END}\n")
    
    try:
        sniff(prn=packet_handler, count=20, store=0)
    except KeyboardInterrupt:
        print(f"\n{bcolors.RED}Sniffer stopped by user{bcolors.END}")
    finally:
        print(f"{bcolors.UNDERLINE}Capture completed{bcolors.END}")
