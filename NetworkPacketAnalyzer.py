from scapy.all import sniff, IP, TCP, UDP
import datetime

# Function to process each packet
def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[IP].load if len(packet[IP].load) < 100 else packet[IP].load[:100]  # Limiting payload size for display
        
        # Display packet information
        print(f"Timestamp: {datetime.datetime.now()}")
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("-" * 40)

# Main function to start sniffing
def start_sniffing(interface="eth0"):
    print(f"Starting packet sniffing on {interface}...")
    sniff(iface=interface, prn=process_packet, filter="ip", store=0)

if __name__ == "__main__":
    # Replace 'eth0' with your network interface (e.g., 'wlan0' for Wi-Fi)
    start_sniffing("eth0")
