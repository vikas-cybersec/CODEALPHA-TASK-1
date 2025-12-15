from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    """
    Callback function that is executed for every captured packet.
    It parses the packet and prints relevant information.
    """
    
    # Check if the packet has an IP layer (IPv4)
    if IP in packet:
        # Extract the IP layer
        ip_layer = packet[IP]
        
        # Get Source and Destination IP addresses [cite: 27]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Determine the Protocol [cite: 27]
        # Protocol numbers: 1=ICMP, 6=TCP, 17=UDP
        proto = ip_layer.proto
        protocol_name = ""
        
        if proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"
        elif proto == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = f"Other ({proto})"

        # Print the basic packet header info
        print(f"\n[+] New Packet: {src_ip} -> {dst_ip} | Protocol: {protocol_name}")

        # specific handling to try and get the Payload (Data) [cite: 27]
        payload = None
        
        if packet.haslayer(TCP):
            payload = packet[TCP].payload
        elif packet.haslayer(UDP):
            payload = packet[UDP].payload
        elif packet.haslayer(ICMP):
            payload = packet[ICMP].payload

        # Print the payload if it exists and isn't empty
        if payload and len(payload) > 0:
            try:
                # Attempt to decode as UTF-8 for readability, otherwise print raw bytes
                print(f"    Payload (Raw): {bytes(payload)}")
            except:
                print("    Payload: [Non-printable data]")

def start_sniffer():
    print("========================================")
    print("CodeAlpha Task 1: Basic Network Sniffer")
    print("========================================")
    print("[*] Starting Sniffer...")
    print("[*] Press Ctrl+C to stop capturing.")
    
    # Start sniffing
    # store=0: Do not keep packets in memory (prevents RAM issues)
    # prn=packet_callback: The function to run on every packet
    sniff(iface="Intel(R) Wi-Fi 6 AX201 160MHz", prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffer()