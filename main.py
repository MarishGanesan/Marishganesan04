import logging
from scapy.all import sniff, IP, TCP
import pandas as pd
from datetime import datetime

# Set up logging
logging.basicConfig(filename='network_traffic.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Threat signatures (simple example)
THREAT_SIGNATURES = {
    'SYN_FLOOD': {'dport': 80, 'flags': 'S'},
    # Add more signatures here
}

# DataFrame to store captured packets
columns = ['timestamp', 'src', 'dst', 'sport', 'dport', 'protocol', 'flags']
packet_log = pd.DataFrame(columns=columns)

def packet_callback(packet):
    global packet_log
    
    # Filter IP and TCP packets
    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        # Log packet details
        packet_details = {
            'timestamp': datetime.now(),
            'src': ip_layer.src,
            'dst': ip_layer.dst,
            'sport': tcp_layer.sport,
            'dport': tcp_layer.dport,
            'protocol': 'TCP',
            'flags': tcp_layer.flags
        }
        packet_log = packet_log.append(packet_details, ignore_index=True)
        
        # Simple threat detection
        for threat, signature in THREAT_SIGNATURES.items():
            if all(packet_details.get(k) == v for k, v in signature.items()):
                alert_message = f"Potential {threat} detected: {packet_details}"
                logging.warning(alert_message)
                print(alert_message)

def start_sniffing(interface="eth0"):
    print(f"Starting packet sniffing on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

if _name_ == "_main_":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("Stopping packet sniffing...")
        # Save the packet log to a CSV file
        packet_log.to_csv('captured_packets.csv', index=False)
        print("Packet log saved to 'captured_packets.csv'.")
