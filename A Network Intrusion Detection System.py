import scapy.all as scapy
from collections import defaultdict
import time
import threading
import logging

# Dictionary to track packet counts per IP
packet_counts = defaultdict(int)
TIME_WINDOW = 10  # Time window in seconds
THRESHOLD = 50    # Packet count threshold

# Configure logging to store alerts in a file
logging.basicConfig(filename="nids_alerts.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Function to process captured packets
def process_packet(packet):
    if packet.haslayer(scapy.IP):  # Only process IP packets
        src_ip = packet[scapy.IP].src
        packet_counts[src_ip] += 1  # Count packets per source IP

        # Identify the protocol (TCP, UDP, ICMP)
        if packet.haslayer(scapy.TCP):
            protocol = "TCP"
        elif packet.haslayer(scapy.UDP):
            protocol = "UDP"
        elif packet.haslayer(scapy.ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other"

        print(f"📡 Packet from {src_ip} ({protocol}) detected.")  # Display real-time packet activity

# Function to monitor and detect intrusions
def detect_intrusions():
    while True:
        time.sleep(TIME_WINDOW)  # Wait for the time window
        for ip, count in packet_counts.items():
            if count > THRESHOLD:
                alert_message = f"🚨 ALERT! Potential attack detected from {ip} (Packets: {count})"
                print(alert_message)  # Print alert
                logging.info(alert_message)  # Log alert to file

        packet_counts.clear()  # Reset counter after time window

# Start sniffing packets in a separate thread
def start_sniffing():
    print("🔍 Starting NIDS... Monitoring network traffic.")
    scapy.sniff(prn=process_packet, store=False,timeout=10)

# Main function to run both sniffing and detection
def main():
    sniffing_thread = threading.Thread(target=start_sniffing)
    detection_thread = threading.Thread(target=detect_intrusions)

    sniffing_thread.start()
    detection_thread.start()

    sniffing_thread.join()
    detection_thread.join()

if __name__ == "__main__":
    main()
