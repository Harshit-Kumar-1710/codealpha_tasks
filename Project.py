import scapy.all as scapy
import time
import socket
import ctypes

# Function to extract domain names from DNS requests
def extract_dns(packet):
    if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSQR):
        domain_name = packet[scapy.DNSQR].qname.decode().strip('.')
        print(f"🔎 DNS Request for: {domain_name}")  
        return domain_name
    return None

# Function to resolve IP to domain name
def get_domain_name(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain = None
    return domain

# Packet sniffer function
def packet_sniffer(duration, protocol):
    start_time = time.time()
    captured_data = []
    captured_domains = set()

    # Map user choice to Scapy filter
    protocol_filters = {
        "IP": "ip",
        "TCP": "tcp",
        "UDP": "udp",
        "ALL": "ip or tcp or udp"
    }

    def packet_callback(packet):
        nonlocal captured_domains

        if packet.haslayer(scapy.IP):  # Process only IP packets
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst

            # Resolve IPs to domains (if possible)
            domain_src = get_domain_name(ip_src)
            domain_dst = get_domain_name(ip_dst)

            packet_info = f"\n📡 IP Packet: {ip_src} -> {ip_dst}"
            if domain_src:
                packet_info += f"\n🌍 Source Domain: {domain_src}"
                captured_domains.add(domain_src)
            if domain_dst:
                packet_info += f"\n🌎 Destination Domain: {domain_dst}"
                captured_domains.add(domain_dst)

            print(packet_info)
            captured_data.append(packet_info)

        # Capture DNS Requests
        dns_domain = extract_dns(packet)
        if dns_domain:
            captured_domains.add(dns_domain)
            captured_data.append(f"🔎 DNS Request for: {dns_domain}")

        # Stop sniffing if time has elapsed
        if time.time() - start_time > duration:
            return True  

    print(f"\n⏳ Sniffing {protocol} packets for {duration} seconds...")
    scapy.sniff(prn=packet_callback, filter=protocol_filters[protocol], timeout=duration, store=False)

    return captured_domains, captured_data

# Function to check admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Function to save captured packets to a file
def save_to_file(data):
    filename = f"sniffed_packets_{int(time.time())}.txt"
    with open(filename, "w", encoding="utf-8") as file:
        file.write("\n".join(data))
    print(f"\n💾 Packets saved to {filename}")

# Main function
def main():
    print("\n🚀 Welcome to the Advanced Network Sniffer!")

    while True:
        # Choose protocol to capture
        protocols = ["IP", "TCP", "UDP", "ALL"]
        print("\n🔹 Select the protocol to capture:")
        for i, protocol in enumerate(protocols, 1):
            print(f"{i}. {protocol}")

        try:
            protocol_choice = int(input("\nEnter choice (1-4): ").strip())
            if protocol_choice not in range(1, 5):
                print("⛔ Invalid choice! Please enter a number between 1 and 4.")
                continue
        except ValueError:
            print("⛔ Invalid input! Please enter a number.")
            continue

        selected_protocol = protocols[protocol_choice - 1]

        # Choose capture duration
        try:
            duration = int(input("\nEnter the capture duration in seconds: ").strip())
            if duration <= 0:
                print("⛔ Duration must be a positive integer!")
                continue
        except ValueError:
            print("⛔ Invalid input! Please enter a number.")
            continue

        # Start packet sniffing
        domain_names, captured_data = packet_sniffer(duration, selected_protocol)

        # Display unique domain names
        print("\n🔹 Unique domain names visited:")
        if domain_names:
            for domain in domain_names:
                print(f" - {domain}")
        else:
            print("❌ No website domains captured.")

        # Ask to save packets
        save_choice = input("\n💾 Do you want to save the captured packets? (yes/no): ").strip().lower()
        if save_choice == "yes":
            save_to_file(captured_data)

        # Ask if user wants to continue
        continue_choice = input("\n🔄 Continue sniffing? (yes/no): ").strip().lower()
        if continue_choice != 'yes':
            print("👋 Exiting Network Sniffer.")
            break  

if __name__ == '__main__':
    if not is_admin():
        print("\n⚠ This script requires administrator privileges to sniff packets.")
    else:
        main()
