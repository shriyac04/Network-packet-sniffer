import sys
from scapy.all import *

# Function to handle each packet
def process_packet(packet, log_file):
    # Check if the packet contains a TCP layer
    if packet.haslayer(TCP):
        # Extract source and destination IP addresses
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        # Extract source and destination ports
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        # Write packet information to the log file
        log_file.write(f"TCP Connection: {source_ip}:{source_port} -> {destination_ip}:{destination_port}\n")

# Main function to start packet sniffing
def start_sniffing(interface, is_verbose=False):
    # Create log file name based on the network interface
    log_filename = f"sniffer_{interface}_log.txt"
    # Open the log file for writing
    with open(log_filename, 'w') as log_file:
        try:
            # Start packet sniffing on the specified interface
            sniff(iface=interface, prn=lambda pkt: process_packet(pkt, log_file), store=0, verbose=is_verbose)
        except KeyboardInterrupt:
            sys.exit(0)

# Check if the script is being run directly
if __name__ == "__main__":
    # Check if the correct number of arguments is provided
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)
    # Determine if verbose mode is enabled
    is_verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        is_verbose = True
    # Call the main function with the specified interface and verbose option
    start_sniffing(sys.argv[1], is_verbose)
