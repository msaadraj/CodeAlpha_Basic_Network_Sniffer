# CodeAlpha_Basic_Network_Sniffer
I have built a real-time network sniffer in Python to capture and analyze network traffic. This project enhances understanding of network data flow and packet structures by supporting TCP, UDP, and ICMP analysis. 

import os
import sys
import time
from scapy.all import *

def display_banner():
    print("\n" + "=" * 60)
    print("🔥 Professional Python Network Sniffer 🔥")
    print("📡 Capturing live network traffic in real time")
    print("🔍 Developed for educational and ethical purposes")
    print("=" * 60 + "\n")

    print("🚨 Disclaimer:")
    print("⚠️ Use this tool only on networks you have permission to monitor.")
    print("⚠️ Unauthorized use may violate laws and regulations.")
    print("⚠️ The developer is not responsible for misuse.")
    print("\n" + "=" * 60)

    accept_terms = input("Do you accept the terms and conditions? (y/n): ")
    if accept_terms.lower() != 'y':
        print("❌ You must accept the terms to proceed.")
        sys.exit()

def analyze_packet(packet):
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
        protocol = "Unknown"
        details = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            details = f"Source Port: {src_port}, Destination Port: {dst_port}"

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            details = f"Source Port: {src_port}, Destination Port: {dst_port}"

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            details = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"

        log_entry = f"[{timestamp}] Protocol: {protocol} | Source: {src_ip} -> Destination: {dst_ip} | {details}\n"
        print(log_entry.strip())

        with open("network_sniffer_log.txt", "a") as log_file:
            log_file.write(log_entry)

    except Exception as e:
        print(f"⚠️ Error processing packet: {e}")

def start_sniffing():
    print("\n🚀 Sniffer is running... Press Ctrl+C to stop.\n")
    try:
        sniff(prn=analyze_packet, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Sniffer stopped by user. Log saved to 'network_sniffer_log.txt'.")
    except Exception as e:
        print(f"⚠️ Error: {e}")

if __name__ == "__main__":
    display_banner()
    start_sniffing()
