from scapy.all import sniff, IP, TCP
import time

LOG_FILE = "./logs/network_log.txt"


def detect_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        flags = packet[TCP].flags
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        if flags == "S":
            alert = f"[ALERT] Possible Nmap scan from {src_ip} to {dst_ip}:{dst_port}"
            print(alert)

            with open(LOG_FILE, "a") as f:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                f.write(f"{timestamp} - {alert}\n")


def start_sniffer():
    print("listening for TCP traffic")
    sniff(filter="tcp", prn=detect_scan, store=False)
