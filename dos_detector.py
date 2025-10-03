
#!/usr/bin/env python3
import socket
import struct
import threading
import time
import os
import subprocess
from collections import defaultdict
from datetime import datetime

# === Configuration ===
THRESHOLD = 100          # Packets per 10s before detection
WINDOW = 10              # Sliding window (seconds)
LOG_FILE = "logs/dos_log.txt"
running = True
packet_count = defaultdict(list)
blocked_ips = set()

# === Color codes for dashboard ===
RESET = "\033[0m"
HEADER = "\033[1;36m"
IP_COLOR = "\033[32m"
PROTO_COLOR = "\033[33m"
ALERT_COLOR = "\033[31m"
COUNT_COLOR = "\033[37m"

# === Logging ===
os.makedirs("logs", exist_ok=True)

def log_event(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

# === Packet Capture ===
def packet_sniffer():
    global running
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("[!] Run this script as root.")
        return

    print("[+] Sniffer started (Ctrl+C to stop).")
    while running:
        try:
            raw_data, _ = sock.recvfrom(65535)
            eth_proto = struct.unpack("!H", raw_data[12:14])[0]
            if eth_proto == 0x0800:  # IPv4
                ip_header = raw_data[14:34]
                iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                proto = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                packet_count[(src_ip, proto)].append(time.time())
        except Exception:
            continue

# === Dashboard ===
def dashboard():
    global running
    while running:
        os.system("clear")
        print(HEADER + "=== Live DoS Detection Dashboard ===" + RESET)
        print(f"{HEADER}{'Source IP':<18} {'Proto':<6} {'Packets(last 10s)':<18}{RESET}")
        print("-" * 50)

        cutoff = time.time() - WINDOW
        for (ip, proto), times in list(packet_count.items()):
            packet_count[(ip, proto)] = [t for t in times if t > cutoff]
            count = len(packet_count[(ip, proto)])

            count_color = ALERT_COLOR if count >= THRESHOLD else COUNT_COLOR
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))

            print(f"{IP_COLOR}{ip:<18}{RESET} "
                  f"{PROTO_COLOR}{proto_name:<6}{RESET} "
                  f"{count_color}{count:<18}{RESET}")

            if count >= THRESHOLD and ip not in blocked_ips:
                print(ALERT_COLOR + f"[!] ALERT: Possible DoS from {ip} ({proto_name})" + RESET)
                log_event(f"DoS detected: {ip} using {proto_name}, count={count}")
                block_ip(ip)
        time.sleep(1)

# === Blocking Function ===
def block_ip(ip):
    try:
        subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        blocked_ips.add(ip)
        log_event(f"Blocked IP {ip}")
        print(ALERT_COLOR + f"[+] Blocked IP: {ip}" + RESET)
    except Exception as e:
        print(f"[!] Failed to block {ip}: {e}")

# === Main ===
if __name__ == "__main__":
    try:
        t1 = threading.Thread(target=packet_sniffer, daemon=True)
        t2 = threading.Thread(target=dashboard, daemon=True)
        t1.start()
        t2.start()

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        running = False
        print("\n[+] Stopping detector...")
        log_event("Detector stopped.")
        print("[+] Exited cleanly.")
