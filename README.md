# 🛡️ DoS Detector Tool (Python + Kali Linux)

A real-time **Denial-of-Service (DoS) detection and mitigation tool** built in Python using only standard libraries.  
Runs on Kali Linux (root required) and provides a **live updating terminal dashboard** with automatic attacker blocking via `iptables`.

---

## 🚀 Features
- 📡 **Packet Sniffing** – Captures all incoming traffic (TCP, UDP, ICMP).
- 📊 **Live Dashboard** – Real-time stats per source IP & protocol.
- ⚡ **Flood Detection** – Detects high-rate traffic (SYN floods, UDP floods, ICMP floods).
- 🔒 **Auto Blocking** – Blocks suspicious IPs with `iptables`.
- 📝 **Logging** – Records events in `logs/dos_log.txt`.
- 🎨 **Colored Interface** – Easy-to-read terminal output using ANSI colors.

---
## ⚙️ Installation & Usage


### 1. Clone Repository
```bash
git clone https://github.com/yourusername/dos-detector.git
cd dos-detector

2. Run the Detector
sudo python3 dos_detector.py

📊 Dashboard Example

=== Live DoS Detection Dashboard ===
Source IP          Proto  Packets(last 10s)
--------------------------------------------------
192.168.0.15       TCP    120
[!] ALERT: Possible DoS from 192.168.0.15 (TCP)
[+] Blocked IP: 192.168.0.15


📂 Project Structure


dos-detector/
│── dos_detector.py     # Main script
│── README.md           # Documentation
│── LICENSE             # License (MIT)
│── logs/
│   └── dos_log.txt     # Detection logs


🛑 Stopping the Detector

Press Ctrl + C in the terminal.
This stops packet capture and the dashboard, then exits cleanly.

Logs
Events are recorded in:
logs/dos_log.txt

Attack Simulation (lab only)
Use these commands from another machine in the same network (recommended) or from the same Kali machine (careful — local flooding can affect the host).
Replace <kali-ip> with your Kali machine IP (check with ip a).
1) TCP SYN Flood (SYN flood simulation)
From another Linux machine (or from Kali if you understand the risk):
sudo hping3 -S -p 80 -i u1000 <kali-ip>

-S = SYN flag
-p 80 = destination port 80
-i u1000 = inter-packet delay (microseconds) — u1000 is fast; lower -> faster flood
Expected result:
Dashboard shows the source IP increasing packet count rapidly.
When count ≥ THRESHOLD, detector prints an alert, logs it, and iptables blocks the IP.
sudo iptables -L -n shows an INPUT rule dropping that source IP.
Stop hping3 with Ctrl+C on the attacker machine.

2) UDP Flood

sudo hping3 --udp -p 53 -i u1000 <kali-ip>

--udp sends UDP datagrams (port 53 is an example).
Expected result: similar behaviour — dashboard counts increase, alert & auto-block triggers.

3) ICMP Flood (ping flood)

From Linux:
ping -f <kali-ip>
-f flood pings; may need root on some systems.
Expected result: ICMP packet counts increase; detector alerts if threshold exceeded.

Verify Blocking
List iptables rules to confirm blocks:
sudo iptables -L -n --line-numbers


Troubleshooting:

Dashboard is empty (no IP rows):
Ensure you ran the script with sudo.
Ensure traffic is actually reaching the machine (try ping <kali-ip> from another host).
Enable debug mode (DEBUG = True) and look for [DEBUG] Captured packet ... lines.
If you see DEBUG lines but no table rows: check that packet protocol is TCP/UDP/ICMP and the code’s mapping matches (protocol numbers 6, 17, 1 respectively).
PermissionError when creating raw socket:
Did you run with root? Use sudo python3 dos_detector.py.
Iptables blocking didn’t work:
Confirm iptables is available and you have privileges.
Check that the block_ip() function runs (look for Blocked IP ... messages).
On some systems, ufw or nftables may be active instead of traditional iptables.
False positives on busy networks:
Raise THRESHOLD or increase WINDOW.
Consider testing in an isolated lab or using stricter rules (e.g., only block if sustained over multiple windows).
Safety & Ethics
Only perform attack simulations on devices you own or on networks where you have explicit permission.
Do not run destructive tests on production systems.
This tool demonstrates basic detection and mitigation; it’s intended for learning and lab use only.
Optional: Automate Running as a Service (Advanced)
If you want the detector to run on boot, create a systemd service. Be careful — a service running as root that auto-blocks could lock you out. Only do this on machines where you have console access.
FAQ
Q: Can I test from the same Kali machine?
A: Yes, but be careful — flooding local interfaces can disrupt your host. Prefer a separate test machine or VM.
Q: How to tune for my network?
A: Increase THRESHOLD and/or WINDOW to reduce false positives on busy networks.
Q: Can this run on non-Linux systems?
A: The script uses AF_PACKET sockets and iptables, so it’s Linux-specific.





📝 License


---

# ⚖️ `LICENSE`
Use MIT License (simple and permissive):

```text
MIT License

Copyright (c) 2025 <Your Name>

Permission is hereby granted, free of charge, to any person obtaining a copy
...
