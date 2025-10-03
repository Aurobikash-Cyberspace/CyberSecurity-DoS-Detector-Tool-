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
