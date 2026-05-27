# 🕷️ NetWraith
### network security analysis. built different.

[![Status](https://img.shields.io/badge/status-active-00e5ff.svg?style=flat-square)](#)
[![Python](https://img.shields.io/badge/python-3.10+-bb86fc.svg?style=flat-square)](#)
[![License](https://img.shields.io/badge/license-MIT-4caf50.svg?style=flat-square)](#)

NetWraith is a high-key professional, low-key aesthetic network auditing and threat detection suite built with Python, PyQt6, and Scapy. Designed for systems administrators and security researchers who want Wireshark-level depth wrapped in a premium, flat-panel dark mode GUI.

Because looking at terminal walls of text in 2026 is simply not the vibe, and legacy packet sniffers look like they were designed in the 90s.

---

## ⚡ It's Giving...
* **Main Character Visibility** — Real-time packet parsing, hex dumps, and layer breakdown with zero gatekeeping.
* **No Cap Performance** — Native Python multithreading (`QThread`) keeps the UI highly responsive while Scapy handles raw sockets in the background.
* **Receipts-Driven Security** — Persists anomalies to local logs and alerts you in real-time if someone starts acting sus on the subnet.

---

## 🖥️ Feature Breakdown

### 📊 1. Dashboard Tab
* Live pyqtgraph sparkline showing rolling packets/sec over the last 60 seconds (performance hits different).
* Summary cards for active hosts, packets captured, alerts, and open ports.
* Prepend list of recent alert logs for quick triage.

### 🖥️ 2. Hosts (ARP Discovery) Tab
* Subnet sweeps comparing discoveries against a `trusted_hosts.json` baseline.
* Colored status badges to track device state: `TRUSTED` (green), `NEW` (cyan), `CHANGED` (amber), or `SUSPICIOUS` (red).
* Context menus for fast actions: port scans, MAC copy, and vendor lookups.

### 🛡️ 3. ARP Monitor Tab
* Continuous monitoring for IP-MAC mapping mismatches.
* Alerts you on unsolicited/gratuitous ARP replies that try to poison your routing table.
* Re-baseline hosts in one click.

### 🌐 4. DNS Monitor Tab
* Live DNS query stream displaying domain requests and lookup latency.
* Out-of-the-box anomaly detection: flags sus DNS tunneling (subdomains > 50 chars) and query rate spikes from single hosts.

### 📦 5. Packet Inspector Tab
* Raw packet streaming with protocol-specific color coding (TCP, UDP, ARP, ICMP, DNS).
* Interactive layer tree (Ethernet ➔ IP ➔ TCP ➔ Payload) with hex dumps and decoded fields.
* Save captures directly to standard `.pcap` files for deep Wireshark analysis.

### 🔍 6. Port Scanner Tab
* Highly parallel port scans using a configurable thread pool (1–500 threads).
* Supports TCP Connect, SYN scans, and UDP checks.
* Automated banner grabbing (256 bytes) and socket service identification.

### 📡 7. Rogue DHCP Detector Tab
* Dynamically learns the legitimate DHCP server from the first OFFER/ACK handshake.
* Instantly alerts if an unauthorized server begins leasing IP addresses on the network.

### 🔒 8. SSL/TLS Inspector Tab
* Pulls full certificate chains from target endpoints.
* Flags vulnerabilities: expired/expiring certs, self-signed signatures, weak hashing algorithms (MD5/SHA1), or domain name mismatches.

### 🕷️ 9. MITM Detector Tab
* 5-vector parallel detection engine checking for:
  1. Gateway MAC alterations (critical severity)
  2. Duplicate local IP conflicts
  3. ICMP redirect packets (type 5)
  4. Sudden gateway TTL shifts (indicates routing interception)
  5. MAC conflict consistency (multiple IPs sharing the same MAC)

### 📋 10. Unified Logs Tab
* One-stop-shop for all security events and module exceptions.
* Multi-parameter filter options (module, severity, timestamp) and persistent exports to CSV, JSON, or plain text.

---

## 🛠️ Stack & Aesthetic

NetWraith uses a minimalist cyber-themed design palette:
* **Background Dark:** `#0d0f14`
* **Panel BG:** `#1a1d24`
* **Accent Cyan:** `#00e5ff`
* **Danger Red:** `#ff4c4c`

We chose `pyqtgraph` over `matplotlib` for the rolling sparkline because rendering latency is simply not allowed.

---

## 🚀 Installation & Running

### Requirements
* Python 3.10+
* **Administrative Privileges** (Scapy needs raw socket capabilities. Run terminal as Admin on Windows or with `sudo` on Linux).
* **Npcap / libpcap** (Windows users: install [Npcap](https://npcap.com/) first. Linux users: `sudo apt install libpcap-dev`).

### Quick Start
```bash
# Clone the repository
git clone https://github.com/taezeem14/NetWraith.git
cd NetWraith

# Install dependencies (pure-Python dependencies install instantly)
pip install -r requirements.txt

# Run the analyzer (requires Admin/Sudo)
python netwraith.py
```

---

## ⚖️ Legal (Read the room)

> **FOR AUTHORIZED SECURITY RESEARCH & AUDITING ONLY.**
>
> NetWraith is designed for educational labs, authorized network administration, and legitimate security audits. interception of traffic on networks you do not own or lack written permission to analyze is illegal and highly cringe.
>
> Developers assume zero liability. The launch warning dialog cannot be bypassed or configured away. Protect your packets responsibly.

---

*Made with 💀, energy drinks, and zero tolerance for basic interfaces.*
