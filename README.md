# 🕸️ NetWraith v1.0

> *your network's sleep paralysis demon* 💀

## bro what is this

NetWraith is a **network security analyzer** that watches your network like a paranoid security guard who had too much coffee. Built with Python, Scapy, and pure unhinged energy.

it's basically wireshark if wireshark was a goth kid who actually understood networking

## ✨ features that go hard

- 📊 **Real-time Dashboard** — live stats, graphs, and network activity that hits different
- 🖥️ **Host Discovery** — finds every device on your network faster than your mom finds your browser history
- 🛡️ **ARP Spoofing Detection** — catches ARP poisoning attacks like a network bouncer
- 🌐 **DNS Monitoring** — watches DNS queries like a hawk with a PhD in networking
- 📦 **Packet Capture** — sniffs packets with protocol-level color coding (it's giving wireshark but aesthetic)
- 🔍 **Port Scanner** — scans ports faster than you can say "nmap" (ok maybe not THAT fast but still)
- 📡 **Rogue DHCP Detection** — finds unauthorized DHCP servers trying to be sneaky
- 🔒 **SSL/TLS Inspector** — checks certificates so you don't get catfished by fake websites
- 🕷️ **MITM Detection** — continuous monitoring for gateway MAC changes, ICMP redirects, TTL anomalies, duplicate IPs, and ARP table inconsistencies
- 📋 **Logging System** — keeps receipts of everything (accountability queen 👑)

## 🚀 installation (it's not that deep)

```bash
# clone the repo (duh)
git clone https://github.com/yourusername/NetWraith.git
cd NetWraith

# install dependencies
pip install -r requirements.txt

# run it (you need admin/root btw, raw sockets are needy like that)
python netwraith.py
```

## ⚠️ requirements

- Python 3.10+ (we're not cavemen)
- **Admin/Root privileges** (scapy needs raw socket access, skill issue if you can't get it)
- Windows/Linux/macOS (we don't discriminate)
- A network to analyze (obviously)

## 📦 dependencies

| Package | Why |
|---------|-----|
| `scapy` | packet crafting & sniffing (the backbone fr) |
| `PyQt6` | GUI framework (making it pretty) |
| `pyqtgraph` | real-time graphs (because matplotlib is too slow and we have standards) |
| `netifaces` | network interface detection (knowing what we're working with) |
| `cryptography` | SSL/TLS certificate analysis (trust issues but make it technical) |
| `mac-vendor-lookup` | MAC address vendor identification (doxxing your devices /j) |
| `requests` | HTTP requests (for API lookups) |

## 🎨 the aesthetic

NetWraith uses a **dark cyber theme** because we're not animals. Think cyberpunk meets professional security tool. The UI features:
- Dark backgrounds (`#0d0f14`, `#1a1d24`)
- Cyan accents (`#00e5ff`) for that hacker aesthetic
- Red alerts (`#ff4c4c`) for when things get spicy
- Color-coded everything because we're extra like that

## 🔧 usage tips

1. **Select your network interface** from the dropdown (it auto-detects, we're thoughtful like that)
2. **Hit Start Monitoring** and watch the packets flow
3. **Check the Dashboard** for the big picture
4. **Explore tabs** for specific analysis tools
5. **Export logs** when you need receipts

## ⚖️ legal stuff (boring but necessary)

> **FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**
>
> Using this tool against networks you don't own or have permission to test is illegal and cringe. Don't be that person. NetWraith is designed for:
> - Learning about network security
> - Testing YOUR OWN network
> - Authorized penetration testing
> - Network administration
>
> The developers are not responsible for misuse. Period. No cap.

## 🤝 contributing

Pull requests are welcome. For major changes, please open an issue first because we need to talk about it.

## 📜 license

MIT License — because sharing is caring

---

*made with 💀 and an unhealthy amount of energy drinks*

*"i'm not paranoid, my network traffic is just interesting"* — NetWraith, probably
