<div align="center">

# 🐸 SAPO v1.1 — Beyond Deauthentication
### *Wireless Auditing & PNL Disclosure Tool*

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Scapy](https://img.shields.io/badge/Library-Scapy-red.svg)](https://scapy.net/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://www.linux.org/)
</div>

<div align="center">
  <a href="https://www.youtube.com/watch?v=mLPtlVVfAF4">
    <img src="https://github.com/user-attachments/assets/5644e0fc-1dab-4342-8bd8-74d97bf7ce1f" alt="SAPO in action" width="600">
  </a>
</div>

🐸 SAPO is an advanced wireless security auditing tool designed to automate handshake captures and extract intelligence through PNL (Preferred Network List) Disclosure.

## Disclaimer
This tool is provided for educational purposes and authorized ethical auditing only. Using 🐸 SAPO against networks without explicit permission is illegal. The author is not responsible for any misuse of this software.

## Why use 🐸 SAPO?
The true power of SAPO lies not just in disconnecting users, but in the intelligence gathered during the process:

**Handshake Capture for Cracking**
- 🐸 SAPO automates the injection of deauthentication frames to force clients to reconnect. During this reconnection, the tool captures the 4-way handshake, which is essential for performing offline brute-force or dictionary attacks to recover the network password using tools like Hashcat or John the Ripper.

**Hidden SSID Revelation**
- Many Access Points hide their SSID (Network Name). However, when a client attempts to connect to a hidden network, it broadcasts a "Probe Request" containing the network name. 🐸 SAPO analyzes these requests, allowing you to identify hidden SSIDs by correlating the activity of deauthenticated clients.

**Evil Twin Attack Preparation**
- By discovering the PNL (the list of preferred/trusted networks) of a target, an auditor knows exactly which network names the device considers "safe."
Strategy: If a client is probing for "Home_WiFi_123", you can set up a Rogue Access Point (Evil Twin) with that exact name. After deauthenticating them from their current network, the device will automatically connect to your rogue AP because it recognizes the SSID as a trusted one.

**Behavioral Profiling (OSINT)**
- A PNL acts as a digital footprint. Seeing a device probing for networks like "Sede_Office_A", "London_Heathrow_FreeWiFi", or "Luxury_Hotel_Spain" allows an auditor to build a geographical and professional profile of the target user based on their connection history.

## Main Features
- PNL Discovery: Real-time mapping of which MAC addresses are probing for which SSIDs.
- Deep Scanning: Color-coded Signal Power (PWR) visualization, channel tracking, and active client counting.
- Multichannel Intelligence: Integrated channel hopping engine to monitor the entire 2.4GHz spectrum (and 5GHz if supported) simultaneously before targeting.
- Automatic Conversion: Exports to .pcap and generates .hc22000 files compatible with Hashcat.
- Safe Restoration: Automatically reverts the network interface to its original "Managed" state upon exit.

## Recommended Hardware (Monitor Mode & Injection)
For 🐸 SAPO to work correctly, your wireless adapter must support Monitor Mode and Packet Injection. Below is a list of tested and compatible hardware:
- 💣 Alfa AWUS036ACM: Dual-band (2.4GHz/5GHz), MT7612U chipset. Excellent plug-and-play support in Linux.
- 💣 Alfa AWUS036ACH: Powerful dual-band, Realtek RTL8812AU chipset (requires driver installation).
- 💣 Alfa AWUS036NHA: 2.4GHz, Atheros AR9271 chipset. Extremely stable and native to Kali Linux.

# Installation
```bash
sudo apt update && sudo apt install hcxtools tcpdump -y
git clone https://github.com/far00t01/SAPO.git
cd SAPO
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage
```
sudo python3 sapo.py
```

## Output Files
Every session creates a folder named [SSID]-result/ containing:
- handshake.pcap: Raw traffic capture.
- handshake.hc22000: Hash formatted for Hashcat. You can crack the `.hc22000` file using: `hashcat -m 22000 handshake.hc22000 wordlist.txt` 
- pnl-discovery.txt: Detailed log of discovered networks per client. Note: PNL results may include false positives from networks intercepted while in transit. Connection HITS serve as the primary metric to filter and authenticate the most relevant networks for the auditor.

_⚠️ Note: PNL results may include "noise" or false positives from transient networks (e.g., airport or hotel Wi-Fi) intercepted while in transit. Connection HITS should be used as the primary metric to identify and validate high-confidence target networks._

## Author
_Developed by: Fabián Rosales [@far00t01](https://medium.com/@far00t01)_
