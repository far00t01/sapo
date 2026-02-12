# sapo
SAPO is an advanced wireless auditing tool designed to automate handshake captures and extract intelligence through PNL (Preferred Network List) disclosure from client devices.



### Disclaimer
This tool is provided for educational purposes and authorized ethical auditing only. Using SAPO against networks without explicit permission is illegal. The author is not responsible for any misuse of this software.

_Developed by: Fabián Rosales (@far00t01)_

### Why use SAPO
The true power of SAPO lies not just in disconnecting users, but in the intelligence gathered during the process:

- Handshake Capture for Cracking
SAPO automates the injection of deauthentication frames to force clients to reconnect. During this reconnection, the tool captures the 4-way handshake, which is essential for performing offline brute-force or dictionary attacks to recover the network password using tools like Hashcat or John the Ripper.

- Hidden SSID Revelation
Many Access Points hide their SSID (Network Name). However, when a client attempts to connect to a hidden network, it broadcasts a "Probe Request" containing the network name. SAPO analyzes these requests, allowing you to identify hidden SSIDs by correlating the activity of deauthenticated clients.

- Evil Twin Attack Preparation
By discovering the PNL (the list of preferred/trusted networks) of a target, an auditor knows exactly which network names the device considers "safe."
Strategy: If a client is probing for "Home_WiFi_123", you can set up a Rogue Access Point (Evil Twin) with that exact name. After deauthenticating them from their current network, the device will automatically connect to your rogue AP because it recognizes the SSID as a trusted one.

- Behavioral Profiling (OSINT)
A PNL acts as a digital footprint. Seeing a device probing for networks like "Sede_Office_A", "London_Heathrow_FreeWiFi", or "Luxury_Hotel_Spain" allows an auditor to build a geographical and professional profile of the target user based on their connection history.

### Main Features
- PNL Discovery: Real-time mapping of which MAC addresses are probing for which SSIDs.
- Deep Scanning: Color-coded Signal Power (PWR) visualization, channel tracking, and active client counting.
- Automatic Conversion: Exports to .pcap and generates .hc22000 files compatible with Hashcat.
- Safe Restoration: Automatically reverts the network interface to its original "Managed" state upon exit.

##### Recommended Hardware (Monitor Mode & Injection)
For SAPO to work correctly, your wireless adapter must support Monitor Mode and Packet Injection. Below is a list of tested and compatible hardware:
- Alfa AWUS036ACM: Dual-band (2.4GHz/5GHz), MT7612U chipset. Excellent plug-and-play support in Linux.
- Alfa AWUS036ACH: Powerful dual-band, Realtek RTL8812AU chipset (requires driver installation).
- Alfa AWUS036NHA: 2.4GHz, Atheros AR9271 chipset. Extremely stable and native to Kali Linux.

## Installation & Usage
```
git clone https://github.com/your-username/SAPO.git
cd SAPO
pip install -r requirements.txt
```
```
sudo python3 sapo.py
```

### Output Files
Every session creates a folder named [SSID]-result/ containing:
- handshake.pcap: Raw traffic capture.
- handshake.hc22000: Hash formatted for Hashcat.
- pnl-discovery.txt: Detailed log of discovered networks per client.

