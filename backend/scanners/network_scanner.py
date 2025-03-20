from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP, sr, sr1, srp
import socket
import threading
import time
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db_handler import store_fingerprint


# ARP Scan for live hosts in a network
def arp_scan(network):
    
    print(f"[*] Sending ARP Request to {network}")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=3, verbose=0)
    return [recv.psrc for _, recv in answered]


# TCP SYN packets are sent to check which ports are open
def tcp_syn_scan(host, ports):
    open_ports = []  

    for port in ports:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=2, verbose=0)

        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12: 
                print(f"[+] Port {port} is OPEN")
                open_ports.append(port)
                sr1(IP(dst=host) / TCP(dport=port, flags="R"), timeout=1, verbose=0)  
            elif response[TCP].flags == 0x14: 
                print(f"[-] Port {port} is CLOSED")
        else:
            print(f"[!] Port {port} is FILTERED (No response)")

    return open_ports



# Scanning for UDP ports
def udp_scan(host, ports):
    for port in ports:
        pkt = IP(dst=host) / UDP(dport=port)
        response = sr1(pkt, timeout=3, verbose=0)
        
        if response is None:
            print(f"[?] UDP Port {port} is OPEN or FILTERED")
        elif response.haslayer(ICMP) and response[ICMP].type == 3:
            print(f"[-] UDP Port {port} is CLOSED")



#ICMP echo, timestamp and address mask requests 
def icmp_scan(host):
    packets = [IP(dst=host)/ICMP(), IP(dst=host)/ICMP(type=13), IP(dst=host)/ICMP(type=17)]
    responses, _ = sr(packets, timeout=2, verbose=0)
    
    for sent, received in responses:
        if received.haslayer(ICMP):
            print(f"[+] Received ICMP response from {host}: Type={received.type}, Code={received.code}")

            # ICMP Echo Reply (Ping response)
            if received.type == 0:
                print(f"    - {host} is UP (ICMP Echo Reply)")

            # ICMP Destination Unreachable
            elif received.type == 3:
                reason = {
                    0: "Net Unreachable",
                    1: "Host Unreachable",
                    2: "Protocol Unreachable",
                    3: "Port Unreachable",
                    4: "Fragmentation Needed",
                    5: "Source Route Failed"
                }.get(received.code, "Unknown reason")
                print(f"    - Destination Unreachable: {reason}")

            # ICMP Time Exceeded (TTL expired)
            elif received.type == 11:
                if received.code == 0:
                    print(f"    - TTL expired in transit")
                elif received.code == 1:
                    print(f"    - Fragment reassembly time exceeded")

            # ICMP Parameter Problem (Bad header fields)
            elif received.type == 12:
                print(f"    - Parameter problem in packet header")

            # ICMP Timestamp Reply
            elif received.type == 14:
                print(f"    - ICMP Timestamp Reply:")
                print(f"        - Original Timestamp: {received.ts_ori}")
                print(f"        - Received Timestamp: {received.ts_rx}")
                print(f"        - Transmit Timestamp: {received.ts_tx}")

            # ICMP Address Mask Reply
            elif received.type == 18:
                print(f"    - ICMP Address Mask Reply: Mask = {received.addr_mask}")

            # ICMP Router Advertisement
            elif received.type == 9:
                print(f"    - ICMP Router Advertisement received")

            # ICMP Router Solicitation
            elif received.type == 10:
                print(f"    - ICMP Router Solicitation received")

            # ICMP Redirect (Host/Network redirection)
            elif received.type == 5:
                redirect_reason = {
                    0: "Redirect for Network",
                    1: "Redirect for Host",
                    2: "Redirect for TOS & Network",
                    3: "Redirect for TOS & Host"
                }.get(received.code, "Unknown redirect reason")
                print(f"    - ICMP Redirect: {redirect_reason}")

            # Unknown ICMP Response
            else:
                print(f"    - Unknown ICMP response received (Type={received.type})")   



# OS detection based on TTL and TCP window size
def os_detection(host):
    pkt = IP(dst=host) / TCP(dport=80, flags="S")
    response = sr1(pkt, timeout=2, verbose=0)

    if response and response.haslayer(IP):
        ttl = response[IP].ttl
        window_size = response[TCP].window if response.haslayer(TCP) else 0

        if ttl <= 32:
            os_guess = "Very restricted system (e.g., embedded devices, routers)"
        elif 33 <= ttl <= 64:
            os_guess = "Linux/Unix (MacOS, Android, BSD)"
        elif 65 <= ttl <= 128:
            if window_size == 8192:
                os_guess = "Windows 7/8/10"
            elif window_size == 64240:
                os_guess = "Windows 10/11 (Modern TCP stack)"
            elif window_size == 5840:
                os_guess = "Old Linux Kernel (2.4)"
            else:
                os_guess = "Windows (General)"
        elif 129 <= ttl <= 255:
            os_guess = "Cisco/Networking Devices (Some UNIX variants)"
        else:
            os_guess = "Unknown OS"

        print(f"[+] OS likely {os_guess} (TTL={ttl}, Window={window_size})")

        # Store in database
        store_fingerprint(host, ttl, window_size, os_guess)


 
# Firewall detection 
def detect_firewall(host):

    pkt = IP(dst=host) / TCP(dport=80, flags="S")  
    responses = []

    for _ in range(3):
        response = sr1(pkt, timeout=2, verbose=0)
        responses.append(response)
        time.sleep(1)  

    if all(r is None for r in responses):
        print(f"[!] No response from {host}.")
        
        # Ping to check if the host is up
        icmp_response = sr1(IP(dst=host)/ICMP(), timeout=2, verbose=0)
        if icmp_response:
            print(f"[+] Host {host} is UP (ICMP Echo Reply received).")
            print("    🔹 Possible cause: Firewall is blocking TCP port 80.")
            
            # Scanning port 443 cause it's a common port
            alt_pkt = IP(dst=host) / TCP(dport=443, flags="S")
            alt_response = sr1(alt_pkt, timeout=2, verbose=0)
            if alt_response:
                print("[+] Port 443 is responding. Port 80 might be blocked by a firewall.")
            else:
                print("[!] No response on port 443 either. Strong firewall or host blocking all TCP traffic.")

        else:
            print(f"[!] No ICMP response from {host}.")
            print("    🔹 Possible causes: Host is down, Network issue, or Firewall blocking all traffic.")
    
    else:
        print(f"[+] {host} responded to TCP SYN. No firewall detected on port 80.")


def banner_grab(host, port):
    """Attempts to grab banners from open ports using different payloads."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore")
        sock.close()
        print(f"[+] Banner on {host}:{port}: {banner.strip()}")
    except Exception as e:
        print(f"[!] No banner from {host}:{port}: {e}")

def main():
    target = input("Enter target IP or network: ")
    
    if "/" in target:
        hosts = arp_scan(target)
    else:
        hosts = [target]
    
    print(f"[*] Found {len(hosts)} host(s): {', '.join(hosts)}")
    
    threads = []
    for host in hosts:
        print(f"\n[*] Scanning {host}")
        t1 = threading.Thread(target=icmp_scan, args=(host,))
        t2 = threading.Thread(target=os_detection, args=(host,))
        t3 = threading.Thread(target=detect_firewall, args=(host,))
        t4 = threading.Thread(target=tcp_syn_scan, args=(host, range(1, 1025)))
        t5 = threading.Thread(target=udp_scan, args=(host, range(1, 1025)))
        t1.start(), t2.start(), t3.start(), t4.start(), t5.start()
        threads.extend([t1, t2, t3, t4, t5])
    
    for t in threads:
        t.join()
    
    print("[+] Scanning complete!")

if __name__ == "__main__":
    main()