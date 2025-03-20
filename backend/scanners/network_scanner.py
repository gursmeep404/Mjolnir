from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP, sr, sr1, srp
import socket
import threading
import time
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db_handler import store_fingerprint



def arp_scan(network):
    """Performs an ARP scan to detect live hosts in a local network."""
    print(f"[*] Sending ARP Request to {network}")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=3, verbose=0)
    return [recv.psrc for _, recv in answered]

def tcp_syn_scan(host, ports):
    """Performs a TCP SYN scan on the target host."""
    open_ports = []
    for port in ports:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=2, verbose=0)
        
        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:
                open_ports.append(port)
                sr1(IP(dst=host) / TCP(dport=port, flags="R"), timeout=1, verbose=0)
    return open_ports

def udp_scan(host, ports):
    """Performs a UDP scan on the target host."""
    for port in ports:
        pkt = IP(dst=host) / UDP(dport=port)
        response = sr1(pkt, timeout=3, verbose=0)
        
        if response is None:
            print(f"[?] UDP Port {port} is OPEN or FILTERED")
        elif response.haslayer(ICMP) and response[ICMP].type == 3:
            print(f"[-] UDP Port {port} is CLOSED")

def icmp_scan(host):
    """Sends ICMP Echo, Timestamp, and Address Mask requests."""
    packets = [IP(dst=host)/ICMP(), IP(dst=host)/ICMP(type=13), IP(dst=host)/ICMP(type=17)]
    responses, _ = sr(packets, timeout=2, verbose=0)
    
    for sent, received in responses:
        if received.haslayer(ICMP):
            if received.type == 0:
                print(f"[+] {host} is UP (ICMP Echo Reply)")

def detect_firewall(host):
    """Detects firewalls by analyzing packet loss and filtering behavior."""
    pkt = IP(dst=host) / TCP(dport=80, flags="S")
    responses = []
    for _ in range(3):
        response = sr1(pkt, timeout=2, verbose=0)
        responses.append(response)
        time.sleep(1)
    
    if all(r is None for r in responses):
        print(f"[!] Firewall detected on {host} (No responses)")

def os_detection(host):
    """Performs OS detection based on TTL and TCP Window Size."""
    pkt = IP(dst=host) / TCP(dport=80, flags="S")
    response = sr1(pkt, timeout=2, verbose=0)
    
    if response and response.haslayer(IP):
        ttl = response[IP].ttl
        window_size = response[TCP].window if response.haslayer(TCP) else 0
        os_guess = "Linux/Unix" if ttl <= 64 else "Windows" if 64 < ttl <= 128 else "Unknown"
        store_fingerprint(host,ttl, window_size, os_guess)
        print(f"[+] OS likely {os_guess} (TTL={ttl}, Window={window_size})")

         # Store in database
        store_fingerprint(host, ttl, window_size, os_guess)
        print(f"[+] OS likely {os_guess} (TTL={ttl}, Window={window_size})")

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
        t1.start(), t2.start(), t3.start(), t4.start()
        threads.extend([t1, t2, t3, t4])
    
    for t in threads:
        t.join()
    
    print("[+] Scanning complete!")

if __name__ == "__main__":
    main()