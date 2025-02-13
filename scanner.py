import socket
import threading
import argparse
import nmap
from scapy.all import IP, TCP, sr1, send
from queue import Queue
import ipaddress

# Queue for Multi-threading
queue = Queue()

# Function to Perform Basic Port Scan using socket
def socket_scan(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout for connection attempt
        result = sock.connect_ex((target, port))  # 0 = Open, else Closed
        if result == 0:
            print(f"[+] {target}: Port {port} is OPEN")
        sock.close()
    except:
        pass

# Function to Perform SYN Scan using Scapy
def syn_scan(target, port):
    try:
        # Craft SYN packet
        syn_packet = IP(dst=target) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK response
                print(f"[+] {target}: Port {port} is OPEN (SYN Scan)")
                send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=0)  # Send RST
    except:
        pass

# Worker function for Multi-threaded Scanning
def threader(target):
    while not queue.empty():
        port = queue.get()
        socket_scan(target, port)  # Basic scan
        syn_scan(target, port)     # SYN stealth scan
        queue.task_done()

# Multi-threaded Port Scanner
def run_scan(target, ports=range(1, 1025)):
    print(f"\n🔍 Scanning {target} on {len(ports)} ports...\n")

    # Fill queue with ports
    for port in ports:
        queue.put(port)

    # Create & Start Threads
    for _ in range(50):  # 50 threads
        thread = threading.Thread(target=threader, args=(target,))
        thread.start()

    queue.join()

# Function to Use Nmap for Service & OS Detection
def nmap_scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-sV -O")  # -sV for service version, -O for OS detection

    print(f"\n📌 Nmap Results for {target}")
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")

        # Print open ports and services
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = scanner[host][proto].keys()
            for port in ports:
                service = scanner[host][proto][port]['name']
                print(f"  Port: {port} | Service: {service}")

        # OS Detection
        if "osmatch" in scanner[host]:
            print("\nPossible OS Matches:")
            for os in scanner[host]["osmatch"]:
                print(f"  {os['name']} (Accuracy: {os['accuracy']}%)")

# Function to Scan an Entire Network
def scan_network(network_cidr):
    print(f"\n🌐 Scanning Network: {network_cidr}")

    # Convert CIDR to a list of IPs
    network = ipaddress.ip_network(network_cidr, strict=False)

    for host in network.hosts():  # Exclude network/broadcast IPs
        print(f"\n🚀 Scanning Host: {host}")
        run_scan(str(host))
        nmap_scan(str(host))

# Parse Command-Line Arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Network & Web Vulnerability Scanner")
    parser.add_argument("--network", type=str, help="Network CIDR to scan (e.g., 192.168.1.1/24)")
    parser.add_argument("--target", type=str, help="Single IP or domain to scan")
    return parser.parse_args()

# Main Execution
if __name__ == "__main__":
    args = parse_args()

    if args.network:
        scan_network(args.network)  # Scan entire network
    elif args.target:
        run_scan(args.target)  # Scan single target
        nmap_scan(args.target)
    else:
        print("⚠️ Please provide either --network or --target. Use --help for more info.")
