import nmap
from scapy.all import *
from scapy.all import IP, TCP, ARP, Ether
import socket

def scan_network(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-O -sV --script vuln")
    open_ports_by_host = {}
    
    for host in nm.all_hosts():
        print(f"\n[+] Host:{host} ({nm[host].hostname()})")
        print(f"      State: {nm[host].state()}")

        if 'osmatch' in nm[host]:
            print("     Operating System Details:")

            for os in nm[host]['osmatch']:
                print(f"            -{os['name']} (Accuracy: {os['accuracy']}%)")

        for protocol in nm[host].all_protocols():
            print(f"        Protocol: {protocol}")
            ports = nm[host][protocol].keys()
            for port in ports:
                service = nm[host][protocol][port]
                print(f"      Port {port}: {service['name']} ({service['state']})")

        if 'script' in nm[host]:
            print("      Vulnerabilities:")
            for script_id, script_output in nm[host]['script'].items():
                print(f"        - {script_id}: {script_output}")
        else:
            print("      No vulnerabilities found.")        

        open_ports = []
        for protocol in nm[host].all_protocols():
            for port in nm[host][protocol].keys():
                service = nm[host][protocol][port]
                if service['state'] == "open":
                    open_ports.append(port)
        open_ports_by_host[host] = open_ports

    return open_ports_by_host


def arp_scan(network):
    print(f"[*] Performing ARP scan on network: {network}")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=3, verbose=0)
    
    hosts = []
    for sent, received in answered:
        hosts.append(received.psrc)
    return hosts

def tcp_syn_scan(host, ports):
    open_ports = []
    print(f"[*] Scanning host {host} for open ports on: {ports}")
    for port in ports:
        # Craft a TCP SYN packet
        pkt = IP(dst=host)/TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=0)
        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12: 
                open_ports.append(port)
                rst_pkt = IP(dst=host)/TCP(dport=port, flags="R")
                sr1(rst_pkt, timeout=1, verbose=0)
    return open_ports

def grab_banner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        if port in [80, 443]:
            sock.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        elif port == 21:
            pass
        banner = sock.recv(1024)
        sock.close()
        return banner.decode(errors="ignore")
    except Exception as e:
        return ""

def analyze_banner(banner):
    vulns = []
    if "Apache/2.2" in banner:
        vulns.append("Apache 2.2 is outdated and may have multiple vulnerabilities.")
    if "Microsoft-IIS/6.0" in banner:
        vulns.append("IIS 6.0 is outdated and vulnerable to known exploits.")
    return vulns

def main():
    target_ip = input("Enter IP address or subnet to scan: ")
    open_ports_by_nmap = scan_network(target_ip)
    
    rigorous_scan = input("Do you want to perform a more rigorous scan using Scapy? (yes/no): ").strip().lower()
    if rigorous_scan == 'yes':
        if "/" in target_ip:
            print("[*] Starting ARP scan for host discovery...")
            hosts = arp_scan(target_ip)
        else:
            hosts = [target_ip]
        
        if not hosts:
            print("[!] No hosts found during ARP scan. Exiting.")
            return  
        
        print(f"[*] Found {len(hosts)} host(s): {', '.join(hosts)}")
        
        for host in hosts:
            print(f"\n[*] Scanning host: {host}")
            if host in open_ports_by_nmap and open_ports_by_nmap[host]:
                    ports_to_scan = open_ports_by_nmap[host]
                    print(f"[*] Using open ports from Nmap scan: {ports_to_scan}")
            else:
                ports_to_scan = range(1, 1025)
                print("[*] No open ports from Nmap; performing full scan (ports 1-1024).")
        
            syn_open_ports = tcp_syn_scan(host, ports_to_scan)
            if not syn_open_ports:
                print(f"[!] No open ports found on {host} with rigorous SYN scan.")
                continue
        
        print(f"[*] Open ports (rigorous SYN scan) on {host}: {', '.join(map(str, syn_open_ports))}")
        for port in syn_open_ports:
            banner = grab_banner(host, port)
            if banner:
                print(f"[*] Banner from {host}:{port}: {banner}")
                vulns = analyze_banner(banner)
                if vulns:
                    for vuln in vulns:
                        print(f"[!] Vulnerability found: {vuln}")
                else:
                    print("[*] No obvious vulnerabilities detected based on the banner.")
            else:
                print(f"[!] No banner retrieved from {host}:{port}.")
    else:
        print("[*] Skipping rigorous scan. Exiting.")

if __name__ == "__main__":
    main()