import nmap
from scapy.all import IP, TCP, ARP, Ether, srp, sr1
import socket
import time
from pymetasploit3.msfrpc import MsfRpcClient

# ---- Nmap Scan ---- #
def scan_network(target):
    nm = nmap.PortScanner()
    print(f"\n[*] Running Nmap scan on {target}...")
    nm.scan(hosts=target, arguments="-O -sV --script vuln --min-rate=5000")

    open_ports_by_host = {}

    for host in nm.all_hosts():
        print(f"\n[+] Host: {host} ({nm[host].hostname()})")
        print(f"    State: {nm[host].state()}")

        if 'osmatch' in nm[host]:
            print("    OS Details:")
            for os in nm[host]['osmatch']:
                print(f"      - {os['name']} (Accuracy: {os['accuracy']}%)")

        open_ports = []
        for protocol in nm[host].all_protocols():
            print(f"    Protocol: {protocol}")
            for port, service in nm[host][protocol].items():
                print(f"      Port {port}: {service['name']} ({service['state']})")
                if service['state'] == "open":
                    open_ports.append(port)

        open_ports_by_host[host] = open_ports

        # Check Vulnerabilities
        if 'script' in nm[host]:
            print("    Vulnerabilities Found:")
            for script_id, script_output in nm[host]['script'].items():
                print(f"      - {script_id}: {script_output}")

    return open_ports_by_host


# ---- ARP Scan ---- #
def arp_scan(network):
    print(f"\n[*] Performing ARP scan on {network}...")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=3, verbose=0)

    hosts = [received.psrc for sent, received in answered]
    print(f"[*] Discovered {len(hosts)} hosts: {', '.join(hosts)}")
    return hosts


# ---- TCP SYN Scan ---- #
def tcp_syn_scan(host, ports):
    open_ports = []
    print(f"\n[*] Performing SYN scan on {host} for ports {ports}...")
    
    for port in ports:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=0)

        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            open_ports.append(port)
            rst_pkt = IP(dst=host) / TCP(dport=port, flags="R")
            sr1(rst_pkt, timeout=1, verbose=0)

    print(f"[*] Open ports on {host}: {open_ports}")
    return open_ports


# ---- Banner Grabbing ---- #
def grab_banner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))

        if port in [80, 443]:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore")
        sock.close()
        return banner
    except:
        return None


# ---- Analyze Banner for Vulnerabilities ---- #
def analyze_banner(banner):
    vulns = []
    if "Apache/2.2" in banner:
        vulns.append("❌ Apache 2.2 is outdated (Security Risk)")
    if "Microsoft-IIS/6.0" in banner:
        vulns.append("❌ IIS 6.0 is vulnerable to known exploits.")
    return vulns


def check_vulns_with_msf(target):
    try:
        # Connect to Metasploit (Update IP & Password as needed)
        client = MsfRpcClient('mypassword', server='10.0.2.15', port=55553)

        # Use the MS17-010 Scanner Module
        scanner = client.modules.use('auxiliary', 'scanner/smb/smb_ms17_010')
        scanner['RHOSTS'] = target

        # Execute the scan
        job_id = scanner.execute()
        print(f"[*] MSF Scan for MS17-010 initiated on {target} (Job ID: {job_id})")

        # Wait for the scan to finish (adjust sleep time if needed)
        time.sleep(5)

        # Retrieve & display results
        jobs = client.jobs.list
        if str(job_id) not in jobs:
            print(f"[+] Scan completed for {target}")
        else:
            print(f"[-] Scan is still running...")

    except Exception as e:
        print(f"[!] Metasploit RPC Error: {e}")

# ---- Main Execution ---- #
def main():
    target_ip = input("Enter IP or subnet to scan: ")
    open_ports_by_nmap = scan_network(target_ip)

    # Rigorous Scanning Option
    rigorous_scan = input("\nDo you want a deeper scan with Scapy? (yes/no): ").strip().lower()
    if rigorous_scan == 'yes':
        if "/" in target_ip:
            print("[*] Running ARP scan to discover hosts...")
            hosts = arp_scan(target_ip)
        else:
            hosts = [target_ip]

        if not hosts:
            print("[!] No hosts found. Exiting.")
            return  

        for host in hosts:
            print(f"\n[*] Running SYN scan on {host}...")
            ports_to_scan = open_ports_by_nmap.get(host, list(range(1, 1025)))
            syn_open_ports = tcp_syn_scan(host, ports_to_scan)

            if not syn_open_ports:
                print(f"[!] No open ports found on {host}.")
                continue

            print(f"[*] Running Banner Grabbing on {host}...")
            for port in syn_open_ports:
                banner = grab_banner(host, port)
                if banner:
                    print(f"    Banner from {host}:{port}: {banner.strip()}")
                    vulns = analyze_banner(banner)
                    for vuln in vulns:
                        print(f"    [!] {vuln}")
                else:
                    print(f"    No banner retrieved from {host}:{port}.")

        # Run MSF Vulnerability Check
        use_msf = input("\nDo you want to check vulnerabilities with Metasploit? (yes/no): ").strip().lower()
        if use_msf == 'yes':
            target_ip = input("Enter target IP: ").strip()
            check_vulns_with_msf(target_ip)

    else:
        print("[*] Skipping rigorous scan. Exiting.")


if __name__ == "__main__":
    main()
