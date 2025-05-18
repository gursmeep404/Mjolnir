from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP, sr, sr1, srp, sniff
import threading
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db_handler import get_or_create_host, store_arp_results, store_tcp_results, store_udp_results,store_icmp_results,store_os_results,store_firewall_results, store_service_results,clear_old_packets, store_packet_summary

sniffer = None
sniffer_lock = threading.Lock()


def process_packet(packet):
    packet_summary = packet.summary()
    # print(f"Captured packet: {packet_summary}")

    global host_id  
    if host_id is not None:
        store_packet_summary(host_id, packet_summary)


# capturing packets in real time
def capture_packets():
    sniff(prn=process_packet, store=False)


# ARP Scan for live hosts in a network
def arp_scan(network):
    print(f"[*] Sending ARP Request to {network}")
    try:
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, _ = srp(packet, timeout=3, verbose=0)

        results = [recv.psrc for _, recv in answered]

        if not results:
            print("[!] No hosts responded to ARP request.")
        return results

    except Exception as e:
        print(f"[!] ARP scan failed for {network}: {e}")
        return []



# TCP SYN packets are sent to check which ports are open
def tcp_syn_scan(host, ports):
    global host_id

    open_ports = []
    closed_ports = []
    filtered_ports = []

    try:
        for port in ports:
            pkt = IP(dst=host) / TCP(dport=port, flags="S")
            response = sr1(pkt, timeout=2, verbose=0)

            if response is None:
                filtered_ports.append(port)
            elif response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    open_ports.append(port)
                    sr1(IP(dst=host) / TCP(dport=port, flags="R"), timeout=1, verbose=0)
                elif response[TCP].flags == 0x14:
                    closed_ports.append(port)

        if not (open_ports or closed_ports or filtered_ports):
            store_tcp_results(host_id, [], [], ["Scan Failed or No Response"])
        else:
            store_tcp_results(host_id, open_ports, closed_ports, filtered_ports)

        print(f"[+] Stored TCP scan results for {host}")
        return open_ports

    except Exception as e:
        print(f"[!] TCP scan failed for {host}: {e}")
        store_tcp_results(host_id, [], [], ["Scan Error"])
        return []
    


# Scanning for UDP ports
def udp_scan(host, ports):
    global host_id

    open_ports = []
    closed_ports = []
    filtered_ports = []

    try:
        for port in ports:
            pkt = IP(dst=host) / UDP(dport=port)
            response = sr1(pkt, timeout=3, verbose=0)

            if response is None:
                open_ports.append(port)  # Possible open/filtered
            elif response.haslayer(ICMP):
                icmp_type = response[ICMP].type
                icmp_code = response[ICMP].code
                if icmp_type == 3 and icmp_code == 3:
                    closed_ports.append(port)
                else:
                    filtered_ports.append(port)

        if not (open_ports or closed_ports or filtered_ports):
            store_udp_results(host_id, [], [], ["Scan Failed or No Response"])
        else:
            store_udp_results(host_id, open_ports, closed_ports, filtered_ports)

        print(f"[+] Stored UDP scan results for {host}")
        return open_ports

    except Exception as e:
        print(f"[!] UDP scan failed for {host}: {e}")
        store_udp_results(host_id, [], [], ["Scan Error"])
        return []




#ICMP echo, timestamp and address mask requests 
def icmp_scan(host):
    global host_id

    try:
        packets = [
            IP(dst=host) / ICMP(),               # Echo Request
            IP(dst=host) / ICMP(type=13),        # Timestamp Request
            IP(dst=host) / ICMP(type=17)         # Address Mask Request
        ]
        responses, _ = sr(packets, timeout=2, verbose=0)

        results = []

        for sent, received in responses:
            if received.haslayer(ICMP):
                response_details = {
                    'host': host,
                    'type': received.type,
                    'code': received.code,
                    'description': ''
                }

                if received.type == 0:
                    response_details['description'] = 'Host is UP (ICMP Echo Reply)'
                elif received.type == 3:
                    reason = {
                        0: "Net Unreachable",
                        1: "Host Unreachable",
                        2: "Protocol Unreachable",
                        3: "Port Unreachable",
                        4: "Fragmentation Needed",
                        5: "Source Route Failed"
                    }.get(received.code, "Unknown reason")
                    response_details['description'] = f'Destination Unreachable: {reason}'
                elif received.type == 11:
                    if received.code == 0:
                        response_details['description'] = 'TTL expired in transit'
                    elif received.code == 1:
                        response_details['description'] = 'Fragment reassembly time exceeded'
                elif received.type == 12:
                    response_details['description'] = 'Parameter problem in packet header'
                elif received.type == 14:
                    response_details['description'] = 'ICMP Timestamp Reply'
                    response_details['timestamps'] = {
                        'original': received.ts_ori,
                        'received': received.ts_rx,
                        'transmit': received.ts_tx
                    }
                elif received.type == 18:
                    response_details['description'] = f'ICMP Address Mask Reply: Mask = {received.addr_mask}'
                elif received.type == 9:
                    response_details['description'] = 'ICMP Router Advertisement received'
                elif received.type == 10:
                    response_details['description'] = 'ICMP Router Solicitation received'
                elif received.type == 5:
                    redirect_reason = {
                        0: "Redirect for Network",
                        1: "Redirect for Host",
                        2: "Redirect for TOS & Network",
                        3: "Redirect for TOS & Host"
                    }.get(received.code, "Unknown redirect reason")
                    response_details['description'] = f'ICMP Redirect: {redirect_reason}'
                else:
                    response_details['description'] = 'Unknown ICMP response received'

                results.append(response_details)

        if not results:
            results.append({
                'host': host,
                'type': None,
                'code': None,
                'description': 'No ICMP response received'
            })

        store_icmp_results(host_id, results)
        print(f"[+] Stored ICMP scan results for {host}")

    except Exception as e:
        print(f"[!] ICMP scan failed for {host}: {e}")
        store_icmp_results(host_id, [{
            'host': host,
            'type': None,
            'code': None,
            'description': 'ICMP scan error'
        }])

    



# OS detection based on TTL and TCP window size
def os_detection(host):
    global host_id

    try:
        pkt = IP(dst=host) / TCP(dport=80, flags="S")
        response = sr1(pkt, timeout=2, verbose=0)

        ttl = None
        window_size = None

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

        else:
            os_guess = "No response received - OS unknown"
            print(f"[!] No response from {host} for OS detection")

        store_os_results(host_id, ttl, window_size, os_guess)
        print(f"[+] Stored OS scan results for {host}")

    except Exception as e:
        print(f"[!] OS detection failed for {host}: {e}")
        store_os_results(host_id, None, None, "OS detection error")

    


 
# Firewall detection 
def detect_firewall(host):
    global host_id

    results = {
        'host': host,
        'tcp_syn_responses': [],
        'icmp_response': None,
        'port_443_response': None,
        'conclusion': None
    }

    try:
        pkt = IP(dst=host) / TCP(dport=80, flags="S")
        responses = []

        for _ in range(3):
            response = sr1(pkt, timeout=2, verbose=0)
            responses.append(response)
            time.sleep(1)

        results['tcp_syn_responses'] = responses

        if all(r is None for r in responses):
            icmp_response = sr1(IP(dst=host)/ICMP(), timeout=2, verbose=0)
            results['icmp_response'] = icmp_response

            if icmp_response:
                alt_pkt = IP(dst=host) / TCP(dport=443, flags="S")
                alt_response = sr1(alt_pkt, timeout=2, verbose=0)
                results['port_443_response'] = alt_response

                if alt_response:
                    results['conclusion'] = "Port 80 might be blocked by a firewall; Port 443 is responding."
                else:
                    results['conclusion'] = "Strong firewall or host blocking all TCP traffic; no response on ports 80 and 443."
            else:
                results['conclusion'] = "Host is down, network issue, or firewall blocking all traffic; no ICMP response."
        else:
            results['conclusion'] = "No firewall detected on port 80; host responded to TCP SYN."

    except Exception as e:
        print(f"[!] Firewall detection failed for {host}: {e}")
        results['conclusion'] = "Firewall detection failed due to an error."
        results['tcp_syn_responses'] = []
        results['icmp_response'] = None
        results['port_443_response'] = None

    store_firewall_results(
        host_id,
        results['tcp_syn_responses'],
        results['icmp_response'],
        results['port_443_response'],
        results['conclusion']
    )
    print(f"[+] Stored firewall scan results for {host}")



# Service Detection
def detect_service(host, port):

    global host_id
    print(f'hi, i am {port} ');
    known_services = {
    7: "Echo",
    9: "Discard",
    13: "Daytime",
    17: "Quote of the Day (QOTD)",
    19: "Chargen",
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "Time Protocol",
    42: "WINS Replication",
    43: "WHOIS",
    49: "TACACS",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    80: "HTTP",
    88: "Kerberos",
    109: "POP2",
    110: "POP3",
    111: "RPCbind / portmapper",
    113: "Ident / Authentication",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service / SMB",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    177: "XDMCP",
    179: "BGP",
    194: "IRC",
    201: "AppleTalk",
    264: "BGMP",
    311: "Apple AirPort Admin Utility",
    318: "TSP (Time Stamp Protocol)",
    383: "HP Data Protector",
    389: "LDAP",
    427: "SLP (Service Location Protocol)",
    443: "HTTPS",
    445: "Microsoft-DS / SMB over TCP",
    464: "Kerberos Change/Set Password",
    500: "ISAKMP / IKE",
    512: "rexec",
    513: "rlogin",
    514: "syslog",
    515: "LPD (Line Printer Daemon)",
    520: "RIP (Routing Information Protocol)",
    524: "NCP (NetWare Core Protocol)",
    530: "RPC",
    543: "klogin",
    544: "kshell",
    546: "DHCPv6 Client",
    547: "DHCPv6 Server",
    554: "RTSP",
    587: "SMTP (Submission)",
    631: "IPP (Internet Printing Protocol)",
    636: "LDAPS",
    646: "LDP (Label Distribution Protocol)",
    691: "MS Exchange Routing",
    860: "iSCSI",
    873: "rsync",
    902: "VMware Server Console",
    989: "FTPS (Data)",
    990: "FTPS (Control)",
    992: "Telnet over SSL",
    993: "IMAPS",
    995: "POP3S",
    1025: "Microsoft RPC (Dynamic)",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel (SSL)",
    2483: "Oracle DB Listener",
    2484: "Oracle DB Listener (SSL)",
    3306: "MySQL",
    3389: "RDP",
    3690: "Subversion (SVN)",
    4444: "Metasploit Handler",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    8000: "Common Web App Port",
    8008: "HTTP Alternative",
    8080: "HTTP Proxy / Alt",
    8443: "HTTPS Alt",
    8888: "Web Interface (Alt)"
}


    service_name = known_services.get(port, "Unknown")
    store_service_results(host_id, port, service_name)
    print(f"[+] Stored services results for {host}")

def scan_host(host):
    print(f"\n[*] Scanning {host}")
    icmp_scan(host)
    os_detection(host)
    detect_firewall(host)
    tcp_open_ports=tcp_syn_scan(host, range(1, 1025))
    udp_open_ports=udp_scan(host, range(1, 1025))

    for port in tcp_open_ports:
        detect_service(host, port)

    for port in udp_open_ports:
        detect_service(host, port)

def main():
    global host_id

    if len(sys.argv) < 2:
        print("Usage: python network_scanner.py <target_ip_or_network>")
        return

    target = sys.argv[1]

    host_id = get_or_create_host(target) 
    clear_old_packets(host_id)

    print(f"[+] Stored target '{target}' in database (host_id: {host_id})")
    
    if "/" in target:
        scanned_ips = arp_scan(target)
    else:
        scanned_ips = [target]
    
    store_arp_results(host_id, scanned_ips)
    print(f"[+] Stored {len(scanned_ips)} ARP results in database")

    sniffer_thread = threading.Thread(target=capture_packets, daemon=True)
    sniffer_thread.start()

    # Scan host() function run side by side for hosts 
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(scan_host, scanned_ips) 

    print("[+] Scanning complete!")

if __name__ == "__main__":
    main()
