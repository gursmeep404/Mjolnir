from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP, sr, sr1, srp
from scapy.sendrecv import AsyncSniffer
import threading
import time
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db_handler import get_or_create_host, store_arp_results, store_tcp_results, store_udp_results,store_icmp_results,store_os_results,store_firewall_results, clear_old_packets, store_packet_summary

sniffer = None
sniffer_lock = threading.Lock()


def process_packet(packet):
    packet_summary = packet.summary()
    # print(f"Captured packet: {packet_summary}")

    global host_id  
    if host_id is not None:
        store_packet_summary(host_id, packet_summary)


# Starting asynchronous packet sniffer
def start_sniffer():
    global sniffer
    with sniffer_lock: 
        if sniffer is None:
            print("[+] Starting sniffer...")
            sniffer = AsyncSniffer(prn=process_packet, store=False)
            sniffer.start()

# Stopping the sniffer
def stop_sniffer():
    global sniffer
    with sniffer_lock:
        if sniffer is not None:
            print("[+] Stopping sniffer safely...")
            sniffer.stop()
            sniffer = None

# ARP Scan for live hosts in a network
def arp_scan(network):
    
    print(f"[*] Sending ARP Request to {network}")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=3, verbose=0)

    results = [recv.psrc for _, recv in answered]
    return [recv.psrc for _, recv in answered]


# TCP SYN packets are sent to check which ports are open
def tcp_syn_scan(host, ports):
    open_ports = []
    closed_ports = []
    filtered_ports = []

    for port in ports:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=2, verbose=0)

        if response is None:
            filtered_ports.append(port)
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x12: 
                open_ports.append(port)
                # Send RST to close the connection
                sr1(IP(dst=host) / TCP(dport=port, flags="R"), timeout=1, verbose=0)
            elif response[TCP].flags == 0x14: 
                closed_ports.append(port)

    host_id = get_or_create_host(host) 
    store_tcp_results(host_id, open_ports, closed_ports, filtered_ports)
    print(f"[+] Stored TCP scan results for {host}")
    


# Scanning for UDP ports
def udp_scan(host, ports):
    open_ports = []
    closed_ports = []
    filtered_ports = []

    for port in ports:
        pkt = IP(dst=host) / UDP(dport=port)
        response = sr1(pkt, timeout=3, verbose=0)

        if response is None:
            open_ports.append(port)  # Treat as open or filtered
        elif response.haslayer(ICMP):
            icmp_type = response[ICMP].type
            icmp_code = response[ICMP].code
            if icmp_type == 3 and icmp_code == 3:
                closed_ports.append(port)
            else:
                filtered_ports.append(port)

    host_id = get_or_create_host(host) 
    store_udp_results(host_id, open_ports, closed_ports, filtered_ports)
    print(f"[+] Stored UDP scan results for {host}")
    
    




#ICMP echo, timestamp and address mask requests 
def icmp_scan(host):
    packets = [IP(dst=host)/ICMP(), IP(dst=host)/ICMP(type=13), IP(dst=host)/ICMP(type=17)]
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

                # ICMP Echo Reply (Ping response)
                if received.type == 0:
                    response_details['description'] = 'Host is UP (ICMP Echo Reply)'

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
                    response_details['description'] = f'Destination Unreachable: {reason}'

                # ICMP Time Exceeded (TTL expired)
                elif received.type == 11:
                    if received.code == 0:
                        response_details['description'] = 'TTL expired in transit'
                    elif received.code == 1:
                        response_details['description'] = 'Fragment reassembly time exceeded'

                # ICMP Parameter Problem (Bad header fields)
                elif received.type == 12:
                    response_details['description'] = 'Parameter problem in packet header'

                # ICMP Timestamp Reply
                elif received.type == 14:
                    response_details['description'] = 'ICMP Timestamp Reply'
                    response_details['timestamps'] = {
                        'original': received.ts_ori,
                        'received': received.ts_rx,
                        'transmit': received.ts_tx
                    }

                # ICMP Address Mask Reply
                elif received.type == 18:
                    response_details['description'] = f'ICMP Address Mask Reply: Mask = {received.addr_mask}'

                # ICMP Router Advertisement
                elif received.type == 9:
                    response_details['description'] = 'ICMP Router Advertisement received'

                # ICMP Router Solicitation
                elif received.type == 10:
                    response_details['description'] = 'ICMP Router Solicitation received'

                # ICMP Redirect (Host/Network redirection)
                elif received.type == 5:
                    redirect_reason = {
                        0: "Redirect for Network",
                        1: "Redirect for Host",
                        2: "Redirect for TOS & Network",
                        3: "Redirect for TOS & Host"
                    }.get(received.code, "Unknown redirect reason")
                    response_details['description'] = f'ICMP Redirect: {redirect_reason}'

                # Unknown ICMP Response
                else:
                    response_details['description'] = 'Unknown ICMP response received'

                results.append(response_details)
    host_id = get_or_create_host(host) 
    store_icmp_results(host_id, results)
    print(f"[+] Stored ICMP scan results for {host}")
    



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

    host_id = get_or_create_host(host) 
    store_os_results(host_id, ttl, window_size, os_guess)
    print(f"[+] Stored OS scan results for {host}")
    


 
# Firewall detection 
def detect_firewall(host):
    results = {
        'host': host,
        'tcp_syn_responses': [],
        'icmp_response': None,
        'port_443_response': None,
        'conclusion': None
    }

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

    host_id = get_or_create_host(host) 
    store_firewall_results(host_id, results['tcp_syn_responses'], results['icmp_response'], results['port_443_response'], results['conclusion'])
    print(f"[+] Stored firewall scan results for {host}")

    


# def banner_grab(host, port):
#     """Attempts to grab banners from open ports using different payloads."""
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(3)
#         sock.connect((host, port))
#         sock.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
#         banner = sock.recv(1024).decode(errors="ignore")
#         sock.close()
#         print(f"[+] Banner on {host}:{port}: {banner.strip()}")
#     except Exception as e:
#         print(f"[!] No banner from {host}:{port}: {e}")


def main():

    global host_id

    target = input("Enter target IP or network: ")

    host_id = get_or_create_host(target) 

    clear_old_packets(host_id)

    print(f"[+] Stored target '{target}' in database (host_id: {host_id})")
    
    if "/" in target:
        scanned_ips = arp_scan(target)
    else:
        scanned_ips = [target]
    
    store_arp_results(host_id, scanned_ips)
    print(f"[+] Stored {len(scanned_ips)} ARP results in database")
    # print(f"[*] Found {len(hosts)} host(s): {', '.join(hosts)}")
    
    start_sniffer()

    threads = []
    for host in scanned_ips:
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

    stop_sniffer()    
    
    print("[+] Scanning complete!")

if __name__ == "__main__":
    main()