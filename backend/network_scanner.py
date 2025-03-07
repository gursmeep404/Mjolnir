import nmap

def scan_network(target):
    print('hi')
    nm = nmap.PortScanner()
    print('hi')
    nm.scan(hosts=target, arguments="-O -sV")
    print('hi')
    print(nm.all_hosts())
    for host in nm.all_hosts():
        print("hi")
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

                

if __name__ == "__main__":
    target_ip = input("Enter IP address or subnet to scan: ")
    scan_network(target_ip)