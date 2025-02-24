<h1 align="center"> Research Documentation 📃</h1>

This document contains my research on existing scanning tools, network and web vulnerabilities and CVE detection.


# **Network Scanning**


## Nmap 🔍

### About
It is commonly used for security audits. It is opensource and uses Npcap system driver to capture traffic. It uses probes like ICMP echo requests, TCP/UDP packets, ARP requests, etc.

### Features
- **Port Scanning:** It sends specially crafted packets to the hosts and analyzes their response. Ports can be in either of the following states - Open, Closed, filtered or unfiltered or it could be a combination of two.Open ports are those which have an applicatin running on the target listening on them. Closed ports don't have any such application listening. We can recognise this by sending a SYN packet. If a SYN-ACK is recieved meaning port is open. If RST then it is closed. Filtered status we get when firewall blocks the Nmap probe and unfiltered when probes are not blocked but the target is unresponsive to them. In both cases we can't determine whether the port is open or closed.

- **OS Fingerprinting:** It performs fingerprinting of the TCP/IP Stack since every OS implements network protocols differently. This then helps identify the OS on the target machine

- **Service and Version Detection:** Nmap connects to the target machine's open ports using it's probes and then tries to determine which service is running. It also tells which version of the service is being used. When I say service it means protocols like SSH, HTTP, etc or web server applications like Apache.I also read that Nmap performs banner grabbing for this purpose. The banner is sent by the service running on the port and contains useful metadata like service name, software version, etc. Now, as far as I understood, sometimes the admin modifies the banners to avoid theft and hence nmap captures the banner and then checks with its database of already known banners to authenticate the service. I am not completely sure about this though. 

### Basic commands to run
- nmap --version
- nmap IP_addr
- nmap -sV Ip_addr


## Shodan 🌍

### About
It is a search engine for all devices on the internet.

### Features
Majority of the data collected is from banners but the sad thing is that it is paid 💵. So if you are not a broke college student,buy it but I won't. Would have been cool though to passively scan the network using shodan and then moving on to active scanning.


## Scapy ⚙️

### About
This is a python library for intercepting network traffic. It performs sniffing, crafting and sending packets and also manipulates them. 


Fun Fact 🎈 (Learned it the hard way) : Scapy uses a function sniff() to capture packets and this function works just fine on Linux/Mac but windows like always has a problem with it. Which is why you need a system driver like npcap or winpcap(outdated now) to be able to capture packets. Whereas Linux/Mac allow direct raw socket access. So scapy directly interacts  with network interfaces using raw sockets (AF_INET). 

Windows I feel is like Gollum. Starts out with good intentions but you don't know when he will lose it and all hell will break loose.😏


## What will I use?
- Nmap for active scanning of ports, OS and services: It would be beneficial to use Nmap's large database for such detection.
- Scapy for stealth scanning: It can craft raw packets to bypass firewalls and IDS if required.


# **Web scanning**

## Nikto 

### About
It is an open source web server scanner. Scans servers for misconfigurations, dangerous files and programs and even reveals outdated servers.

### Features
- **Banner Grabbing:** Performs banner grabbing to identify web server software and version. Then it checks if the version is outdated and what are the known vulnerabilities in that version.
- **File Checking:** It looks for files that might expose sensitive information.
- **SSL/TLS security check:** It checks for weak SSL/TLS (cryptographic protocols - TLS handshake to establish a secure connection) ciphers. Identifies issues with SSL/TLS certificate and hence can help prevent man in the middle attacks.

### Basic commands
- nikto -h IP_addr/domain_name


## OWASP ZAP

### About
It is a web application scanner developed


# **Web Vulnerabilities**

## SQLi

## XSS

## LFI

# **CVE Mapping and Exploit Detection**

# **Challenges**
- Eliminating false positives in vulnerability detection
- Handling large scan results

# **References** 📚
- [Nmap Documentation](https://nmap.org/book/man.html)
- [Shodan Documentation](https://help.shodan.io/the-basics/what-is-shodan)
- [Scapy Documentation](https://scapy.readthedocs.io/en/latest/)
- [Nikto](https://cirt.net/nikto2)
- [OWASP ZAP](https://www.zaproxy.org/getting-started/)
- [NIST National vulnerability Database](https://nvd.nist.gov/)
- [Exploit Database](https://www.exploit-db.com/?author=11688)