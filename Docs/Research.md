<h1 align="center"> Research Documentation 📃</h1>

This document contains my research on existing scanning tools and libraries, network and web vulnerabilities and CVE detection.


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
Majority of the data collected is from banners but the sad thing is that it is paid 💵. So if you are not a broke college student,buy it. I won't. Would have been cool though to passively scan the network using shodan and then moving on to active scanning.


## Scapy ⚙️

### About
This is a python library for intercepting network traffic. It performs sniffing, crafting and sending packets and also manipulates them. 


Fun Fact 🎈 (Learned it the hard way) : Scapy uses a function sniff() to capture packets and this function works just fine on Linux/Mac but windows like always has a problem with it. Which is why you need a system driver like npcap or winpcap(outdated now) to be able to capture packets. Whereas Linux/Mac allow direct raw socket access. So scapy directly interacts  with network interfaces using raw sockets (AF_INET). 

Windows I feel is like Gollum. Starts out with good intentions but you don't know when he will lose it and all hell will break loose.😏


## What will I use?
- Python-nmap /Nmap for active scanning of ports, OS and services: It would be beneficial to use Nmap's large database for such detection.
- Scapy for stealth scanning: It can craft raw packets to bypass firewalls and IDS if required.


# **Web scanning**

## Nikto 💎

### About
It is an open source web server scanner. Scans servers for misconfigurations, dangerous files and programs and even reveals outdated servers.

### Features
- **Banner Grabbing:** Performs banner grabbing to identify web server software and version. Then it checks if the version is outdated and what are the known vulnerabilities in that version.
- **File Checking:** It looks for files that might expose sensitive information.
- **SSL/TLS security check:** It checks for weak SSL/TLS (cryptographic protocols - TLS handshake to establish a secure connection) ciphers. Identifies issues with SSL/TLS certificate and hence can help prevent man in the middle attacks.

### Basic commands
- nikto -h IP_addr/domain_name


## OWASP ZAP 🤖

### About
It is a web application scanner developed by OWASP. It performs both active and passive scanning of the application.

### Features
- **Passive Scanning:** Monitors the request and response packets
- **Active Scanning:** Sends malicious payloads and tests for SQLi, XSS, etc
- **fuzzing:** It performs fuzzing to check for failures if malicious input is passed

### Basic Command
- zaproxy : Opens the GUI for ZAP. You enter the URL you wish to scan and hit attack. It gives you an active scan and shows all the alerts.


## BeautifulSoup 🍲

### About 
It is a python library used for web scraping (extracting data from websites). It parses HTML and XML documents.

### Features
- Extracts data using tags, attributes, classes, IDs
- Capable of navigating the DOM and modifying HTML
- It uses tools called parsers to read and understand HTML and XML. Most commomn are html5lib and lxml
- Latest version at the time I am writing this is beautifulsoup 4.13.2

## Requests 🧲

### About
It is a python library used to send HTTP requests and interact with websites and APIs

### Features
- It uses GET request to fetch data and POST to send data
- It can also send headers and parameters
- It works with beautiful soup where it fetches webpages that are then analysed and parsed by beautifulsoup


## What will I use?
- Requests to fetch webpages and analyze responses
- BeautifulSoup for web scraping
- Nikto to scan for vulnerabilities and misconfigurations in web servers
- Zap to perform active scanning and detect SQLi, XSS, etc


# **CVE Mapping and Exploit Detection**

## NIST NVD 🗃️

### About
It is a publicly available database managed by NIST. It stores CVE details.


## Exploit-DB 🪬

### About
It is a database which stores public exploits for known vulnerabilities.


## What will I use?
- NVD API to get a CVE list and severity of it for the versions detected
- Exploit-DB to query it and see if an exploit is available for the CVE

# **Challenges**
- Eliminating false positives in vulnerability detection
- Handling large scan results

Just for my reference : Most commonly used file formats are csv(table structure), json(key-value pairs), XML (tags), md(documentation on github), txt(normal text) 

# **References** 📚
- [Nmap Documentation](https://nmap.org/book/man.html)
- [Shodan Documentation](https://help.shodan.io/the-basics/what-is-shodan)
- [Scapy Documentation](https://scapy.readthedocs.io/en/latest/)
- [Nikto](https://cirt.net/nikto2)
- [OWASP ZAP](https://www.zaproxy.org/getting-started/)
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)
- [Requests](https://requests.readthedocs.io/en/latest/)
- [NIST National vulnerability Database](https://nvd.nist.gov/)
- [Exploit Database](https://www.exploit-db.com/?author=11688)

### Temporary
Phase 1 : Build the core scanner (network scanner, web scanner, CVE and exploit mapping) -----Python

Phase 2 : Build the web dashboard 
- Frontend: Main page(start scan- network, web, full), Results page (table + charts), Vulnerability details page (CVEs and fixes), Reports page (Download Scan results)
- Backend: API to trigger scans and retrieve results, database to store results (SQLite, PostgreSQL)

Phase 3 : Testing and advancement

Phase 4 : Final look on Github

vuln_scanner/
│── backend/
│   ├── scanner/
│   │   ├── network_scanner.py      # Uses Nmap & Scapy for network scanning
│   │   ├── web_scanner.py          # Uses OWASP ZAP, Nikto, Requests, BeautifulSoup
│   │   ├── cve_checker.py          # Maps detected versions to CVEs using NIST NVD
│   │   ├── exploit_lookup.py       # Checks Exploit-DB for known exploits
│   │   ├── utils.py                # Common helper functions
│   │   └── __init__.py
│   ├── api/
│   │   ├── api.py                   # Flask API to communicate with frontend
│   │   ├── database.py               # Handles saving scan results to a database
│   │   ├── models.py                 # Defines data structure for scan results
│   │   └── __init__.py
│   ├── config.py                     # Configuration file (API keys, database settings)
│   └── requirements.txt               # List of Python dependencies
│
│── frontend/
│   ├── static/
│   │   ├── styles.css                 # Styling for UI
│   │   ├── scripts.js                  # JavaScript for interactivity
│   ├── templates/
│   │   ├── index.html                  # Main UI page
│   │   ├── results.html                 # Page to display scan results
│   │   ├── report.html                  # Page to download reports
│   ├── app.py                           # Flask/Django backend for the web UI
│
│── docs/
│   ├── README.md                        # Project documentation
│   ├── research_paper.md                # Your research documentation
│   ├── API_docs.md                       # API documentation
│
│── scripts/
│   ├── install_dependencies.sh           # Script to install necessary tools
│   ├── run_scanner.sh                    # Script to run the scanner
│
└── .gitignore                            # Ignore unnecessary files for Git


