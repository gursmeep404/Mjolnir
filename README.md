![Project Logo](./frontend/public/headerpic.png "scanner")
[![Live Demo](https://img.shields.io/badge/Live-Demo-blue?logo=vercel)](https://mjolnir-uy37.vercel.app/)
![React](https://img.shields.io/badge/Frontend-React-blue?logo=react)
![Flask](https://img.shields.io/badge/Backend-Flask-yellow?logo=flask)
![MIT License](https://img.shields.io/badge/License-MIT-green.svg)
![Last Commit](https://img.shields.io/github/last-commit/16aurora/Mjolnir)
![Repo Size](https://img.shields.io/github/repo-size/16aurora/Mjolnir)
![Languages](https://img.shields.io/github/languages/count/16aurora/Mjolnir)
![Top Language](https://img.shields.io/github/languages/top/16aurora/Mjolnir)


---

Mjolnir is a web-based network scanner designed to analyze a specific IP address or an entire subnet to gather detailed network information. The scanner performs a range of active and passive reconnaissance techniques to provide insights into the network structure and host behavior. Later it also provides a list of CVEs for that IP which are fetched from The NVD.



## Table of Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
    - [Dependencies](#dependencies)
    - [Building the Project](#building-the-project)
- [Notes & Usage Tips](#notes--usage-tips)    
- [Limitations](#limitations)    
- [License](#license)    




## Features

**ICMP Scanning**: Sends multiple ICMP types (Echo, Timestamp, Mask) and interprets various response codes.

**Firewall Detection**: Detects firewall behavior by analyzing responses to TCP and ICMP packets.

**OS Detection**: Estimates the target's operating system using TTL and TCP window size analysis. Since it is a passive fingerprinting technique the exact details of the OS can not be provided.

**Port Scanning**: Classifies ports as open, filtered, or closed for both TCP and UDP services.

**Service Identification**: Maps open ports to common services using standard port-to-service mappings.

**Packet Summary**: Provides a concise summary of the captured packets exchanged during the scan.

**Database Handling**: Caching ensures subsequent scans of the same IP are significantly faster.

**CVE report** : A report of the detected vulnerabilities is generated using NVD API key.

**Web Interface**: Simple, intuitive interface accessible through a browser. No need for command-line tools.


## Limitations

- **Restricted IP Scanning**: The scanner may not be able to probe certain IP addresses due to security measures such as firewalls, intrusion detection systems, or rate-limiting policies that block or filter scan traffic. This is a common limitation shared by even well-known tools like Nmap.

-**OS Fingerprinting Accuracy**: The tool uses passive techniques for OS detection, relying on factors like TTL and TCP window size. As a result, the identified operating system may not be exact, and any inferred vulnerabilities might not accurately reflect the specific version or configuration in use.


- takes time so wait
- recommend to first test using your system's ip or loopback ip(fast)

deployed frontend link and screenshots



