
# Net Crafts

A Bash-powered network reconnaissance and mapping toolkit for cybersecurity fundamentals.

## 📋 Project Overview

**Net Crafts** is a comprehensive Bash script designed to automate the process of mapping your local network, identifying all connected devices, their MAC addresses (with vendor), connection type (Ethernet/Wi-Fi), DNS/DHCP servers, and external IP/ISP information.  
The script also performs protocol sniffing, analyzes your network’s public presence using Shodan and WHOIS, and generates a detailed markdown report.

## 🚀 Features

- **Network Mapping**
  - Automatically scans and lists all active devices on the local network (using `nmap`).
  - Displays each device’s:
    - **IP Address**
    - **MAC Address** (and Vendor lookup via online APIs)
    - **Hostname**
    - **Connection Type** (Ethernet/Wi-Fi)
  - Identifies the router’s internal and external IP addresses.
  - Shows DNS and DHCP server addresses in the network.

- **ISP and Public IP Intelligence**
  - Fetches and displays public IP address.
  - Identifies the ISP (via `ipinfo.io`).
  - Provides a direct link to your Shodan page for your public IP.
  - Fetches WHOIS registration data for the public IP.

- **Protocol Sniffing & Analysis**
  - Captures real network traffic (`tcpdump`) and detects the top 3 network protocols in use (e.g., TCP, UDP, ARP).
  - For each detected protocol, provides a usage explanation and common port numbers.

- **Automated Report Generation**
  - Generates a detailed Markdown report (`netcrafts_report.md`) containing all network findings, protocol details, and a template for your network diagram.

- **User-Friendly**
  - Colored, formatted CLI output.
  - Interactive prompts for choosing network interface and packet capture count.
  - Automatic dependency check (installs missing tools if approved).

## 🛠️ Usage

1. **Clone the repository**
   ```bash
   git clone https://github.com/elior2000/Net-Crafts.git
   cd Net-Crafts
   ```

2. **Make the script executable**
   ```bash
   chmod +x Net\ Crafts.sh
   ```

3. **Run the script**  
   (For full scanning and packet capture, use `sudo`.)
   ```bash
   sudo ./Net\ Crafts.sh
   ```

4. **Follow the interactive prompts:**
   - Select the network interface for scanning/sniffing.
   - Choose the number of packets to capture for protocol analysis.

5. **Report Output**
   - The script creates a Markdown report file: `netcrafts_report.md`.
   - Convert the report to PDF for submission using tools like [pandoc](https://pandoc.org/) or any Markdown-to-PDF converter.

6. **Draw your network diagram**
   - Use [draw.io](https://draw.io) or [diagrams.net](https://diagrams.net) to create a network schema, and attach/export it as instructed in your project guidelines.

## 📦 Requirements

- Bash (v4+)
- **Mandatory Tools:**  
  `nmap`, `arp`, `curl`, `whois`, `awk`, `grep`, `hostname`, `ip`, `iwgetid`, `tcpdump`, `jq`
- Internet access (for vendor lookup, ISP info, and public APIs)
- `sudo` permissions recommended for network scanning and packet capture

## 📑 Project Structure

- `Net Crafts.sh` — Main Bash script
- `netcrafts_report.md` — Generated Markdown report
- `README.md` — This documentation file

## 🖥️ Example Output

```
--------------------------------------------------------
 NetCrafts Network Recon Script (Project Version)
--------------------------------------------------------
Date: 2025-07-12 20:05:05

Detected Network Range: 192.168.1.0/24
Local IP: 192.168.1.xxx
Gateway (Router) IP: 192.168.1.1
DNS Servers: 8.8.8.8, 1.1.1.1
DHCP Server: 192.168.1.1

Active Devices on Network:
+---------------+-------------------+------------------------+--------------------+--------+
|     IP        |    MAC Address    |        Vendor          |      Host          | Conn   |
+---------------+-------------------+------------------------+--------------------+--------+
| 192.168.1.1   | 00:11:XX:XX:XX:XX | Example Vendor         | router             | Ethernet |
| 192.168.1.200 | AA:BB:XX:XX:XX:XX | Example Vendor         | device1            | Wi-Fi    |
...

Your Public IP: xxx.xxx.xxx.xxx
ISP: N/A
Shodan link for your IP: https://www.shodan.io/host/xxx.xxx.xxx.xxx

WHOIS result for your Public IP:
OrgName: N/A
Country: N/A
...

Top 3 Protocols Detected (tcpdump 30 packets on eth0):
  15 TCP
  10 UDP
   5 ARP

| Protocol | Usage Explanation                                  | Example Port(s)   |
|----------|----------------------------------------------------|-------------------|
| TCP      | Reliable, connection-oriented (web, email, FTP)    | 80 (HTTP), 443    |
| UDP      | Fast, connectionless (streaming, DNS, VoIP)        | 53 (DNS), 67      |
| ARP      | Resolves IP to MAC on local networks               | N/A               |
```

## 📃 License

This project was created for the ThinkCyber “Intro to Cyber” program (XE101) as an educational exercise.  
Feel free to adapt or reuse with credit.

---

**Created by Elior Salimi**  
Intro to Cyber — Project: Net Crafts

[View on GitHub](https://github.com/elior2000/Net-Crafts)
