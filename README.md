# NetCrafts Network Recon Script

A Bash-based reconnaissance and documentation tool for mapping home/office networks as part of an introductory cyber security project.  
**This project was built for educational purposes, and fits the requirements of ThinkCyber's "Net Crafts" assignment.**

---

## 📋 Features

- **Scans the local network** for all connected devices (shows IP, MAC, Vendor, Hostname, Connection type)
- **Detects key infrastructure**: DNS, DHCP, Gateway (Router), ISP, and your public IP address
- **Performs external intelligence**: Looks up your public IP on Shodan and via WHOIS
- **Sniffs live traffic**: Identifies and explains the top 3 protocols seen on your network (e.g., TCP, UDP, ARP)
- **Generates a Markdown report** ready for PDF export and submission (`netcrafts_report.md`)

---

## 🚀 Usage

```bash
chmod +x Net\ Crafts.sh
sudo ./Net\ Crafts.sh
