#!/bin/bash

# NetCrafts - Network Recon Script (Project Ready Version)
# Author: [Elior Salimi]
# Version: 2.1
# Last Update: [10/07/2025]

# ----------- DEPENDENCY CHECK -----------
REQUIRED_CMDS=("nmap" "arp" "curl" "whois" "awk" "grep" "hostname" "ip" "iwgetid" "tcpdump" "jq")
PKG_MANAGER=""
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman"
fi

echo -e "\033[1;33mChecking dependencies...\033[0m"
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v $cmd &>/dev/null; then
        echo -e "\033[0;31mMissing: $cmd\033[0m"
        echo -e "\033[1;33mThis script will not work without '$cmd'.\033[0m"
        read -p "Do you want to install '$cmd' now? [Y/n]: " answer
        answer=${answer:-Y}
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            case $PKG_MANAGER in
                apt) sudo apt-get update -y; sudo apt-get install -y $cmd ;;
                dnf) sudo dnf install -y $cmd ;;
                yum) sudo yum install -y $cmd ;;
                pacman) sudo pacman -Sy --noconfirm $cmd ;;
                *) echo "No supported package manager found! Please install $cmd manually."; exit 1 ;;
            esac
        else
            echo -e "\033[1;31m'$cmd' is required. The script will exit now.\033[0m"
            exit 1
        fi
    fi
done
echo -e "\033[0;32mAll required dependencies are installed!\033[0m\n"

# ----------- COLORS -----------
NC='\033[0m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'

print_banner() {
    echo -e "${CYAN}--------------------------------------------------------"
    echo -e " NetCrafts Network Recon Script (Project Version)"
    echo -e "--------------------------------------------------------${NC}"
    echo -e "${YELLOW}Date: $(date "+%Y-%m-%d %H:%M:%S")${NC}\n"
}

detect_network_range() {
    NET_CIDR=$(ip -o -f inet addr show | awk '/scope global/ {print $4; exit}')
    if [[ -z "$NET_CIDR" ]]; then
        NET_CIDR="192.168.1.0/24"
    fi
    echo "$NET_CIDR"
}

get_local_ip() {
    ip route get 1 | awk '{print $7; exit}'
}

get_gateway_ip() {
    ip route | grep default | awk '{print $3}' | head -n 1
}

get_dns_servers() {
    grep "nameserver" /etc/resolv.conf | awk '{print $2}' | paste -sd ', ' -
}

get_dhcp_server() {
    # Option 1: Try to get DHCP server via nmcli (if NetworkManager exists)
    if command -v nmcli &>/dev/null; then
        dhcp_ip=$(nmcli dev show | grep 'DHCP4.OPTION' | grep 'server' | awk -F' ' '{print $2}' | awk -F'=' '{print $2}' | head -n 1)
        if [[ ! -z "$dhcp_ip" ]]; then echo "$dhcp_ip"; return; fi
    fi
    # Option 2: Try to get from lease file (for dhclient)
    dhcp_ip=$(grep -m1 dhcp-server-identifier /var/lib/dhcp/*.lease 2>/dev/null | awk '{print $3}' | tr -d ';')
    if [[ ! -z "$dhcp_ip" ]]; then echo "$dhcp_ip"; return; fi
    # Option 3: Assume gateway is DHCP server
    gateway=$(get_gateway_ip)
    echo "$gateway"
}

# ----------- VENDOR LOOKUP -----------
get_vendor_clean() {
    local mac="$1"
    local vendor=""
    # macvendors.com
    vendor=$(curl -s --max-time 3 "https://api.macvendors.com/$mac")
    if [[ "$vendor" != *"error"* && "$vendor" != *"Too Many Requests"* && "$vendor" != *"Not Found"* && -n "$vendor" ]]; then
        echo "$vendor"
        return
    fi
    # macaddress.io (RECOMMENDED: put your own apiKey)
    MACADDRESS_API_KEY="at_demo"
    vendor=$(curl -s --max-time 5 "https://api.macaddress.io/v1?output=json&search=$mac&apiKey=$MACADDRESS_API_KEY" | jq -r '.vendorDetails.companyName')
    if [[ "$vendor" != "null" && "$vendor" != "" ]]; then
        echo "$vendor"
        return
    fi
    # wifi-api.com
    vendor=$(curl -s --max-time 6 "https://www.wifi-api.com/api/mac-address-lookup?mac=$mac" | jq -r '.result.company')
    if [[ "$vendor" != "null" && "$vendor" != "" ]]; then
        echo "$vendor"
        return
    fi
    echo "Unknown Vendor"
}

get_local_devices() {
    nmap -sn "$NETWORK_RANGE" | grep "Nmap scan report for" | awk '{print $NF}' | tr -d '()' > /tmp/nmap_ips.txt
    while read ip; do ping -c 1 -W 1 "$ip" > /dev/null 2>&1; done < /tmp/nmap_ips.txt
    # Table
    printf "\n${CYAN}Active Devices on Network:${NC}\n"
    printf '+-----------------+-------------------+--------------------------+----------------------+----------+\n'
    printf '| %-15s | %-17s | %-24s | %-20s | %-8s |\n' "IP" "MAC" "Vendor" "Host" "Conn"
    printf '+-----------------+-------------------+--------------------------+----------------------+----------+\n'
    while read ip; do
        mac=$(arp -an "$ip" | grep -oE "(([A-Fa-f0-9]{2}[:-]){5}[A-Fa-f0-9]{2})")
        vendor="Unknown Vendor"
        if [[ ! -z $mac ]]; then
            vendor=$(get_vendor_clean "$mac")
        else
            mac="Unknown"
        fi
        host=$(nslookup $ip 2>/dev/null | awk -F'= ' '/name/ {print $2}' | sed 's/\.$//')
        [[ -z $host ]] && host="Unknown"
        if [[ $ip == "$(get_local_ip)" ]]; then
            if iwgetid -r >/dev/null 2>&1; then
                conn="Wi-Fi"
            else
                conn="Ethernet"
            fi
        else
            conn="Unknown"
        fi
        vendor_disp=$(echo "$vendor" | cut -c 1-24)
        host_disp=$(echo "$host" | cut -c 1-20)
        printf '| %-15s | %-17s | %-24s | %-20s | %-8s |\n' "$ip" "$mac" "$vendor_disp" "$host_disp" "$conn"
    done < /tmp/nmap_ips.txt
    printf '+-----------------+-------------------+--------------------------+----------------------+----------+\n\n'
}

get_public_ip() {
    curl -s ifconfig.me
}

get_isp() {
    curl -s ipinfo.io/org
}

shodan_link() {
    pubip=$(get_public_ip)
    echo "https://www.shodan.io/host/$pubip"
}

run_whois() {
    pubip=$(get_public_ip)
    whois $pubip | grep -E "OrgName|org|Organization|country|address|netname|owner" | head -10
}

protocol_explanation_markdown() {
    proto=$1
    case "$proto" in
        TCP|tcp) echo "| TCP | Reliable, connection-oriented (web, email, file transfers). | 80 (HTTP), 443 (HTTPS) |" ;;
        UDP|udp) echo "| UDP | Fast, connectionless (streaming, DNS, VoIP, etc). | 53 (DNS), 67 (DHCP) |" ;;
        ARP|arp) echo "| ARP | Resolves IP to MAC on local networks. | N/A |" ;;
        ICMP|icmp) echo "| ICMP | Diagnostics and error reporting (ping, traceroute). | N/A |" ;;
        IP|ip) echo "| IP | Responsible for addressing and routing packets (Internet). | N/A |" ;;
        IGMP|igmp) echo "| IGMP | Manages multicast group memberships (IPv4). | N/A |" ;;
        IP6|ip6|IPv6|ipv6) echo "| IP6 | IPv6: Next-generation Internet Protocol (addressing and routing for IPv6 networks). | N/A |" ;;
        ETHER|ether) echo "| ETHER | Ethernet: Used for LAN frames and communication over wired networks. | N/A |" ;;
        DHCP|dhcp) echo "| DHCP | Dynamic Host Configuration Protocol, assigns IPs to hosts automatically. | 67, 68 |" ;;
        DNS|dns) echo "| DNS | Domain Name System, translates domain names to IP addresses. | 53 |" ;;
        HTTP|http) echo "| HTTP | Hypertext Transfer Protocol, used for web traffic. | 80 |" ;;
        HTTPS|https) echo "| HTTPS | Secure Hypertext Transfer Protocol (encrypted web traffic). | 443 |" ;;
        *) echo "| $proto | [No info available. Consider adding a custom explanation.] | N/A |" ;;
    esac
}

# ----------- MAIN INTERACTION -----------
echo "Available interfaces:"
ip -o link show | awk -F': ' '{print $2}'
read -p "Enter interface for sniffing (default: eth0): " INTERFACE
INTERFACE=${INTERFACE:-eth0}
read -p "How many packets to capture for protocol analysis? [Default: 30]: " PACKET_COUNT
PACKET_COUNT=${PACKET_COUNT:-30}

TCPDUMP_TMP="/tmp/tcpdump_netcrafts.txt"
echo -e "\n${CYAN}Capturing $PACKET_COUNT packets on $INTERFACE (this might take a few seconds)...${NC}"
sudo tcpdump -i $INTERFACE -c $PACKET_COUNT -nn -q 2>/dev/null > "$TCPDUMP_TMP"

get_top_protocols_arr() {
    awk '{print $2}' "$TCPDUMP_TMP" | sort | uniq -c | sort -nr | head -3 | awk '{print $2}'
}

sniff_protocols() {
    echo -e "${CYAN}Sniffing top 3 network protocols (tcpdump, $PACKET_COUNT packets on $INTERFACE)...${NC}"
    echo "(analyzing captured packets...)"
    mapfile -t top_protocols < <(get_top_protocols_arr)
    for proto in "${top_protocols[@]}"; do
        count=$(awk '{print $2}' "$TCPDUMP_TMP" | grep -c "^$proto$")
        echo "  $count $proto"
    done
    export TOP_PROTOCOLS_LIST="${top_protocols[*]}"
    echo -e "${YELLOW}Tip:${NC} Protocol is usually 3rd column (tcp, udp, arp, etc)."
    if [[ "${#top_protocols[@]}" -eq 1 && "${top_protocols[0]}" == "IP" ]]; then
        echo -e "${YELLOW}Notice:${NC} Only IP protocol detected. If you want to see more protocols, try to:\n - Generate more traffic in your network (open websites, ping other devices)\n - Make sure you are listening on the correct interface\n - Prefer running on a real device or use Bridge mode in your VM network settings"
    fi
}

add_protocols_table_to_report() {
    echo "" >> "$REPORT_MD"
    echo "## Explanation of Detected Protocols" >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "| Protocol | Usage Explanation | Example Port(s) |" >> "$REPORT_MD"
    echo "|----------|-----------------------------------------------------|------------------------|" >> "$REPORT_MD"
    for proto in $TOP_PROTOCOLS_LIST; do
        protocol_explanation_markdown "$proto" >> "$REPORT_MD"
    done
    echo "" >> "$REPORT_MD"
}

generate_report() {
    echo "# NetCrafts Network Recon Report" > "$REPORT_MD"
    echo "Date: $(date "+%Y-%m-%d %H:%M:%S")" >> "$REPORT_MD"
    echo "Network Range: $NETWORK_RANGE" >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "## Devices Found" >> "$REPORT_MD"
    printf "| %-15s | %-17s | %-25s | %-20s | %-9s |\n" "IP" "MAC" "Vendor" "Host" "Conn" >> "$REPORT_MD"
    printf "|-----------------|-------------------|---------------------------|----------------------|----------|\n" >> "$REPORT_MD"
    while read ip; do
        mac=$(arp -an "$ip" | grep -oE "(([A-Fa-f0-9]{2}[:-]){5}[A-Fa-f0-9]{2})")
        vendor="Unknown Vendor"
        if [[ ! -z $mac ]]; then
            vendor=$(get_vendor_clean "$mac")
        else
            mac="Unknown"
        fi
        host=$(nslookup $ip 2>/dev/null | awk -F'= ' '/name/ {print $2}' | sed 's/\.$//')
        [[ -z $host ]] && host="Unknown"
        if [[ $ip == "$(get_local_ip)" ]]; then
            if iwgetid -r >/dev/null 2>&1; then
                conn="Wi-Fi"
            else
                conn="Ethernet"
            fi
        else
            conn="Unknown"
        fi
        vendor_disp=$(echo "$vendor" | cut -c 1-24)
        host_disp=$(echo "$host" | cut -c 1-20)
        printf "| %-15s | %-17s | %-24s | %-20s | %-9s |\n" "$ip" "$mac" "$vendor_disp" "$host_disp" "$conn" >> "$REPORT_MD"
    done < /tmp/nmap_ips.txt
    echo "" >> "$REPORT_MD"
    echo -n "## DNS Servers: " >> "$REPORT_MD"
    get_dns_servers >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo -n "## DHCP Server: " >> "$REPORT_MD"
    get_dhcp_server >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "## Local IP" >> "$REPORT_MD"
    echo "$(get_local_ip)" >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "## Gateway IP" >> "$REPORT_MD"
    echo "$(get_gateway_ip)" >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "## Public IP & ISP" >> "$REPORT_MD"
    echo "**Public IP:** $(get_public_ip)" >> "$REPORT_MD"
    echo "**ISP:** $(get_isp)" >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "## Shodan Link" >> "$REPORT_MD"
    echo "$(shodan_link)" >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "## WHOIS Data" >> "$REPORT_MD"
    run_whois >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "## Top 3 Protocols Detected (tcpdump $PACKET_COUNT packets on $INTERFACE)" >> "$REPORT_MD"
    echo "\`\`\`" >> "$REPORT_MD"
    for proto in $TOP_PROTOCOLS_LIST; do
        count=$(awk '{print $2}' "$TCPDUMP_TMP" | grep -c "^$proto$")
        echo "$count $proto" >> "$REPORT_MD"
    done
    echo "\`\`\`" >> "$REPORT_MD"
    add_protocols_table_to_report

    echo "" >> "$REPORT_MD"
    echo "## Network Schema - Instruction" >> "$REPORT_MD"
    echo "To complete the project, draw a diagram of your network topology using draw.io or diagrams.net." >> "$REPORT_MD"
    echo "Include each device you found (with IP, name, connection type), your router, and how devices are connected (Wi-Fi, Ethernet)." >> "$REPORT_MD"
    echo "Attach the exported diagram as a PDF or image in your final report." >> "$REPORT_MD"
}

# ----------- MAIN SCRIPT -----------
print_banner

NETWORK_RANGE=$(detect_network_range)
REPORT_MD="netcrafts_report.md"

echo -e "${GREEN}Detected Network Range:${NC} $NETWORK_RANGE"
echo -e "${GREEN}Local IP:${NC} $(get_local_ip)"
echo -e "${GREEN}Gateway (Router) IP:${NC} $(get_gateway_ip)"
echo -e "${GREEN}DNS Servers:${NC} $(get_dns_servers)\n"
echo -e "${GREEN}DHCP Server:${NC} $(get_dhcp_server)\n"

get_local_devices

echo -e "${GREEN}Your Public IP:${NC} $(get_public_ip)"
echo -e "${GREEN}ISP:${NC} $(get_isp)\n"
echo -e "${GREEN}Shodan link for your IP:${NC} $(shodan_link)\n"

echo -e "${YELLOW}WHOIS result for your Public IP:${NC}"
run_whois
echo

sniff_protocols
echo

echo -e "${CYAN}Generating markdown report...${NC}"
generate_report
echo -e "${GREEN}Report saved as: netcrafts_report.md${NC}"
echo -e "\n${YELLOW}You can convert this Markdown file to PDF via pandoc, typora, or any online converter.${NC}"
echo -e "${YELLOW}To complete the project, draw your network schema with draw.io and attach it to your final PDF report.${NC}"

