#!/usr/bin/env python3
import os
import subprocess
import socket
import re

# ANSI Colors
RED = '\033[91m'
GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RESET = '\033[0m'

# Banner
def banner():
    print(f"""{GREEN}
▄▄▄█████▓ ▒█████   ██▓███   ▒█████   ▄▄▄       ██▓███
▓  ██▒ ▓▒▒██▒  ██▒▓██░  ██▒▒██▒  ██▒▒████▄    ▓██░  ██▒
▒ ▓██░ ▒░▒██░  ██▒▓██░ ██▓▒▒██░  ██▒▒██  ▀█▄  ▓██░ ██▓▒
░ ▓██▓ ░ ▒██   ██░▒██▄█▓▒ ▒▒██   ██░░██▄▄▄▄██ ▒██▄█▓▒ ▒
  ▒██▒ ░ ░ ████▓▒░▒██▒ ░  ░░ ████▓▒░ ▓█   ▓██▒▒██▒ ░  ░
  ▒ ░░   ░ ▒░▒░▒░ ▒▓▒░ ░  ░░ ▒░▒░▒░  ▒▒   ▓▒█░▒▓▒░ ░  ░
    ░      ░ ▒ ▒░ ░▒ ░       ░ ▒ ▒░   ▒   ▒▒ ░░▒ ░
  ░      ░ ░ ░ ▒  ░░       ░ ░ ░ ▒    ░   ▒   ░░
             ░ ░               ░ ░        ░  ░

        {YELLOW}DZScan Pro - Coded by BouAbdel Tabouch 🇩🇿
        {RESET}""")

# Network Scanner
def scan_network(ip_range):
    print(f"{CYAN}\n[+] Scanning network: {ip_range}{RESET}")
    result = subprocess.getoutput(f"nmap -sn {ip_range}")
    hosts = re.findall(r"Nmap scan report for (.+)", result)

    for host in hosts:
        try:
            ip = socket.gethostbyname(host)
        except:
            ip = host

        mac_raw = subprocess.getoutput(f"arp -n {ip}")
        mac_match = re.search(r"(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})", mac_raw)
        mac_addr = mac_match.group(0) if mac_match else "Unknown"

        vendor_info = subprocess.getoutput(f"nmap -O {ip} | grep -m 1 'MAC Address'")

        print(f"{GREEN}\n[+] IP: {ip}{RESET}")
        print(f"{YELLOW}    MAC: {mac_addr}{RESET}")
        print(f"{CYAN}    Vendor: {vendor_info.strip()}{RESET}")

# Main Menu
def main():
    banner()
    ip_range = input(f"{CYAN}\nEnter IP range (e.g. 192.168.1.0/24): {RESET}")
    scan_network(ip_range)

if __name__ == "__main__":
    main()
