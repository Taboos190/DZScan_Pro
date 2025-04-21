#!/usr/bin/env python3
import os
import subprocess
import socket
import re

# Banner
def banner():
    print("""
🟥🟥⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛
🟥🟥🟥⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜
🟥🟥🟥🟥⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜
🟥🟥🟥⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜
🟥🟥🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩
🟥🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩
💪💪💪 DZScan Pro by Bouabd El Taboush 🇩🇿
    """)

# Network scanner using ping sweep
def scan_network(ip_range):
    print(f"\n[+] Scanning network: {ip_range}\n")
    result = subprocess.getoutput(f"nmap -sn {ip_range}")
    hosts = re.findall(r"Nmap scan report for (.+)", result)
    for host in hosts:
        try:
            ip = socket.gethostbyname(host)
        except:
            ip = host
        mac = subprocess.getoutput(f"arp -n {ip}")
        mac_match = re.search(r"(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})", mac)
        mac_addr = mac_match.group(0) if mac_match else "Unknown"
        vendor = subprocess.getoutput(f"nmap -O {ip} | grep -m 1 'MAC Address'")
        print(f"\nIP: {ip}")
        print(f"MAC: {mac_addr}")
        print(f"Vendor Info: {vendor}")

# Fake warning screen
def fake_block_screen():
    print("\n[!] This device is under monitoring.")
    print("[!] Unauthorized access detected.")
    print("[!] Your activity is being tracked.\n")

# Menu
def main():
    banner()
    while True:
        print("\n--- MENU ---")
        print("1. Scan Network")
        print("2. Fake Block Screen")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            ip_range = input("Enter IP range (e.g. 192.168.1.0/24): ")
            scan_network(ip_range)
        elif choice == "2":
            fake_block_screen()
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
