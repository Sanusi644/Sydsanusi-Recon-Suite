Sydsanusi Recon Suite Code

#!/usr/bin/env python3

import os
import sys
import requests
import socket

# Banner
def show_banner():
    print("""
    ###################################
    # Sydsanusi Recon Suite           #
    # Created by: Sanusi Saminu       #
    ###################################
    """)

# Option 1: Network Scanner
def network_scan(target):
    print(f"[+] Scanning network: {target}")
    response = os.popen(f"ping -c 4 {target}").read()
    print(response)

# Option 2: Port Scanner
def port_scan(target, ports):
    print(f"[+] Scanning ports on {target}")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    print(f"Port {port}: Open")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

# Option 3: Fetch robots.txt
def fetch_robots(domain):
    url = f"http://{domain}/robots.txt"
    print(f"[+] Fetching {url}")
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print("[+] robots.txt content:")
            print(response.text)
        else:
            print(f"[-] Failed to fetch robots.txt. HTTP Status Code: {response.status_code}")
    except Exception as e:
        print(f"[-] Error: {e}")

# Option 4: IP Geolocation Lookup
def ip_geolocation(ip):
    url = f"http://ip-api.com/json/{ip}"
    print(f"[+] Looking up geolocation for IP: {ip}")
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        if data["status"] == "success":
            print(f"""
            IP: {data['query']}
            Country: {data['country']}
            Region: {data['regionName']}
            City: {data['city']}
            ISP: {data['isp']}
            Latitude: {data['lat']}
            Longitude: {data['lon']}
            """)
        else:
            print(f"[-] Error: {data['message']}")
    except Exception as e:
        print(f"[-] Error: {e}")

# Option 5: Base64 Encoder
def base64_encode(data):
    import base64
    encoded = base64.b64encode(data.encode('utf-8'))
    return encoded.decode('utf-8')

# Option 6: Base64 Decoder
def base64_decode(encoded_data):
    import base64
    decoded = base64.b64decode(encoded_data.encode('utf-8'))
    return decoded.decode('utf-8')

# Main Function
def main():
    show_banner()
    print("""
    Choose an option:
    1) Network Scan
    2) Port Scan
    3) Fetch robots.txt
    4) IP Geolocation Lookup
    5) Base64 Encode
    6) Base64 Decode
    7) Exit
    """)
    choice = input("Enter your choice: ")

    if choice == "1":
        target = input("Enter target IP or domain: ")
        network_scan(target)

    elif choice == "2":
        target = input("Enter target IP or domain: ")
        ports = input("Enter ports to scan (comma-separated, e.g., 22,80,443): ")
        port_list = [int(p.strip()) for p in ports.split(",")]
        port_scan(target, port_list)

    elif choice == "3":
        domain = input("Enter domain: ")
        fetch_robots(domain)

    elif choice == "4":
        ip = input("Enter IP address: ")
        ip_geolocation(ip)

    elif choice == "5":
        data = input("Enter data to encode: ")
        print(f"Encoded Data: {base64_encode(data)}")

    elif choice == "6":
        encoded_data = input("Enter Base64 encoded data to decode: ")
        print(f"Decoded Data: {base64_decode(encoded_data)}")

    elif choice == "7":
        print("Exiting... Goodbye!")
        sys.exit(0)

    else:
        print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

---

Features in the Script:

1. Network Scanner: Pings a target IP or domain.


2. Port Scanner: Scans specific ports on a target.


3. Fetch robots.txt: Retrieves and displays the robots.txt file of a website.


4. IP Geolocation Lookup: Fetches geolocation details of an IP using an API.


5. Base64 Encoder: Converts plain text into Base64 format.


6. Base64 Decoder: Decodes Base64 encoded text.


7. Menu System: Easy-to-use numbered menu to select tasks.
