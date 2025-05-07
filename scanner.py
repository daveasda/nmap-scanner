import nmap
import subprocess
import json
from datetime import datetime

# Create a scanner object
scanner = nmap.PortScanner()

# Function to run the Nmap scan and capture output
def run_nmap_scan(ip_address, port, script=None):
    nmap_command = ['sudo', 'nmap', '-p', str(port), '--open']
    
    if script:
        nmap_command.extend(['--script', script])
    
    nmap_command.append(ip_address)

    # Run the Nmap command and capture the output
    result = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode != 0:
        print(f"Error running Nmap scan on {ip_address}: {result.stderr}")
        return None  # If the scan fails, return None

    return result.stdout

# Function to parse and display the scan results
def parse_and_display_output(scan_output, scan_type, ip_address):
    try:
        # Extract relevant data from the Nmap output
        lines = scan_output.splitlines()
        scan_data = {"ip": ip_address, "scan_type": scan_type, "results": []}

        for line in lines:
            if "open" in line or "closed" in line:
                scan_data["results"].append(line.strip())

        if scan_data["results"]:
            print(f"\n{scan_type} Scan Results for {ip_address}:\n")
            for result in scan_data["results"]:
                print(result)
        else:
            print(f"{scan_type} Scan Results: No issues detected on {ip_address}.")
        
        return scan_data

    except Exception as e:
        print(f"Error parsing output: {e}")
        return None

# Function to run SYN, UDP, and Comprehensive Scans based on user input
def scan_single_ip(scanner, ip_addr, scan_type):
    if scan_type == '1':  # SYN ACK Scan
        print(f"\nRunning SYN/ACK Scan on {ip_addr}")
        scanner.scan(hosts=ip_addr, arguments='-v -sS')  # SYN Scan
        display_results(scanner, ip_addr)
    
    elif scan_type == '2':  # UDP Scan
        print(f"\nRunning UDP Scan on {ip_addr}")
        scanner.scan(hosts=ip_addr, arguments='-v -sU')  # UDP Scan
        display_results(scanner, ip_addr)

    elif scan_type == '3':  # Comprehensive Scan
        print(f"\nRunning Comprehensive Scan on {ip_addr}")
        scanner.scan(hosts=ip_addr, arguments='-v -sS -sU -T4')  # SYN + UDP Scan
        display_results(scanner, ip_addr)

    elif scan_type == '4':  # Service Detection
        print(f"\nRunning Service Detection on {ip_addr}")
        scanner.scan(hosts=ip_addr, arguments='-v -sV')  # Service Version Detection
        display_results(scanner, ip_addr)

    else:
        print("Invalid scan type selected!")

# Function to display the scan results
def display_results(scanner, ip_addr):
    if ip_addr in scanner.all_hosts():
        print(f"\nScan Results for IP: {ip_addr}")
        print(f"Host: {ip_addr}")
        print(f"Status: {scanner[ip_addr].state()}")
        print(f"Protocols: {scanner[ip_addr].all_protocols()}")
        
        for protocol in scanner[ip_addr].all_protocols():
            print(f"\nOpen {protocol.upper()} Ports:")
            for port in scanner[ip_addr][protocol].keys():
                print(f"  Port: {port}, State: {scanner[ip_addr][protocol][port]['state']}")
    else:
        print(f"\nNo information found for IP: {ip_addr}")

# Main function to choose scan type and mode
def main():
    mode = input("""Please choose a mode:

1) Scan a Single IP
2) Scan Multiple IPs
3) Scan a Network Range\n""")

    if mode == '1':
        ip_addr = input("Please enter the IP address you want to scan: ")
        print("The IP you entered is: ", ip_addr)

        resp = input("""\nPlease enter the type of scan you want to run:

                    1) SYN ACK Scan
                    2) UDP Scan
                    3) Comprehensive Scan
                    4) Service Detection\n""")
        print("You have selected option: ", resp)

        if resp in ['1', '2', '3', '4']:
            scan_single_ip(scanner, ip_addr, resp)
        else:
            print("Invalid option selected!")

    elif mode == '2':
        ips = input("Please enter IP addresses to scan (comma-separated): ").split(',')
        for ip in ips:
            print(f"\nScanning IP: {ip.strip()}")
            scan_single_ip(scanner, ip.strip(), '3')  # Default to comprehensive scan

    elif mode == '3':
        network_range = input("Please enter the network range to scan (e.g., 192.168.1.0/24): ")
        print(f"Scanning Network Range: {network_range}")
        try:
            scanner.scan(hosts=network_range, arguments='-v -sS -sU -T4', sudo=True)  # SYN + UDP Scan
            for host in scanner.all_hosts():
                print(f"\nHost: {host}")
                print(f"Status: {scanner[host].state()}")
                print(f"Protocols: {scanner[host].all_protocols()}")
                for protocol in scanner[host].all_protocols():
                    print(f"Open {protocol.upper()} Ports: ", scanner[host][protocol].keys())
        except Exception as e:
            print(f"Error: {e}")

    else:
        print("Invalid mode selected. Please restart the program.")

    print("Scan Complete.")

# Function to run specific Nmap scripts on ports (DNS, SMTP, WAF, etc.)
def run_all_scans(ip_address):
    scans = [
        {"type": "DNS Zone Transfer", "port": 53, "script": "dns-zone-transfer"},
        {"type": "SMTP User Enumeration", "port": 25, "script": "smtp-enum-users"},
        {"type": "WAF Detection", "port": 80, "script": "http-waf-detect"},
        {"type": "SMB OS Discovery", "port": 445, "script": "smb-os-discovery"},
        {"type": "SMB Protocols", "port": 445, "script": "smb-protocols"},
        {"type": "MySQL Info", "port": 3306, "script": "mysql-info"},
        {"type": "MySQL Enumeration", "port": 3306, "script": "mysql-enum"}
    ]
    
    all_scan_data = []

    for scan in scans:
        print(f"\n[+] Running {scan['type']} on {ip_address}")
        scan_output = run_nmap_scan(ip_address, scan["port"], scan["script"])
        
        if scan_output:
            scan_data = parse_and_display_output(scan_output, scan["type"], ip_address)
            if scan_data:
                all_scan_data.append(scan_data)

    # Optionally, you can display the aggregated results
    if all_scan_data:
        print("\n[+] Aggregated Scan Results:")
        for scan in all_scan_data:
            print(f"\nScan Type: {scan['scan_type']}")
            for result in scan['results']:
                print(f"  - {result}")
    else:
        print("\n[+] No results found from scans.")

if __name__ == "__main__":
    # Start the program by choosing scan mode
    mode = input("""Please choose a mode:

1) Scan a Single IP
2) Scan Multiple IPs
3) Scan a Network Range\n""")
    
    if mode == '1':
        target_ip = input("Please enter the IP address to scan: ")
        run_all_scans(target_ip)  # Run all automated scans on the target IP
        main()  # Continue with other scan options

    elif mode == '2':
        target_ips = input("Enter a list of IP addresses to scan (comma-separated): ").split(',')
        for target_ip in target_ips:
            run_all_scans(target_ip.strip())  # Run all automated scans on each IP

    elif mode == '3':
        network_range = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
        print(f"Scanning network range: {network_range}")
        main()  # Run range-based scans
