
import socket
import requests
import json
import argparse
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_network
from ping3 import ping

# Predefined list of common ports
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Proxy"
}

def scan_port(ip, port, timeout, protocol):
    try:
        if protocol == 'TCP':
            sock_type = socket.SOCK_STREAM
        elif protocol == 'UDP':
            sock_type = socket.SOCK_DGRAM
        else:
            raise ValueError("Protocol must be either 'TCP' or 'UDP'")

        with socket.socket(socket.AF_INET, sock_type) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port)) if protocol == 'TCP' else None

            if protocol == 'TCP' and result == 0:  # TCP port is open
                try:
                    banner = s.recv(1024).decode().strip()
                except:
                    banner = "No banner"
                return port, banner
            elif protocol == 'UDP':  # UDP port is open
                return port, "Open (UDP)"
    except:
        return None

def scan_ports(ip, ports, timeout, protocol):
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout, protocol): port for port in ports}
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

def ping_host(ip):
    try:
        response = ping(ip)
        return response is not None
    except:
        return False

def get_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'fail':
            return None
        return {
            'country': data.get('country', 'Unknown'),
            'region': data.get('regionName', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'isp': data.get('isp', 'Unknown')
        }
    except:
        return None

def log_results_json(filename, ip, open_ports, location):
    result_data = {
        'ip': ip,
        'location': location if location else {},
        'open_ports': [{'port': port, 'banner': banner} for port, banner in open_ports]
    }

    try:
        with open(filename, "a") as f:
            json.dump(result_data, f, indent=4)
            f.write("\n")
    except Exception as e:
        print(f"Error saving results to {filename}: {e}")

def parse_ports(port_input):
    if port_input in ["-common", "common"]:
        return list(COMMON_PORTS.keys())
    elif port_input == "all":
        return list(range(1, 65536))
    elif "-" in port_input:
        start_port, end_port = map(int, port_input.split("-"))
        return list(range(start_port, end_port + 1))
    else:
        try:
            return [int(port_input)]
        except ValueError:
            raise ValueError("Invalid port input. Must be a single port, range, 'common', or 'all'.")

def main():
    parser = argparse.ArgumentParser(description="Port scanner script with minimal output.")
    parser.add_argument("ip", help="IP address or CIDR range to scan.")
    parser.add_argument("ports", help="Port range, single port, or 'common' for predefined ports.")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout for each port scan.")
    parser.add_argument("-p", "--protocol", choices=['TCP', 'UDP', 'BOTH'], default='TCP', help="Protocol to scan.")
    parser.add_argument("-o", "--output", default="scan_results.json", help="File to save results.")
    args = parser.parse_args()

    try:
        ip_list = [str(ip) for ip in ip_network(args.ip, strict=False)]
    except ValueError:
        print("Invalid IP address or range.")
        return

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print("Invalid port input.")
        return

    print("Scanning...")

    for ip in ip_list:
        if not ping_host(ip):
            continue

        protocols_to_scan = []
        if args.protocol in ['TCP', 'BOTH']:
            protocols_to_scan.append('TCP')
        if args.protocol in ['UDP', 'BOTH']:
            protocols_to_scan.append('UDP')

        for proto in protocols_to_scan:
            open_ports = scan_ports(ip, ports, args.timeout, proto)
            location = get_geolocation(ip)
            log_results_json(args.output, ip, open_ports, location)

if __name__ == "__main__":
    main()


'''
Kako koristiti?

Na primer, za skeniranje predefinisanih portova za određenu IP adresu:

python3 port_scanner.py 91.187.132.11 common -p TCP -o results.json

Skripta će skenirati najčešće portove (common), TCP protokol, i sačuvati rezultate u results.json.
'''

