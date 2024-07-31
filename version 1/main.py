import argparse
import re
import logging
import os
import time
from scapy.all import ARP, Ether, srp, conf
from datetime import datetime

def validate_ip_range(ip_range):
    pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")
    if not pattern.match(ip_range):
        raise argparse.ArgumentTypeError("Invalid IP range format. Use CIDR notation (e.g., 192.168.1.0/24).")
    return ip_range

def validate_iface(iface):
    
    valid_iface = "wlan0"
    if iface != valid_iface:
        raise argparse.ArgumentTypeError(f"Invalid interface name. Expected {valid_iface}.")
    return iface

def scan_network(ip_range, iface):
    try:
       
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=2, iface=iface, verbose=0)[0]
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        return devices
    except Exception as e:
        logging.error(f"Error while scanning network: {e}")
        return []

def save_results_to_file(devices, filename, timestamp):
    try:
        with open(filename, 'a') as file:
            file.write("\n\n" + "*" * 40 + "\n")
            file.write(f"Date and time: {timestamp}")
            file.write("\n\n")
            file.write("IP\t\tMAC Address\n")
            file.write("-" * 40 + "\n")
            for device in devices:
                file.write(f"{device['ip']}\t{device['mac']}\n")
        logging.info(f"Results successfully saved to {filename}")

        os.chmod(filename, 0o600)
        logging.info(f"File permissions set to 600 (readable and writable only by root) for {filename}")
    except Exception as e:
        logging.error(f"Error while saving results to file: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root. Please use sudo.")
        exit(1)

    parser = argparse.ArgumentParser(description="Network Analyzer")
    parser.add_argument("filename", type=str, help="The filename to store the results")
    parser.add_argument("ip_range", type=validate_ip_range, help="The IP range to scan (in CIDR notation, e.g., 192.168.1.0/24)")
    parser.add_argument("iface", type=validate_iface, help="The network interface to use for scanning")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    while True:
        devices = scan_network(args.ip_range, args.iface)

        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
        save_results_to_file(devices, args.filename, timestamp)
        print(f"Results saved to {args.filename}")
        for device in devices:
            print(f"IP: {device['ip']}  MAC: {device['mac']}")
        print(f"\nTotal devices found: {len(devices)}")
        time.sleep(60) 
