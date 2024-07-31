import argparse
import re
import logging
import os
import time
from scapy.all import ARP, Ether, srp

def validate_ip_range(ip_range):
    pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")
    if not pattern.match(ip_range):
        raise argparse.ArgumentTypeError("Invalid IP range format. Use CIDR notation (e.g., 192.168.1.0/24).")
    return ip_range

def validate_iface(iface):
    return iface

def scan_network(ip_range, iface):
    try:
        
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=5, iface=iface, verbose=0)[0]
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        return devices
    except Exception as e:
        logging.error(f"Error while scanning network: {e}")
        return []

def load_previous_results(filename):
    previous_devices = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if line and "\t" in line:
                    parts = line.split('\t')
                    if len(parts) == 2:
                        ip, mac = parts
                        previous_devices.append({'ip': ip, 'mac': mac})
                    else:
                        logging.warning(f"Ignore malformed line: {line}. Expected format: 'IP\\tMAC'")
        logging.info(f"Previous results successfully loaded from {filename}")
    except Exception as e:
        logging.error(f"Error while loading previous results from file: {e}")
    return previous_devices

def detect_arp_poisoning(current_devices, previous_devices):
    poisoning_detected = False
    for prev_device in previous_devices:
        for curr_device in current_devices:
            if prev_device['ip'] == curr_device['ip'] and prev_device['mac'] != curr_device['mac']:
                logging.warning(f"ARP poisoning detected: IP {prev_device['ip']} had MAC {prev_device['mac']} but now has MAC {curr_device['mac']}")
                poisoning_detected = True
    if not poisoning_detected:
        logging.info("No ARP poisoning detected.")
    return poisoning_detected

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root. Please use sudo.")
        exit(1)
    parser = argparse.ArgumentParser(description="ARP Poisoning Detector")
    parser.add_argument("filename", type=str, help="The filename to read the previous results")
    parser.add_argument("ip_range", type=validate_ip_range, help="The IP range to scan (in CIDR notation, e.g., 192.168.1.0/24)")
    parser.add_argument("iface", type=validate_iface, help="The network interface to use for scanning")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    previous_devices = load_previous_results(args.filename)
    try:
        while True:

            devices = scan_network(args.ip_range, args.iface)

            detect_arp_poisoning(devices, previous_devices)

            print(f"\nTotal devices found: {len(devices)}")
                       
            time.sleep(60) 

    except KeyboardInterrupt:
        print("Script terminated by user.")
        exit(0)
