# Network Analyzer

This project consists of two Python scripts: `main.py` and `arp.py`. These scripts are used to scan a network for devices and detect ARP poisoning attacks respectively.

## Requirements

- Python 3.x
- Scapy library (`pip install scapy`)
- Root privileges to run the scripts

## Usage

### `main.py`

This script performs the following functions:
- Validates the IP range and network interface.
- Scans the network for devices using ARP requests.
- Logs the IP and MAC addresses of the detected devices to a file.
- Runs continuously, scanning the network and logging results every 60 seconds.

### `arp.py`

This script performs the following functions:
- Validates the IP range and network interface.
- Scans the network for devices using ARP requests.
- Loads previous scan results from a file.
- Detects ARP poisoning by comparing current scan results with previous results.

#### Example

```bash
sudo python3 main.py filename ip_range iface
```

- `filename`: The filename to store the results
- `ip_range`: The IP range to scan (in CIDR notation, e.g., `192.168.1.0/24`)
- `iface`: The network interface to use for scanning (e.g., `wlan0`)
