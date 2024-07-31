# Network Analyzer

## Introduction
The Network Analyzer is a project designed to analyze and monitor your network. It provides functionality for scanning network devices, saving scan results, and detecting ARP poisoning attacks.

## Features
- **Network Scanning**: The Network Analyzer scans the network and retrieves the IP and MAC addresses of connected devices.
- **ARP Poisoning Detection**: It detects ARP poisoning attacks by comparing current and previous network scans.
- **Secure Result Storage**: Scan results are securely stored in a file with restricted permissions.

## Installation
To install the Network Analyzer, follow these steps:

1. Clone the repository:
    ```bash
    git clone https://github.com/SwayamRao/Network_Analyzer/tree/main/version%201
    ```

2. Change to the project directory:
    ```bash
    cd network-analyzer
    ```

3. Install the dependencies:
    ```bash
    pip install `scapy`
    ```
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

## Contact
For any inquiries or support, please contact me at work.mail.g@proton.me
