# Network-Analyzer

[![Go Version](https://img.shields.io/badge/Go-1.18%2B-blue)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/elliotsecops/network-analyzer)

**Network-Analyzer** is a powerful Go script designed to capture and analyze real-time network traffic passing through network interfaces. This tool is invaluable for network administrators, cybersecurity analysts, and DevOps engineers who need to monitor network activity, identify patterns, and troubleshoot issues.

## Table of Contents

- [Features](#features)
- [Target Audience](#target-audience)
- [Value Proposition](#value-proposition)
- [Example Use Cases](#example-use-cases)
- [Installation](#installation)
- [Usage](#usage)
- [Anomaly Detection](#anomaly-detection)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Real-time Packet Capture:** Captures network packets in real-time, providing detailed information on source/destination IP addresses, ports, protocols, and packet size. This data is crucial for monitoring network activity, identifying traffic patterns, and troubleshooting network issues.
- **Protocol Classification:** Breaks down network traffic by protocol (TCP, UDP, ICMP, etc.), allowing you to analyze the distribution of different protocol types on your network. This helps understand which applications and services are using the most bandwidth.
- **Traffic Statistics:** Calculates and displays comprehensive statistics, including total packets, total bytes transferred, and per-protocol packet counts. These statistics are updated every 5 seconds, providing a real-time overview of network activity. You can use this information to identify trends and potential bottlenecks.
- **Top Talkers (IPs and Ports):** Identifies the most active IP addresses and ports, allowing you to quickly pinpoint the sources and destinations of heavy network traffic. This is valuable for identifying bandwidth hogs, potential security threats, and optimizing network performance.
- **CSV Logging (Optional):** Logs all captured packet data to a CSV file for later analysis or reporting. The CSV file includes timestamps, source/destination IPs, protocols, and packet lengths. This feature enables historical analysis and trend identification.

## Target Audience

This tool is designed for:

- Network Administrators
- Cybersecurity Analysts
- DevOps Engineers
- IT Professionals needing real-time network monitoring and analysis

## Value Proposition

- **Real-time Insights:** Get immediate insights into network activity without the need for complex setups.
- **Comprehensive Analysis:** Analyze traffic by protocol, IP, and port to understand network usage patterns.
- **Easy to Use:** Simple command-line interface with options for detailed logging and verbose output.
- **Open Source:** Free to use and modify, encouraging community contributions and improvements.

## Example Use Cases

1. **Network Troubleshooting:** Identify and resolve network bottlenecks by analyzing traffic patterns.
2. **Security Monitoring:** Detect unusual traffic patterns that may indicate security threats.
3. **Performance Optimization:** Optimize network performance by identifying and addressing bandwidth hogs.
4. **Historical Analysis:** Log network traffic to CSV for historical analysis and trend identification.

## Installation

**Go 1.18 or later is required.** [Download Go](https://golang.org/dl/)

### Using `go install` (Recommended)

```bash
go install github.com/elliotsecops/Network-Analyzer@latest  # Correct path for go install
```

This will install the `network-analyzer` binary to your `$GOBIN` directory. Make sure `$GOBIN` is in your `$PATH`.

### Manual Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/elliotsecops/network-analyzer.git
   cd network-analyzer
   ```

2. **Install Dependencies:**
   ```bash
   go mod tidy
   ```

3. **Build the Binary:**
   ```bash
   go build -o network-analyzer
   ```

### Installing libpcap

- **Ubuntu/Debian:**
  ```bash
  sudo apt-get install libpcap-dev
  ```
- **macOS (using Homebrew):**
  ```bash
  brew install libpcap
  ```
- **Other Linux distributions:** Consult your distribution's package manager documentation.
- **Windows:** [See WinPcap Installation Instructions](https://www.winpcap.org/install/) (or Npcap).

## Usage

### Identifying Network Interface

First, identify the correct active network interface using:
```bash
ip link show
```

### Running the Script

The script can be executed with various options:

| Flag | Description | Default Value |
|------|-------------|---------------|
| `-i` | Network interface to capture from | `eth0` |
| `-t` | Duration to capture packets (0 for indefinite) | `0s` |
| `-v` | Enable verbose logging | `false` |
| `-o` | Output log file (CSV format) | (none) |

#### Example Commands

- **Basic Execution:**
  ```bash
  sudo ./network-analyzer -i <interface_name> -t <duration>
  ```
- **Verbose Mode:**
  ```bash
  sudo ./network-analyzer -i <interface_name> -t <duration> -v
  ```
- **Output to a File:**
  ```bash
  sudo ./network-analyzer -i <interface_name> -t <duration> -o log.txt
  ```
- **Run Indefinitely:**
  ```bash
  sudo ./network-analyzer -i <interface_name> -t 0
  ```

### Example Output

The following is an example of the output. The actual values will vary depending on your network traffic.

```plaintext
--- Traffic Statistics ---
Total Packets: 12345
Total Bytes: 123456789
TCP Packets: 10000
UDP Packets: 2000
ICMP Packets: 345

Top 5 Active IPs:
192.168.1.10: 5000
192.168.1.11: 3000
192.168.1.12: 2000
192.168.1.13: 1000
192.168.1.14: 500

Top 5 Active Ports:
80: 4000
443: 3000
53: 2000
22: 1000
3389: 500
```

### Interpreting Results

- **Total Packets:** The total number of packets captured.
- **Total Bytes:** The total number of bytes transferred.
- **TCP/UDP/ICMP Packets:** The count of packets for each protocol.
- **Top Active IPs:** The most active IP addresses on the network.
- **Top Active Ports:** The most active ports on the network.

## Anomaly Detection

**Network-Analyzer** includes basic anomaly detection that alerts on unusual or potentially malicious traffic patterns. This feature enhances security monitoring by identifying:
- Unusual protocol usage
- High traffic from unexpected IP addresses
- Uncommon port activity

## Troubleshooting

- **Insufficient Permissions:** Ensure the script runs with appropriate privileges.
- **Interface Not Found:** Verify that the specified interface is active and correctly named.
- **Packet Loss:** If packet loss occurs, consider adjusting buffer sizes or optimizing performance.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes and commit them (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a new Pull Request.

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) to ensure a welcoming and inclusive environment for all contributors.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
