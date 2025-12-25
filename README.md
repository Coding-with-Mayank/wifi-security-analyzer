# Wi-Fi Security Analyzer

A comprehensive Python-based tool to scan Wi-Fi networks for security vulnerabilities, weak encryption protocols, unauthorized devices, and performance issues.

![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

## 🎯 Features

- **Network Discovery**: Automatically detects all nearby Wi-Fi networks
- **Encryption Analysis**: Identifies encryption types (Open, WEP, WPA, WPA2, WPA3)
- **Vulnerability Detection**: Flags weak or deprecated encryption protocols
- **Client Monitoring**: Tracks connected devices and probe requests
- **Signal Strength**: Measures network signal strength
- **Comprehensive Reports**: Generates detailed security assessment reports
- **Real-time Analysis**: Captures and analyzes network packets in real-time

## 🛡️ Security Checks

- ✅ Detects open/unencrypted networks
- ✅ Identifies deprecated WEP encryption
- ✅ Flags outdated WPA (without WPA2)
- ✅ Recommends WPA3 upgrade
- ✅ Monitors unauthorized devices
- ✅ Tracks client probe requests

## 📋 Prerequisites

### System Requirements
- Linux operating system (Ubuntu, Debian, Kali Linux recommended)
- Python 3.7 or higher
- Wireless network adapter that supports monitor mode
- Root/sudo privileges

### Dependencies
```bash
# Install Python dependencies
pip install scapy

# Install system tools (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y wireless-tools net-tools
```

## 🚀 Installation

1. **Clone the repository**
```bash
git clone https://github.com/Coding-with-Mayank/wifi-security-analyzer.git
cd wifi-security-analyzer
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Make script executable**
```bash
chmod +x wifi_analyzer.py
```

## 💻 Usage

### Basic Scan
```bash
sudo python3 wifi_analyzer.py
```

### Step-by-step
1. Run the script with sudo privileges
2. Enter your wireless interface name (e.g., `wlan0`)
3. Specify scan duration (default: 60 seconds)
4. Wait for the scan to complete
5. Review the generated security report

### Example Output
```
╔══════════════════════════════════════════════════════════╗
║          Wi-Fi Security Analyzer v1.0                    ║
║  Scan networks for vulnerabilities and security issues   ║
╚══════════════════════════════════════════════════════════╝

[*] Starting Wi-Fi security scan on wlan0
[*] Scanning for 60 seconds...

================================================================================
                    Wi-Fi SECURITY ANALYSIS REPORT
================================================================================

[+] Discovered Networks: 5
--------------------------------------------------------------------------------

SSID: MyHomeNetwork
BSSID: AA:BB:CC:DD:EE:FF
Channel: 6
Encryption: WPA2
Signal Strength: -45 dBm
Discovered at: 14:32:15
Connected Clients: 3
  - 11:22:33:44:55:66
  - 77:88:99:AA:BB:CC
```

## ⚠️ Important Notes

### Legal Disclaimer
**This tool is for EDUCATIONAL and AUTHORIZED TESTING purposes only.**

- ⚖️ Only scan networks you own or have explicit permission to test
- ⚖️ Unauthorized network scanning may be illegal in your jurisdiction
- ⚖️ The author assumes no liability for misuse of this tool
- ⚖️ Always comply with local laws and regulations

### Ethical Guidelines
- Use in controlled lab environments
- Obtain written permission before testing
- Report vulnerabilities responsibly
- Respect privacy and security

## 🔧 Troubleshooting

### Monitor Mode Issues
```bash
# Check if interface supports monitor mode
sudo iwconfig

# Manually enable monitor mode
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

### Permission Errors
- Always run with `sudo`
- Ensure your user is in the `netdev` group

### No Networks Found
- Check antenna connection
- Verify monitor mode is enabled
- Increase scan duration
- Try different channels

## 🛠️ Technical Details

### Architecture
- **Packet Capture**: Uses Scapy library for packet sniffing
- **Frame Analysis**: Processes 802.11 management frames
- **Encryption Detection**: Analyzes beacon frames and RSN information elements
- **Client Tracking**: Monitors probe requests and data frames

### Supported Encryption Types
- Open (No encryption)
- WEP (Wired Equivalent Privacy)
- WPA (Wi-Fi Protected Access)
- WPA2 (WPA version 2)
- WPA3 (WPA version 3)

## 📊 Project Structure

```
wifi-security-analyzer/
│
├── wifi_analyzer.py          # Main script
├── requirements.txt           # Python dependencies
├── README.md                  # Documentation
├── LICENSE                    # MIT License
└── .gitignore                # Git ignore file
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 TODO

- [ ] Add WPA3 handshake capture
- [ ] Implement deauth attack detection
- [ ] Add GUI interface
- [ ] Export reports to JSON/CSV
- [ ] Add password strength testing
- [ ] Implement channel hopping
- [ ] Add MAC vendor lookup

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Mayank**
- GitHub: [@Coding-with-Mayank](https://github.com/Coding-with-Mayank)

## 🙏 Acknowledgments

- Scapy library developers
- Python community
- Cybersecurity researchers

## 📞 Support

If you encounter any issues or have questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the troubleshooting section

---

**⭐ If you find this project helpful, please give it a star!**

**Remember: With great power comes great responsibility. Use ethically!**
