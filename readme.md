# Fortify Shield Security Hardener

```
 ______          _   _  __          _____ _     _      _     _ 
|  ____|        | | (_)/ _|        / ____| |   (_)    | |   | |
| |__ ___  _ __ | |_ _| |_ _   _  | (___ | |__  _  ___| | __| |
|  __/ _ \| '_ \| __| |  _| | | |  \___ \| '_ \| |/ _ \ |/ _` |
| | | (_) | | | | |_| | | | |_| |  ____) | | | | |  __/ | (_| |
|_|  \___/|_| |_|\__|_|_|  \__, | |_____/|_| |_|_|\___|_|\__,_|
                            __/ |                              
                           |___/                               
```

A comprehensive security hardening script for Debian and RHEL-based Linux systems.

![Security Banner](https://img.shields.io/badge/Security-Hardening-blue)
![Debian](https://img.shields.io/badge/OS-Debian-red)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview

Fortify Shield is an advanced interactive security hardening tool designed to secure Linux servers according to industry best practices. The script systematically hardens various components of your system including SSH, firewall, kernel parameters, system configuration, and more.

## Features

- **Cross-Platform Support**: Works on both Debian-based (Debian, Ubuntu) and RHEL-based (RHEL, CentOS, Fedora, Rocky Linux, AlmaLinux) distributions
- **Interactive Menu System**: Easy-to-navigate menu system for selective security measure application
- **Security Scoring**: Provides a security score to help track your hardening progress
- **Comprehensive Reporting**: Generates detailed security reports and summaries
- **Configuration Backup**: Automatically backs up all configuration files before modification
- **Colorized Output**: Clear visual feedback with color-coded status indicators

### Security Measures

- **SSH Hardening**
  - Non-standard port configuration
  - Strong cryptographic settings
  - Two-factor authentication (Google Authenticator)
  - User/group access restrictions
  
- **Firewall Configuration**
  - UFW (Debian) and firewalld (RHEL) support
  - Standard and strict modes
  - IP allowlisting
  
- **System Hardening**
  - /proc filesystem security
  - Strong password policies
  - Secure UMASK settings
  - Root account protection
  - Core dump disabling
  
- **Kernel Hardening**
  - ASLR (Address Space Layout Randomization)
  - Protection against various exploits
  - Secure sysctl parameters
  
- **Module Blacklisting**
  - Disables uncommon filesystems
  - Restricts unused network protocols
  - Secures hardware interfaces
  
- **Intrusion Detection**
  - AIDE file integrity monitoring
  - ClamAV antivirus
  - Fail2Ban brute force protection
  - Comprehensive system auditing
  
- **Automatic Updates**
  - Unattended security upgrades
  - Configurable email notifications

## Requirements

- Root access to the server
- Debian or RHEL-based Linux distribution
- Internet connectivity (for package installation)

## Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/j551n-ncloud/fortify-shield.git

# Navigate to the directory
cd fortify-shield

# Make the script executable
chmod +x fortify_shield.sh

# Run the script
sudo ./fortify_shield.sh
```

### Manual Installation

```bash
# Download the script
curl -O https://raw.githubusercontent.com/j551n-ncloud/fortify-shield/main/fortify_shield.sh

# Make the script executable
chmod +x fortify_shield.sh

# Run the script
sudo ./fortify_shield.sh
```

## Usage

### Interactive Mode

```bash
sudo ./fortify_shield.sh
```

This will launch the interactive menu where you can select which security measures to apply.

### Non-Interactive Mode

```bash
# Run with all default settings
sudo ./fortify_shield.sh --no-interaction

# Run with custom settings
sudo ./fortify_shield.sh --ssh-port 2222 --ssh-users admin,user1 --strict-firewall
```

### Available Options

```
Options:
  -h, --help                 Show this help message
  -q, --quiet                Run in quiet mode (minimal output)
  -n, --no-interaction       Run in non-interactive mode with defaults
  -c, --config FILE          Use specified configuration file
  --ssh-port PORT            Set SSH port
  --ssh-users USERS          Set SSH users (comma-separated)
  --no-mfa                   Disable MFA setup
  --no-firewall              Skip firewall configuration
  --strict-firewall          Use strict firewall rules
  --no-updates               Disable automatic updates
  --no-aide                  Disable AIDE setup
  --no-clamav                Disable ClamAV setup
  --no-fail2ban              Disable Fail2Ban setup
  --disable-root             Completely disable root account
  --lock-root                Lock root account password
  --ip-allowlist IPs         Specify allowed IPs (comma-separated)
```

## Security Considerations

### SSH Access

After enabling 2FA and restricting SSH users, make sure you:
1. Have a working SSH connection before closing existing sessions
2. Configure your SSH client to work with the new settings
3. Backup emergency access methods (console access if available)

### Firewall

When configuring strict firewall rules:
1. Ensure your current connection won't be dropped
2. Consider adding your current IP to the allowlist
3. Know how to access the server if you get locked out

### Root Account

When locking the root account:
1. Ensure at least one user has sudo privileges
2. Test sudo access before closing your session

## Security Report

The script generates two report files:

1. **Detailed Report** (`/root/security_report.md`): A comprehensive markdown report with all security measures applied and recommendations.

2. **Summary Report** (`/root/security_summary.txt`): A quick overview of the security status and top recommendations.

## Logs

All operations are logged to `/var/log/fortify-shield.log` for auditing and troubleshooting.

## Backup & Recovery

Configuration backups are stored in `/root/security_backups/TIMESTAMP/` directory. If you need to restore a configuration, you can find the original files there.

## Customization

You can customize the script behavior by:

1. Using command-line options for specific settings
2. Creating a configuration file for persistent settings
3. Modifying script constants at the beginning of the file

## Compatibility

Tested on:
- Debian 10, 11, 12
- Ubuntu 20.04, 22.04, 24.04
- CentOS 7, 8, Stream 9
- RHEL 8, 9
- Fedora 36, 37, 38
- Rocky Linux 8, 9
- AlmaLinux 8, 9

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/my-new-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- Inspired by various security hardening guides and best practices
- Special thanks to the cybersecurity community for sharing knowledge and tools

## Disclaimer

This script is provided as-is with no warranty. Always test in a non-production environment first and ensure you have a way to recover your system if something goes wrong.

---

⚠️ **IMPORTANT**: Always maintain an alternative way to access your server in case you get locked out due to security changes. When possible, test this script in a controlled environment before using it on production servers.
