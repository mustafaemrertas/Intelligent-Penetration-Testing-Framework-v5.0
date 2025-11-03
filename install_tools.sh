#!/bin/bash

# Ultra Penetration Testing Framework v5.0 - Tool Installation Script
# This script installs all required Kali Linux tools for the framework
# Run with: chmod +x install_tools.sh && sudo ./install_tools.sh

echo "🛡️ Ultra Penetration Testing Framework v5.0 - Tool Installer"
echo "=========================================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (sudo)"
   exit 1
fi

echo "📦 Updating package lists..."
apt update

echo "🔧 Installing essential penetration testing tools..."
apt install -y \
    nmap \
    nikto \
    nuclei \
    zaproxy \
    openvas \
    metasploit-framework \
    dirb \
    wfuzz \
    masscan \
    whatweb \
    wafw00f \
    amass \
    dnsenum \
    sqlmap \
    hydra \
    john \
    hashcat \
    burpsuite \
    gobuster \
    ffuf \
    seclists \
    wordlists

echo ""
echo "✅ Tool installation completed!"
echo ""
echo "📋 Installed Tools:"
echo "  - nmap: Network scanning"
echo "  - nikto: Web server scanner"
echo "  - nuclei: Vulnerability scanner"
echo "  - zaproxy: Web application proxy"
echo "  - openvas: Vulnerability management"
echo "  - metasploit-framework: Exploitation framework"
echo "  - dirb/wfuzz: Directory brute-forcing"
echo "  - masscan: Ultra-fast port scanner"
echo "  - whatweb: Web technology fingerprinting"
echo "  - wafw00f: WAF detection"
echo "  - amass: Subdomain enumeration"
echo "  - dnsenum: DNS enumeration"
echo "  - sqlmap: SQL injection tool"
echo "  - hydra: Password cracking"
echo "  - john/hashcat: Password recovery"
echo "  - burpsuite: Web vulnerability scanner"
echo "  - gobuster/ffuf: Directory/file enumeration"
echo "  - seclists/wordlists: Security wordlists"
echo ""
echo "🚀 Next steps:"
echo "  1. Install Python dependencies: pip install -r requirements.txt"
echo "  2. Start web interface: python ultra_intelligent_pentest_v5.py --web"
echo "  3. Access at: http://localhost:5000"
echo ""
echo "⚠️  Remember: Only use these tools on systems you own or have permission to test!"
