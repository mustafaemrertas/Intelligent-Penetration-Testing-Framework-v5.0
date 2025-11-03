# Ultra Intelligent Penetration Testing Framework v5.0

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

**ULTRA-COMPREHENSIVE AI-ENHANCED Intelligent Web Penetration Testing Framework**

An advanced, AI-powered penetration testing framework that integrates all major Kali Linux tools with intelligent automation, comprehensive reporting, and web-based management interface.

## 🔥 Key Features

### 🤖 AI-Powered Intelligence
- **Adaptive Scanning**: AI-driven decision making for optimal scan strategies
- **Smart Correlations**: Automatic vulnerability correlation and attack chain detection
- **Risk-Based Prioritization**: Intelligent prioritization based on CVSS scores and exploitability

### 🛠️ Comprehensive Tool Integration
- **All Kali Tools**: Nikto, Nuclei, OWASP ZAP, OpenVAS, Metasploit, SQLMap
- **Advanced Scanners**: Masscan, WhatWeb, WAF detection, Directory brute-forcing
- **Custom Payloads**: Underground techniques with zero-day detection capabilities

### 🎯 Complete Testing Coverage
- **18 Vulnerability Types**: SQLi, XSS, CSRF, LFI, RFI, XXE, SSRF, IDOR, and more
- **API Testing**: REST API fuzzing, GraphQL, Swagger detection
- **WordPress Deep Scan**: Specialized WordPress vulnerability assessment
- **File Upload Testing**: Comprehensive file upload vulnerability detection

### 📊 Professional Reporting
- **Multiple Formats**: HTML, JSON, PDF, Executive Summary
- **CVSS Scoring**: Automated CVSS v3.1 vulnerability scoring
- **Risk Matrix**: Visual risk assessment and prioritization
- **Executive Reports**: Business-friendly security assessments

### 🌐 Web Interface
- **Modern UI**: Clean, responsive web interface
- **Real-time Monitoring**: Live scan progress and status updates
- **REST API**: Full REST API for integration and automation
- **Authentication**: Secure login system with rate limiting

### 🔒 Security & Stealth
- **Stealth Mode**: Quiet scanning with user-agent rotation and proxy support
- **Rate Limiting**: Built-in protection against abuse
- **Logging**: Comprehensive audit logging
- **Underground Techniques**: Advanced evasion methods

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Command Line Interface](#command-line-interface)
  - [Web Interface](#web-interface)
  - [REST API](#rest-api)
- [Architecture](#architecture)
- [Modules](#modules)
- [Configuration](#configuration)
- [Examples](#examples)
- [Reporting](#reporting)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## 🚀 Installation

### Prerequisites

- **Python 3.8+**
- **Kali Linux** (recommended) or Linux with penetration testing tools
- **Root privileges** for some advanced features

### Install Required Tools (Kali Linux)

#### Option 1: Automated Installation (Recommended)

```bash
# Make script executable and run
chmod +x install_tools.sh
sudo ./install_tools.sh
```

#### Option 2: Manual Installation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential pentesting tools
sudo apt install -y nmap nikto nuclei zaproxy openvas wfuzz dirb sqlmap metasploit-framework masscan whatweb wafw00f amass dnsenum

# Install Python dependencies
pip install -r requirements.txt
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ultra-pentest-framework.git
cd ultra-pentest-framework

# Install Python dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x ultra_intelligent_pentest_v5.py
```

### Requirements File

```
requests==2.31.0
beautifulsoup4==4.12.2
lxml==4.9.3
urllib3==2.0.7
flask==2.3.3
flask-limiter==3.5.0
werkzeug==2.3.7
reportlab==4.0.7
pexpect==4.8.0
python-dotenv==1.0.0
```

## ⚡ Quick Start

### Basic Scan (CLI)

```bash
# Simple target scan
python ultra_intelligent_pentest_v5.py example.com

# Stealth mode scan
python ultra_intelligent_pentest_v5.py example.com --stealth

# Web interface mode
python ultra_intelligent_pentest_v5.py --web
```

### Web Interface

```bash
# Start web server
python ultra_intelligent_pentest_v5.py --web

# Access at: http://localhost:5000
# Default login: admin / ultra_pentest_2024
```

## 📖 Usage

### Command Line Interface

#### Basic Syntax

```bash
python ultra_intelligent_pentest_v5.py [TARGET] [OPTIONS]
```

#### Options

| Option | Description | Example |
|--------|-------------|---------|
| `--web` | Start web interface | `python ultra_intelligent_pentest_v5.py --web` |
| `--stealth` | Enable stealth mode | `python ultra_intelligent_pentest_v5.py target.com --stealth` |
| `--proxy` | Use proxy | `python ultra_intelligent_pentest_v5.py target.com --proxy http://proxy:8080` |

#### Examples

```bash
# Basic web application scan
python ultra_intelligent_pentest_v5.py http://example.com

# Comprehensive scan with all tools
python ultra_intelligent_pentest_v5.py https://target.com --stealth

# Network infrastructure scan
python ultra_intelligent_pentest_v5.py 192.168.1.100
```

### Web Interface

1. **Start the server**:
   ```bash
   python ultra_intelligent_pentest_v5.py --web
   ```

2. **Access the interface**:
   - Open browser: `http://localhost:5000`
   - Login with: `admin` / `ultra_pentest_2024`

3. **Dashboard Features**:
   - Real-time scan status
   - Vulnerability summary
   - Quick action buttons
   - Results viewer

4. **Starting a Scan**:
   - Enter target URL/IP
   - Choose scan mode (Normal/Stealth)
   - Click "Start Scan"
   - Monitor progress in real-time

### REST API

#### Welcome Endpoint

```bash
# Test the welcome endpoint
curl -X GET http://localhost:5000/welcome
curl -X POST http://localhost:5000/welcome
curl -X PUT http://localhost:5000/welcome
curl -X DELETE http://localhost:5000/welcome
```

**Response**:
```json
{
  "message": "Welcome to the Ultra Penetration Testing Framework API!",
  "timestamp": "2024-01-01T12:00:00.000000",
  "request_info": {
    "method": "GET",
    "path": "/welcome",
    "ip": "127.0.0.1"
  }
}
```

#### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/welcome` | GET, POST, PUT, DELETE | Welcome endpoint with logging |
| `/api/v1/scan` | POST | Start new scan |
| `/api/v1/status` | GET | Get scan status |
| `/scan_status` | GET | Web interface scan status |

## 🏗️ Architecture

```
ultra-pentest-framework/
├── ultra_intelligent_pentest_v5.py  # Main framework
├── api.py                           # Flask web API
├── utils.py                         # Utilities and logging
├── reporter.py                      # Report generation
├── scanner.py                       # Vulnerability scanners
├── recon.py                         # Reconnaissance module
├── requirements.txt                 # Python dependencies
├── TODO.md                          # Development tasks
└── README.md                        # This file
```

### Core Components

1. **Main Framework** (`ultra_intelligent_pentest_v5.py`)
   - Orchestrates all scanning phases
   - Manages tool integration
   - Handles reporting

2. **Web API** (`api.py`)
   - Flask-based REST API
   - Web interface templates
   - Authentication and rate limiting

3. **Utility Modules**
   - `utils.py`: Logging, configuration, colors
   - `reporter.py`: HTML/PDF/JSON report generation
   - `scanner.py`: Vulnerability scanning logic
   - `recon.py`: Reconnaissance and enumeration

## 📚 Modules

### Phase 1: Ultra Reconnaissance (12 Tests)
- Target resolution and IP discovery
- Comprehensive Nmap scanning
- Masscan for ultra-fast port scanning
- Technology fingerprinting (WhatWeb)
- WAF detection
- Subdomain enumeration
- DNS enumeration
- Web crawling and structure discovery
- API endpoint discovery
- Git repository exposure checks
- Backup file discovery

### Phase 2: Vulnerability Scanning (18 Tests)
- Nikto web server scanning
- Nuclei template-based scanning
- OWASP ZAP integration
- OpenVAS vulnerability management
- SQL Injection testing
- XSS (Cross-Site Scripting)
- Command Injection
- LFI (Local File Inclusion)
- RFI (Remote File Inclusion)
- CSRF testing
- IDOR (Insecure Direct Object Reference)
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- Advanced directory enumeration
- Header security analysis
- File upload vulnerability testing
- Session management analysis
- WordPress deep scanning
- API vulnerability testing
- Deep SSRF/LFI scanning

### Phase 3: Exploitation
- Automated exploit attempts
- SQLMap integration
- Metasploit Framework integration
- Attack chain execution
- Intelligent exploit chaining

### Phase 4: Post-Exploitation
- Privilege escalation attempts
- Data exfiltration
- Persistence mechanisms
- Lateral movement detection

### Phase 5: Reporting
- HTML reports with modern styling
- JSON structured data
- PDF executive reports
- Risk matrix generation
- Executive summaries

## ⚙️ Configuration

### Environment Variables

```bash
# Flask secret key
export SECRET_KEY="your-secret-key-here"

# Default admin password (change in production)
export ADMIN_PASSWORD="your-secure-password"
```

### Configuration Files

The framework uses `ConfigManager` for configuration. Default settings are in `utils.py`.

## 📋 Examples

### Complete Web Application Assessment

```bash
# Start web interface
python ultra_intelligent_pentest_v5.py --web

# In browser, enter target: https://example.com
# Choose stealth mode for production targets
# Monitor scan progress and view comprehensive reports
```

### API Integration Example

```python
import requests

# Start scan via API
response = requests.post('http://localhost:5000/api/v1/scan',
                        json={'target': 'example.com', 'stealth': True})
print(response.json())

# Check status
status = requests.get('http://localhost:5000/api/v1/status')
print(status.json())
```

### Automated Batch Scanning

```bash
# Scan multiple targets
for target in targets.txt; do
    python ultra_intelligent_pentest_v5.py $target --stealth
done
```

## 📊 Reporting

### Report Types

1. **HTML Report** (`final_report.html`)
   - Modern, responsive design
   - Interactive vulnerability details
   - Risk matrix visualization
   - Executive summary

2. **JSON Report** (`report.json`)
   - Structured data for integration
   - Complete vulnerability details
   - Scan metadata

3. **PDF Report** (`report.pdf`)
   - Professional formatting
   - Executive-friendly
   - Printable format

4. **Executive Summary** (`executive_summary.txt`)
   - Key findings
   - Risk assessment
   - Recommendations

5. **Risk Matrix** (`risk_matrix.txt`)
   - Prioritized vulnerabilities
   - Impact analysis

### Sample Report Structure

```
ultra_pentest_target.com_YYYYMMDD_HHMMSS/
├── scans/                    # Raw scan outputs
├── leaked_data/             # Extracted sensitive data
├── post_exploitation/       # Post-exploit findings
├── exploits/                # Exploit attempts
└── reports/                 # Generated reports
    ├── final_report.html
    ├── report.json
    ├── report.pdf
    ├── executive_summary.txt
    └── risk_matrix.txt
```

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes: `git commit -m 'Add amazing feature'`
4. **Push** to the branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add comprehensive docstrings
- Include unit tests for new features
- Update documentation
- Test on multiple Python versions

### Adding New Modules

1. Create module in appropriate directory
2. Add imports to main framework
3. Update phase execution logic
4. Add configuration options
5. Update documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**This tool is for educational and authorized security testing purposes only.**

- Only use on systems you own or have explicit permission to test
- Unauthorized use may violate laws and regulations
- The authors are not responsible for misuse
- Always obtain written permission before testing
- Use at your own risk

### Legal Notice

This penetration testing framework is provided "as is" without warranty of any kind. Users are solely responsible for compliance with applicable laws and regulations.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/ultra-pentest-framework/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/ultra-pentest-framework/discussions)
- **Documentation**: [Wiki](https://github.com/yourusername/ultra-pentest-framework/wiki)

## 🙏 Acknowledgments

- Kali Linux team for providing excellent tools
- OWASP community for security research
- Open source security researchers worldwide

---

**Made with ❤️ for the security community**

*Stay secure, stay ethical*
