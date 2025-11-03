"""
Reconnaissance module for Ultra Penetration Testing Framework v5.0
Handles passive and active reconnaissance operations
"""

import socket
import requests
import dns.resolver
import whois
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import json
import time
from typing import List, Dict, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import Colors, Logger, ToolChecker, save_to_file, validate_target


class ReconnaissanceEngine:
    """Comprehensive reconnaissance engine"""

    def __init__(self, target: str, logger: Logger, stealth_mode: bool = False):
        self.target = target
        self.parsed_url = urlparse(target if target.startswith('http') else f'http://{target}')
        self.domain = self.parsed_url.netloc or self.parsed_url.path
        self.ip = None
        self.logger = logger
        self.stealth_mode = stealth_mode
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = 10

        # Results storage
        self.subdomains: Set[str] = set()
        self.ips: Set[str] = set()
        self.technologies: Dict[str, str] = {}
        self.emails: Set[str] = set()
        self.social_media: List[Dict[str, str]] = []
        self.dns_records: Dict[str, List[str]] = {}
        self.whois_data: Dict[str, str] = {}
        self.open_ports: List[Tuple[str, int, str]] = []
        self.web_paths: Set[str] = set()
        self.api_endpoints: Set[str] = set()

    def run_full_recon(self) -> Dict[str, any]:
        """Run complete reconnaissance suite"""
        self.logger.info("Starting comprehensive reconnaissance...")

        # Passive reconnaissance
        self.passive_recon()

        # Active reconnaissance
        self.active_recon()

        # Web-specific reconnaissance
        if self._is_web_target():
            self.web_recon()

        # Compile results
        results = {
            'target': self.target,
            'domain': self.domain,
            'ip': self.ip,
            'subdomains': list(self.subdomains),
            'ips': list(self.ips),
            'technologies': self.technologies,
            'emails': list(self.emails),
            'social_media': self.social_media,
            'dns_records': self.dns_records,
            'whois_data': self.whois_data,
            'open_ports': self.open_ports,
            'web_paths': list(self.web_paths),
            'api_endpoints': list(self.api_endpoints)
        }

        self.logger.info("Reconnaissance completed")
        return results

    def passive_recon(self):
        """Perform passive reconnaissance"""
        self.logger.info("Performing passive reconnaissance...")

        # DNS enumeration
        self.dns_enumeration()

        # WHOIS lookup
        self.whois_lookup()

        # Subdomain enumeration (passive)
        self.subdomain_enum_passive()

        # Email harvesting
        self.email_harvesting()

        # Social media discovery
        self.social_media_discovery()

    def active_recon(self):
        """Perform active reconnaissance"""
        self.logger.info("Performing active reconnaissance...")

        # IP resolution
        self.resolve_ip()

        # Port scanning
        self.port_scanning()

        # Service detection
        self.service_detection()

    def web_recon(self):
        """Perform web-specific reconnaissance"""
        self.logger.info("Performing web reconnaissance...")

        # Technology fingerprinting
        self.tech_fingerprinting()

        # Directory enumeration
        self.directory_enumeration()

        # API discovery
        self.api_discovery()

        # Content discovery
        self.content_discovery()

    def dns_enumeration(self):
        """Enumerate DNS records"""
        self.logger.info("Enumerating DNS records...")

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV']

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.dns_records[record_type] = [str(rdata) for rdata in answers]
                self.logger.info(f"DNS {record_type}: {len(answers)} records found")
            except dns.resolver.NoAnswer:
                continue
            except Exception as e:
                self.logger.warning(f"DNS {record_type} lookup failed: {e}")

    def whois_lookup(self):
        """Perform WHOIS lookup"""
        self.logger.info("Performing WHOIS lookup...")

        try:
            w = whois.whois(self.domain)
            self.whois_data = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
            self.logger.info("WHOIS data retrieved")
        except Exception as e:
            self.logger.warning(f"WHOIS lookup failed: {e}")

    def subdomain_enum_passive(self):
        """Passive subdomain enumeration using various sources"""
        self.logger.info("Performing passive subdomain enumeration...")

        # Certificate transparency logs
        self.subdomain_from_cert_transparency()

        # Public DNS datasets
        self.subdomain_from_public_dns()

        # Wayback machine
        self.subdomain_from_wayback()

        self.logger.info(f"Found {len(self.subdomains)} subdomains")

    def subdomain_from_cert_transparency(self):
        """Extract subdomains from certificate transparency logs"""
        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                certs = response.json()
                for cert in certs:
                    name_value = cert.get('name_value', '')
                    if name_value and self.domain in name_value:
                        subdomains = name_value.split('\n')
                        for sub in subdomains:
                            sub = sub.strip()
                            if sub and sub != self.domain and sub.endswith(f'.{self.domain}'):
                                self.subdomains.add(sub)
        except Exception as e:
            self.logger.warning(f"Certificate transparency lookup failed: {e}")

    def subdomain_from_public_dns(self):
        """Extract subdomains from public DNS datasets"""
        # This would integrate with various public DNS APIs
        # For now, just a placeholder
        pass

    def subdomain_from_wayback(self):
        """Extract subdomains from Wayback Machine"""
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    url_path = entry[0]
                    parsed = urlparse(url_path)
                    if parsed.netloc and parsed.netloc.endswith(f'.{self.domain}'):
                        self.subdomains.add(parsed.netloc)
        except Exception as e:
            self.logger.warning(f"Wayback Machine lookup failed: {e}")

    def email_harvesting(self):
        """Harvest email addresses from various sources"""
        self.logger.info("Harvesting email addresses...")

        # From WHOIS data
        if 'emails' in self.whois_data and self.whois_data['emails']:
            if isinstance(self.whois_data['emails'], list):
                self.emails.update(self.whois_data['emails'])
            else:
                self.emails.add(self.whois_data['emails'])

        # From web pages (if web target)
        if self._is_web_target():
            self.emails_from_web()

        # From search engines (simulated)
        self.emails_from_search()

    def emails_from_web(self):
        """Extract emails from web pages"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                text = soup.get_text()

                email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                found_emails = re.findall(email_pattern, text)
                self.emails.update(found_emails)
        except Exception as e:
            self.logger.warning(f"Email extraction from web failed: {e}")

    def emails_from_search(self):
        """Extract emails from search engine results (simulated)"""
        # This would integrate with search APIs
        # For now, just a placeholder
        pass

    def social_media_discovery(self):
        """Discover social media profiles"""
        self.logger.info("Discovering social media profiles...")

        social_platforms = [
            'twitter.com', 'facebook.com', 'linkedin.com', 'instagram.com',
            'github.com', 'youtube.com', 'reddit.com'
        ]

        for platform in social_platforms:
            try:
                url = f"https://{platform}/{self.domain.split('.')[0]}"
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    self.social_media.append({
                        'platform': platform,
                        'url': url,
                        'exists': True
                    })
            except:
                continue

    def resolve_ip(self):
        """Resolve target to IP address"""
        self.logger.info("Resolving IP address...")

        try:
            self.ip = socket.gethostbyname(self.domain)
            self.ips.add(self.ip)
            self.logger.info(f"Resolved {self.domain} to {self.ip}")

            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(self.ip)[0]
                self.logger.info(f"Reverse DNS: {hostname}")
            except:
                pass
        except socket.gaierror as e:
            self.logger.error(f"DNS resolution failed: {e}")

    def port_scanning(self):
        """Perform port scanning"""
        self.logger.info("Performing port scanning...")

        tool_checker = ToolChecker()

        if tool_checker.check_tool('nmap'):
            self.port_scan_nmap()
        elif tool_checker.check_tool('masscan'):
            self.port_scan_masscan()
        else:
            self.port_scan_basic()

    def port_scan_nmap(self):
        """Port scanning with nmap"""
        import subprocess

        cmd = ['nmap', '-sS', '-T4', '-p1-1000', '--open', self.domain]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                self._parse_nmap_output(result.stdout)
        except subprocess.TimeoutExpired:
            self.logger.warning("Nmap port scan timed out")
        except Exception as e:
            self.logger.error(f"Nmap port scan failed: {e}")

    def port_scan_masscan(self):
        """Port scanning with masscan"""
        import subprocess

        if not self.ip:
            return

        cmd = ['masscan', self.ip, '-p1-1000', '--rate=10000']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                self._parse_masscan_output(result.stdout)
        except Exception as e:
            self.logger.error(f"Masscan port scan failed: {e}")

    def port_scan_basic(self):
        """Basic port scanning using socket"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389]

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.ip, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None

        self.logger.info("Performing basic port scan...")
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in common_ports]
            for future in as_completed(futures):
                port = future.result()
                if port:
                    self.open_ports.append((self.ip, port, 'unknown'))
                    self.logger.info(f"Port {port} open")

    def _parse_nmap_output(self, output: str):
        """Parse nmap output"""
        lines = output.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = int(parts[0].split('/')[0])
                    service = parts[2]
                    self.open_ports.append((self.ip, port, service))

    def _parse_masscan_output(self, output: str):
        """Parse masscan output"""
        lines = output.split('\n')
        for line in lines:
            if line.startswith('open tcp'):
                parts = line.split()
                if len(parts) >= 4:
                    port = int(parts[2])
                    self.open_ports.append((self.ip, port, 'unknown'))

    def service_detection(self):
        """Detect services on open ports"""
        self.logger.info("Performing service detection...")

        for ip, port, _ in self.open_ports:
            try:
                # Basic service detection
                if port == 80:
                    service = 'http'
                elif port == 443:
                    service = 'https'
                elif port == 22:
                    service = 'ssh'
                elif port == 21:
                    service = 'ftp'
                elif port == 25:
                    service = 'smtp'
                elif port == 53:
                    service = 'dns'
                elif port == 3306:
                    service = 'mysql'
                else:
                    service = 'unknown'

                # Update the port entry
                index = self.open_ports.index((ip, port, _))
                self.open_ports[index] = (ip, port, service)

            except Exception as e:
                self.logger.warning(f"Service detection failed for port {port}: {e}")

    def tech_fingerprinting(self):
        """Fingerprint web technologies"""
        self.logger.info("Performing technology fingerprinting...")

        try:
            response = self.session.get(self.target, timeout=self.timeout)
            headers = response.headers

            # Server header
            if 'Server' in headers:
                self.technologies['server'] = headers['Server']

            # X-Powered-By header
            if 'X-Powered-By' in headers:
                self.technologies['powered_by'] = headers['X-Powered-By']

            # Content analysis
            soup = BeautifulSoup(response.text, 'html.parser')

            # Check for common frameworks
            if soup.find('script', src=re.compile(r'jquery')):
                self.technologies['javascript'] = 'jQuery'

            if soup.find('meta', attrs={'name': 'generator'}):
                generator = soup.find('meta', attrs={'name': 'generator'})
                self.technologies['cms'] = generator.get('content', '')

            # Check for WordPress
            if soup.find('link', href=re.compile(r'wp-content')):
                self.technologies['cms'] = 'WordPress'

            # Check for common libraries
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src'].lower()
                if 'bootstrap' in src:
                    self.technologies['css_framework'] = 'Bootstrap'
                elif 'angular' in src:
                    self.technologies['javascript_framework'] = 'Angular'
                elif 'react' in src:
                    self.technologies['javascript_framework'] = 'React'
                elif 'vue' in src:
                    self.technologies['javascript_framework'] = 'Vue.js'

        except Exception as e:
            self.logger.warning(f"Technology fingerprinting failed: {e}")

    def directory_enumeration(self):
        """Enumerate web directories"""
        self.logger.info("Performing directory enumeration...")

        common_paths = [
            'admin', 'administrator', 'login', 'admin/login', 'admin/index',
            'wp-admin', 'wp-login', 'administrator', 'adminer', 'phpmyadmin',
            'mysql', 'db', 'database', 'backup', 'backups', 'old', 'test', 'dev',
            'api', 'api/v1', 'api/v2', 'rest', 'graphql', 'swagger', 'docs',
            'config', 'configuration', 'settings', 'install', 'setup', 'update',
            '.git', '.svn', '.DS_Store', '.env', 'composer.json', 'package.json',
            'web.config', 'server-status', 'phpinfo.php', 'info.php', 'test.php'
        ]

        for path in common_paths:
            url = urljoin(self.target, path)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    self.web_paths.add(url)
                    self.logger.info(f"Found path: {url}")
            except:
                continue

    def api_discovery(self):
        """Discover API endpoints"""
        self.logger.info("Discovering API endpoints...")

        api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger',
            '/docs', '/api/docs', '/api/swagger', '/api/admin', '/api/users',
            '/api/auth', '/api/login'
        ]

        for path in api_paths:
            url = urljoin(self.target, path)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    self.api_endpoints.add(url)
                    self.logger.info(f"Found API endpoint: {url}")

                    # Check for API documentation
                    if 'swagger' in response.text.lower() or 'api' in response.text.lower():
                        self.logger.info(f"API documentation found: {url}")
            except:
                continue

    def content_discovery(self):
        """Discover web content"""
        self.logger.info("Performing content discovery...")

        # Look for common file extensions
        extensions = ['.txt', '.pdf', '.doc', '.xls', '.zip', '.tar.gz', '.bak', '.old', '.backup']

        for ext in extensions:
            url = urljoin(self.target, f'backup{ext}')
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    self.web_paths.add(url)
                    self.logger.info(f"Found backup file: {url}")
            except:
                continue

    def _is_web_target(self) -> bool:
        """Check if target is a web application"""
        return self.parsed_url.scheme in ['http', 'https'] or self.domain

    def save_results(self, output_dir: str):
        """Save reconnaissance results to files"""
        results = {
            'subdomains': list(self.subdomains),
            'ips': list(self.ips),
            'technologies': self.technologies,
            'emails': list(self.emails),
            'social_media': self.social_media,
            'dns_records': self.dns_records,
            'whois_data': self.whois_data,
            'open_ports': self.open_ports,
            'web_paths': list(self.web_paths),
            'api_endpoints': list(self.api_endpoints)
        }

        save_to_file(f"{output_dir}/recon_results.json", json.dumps(results, indent=2))
        self.logger.info(f"Reconnaissance results saved to {output_dir}/recon_results.json")
