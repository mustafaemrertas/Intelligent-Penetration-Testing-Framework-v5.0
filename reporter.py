"""
Reporting module for Ultra Penetration Testing Framework v5.0
Handles generation of various report formats and compliance reporting
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from jinja2 import Template
try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False
from utils import Colors, Logger, save_to_file


@dataclass
class Vulnerability:
    """Vulnerability data structure"""
    vuln_type: str
    severity: str
    cvss_score: float
    risk_score: float
    url: str
    parameter: str = ""
    payload: str = ""
    detail: str = ""
    exploited: bool = False
    mitigations: List[str] = None
    poc_code: str = ""

    def __post_init__(self):
        if self.mitigations is None:
            self.mitigations = []


@dataclass
class ScanResult:
    """Complete scan result data structure"""
    target: str
    timestamp: str
    vulnerabilities: List[Vulnerability]
    correlations: List[Dict[str, Any]]
    leaked_data: Dict[str, set]
    exploited_vulns: int
    scan_duration: float


class ReportGenerator:
    """Base class for report generation"""

    def __init__(self, results_dir: str, logger: Logger):
        self.results_dir = results_dir
        self.logger = logger
        self.reports_dir = f"{results_dir}/reports"
        os.makedirs(self.reports_dir, exist_ok=True)

    def generate_all_reports(self, scan_result: ScanResult):
        """Generate all report formats"""
        self.logger.info("Generating comprehensive reports...")

        # Generate each report format
        self.generate_html_report(scan_result)
        self.generate_json_report(scan_result)
        self.generate_pdf_report(scan_result)
        self.generate_executive_summary(scan_result)
        self.generate_risk_matrix(scan_result)

        self.logger.info("All reports generated successfully")

    def generate_html_report(self, scan_result: ScanResult):
        """Generate HTML report"""
        template = self._get_html_template()
        html_content = template.render(
            scan_result=scan_result,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            vuln_count=len(scan_result.vulnerabilities),
            critical_count=len([v for v in scan_result.vulnerabilities if v.severity == 'CRITICAL']),
            high_count=len([v for v in scan_result.vulnerabilities if v.severity == 'HIGH']),
            correlation_count=len(scan_result.correlations),
            data_leaks=sum(len(v) for v in scan_result.leaked_data.values())
        )

        report_file = f"{self.reports_dir}/final_report.html"
        save_to_file(report_file, html_content)
        self.logger.info(f"HTML report generated: {report_file}")

    def generate_json_report(self, scan_result: ScanResult):
        """Generate JSON report"""
        # Convert dataclasses to dicts for JSON serialization
        report_data = {
            'target': scan_result.target,
            'timestamp': scan_result.timestamp,
            'scan_duration': scan_result.scan_duration,
            'summary': {
                'total_vulnerabilities': len(scan_result.vulnerabilities),
                'critical_count': len([v for v in scan_result.vulnerabilities if v.severity == 'CRITICAL']),
                'high_count': len([v for v in scan_result.vulnerabilities if v.severity == 'HIGH']),
                'correlation_count': len(scan_result.correlations),
                'data_leaks': sum(len(v) for v in scan_result.leaked_data.values()),
                'exploited_vulns': scan_result.exploited_vulns
            },
            'vulnerabilities': [self._vuln_to_dict(v) for v in scan_result.vulnerabilities],
            'correlations': scan_result.correlations,
            'leaked_data': {k: list(v) for k, v in scan_result.leaked_data.items()}
        }

        report_file = f"{self.reports_dir}/report.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        self.logger.info(f"JSON report generated: {report_file}")

    def generate_pdf_report(self, scan_result: ScanResult):
        """Generate PDF report"""
        html_file = f"{self.reports_dir}/final_report.html"
        pdf_file = f"{self.reports_dir}/report.pdf"

        if os.path.exists(html_file):
            try:
                # Use pdfkit if available, otherwise skip
                import pdfkit
                pdfkit.from_file(html_file, pdf_file)
                self.logger.info(f"PDF report generated: {pdf_file}")
            except ImportError:
                self.logger.warning("pdfkit not available, skipping PDF generation")
            except Exception as e:
                self.logger.error(f"PDF generation failed: {e}")
        else:
            self.logger.warning("HTML report not found, cannot generate PDF")

    def generate_executive_summary(self, scan_result: ScanResult):
        """Generate executive summary"""
        summary_file = f"{self.reports_dir}/executive_summary.txt"

        critical_count = len([v for v in scan_result.vulnerabilities if v.severity == 'CRITICAL'])
        high_count = len([v for v in scan_result.vulnerabilities if v.severity == 'HIGH'])
        total_risk_score = sum(v.risk_score for v in scan_result.vulnerabilities)

        summary = f"""{'='*80}
EXECUTIVE SUMMARY - ULTRA PENETRATION TEST REPORT v5.0
{'='*80}

Target: {scan_result.target}
Date: {scan_result.timestamp}
Scan Duration: {scan_result.scan_duration:.2f} seconds

SECURITY POSTURE OVERVIEW:
{'-'*40}
Total Vulnerabilities Discovered: {len(scan_result.vulnerabilities)}
Critical Severity Issues: {critical_count}
High Severity Issues: {high_count}
Attack Chains Identified: {len(scan_result.correlations)}
Data Leakage Incidents: {sum(len(v) for v in scan_result.leaked_data.values())}
Overall Risk Score: {total_risk_score:.1f}/100

TOP VULNERABILITIES:
{'-'*40}
"""

        # Sort vulnerabilities by CVSS score
        sorted_vulns = sorted(scan_result.vulnerabilities, key=lambda x: x.cvss_score, reverse=True)
        for i, vuln in enumerate(sorted_vulns[:5], 1):
            summary += f"{i}. {vuln.vuln_type} (CVSS: {vuln.cvss_score}) - {vuln.severity}\n"

        summary += f"""
RECOMMENDED IMMEDIATE ACTIONS:
{'-'*40}
"""
        if critical_count > 0:
            summary += "• IMMEDIATE: Address all CRITICAL severity vulnerabilities\n"
        if len(scan_result.correlations) > 0:
            summary += "• HIGH PRIORITY: Review identified attack chains\n"
        if sum(len(v) for v in scan_result.leaked_data.values()) > 0:
            summary += "• URGENT: Investigate data leakage incidents\n"
        summary += "• Implement security headers and input validation\n"
        summary += "• Regular security assessments recommended\n"

        save_to_file(summary_file, summary)
        self.logger.info(f"Executive summary generated: {summary_file}")

    def generate_risk_matrix(self, scan_result: ScanResult):
        """Generate risk matrix"""
        matrix_file = f"{self.reports_dir}/risk_matrix.txt"

        severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        matrix = f"""RISK MATRIX
{'='*50}

Likelihood vs Impact Assessment:

"""

        for severity in severity_levels:
            count = len([v for v in scan_result.vulnerabilities if v.severity == severity])
            risk_level = "CRITICAL" if severity == "CRITICAL" else "HIGH" if severity == "HIGH" else "MEDIUM" if severity == "MEDIUM" else "LOW"
            matrix += f"{severity:10} | {count:3} vulnerabilities | Risk Level: {risk_level}\n"

        matrix += f"""
OVERALL RISK ASSESSMENT:
"""
        total_vulns = len(scan_result.vulnerabilities)
        if total_vulns == 0:
            matrix += "LOW RISK - No vulnerabilities found\n"
        elif len([v for v in scan_result.vulnerabilities if v.severity in ['CRITICAL', 'HIGH']]) > total_vulns * 0.3:
            matrix += "CRITICAL RISK - Immediate attention required\n"
        elif len([v for v in scan_result.vulnerabilities if v.severity in ['CRITICAL', 'HIGH', 'MEDIUM']]) > total_vulns * 0.5:
            matrix += "HIGH RISK - Urgent remediation needed\n"
        else:
            matrix += "MEDIUM RISK - Monitor and address issues\n"

        save_to_file(matrix_file, matrix)
        self.logger.info(f"Risk matrix generated: {matrix_file}")

    def _get_html_template(self) -> Template:
        """Get HTML report template"""
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultra Penetration Test Report - {{ scan_result.target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .vulnerability { padding: 10px; margin: 5px 0; border-left: 5px solid; border-radius: 4px; }
        .CRITICAL { border-color: #dc3545; background-color: #f8d7da; }
        .HIGH { border-color: #fd7e14; background-color: #fff3cd; }
        .MEDIUM { border-color: #ffc107; background-color: #fff3cd; }
        .LOW { border-color: #28a745; background-color: #d4edda; }
        .INFO { border-color: #17a2b8; background-color: #d1ecf1; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat { text-align: center; padding: 20px; background: #e9ecef; border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .risk-matrix { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-top: 20px; }
        .risk-cell { padding: 15px; text-align: center; border-radius: 4px; color: white; font-weight: bold; }
        .risk-high { background-color: #dc3545; }
        .risk-medium { background-color: #ffc107; }
        .risk-low { background-color: #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Ultra Penetration Test Report v5.0</h1>
        <h2>Target: {{ scan_result.target }}</h2>
        <p>Generated on: {{ timestamp }}</p>
        <p>Scan Duration: {{ "%.2f"|format(scan_result.scan_duration) }} seconds</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="stats">
            <div class="stat">
                <h3>{{ vuln_count }}</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="stat">
                <h3>{{ critical_count }}</h3>
                <p>Critical Issues</p>
            </div>
            <div class="stat">
                <h3>{{ correlation_count }}</h3>
                <p>Attack Chains</p>
            </div>
            <div class="stat">
                <h3>{{ data_leaks }}</h3>
                <p>Data Leaks</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Vulnerabilities Found</h2>
        {% for vuln in scan_result.vulnerabilities %}
        <div class="vulnerability {{ vuln.severity }}">
            <h4>{{ vuln.vuln_type }} (CVSS: {{ vuln.cvss_score }})</h4>
            <p><strong>Severity:</strong> {{ vuln.severity }}</p>
            <p><strong>URL:</strong> {{ vuln.url }}</p>
            {% if vuln.parameter %}
            <p><strong>Parameter:</strong> {{ vuln.parameter }}</p>
            {% endif %}
            {% if vuln.payload %}
            <p><strong>Payload:</strong> {{ vuln.payload }}</p>
            {% endif %}
            <p><strong>Details:</strong> {{ vuln.detail }}</p>
            <p><strong>Mitigations:</strong> {{ vuln.mitigations|join('; ') }}</p>
            {% if vuln.poc_code %}
            <details>
                <summary>Proof of Concept Code</summary>
                <pre>{{ vuln.poc_code }}</pre>
            </details>
            {% endif %}
        </div>
        {% endfor %}
    </div>

    <div class="section">
        <h2>Attack Chains & Correlations</h2>
        {% for corr in scan_result.correlations %}
        <div class="vulnerability HIGH">
            <h4>{{ corr.type }}</h4>
            <p><strong>Description:</strong> {{ corr.description }}</p>
            <p><strong>Severity:</strong> {{ corr.severity }}</p>
        </div>
        {% endfor %}
    </div>

    <div class="section">
        <h2>Leaked Data Summary</h2>
        <table>
            <tr><th>Data Type</th><th>Count</th><th>Examples</th></tr>
            {% for key, value in scan_result.leaked_data.items() %}
            <tr><td>{{ key.title() }}</td><td>{{ value|length }}</td><td>{{ value|list|slice(3)|join(', ') }}</td></tr>
            {% endfor %}
        </table>
    </div>

    <div class="section">
        <h2>Risk Matrix</h2>
        <div class="risk-matrix">
            {% set severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] %}
            {% for level in severity_levels %}
                {% set count = scan_result.vulnerabilities|selectattr('severity', 'equalto', level)|list|length %}
                {% set css_class = 'risk-high' if level in ['CRITICAL', 'HIGH'] else 'risk-medium' if level == 'MEDIUM' else 'risk-low' %}
                <div class="risk-cell {{ css_class }}">{{ level }}<br/>{{ count }}</div>
            {% endfor %}
        </div>
    </div>
</body>
</html>
"""
        return Template(template_str)

    def _vuln_to_dict(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert Vulnerability dataclass to dictionary"""
        return {
            'type': vuln.vuln_type,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score,
            'risk_score': vuln.risk_score,
            'url': vuln.url,
            'parameter': vuln.parameter,
            'payload': vuln.payload,
            'detail': vuln.detail,
            'exploited': vuln.exploited,
            'mitigations': vuln.mitigations,
            'poc_code': vuln.poc_code
        }


class ComplianceReporter:
    """Generate compliance reports for various standards"""

    def __init__(self, results_dir: str, logger: Logger):
        self.results_dir = results_dir
        self.logger = logger
        self.compliance_dir = f"{results_dir}/compliance"
        os.makedirs(self.compliance_dir, exist_ok=True)

    def generate_compliance_reports(self, scan_result: ScanResult):
        """Generate reports for various compliance standards"""
        self.logger.info("Generating compliance reports...")

        self.generate_owasp_report(scan_result)
        self.generate_pci_dss_report(scan_result)
        self.generate_nist_report(scan_result)
        self.generate_iso27001_report(scan_result)

        self.logger.info("Compliance reports generated")

    def generate_owasp_report(self, scan_result: ScanResult):
        """Generate OWASP Top 10 compliance report"""
        owasp_mapping = {
            'SQL Injection': 'A03:2021-Injection',
            'XSS': 'A03:2021-Injection',
            'Command Injection': 'A03:2021-Injection',
            'CSRF': 'A01:2021-Broken Access Control',
            'IDOR': 'A01:2021-Broken Access Control',
            'LFI': 'A06:2021-Vulnerable Components',
            'RFI': 'A06:2021-Vulnerable Components',
            'SSRF': 'A10:2021-Server-Side Request Forgery',
            'XXE': 'A05:2021-Security Misconfiguration'
        }

        report = f"""OWASP Top 10 Compliance Report
{'='*40}

Target: {scan_result.target}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

OWASP Top 10 Coverage:
"""

        for vuln in scan_result.vulnerabilities:
            if vuln.vuln_type in owasp_mapping:
                report += f"✓ {owasp_mapping[vuln.vuln_type]} - {vuln.vuln_type} ({vuln.severity})\n"

        report += "\nRecommendations:\n"
        report += "- Implement input validation and sanitization\n"
        report += "- Use parameterized queries\n"
        report += "- Implement proper access controls\n"
        report += "- Regular security assessments\n"

        save_to_file(f"{self.compliance_dir}/owasp_report.txt", report)
        self.logger.info("OWASP compliance report generated")

    def generate_pci_dss_report(self, scan_result: ScanResult):
        """Generate PCI DSS compliance report"""
        pci_requirements = {
            '6.5.1': 'Injection flaws',
            '6.5.2': 'Buffer overflows',
            '6.5.3': 'Insecure cryptographic storage',
            '6.5.4': 'Insecure communications',
            '6.5.5': 'Improper error handling'
        }

        report = f"""PCI DSS Compliance Report
{'='*40}

Target: {scan_result.target}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

PCI DSS Requirement 6.5 Assessment:
"""

        for req, desc in pci_requirements.items():
            violations = [v for v in scan_result.vulnerabilities if desc.lower() in v.detail.lower()]
            status = "PASS" if not violations else "FAIL"
            report += f"{req} ({desc}): {status}\n"
            if violations:
                for v in violations[:3]:
                    report += f"  - {v.vuln_type} ({v.severity})\n"

        save_to_file(f"{self.compliance_dir}/pci_dss_report.txt", report)
        self.logger.info("PCI DSS compliance report generated")

    def generate_nist_report(self, scan_result: ScanResult):
        """Generate NIST compliance report"""
        nist_controls = {
            'SI-10': 'Information Input Validation',
            'AC-3': 'Access Enforcement',
            'SC-8': 'Transmission Confidentiality',
            'SI-11': 'Error Handling'
        }

        report = f"""NIST SP 800-53 Compliance Report
{'='*40}

Target: {scan_result.target}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

NIST Control Assessment:
"""

        for control, desc in nist_controls.items():
            violations = [v for v in scan_result.vulnerabilities if desc.lower() in v.detail.lower()]
            status = "COMPLIANT" if not violations else "NON-COMPLIANT"
            report += f"{control} ({desc}): {status}\n"
            if violations:
                for v in violations[:3]:
                    report += f"  - {v.vuln_type} ({v.severity})\n"

        save_to_file(f"{self.compliance_dir}/nist_report.txt", report)
        self.logger.info("NIST compliance report generated")

    def generate_iso27001_report(self, scan_result: ScanResult):
        """Generate ISO 27001 compliance report"""
        iso_controls = {
            'A.12.1': 'Operational procedures and responsibilities',
            'A.12.2': 'Protection from malware',
            'A.12.3': 'Backup',
            'A.12.4': 'Logging and monitoring',
            'A.12.5': 'Control of operational software'
        }

        report = f"""ISO 27001 Compliance Report
{'='*40}

Target: {scan_result.target}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

ISO 27001 Control Assessment:
"""

        for control, desc in iso_controls.items():
            violations = [v for v in scan_result.vulnerabilities if desc.lower() in v.detail.lower()]
            status = "COMPLIANT" if not violations else "NON-COMPLIANT"
            report += f"{control} ({desc}): {status}\n"
            if violations:
                for v in violations[:3]:
                    report += f"  - {v.vuln_type} ({v.severity})\n"

        save_to_file(f"{self.compliance_dir}/iso27001_report.txt", report)
        self.logger.info("ISO 27001 compliance report generated")
