"""
Utility functions and classes for Ultra Penetration Testing Framework v5.0
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ConfigManager:
    """Configuration management for the framework"""

    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: Invalid config file {self.config_file}")
        return self.get_default_config()

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "stealth_mode": False,
            "proxy_list": [],
            "user_agents": [
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ],
            "timeout": 30,
            "max_threads": 10,
            "output_formats": ["html", "json", "pdf"],
            "risk_threshold": "MEDIUM"
        }

    def save_config(self):
        """Save current configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)

    def set(self, key: str, value: Any):
        """Set configuration value"""
        self.config[key] = value
        self.save_config()


class Logger:
    """Enhanced logging utility"""

    def __init__(self, log_file: str = "pentest.log", level: int = logging.INFO):
        self.logger = logging.getLogger("UltraPentest")
        self.logger.setLevel(level)

        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)

        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def log(self, message: str, level: str = "INFO"):
        """Log a message"""
        if level == "INFO":
            self.logger.info(message)
        elif level == "WARNING":
            self.logger.warning(message)
        elif level == "ERROR":
            self.logger.error(message)
        elif level == "DEBUG":
            self.logger.debug(message)
        elif level == "CRITICAL":
            self.logger.critical(message)

    def info(self, message: str):
        self.log(message, "INFO")

    def warning(self, message: str):
        self.log(message, "WARNING")

    def error(self, message: str):
        self.log(message, "ERROR")

    def critical(self, message: str):
        self.log(message, "CRITICAL")


class ProgressTracker:
    """Track progress of scanning phases"""

    def __init__(self):
        self.phases = {
            "recon": {"completed": False, "progress": 0, "total": 12},
            "scanning": {"completed": False, "progress": 0, "total": 18},
            "exploitation": {"completed": False, "progress": 0, "total": 5},
            "post_exploitation": {"completed": False, "progress": 0, "total": 4},
            "reporting": {"completed": False, "progress": 0, "total": 5}
        }
        self.current_phase = None

    def start_phase(self, phase: str):
        """Start a phase"""
        if phase in self.phases:
            self.current_phase = phase
            self.phases[phase]["progress"] = 0
            print(f"[+] Starting phase: {phase}")

    def update_progress(self, phase: str, step: int = 1):
        """Update progress for a phase"""
        if phase in self.phases:
            self.phases[phase]["progress"] += step
            progress = self.phases[phase]["progress"]
            total = self.phases[phase]["total"]
            percentage = min(100, (progress / total) * 100)
            print(f"[+] {phase.capitalize()} progress: {progress}/{total} ({percentage:.1f}%)")

    def complete_phase(self, phase: str):
        """Mark phase as completed"""
        if phase in self.phases:
            self.phases[phase]["completed"] = True
            self.phases[phase]["progress"] = self.phases[phase]["total"]
            print(f"[+] Phase completed: {phase}")

    def get_overall_progress(self) -> float:
        """Get overall progress percentage"""
        total_phases = len(self.phases)
        completed_phases = sum(1 for p in self.phases.values() if p["completed"])
        total_progress = sum(p["progress"] for p in self.phases.values())
        total_possible = sum(p["total"] for p in self.phases.values())
        return (total_progress / total_possible) * 100 if total_possible > 0 else 0


class ToolChecker:
    """Check availability of external tools"""

    def __init__(self):
        self.tools = {
            "nmap": "Network scanning",
            "nikto": "Web server scanning",
            "nuclei": "Template-based scanning",
            "zaproxy": "Web application scanning",
            "openvas": "Vulnerability management",
            "sqlmap": "SQL injection exploitation",
            "metasploit": "Exploitation framework",
            "dirb": "Directory brute-forcing",
            "wfuzz": "Web fuzzing",
            "masscan": "Fast port scanning",
            "whatweb": "Web technology detection",
            "wafw00f": "WAF detection",
            "amass": "Subdomain enumeration",
            "dnsenum": "DNS enumeration",
            "linpeas": "Privilege escalation",
            "msfconsole": "Metasploit console"
        }

    def check_tool(self, tool: str) -> bool:
        """Check if a tool is available"""
        import subprocess
        try:
            result = subprocess.run([tool, "--version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return False

    def get_available_tools(self) -> List[str]:
        """Get list of available tools"""
        available = []
        for tool in self.tools.keys():
            if self.check_tool(tool):
                available.append(tool)
        return available

    def print_tool_status(self):
        """Print status of all tools"""
        print("\n[+] Tool Availability Check:")
        for tool, description in self.tools.items():
            available = self.check_tool(tool)
            status = "✓" if available else "✗"
            print(f"  {status} {tool}: {description}")


def validate_target(target: str) -> bool:
    """Validate target URL or IP"""
    import re
    from urllib.parse import urlparse

    # Check if it's an IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, target):
        parts = target.split('.')
        return all(0 <= int(part) <= 255 for part in parts)

    # Check if it's a valid URL
    try:
        parsed = urlparse(target)
        return bool(parsed.netloc or parsed.path)
    except:
        return False


def sanitize_input(input_str: str) -> str:
    """Sanitize user input to prevent injection"""
    import re
    # Remove potentially dangerous characters
    return re.sub(r'[;&|`$()<>]', '', input_str)


def create_directory_structure(base_dir: str):
    """Create the standard directory structure for results"""
    dirs = [
        base_dir,
        f"{base_dir}/scans",
        f"{base_dir}/exploits",
        f"{base_dir}/leaked_data",
        f"{base_dir}/payloads",
        f"{base_dir}/chains",
        f"{base_dir}/reports",
        f"{base_dir}/post_exploitation",
        f"{base_dir}/intelligence",
        f"{base_dir}/stealth_logs",
        f"{base_dir}/api_fuzzing",
        f"{base_dir}/deep_scans"
    ]

    for d in dirs:
        os.makedirs(d, exist_ok=True)


def save_to_file(filepath: str, content: str, mode: str = 'w'):
    """Safely save content to file"""
    try:
        with open(filepath, mode, encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"Error saving to {filepath}: {e}")
        return False


def load_from_file(filepath: str) -> Optional[str]:
    """Safely load content from file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Error loading from {filepath}: {e}")
        return None


def format_timestamp() -> str:
    """Get formatted timestamp"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def calculate_file_hash(filepath: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate file hash"""
    import hashlib
    try:
        hash_func = getattr(hashlib, algorithm)()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {filepath}: {e}")
        return None
