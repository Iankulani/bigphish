#!/usr/bin/env python3
"""
Security Scanner for BIG-PHISH
Performs security audits, vulnerability scanning, and compliance checks
"""

import os
import sys
import json
import socket
import subprocess
import platform
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

@dataclass
class SecurityVulnerability:
    name: str
    severity: str  # low, medium, high, critical
    description: str
    recommendation: str
    affected_component: str

@dataclass
class SecurityReport:
    timestamp: str
    hostname: str
    overall_risk: str
    vulnerabilities: List[Dict]
    recommendations: List[str]
    system_checks: Dict
    network_checks: Dict
    compliance_checks: Dict

class SecurityScanner:
    def __init__(self, config_path: str = ".bigphish"):
        self.config_path = config_path
        self.results = []
    
    def run_all_scans(self) -> SecurityReport:
        """Run all security scans"""
        print("🔒 BIG-PHISH Security Scanner")
        print("=" * 60)
        
        vulnerabilities = []
        recommendations = []
        
        # System checks
        print("\n📌 Running System Security Checks...")
        sys_checks = self.check_system_security()
        vulnerabilities.extend(sys_checks.get('vulnerabilities', []))
        recommendations.extend(sys_checks.get('recommendations', []))
        
        # Network checks
        print("\n🌐 Running Network Security Checks...")
        net_checks = self.check_network_security()
        vulnerabilities.extend(net_checks.get('vulnerabilities', []))
        recommendations.extend(net_checks.get('recommendations', []))
        
        # Application checks
        print("\n🐋 Running Application Security Checks...")
        app_checks = self.check_application_security()
        vulnerabilities.extend(app_checks.get('vulnerabilities', []))
        recommendations.extend(app_checks.get('recommendations', []))
        
        # Compliance checks
        print("\n📋 Running Compliance Checks...")
        comp_checks = self.check_compliance()
        
        # Determine overall risk
        overall_risk = self._calculate_risk_level(vulnerabilities)
        
        # Format vulnerabilities for output
        vuln_dicts = [asdict(v) for v in vulnerabilities]
        
        return SecurityReport(
            timestamp=datetime.now().isoformat(),
            hostname=socket.gethostname(),
            overall_risk=overall_risk,
            vulnerabilities=vuln_dicts,
            recommendations=recommendations,
            system_checks=sys_checks,
            network_checks=net_checks,
            compliance_checks=comp_checks
        )
    
    def check_system_security(self) -> Dict:
        """Check system-level security"""
        result = {
            'vulnerabilities': [],
            'recommendations': [],
            'checks': {}
        }
        
        # Check for root/sudo privileges
        is_admin = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        result['checks']['running_as_admin'] = is_admin
        if is_admin:
            result['vulnerabilities'].append(SecurityVulnerability(
                name="Running as Administrator/Root",
                severity="high",
                description="Application running with elevated privileges",
                recommendation="Run with minimal required privileges when possible",
                affected_component="System Security"
            ))
            result['recommendations'].append("Consider running without sudo/admin for normal operations")
        
        # Check for open ports
        open_ports = self._scan_open_ports()
        result['checks']['open_ports'] = open_ports
        if open_ports:
            result['vulnerabilities'].append(SecurityVulnerability(
                name="Open Ports Detected",
                severity="medium",
                description=f"Open ports: {', '.join(map(str, open_ports[:5]))}",
                recommendation="Close unnecessary ports and firewall restricted ones",
                affected_component="Network Security"
            ))
        
        # Check for firewall
        firewall_active = self._check_firewall()
        result['checks']['firewall_active'] = firewall_active
        if not firewall_active:
            result['vulnerabilities'].append(SecurityVulnerability(
                name="Firewall Not Active",
                severity="high",
                description="System firewall is not active",
                recommendation="Enable firewall to protect against unauthorized access",
                affected_component="Network Security"
            ))
            result['recommendations'].append("Enable system firewall")
        
        # Check for antivirus (basic)
        av_installed = self._check_antivirus()
        result['checks']['antivirus_installed'] = av_installed
        if not av_installed:
            result['recommendations'].append("Install antivirus software for malware protection")
        
        # Check for outdated packages (basic)
        outdated = self._check_outdated_packages()
        result['checks']['outdated_packages'] = len(outdated)
        if outdated:
            result['recommendations'].append(f"Update {len(outdated)} outdated packages")
        
        return result
    
    def check_network_security(self) -> Dict:
        """Check network-level security"""
        result = {
            'vulnerabilities': [],
            'recommendations': [],
            'checks': {}
        }
        
        # Check for exposed services
        exposed_services = self._check_exposed_services()
        result['checks']['exposed_services'] = exposed_services
        if exposed_services:
            result['vulnerabilities'].append(SecurityVulnerability(
                name="Exposed Services",
                severity="medium",
                description=f"Services exposed: {', '.join(exposed_services[:3])}",
                recommendation="Restrict access to sensitive services",
                affected_component="Network Security"
            ))
        
        # DNS security check
        dns_secure = self._check_dns_security()
        result['checks']['dns_secure'] = dns_secure
        if not dns_secure:
            result['vulnerabilities'].append(SecurityVulnerability(
                name="DNS Security Issues",
                severity="medium",
                description="DNS configuration may be vulnerable to spoofing",
                recommendation="Configure DNSSEC or use secure DNS servers",
                affected_component="DNS Security"
            ))
        
        # Check for default credentials
        default_creds = self._check_default_credentials()
        result['checks']['default_credentials'] = default_creds
        if default_creds:
            result['vulnerabilities'].append(SecurityVulnerability(
                name="Default Credentials Detected",
                severity="critical",
                description="Default credentials found in configuration",
                recommendation="Change all default passwords immediately",
                affected_component="Authentication Security"
            ))
        
        return result
    
    def check_application_security(self) -> Dict:
        """Check application-level security"""
        result = {
            'vulnerabilities': [],
            'recommendations': [],
            'checks': {}
        }
        
        # Check config file permissions
        config_perms = self._check_config_permissions()
        result['checks']['config_permissions'] = config_perms
        if not config_perms:
            result['vulnerabilities'].append(SecurityVulnerability(
                name="Insecure Configuration Permissions",
                severity="high",
                description="Configuration files have weak permissions",
                recommendation="Restrict config files to user-only access (600/700)",
                affected_component="Configuration Security"
            ))
            result['recommendations'].append("Run: chmod 600 .bigphish/config.json")
        
        # Check for plaintext passwords
        plaintext_passwords = self._check_plaintext_passwords()
        result['checks']['plaintext_passwords'] = plaintext_passwords
        if plaintext_passwords:
            result['vulnerabilities'].append(SecurityVulnerability(
                name="Plaintext Passwords",
                severity="critical",
                description="Passwords stored in plaintext",
                recommendation="Use environment variables or encrypted storage",
                affected_component="Credential Security"
            ))
        
        # Check log security
        log_secure = self._check_log_security()
        result['checks']['log_security'] = log_secure
        if not log_secure:
            result['recommendations'].append("Secure log files and implement log rotation")
        
        # Check for sensitive data exposure
        sensitive_exposed = self._check_sensitive_exposure()
        result['checks']['sensitive_exposed'] = sensitive_exposed
        if sensitive_exposed:
            result['vulnerabilities'].append(SecurityVulnerability(
                name="Sensitive Data Exposure",
                severity="high",
                description="Sensitive data may be exposed",
                recommendation="Review logs and remove sensitive information",
                affected_component="Data Security"
            ))
        
        return result
    
    def check_compliance(self) -> Dict:
        """Check compliance with security standards"""
        result = {
            'checks': {},
            'passed': [],
            'failed': []
        }
        
        # Check encryption usage
        crypto_available = self._check_crypto()
        result['checks']['encryption_available'] = crypto_available
        if crypto_available:
            result['passed'].append("Encryption libraries available")
        else:
            result['failed'].append("No encryption libraries found")
        
        # Check for secure communication
        secure_comm = self._check_secure_communication()
        result['checks']['secure_communication'] = secure_comm
        if secure_comm:
            result['passed'].append("Secure communication available")
        
        # Check logging
        logging_enabled = self._check_logging()
        result['checks']['logging_enabled'] = logging_enabled
        if logging_enabled:
            result['passed'].append("Logging enabled")
        else:
            result['failed'].append("Logging not properly configured")
        
        # Check for security headers (if web server)
        if self._is_web_server_running():
            headers_ok = self._check_security_headers()
            result['checks']['security_headers'] = headers_ok
            if headers_ok:
                result['passed'].append("Security headers configured")
            else:
                result['failed'].append("Missing security headers")
        
        return result
    
    # Helper methods
    def _scan_open_ports(self) -> List[int]:
        """Scan for common open ports"""
        open_ports = []
        common_ports = [22, 80, 443, 3306, 5432, 6379, 27017]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        return open_ports
    
    def _check_firewall(self) -> bool:
        """Check if firewall is active"""
        system = platform.system().lower()
        
        try:
            if system == 'linux':
                result = subprocess.run(['sudo', 'ufw', 'status'], 
                                      capture_output=True, text=True, timeout=5)
                return 'active' in result.stdout.lower()
            elif system == 'windows':
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'],
                                      capture_output=True, text=True, timeout=5)
                return 'on' in result.stdout.lower()
            elif system == 'darwin':
                result = subprocess.run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'],
                                      capture_output=True, text=True, timeout=5)
                return 'enabled' in result.stdout.lower()
        except:
            pass
        
        return False
    
    def _check_antivirus(self) -> bool:
        """Basic antivirus check"""
        system = platform.system().lower()
        
        common_av = []
        if system == 'windows':
            common_av = ['MsMpEng.exe', 'avast', 'avg', 'norton', 'mcafee']
        elif system == 'linux':
            common_av = ['clamav', 'rkhunter', 'chkrootkit']
        elif system == 'darwin':
            common_av = ['XProtect', 'Malwarebytes']
        
        import psutil
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                for av in common_av:
                    if av.lower() in proc_name:
                        return True
            except:
                continue
        
        return False
    
    def _check_outdated_packages(self) -> List[str]:
        """Check for outdated packages (basic)"""
        outdated = []
        system = platform.system().lower()
        
        try:
            if system == 'linux':
                # Check for outdated packages using apt (Debian/Ubuntu)
                result = subprocess.run(['apt', 'list', '--upgradable'], 
                                      capture_output=True, text=True, timeout=30)
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line and 'upgradable' in line:
                        outdated.append(line.split('/')[0])
            elif system == 'darwin':
                result = subprocess.run(['brew', 'outdated'], 
                                      capture_output=True, text=True, timeout=30)
                outdated = [line for line in result.stdout.strip().split('\n') if line]
        except:
            pass
        
        return outdated[:10]  # Limit to first 10
    
    def _check_exposed_services(self) -> List[str]:
        """Check for exposed services"""
        exposed = []
        services = ['ssh', 'http', 'https', 'mysql', 'postgresql', 'redis', 'mongodb']
        
        for service in services:
            try:
                result = subprocess.run(['pgrep', '-f', service], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0:
                    exposed.append(service)
            except:
                pass
        
        return exposed
    
    def _check_dns_security(self) -> bool:
        """Check DNS security configuration"""
        try:
            # Check if using secure DNS
            resolv_conf = '/etc/resolv.conf'
            if os.path.exists(resolv_conf):
                with open(resolv_conf, 'r') as f:
                    content = f.read()
                    # Check for DNSSEC or secure DNS servers
                    if '8.8.8.8' in content or '1.1.1.1' in content:
                        return True
        except:
            pass
        
        return False
    
    def _check_default_credentials(self) -> bool:
        """Check for default credentials in config"""
        config_file = os.path.join(self.config_path, 'config.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    # Check for default passwords
                    default_passwords = ['password', 'admin', '123456', 'root', 'toor']
                    for key, value in config.items():
                        if isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if 'password' in sub_key.lower() and isinstance(sub_value, str):
                                    if sub_value.lower() in default_passwords:
                                        return True
            except:
                pass
        
        return False
    
    def _check_config_permissions(self) -> bool:
        """Check config file permissions"""
        config_file = os.path.join(self.config_path, 'config.json')
        if os.path.exists(config_file):
            stat_info = os.stat(config_file)
            # Check if file is readable only by owner (Unix)
            if hasattr(stat_info, 'st_mode'):
                mode = stat_info.st_mode
                # Check if others have read permissions (too permissive)
                if mode & 0o004:  # Others read
                    return False
                if mode & 0o044:  # Group read
                    return False
                return True
        return True
    
    def _check_plaintext_passwords(self) -> bool:
        """Check for plaintext passwords in config"""
        config_file = os.path.join(self.config_path, 'config.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                    # Check for password patterns
                    if '"password":' in content or '"pass":' in content:
                        # Check if encrypted
                        if 'encrypted' not in content.lower() and 'crypt' not in content.lower():
                            return True
            except:
                pass
        
        ssh_config = os.path.join(self.config_path, 'ssh_config.json')
        if os.path.exists(ssh_config):
            try:
                with open(ssh_config, 'r') as f:
                    content = f.read()
                    if '"password":' in content and 'encrypted' not in content.lower():
                        return True
            except:
                pass
        
        return False
    
    def _check_log_security(self) -> bool:
        """Check log file security"""
        log_file = os.path.join(self.config_path, 'bigphish.log')
        if os.path.exists(log_file):
            # Check if log file contains sensitive data
            try:
                with open(log_file, 'r') as f:
                    content = f.read()
                    sensitive_patterns = ['password', 'token', 'key', 'secret']
                    for pattern in sensitive_patterns:
                        if pattern in content.lower():
                            return False
            except:
                pass
        
        return True
    
    def _check_sensitive_exposure(self) -> bool:
        """Check for sensitive data exposure"""
        # Check for API keys in config
        config_file = os.path.join(self.config_path, 'config.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    # Check for API keys
                    for key, value in config.items():
                        if isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if 'token' in sub_key.lower() or 'key' in sub_key.lower():
                                    if isinstance(sub_value, str) and len(sub_value) > 10:
                                        return True
            except:
                pass
        
        return False
    
    def _check_crypto(self) -> bool:
        """Check if cryptography is available"""
        try:
            import cryptography
            return True
        except:
            return False
    
    def _check_secure_communication(self) -> bool:
        """Check if secure communication is configured"""
        config_file = os.path.join(self.config_path, 'config.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    # Check for SSL/TLS configuration
                    if config.get('security', {}).get('use_ssl'):
                        return True
            except:
                pass
        
        return False
    
    def _check_logging(self) -> bool:
        """Check logging configuration"""
        log_file = os.path.join(self.config_path, 'bigphish.log')
        return os.path.exists(log_file) and os.path.getsize(log_file) > 0
    
    def _is_web_server_running(self) -> bool:
        """Check if web server is running"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', 8080))
            sock.close()
            return result == 0
        except:
            return False
    
    def _check_security_headers(self) -> bool:
        """Check for security headers on web server"""
        try:
            import requests
            response = requests.get('http://127.0.0.1:8080', timeout=5)
            headers = response.headers
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                               'Strict-Transport-Security', 'Content-Security-Policy']
            for header in security_headers:
                if header not in headers:
                    return False
            return True
        except:
            return False
    
    def _calculate_risk_level(self, vulnerabilities: List[SecurityVulnerability]) -> str:
        """Calculate overall risk level"""
        if any(v.severity == 'critical' for v in vulnerabilities):
            return 'critical'
        elif any(v.severity == 'high' for v in vulnerabilities):
            return 'high'
        elif any(v.severity == 'medium' for v in vulnerabilities):
            return 'medium'
        elif vulnerabilities:
            return 'low'
        else:
            return 'none'
    
    def print_report(self, report: SecurityReport):
        """Print security report in readable format"""
        print("\n" + "=" * 70)
        print("🔒 SECURITY SCAN REPORT")
        print("=" * 70)
        print(f"📅 Time: {report.timestamp}")
        print(f"💻 Host: {report.hostname}")
        
        # Risk level
        risk_symbol = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'none': '✅'
        }.get(report.overall_risk, '⚪')
        print(f"\n📊 Overall Risk: {risk_symbol} {report.overall_risk.upper()}")
        
        # Vulnerabilities
        if report.vulnerabilities:
            print(f"\n🚨 VULNERABILITIES ({len(report.vulnerabilities)})")
            print("-" * 70)
            for vuln in report.vulnerabilities:
                severity_symbol = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(vuln.get('severity', 'low'), '⚪')
                print(f"\n  {severity_symbol} [{vuln.get('severity', 'UNKNOWN').upper()}] {vuln.get('name', 'Unknown')}")
                print(f"     📝 {vuln.get('description', 'No description')}")
                print(f"     💡 {vuln.get('recommendation', 'No recommendation')}")
                print(f"     🔧 Affects: {vuln.get('affected_component', 'Unknown')}")
        
        # Recommendations
        if report.recommendations:
            print(f"\n💡 RECOMMENDATIONS ({len(report.recommendations)})")
            print("-" * 70)
            for i, rec in enumerate(report.recommendations, 1):
                print(f"  {i}. {rec}")
        
        # System Checks Summary
        print(f"\n📋 SYSTEM CHECKS SUMMARY")
        print("-" * 70)
        sys_checks = report.system_checks.get('checks', {})
        for check, value in sys_checks.items():
            symbol = '✅' if value else '❌'
            print(f"  {symbol} {check.replace('_', ' ').title()}: {value}")
        
        # Compliance Checks Summary
        print(f"\n📋 COMPLIANCE CHECKS SUMMARY")
        print("-" * 70)
        comp_checks = report.compliance_checks
        for check in comp_checks.get('passed', []):
            print(f"  ✅ {check}")
        for check in comp_checks.get('failed', []):
            print(f"  ❌ {check}")
        
        print("\n" + "=" * 70)
        
        # Export option
        export = input("\n📁 Export report to JSON? (y/n): ").strip().lower()
        if export == 'y':
            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(asdict(report), f, indent=2)
            print(f"✅ Report saved to: {filename}")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BIG-PHISH Security Scanner')
    parser.add_argument('--output', choices=['text', 'json'], default='text', 
                       help='Output format')
    parser.add_argument('--save', action='store_true', 
                       help='Save report to file')
    
    args = parser.parse_args()
    
    scanner = SecurityScanner()
    report = scanner.run_all_scans()
    
    if args.output == 'json':
        print(json.dumps(asdict(report), indent=2))
    else:
        scanner.print_report(report)
    
    if args.save:
        filename = f"security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(asdict(report), f, indent=2)
        print(f"\n✅ Report saved to: {filename}")

if __name__ == "__main__":
    main()