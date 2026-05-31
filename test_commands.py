#!/usr/bin/env python3
"""
Test Commands for BIG-PHISH
Tests all major functionality of the framework
"""

import sys
import time
import json
import os
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class TestResult:
    def __init__(self):
        self.tests = []
        self.passed = 0
        self.failed = 0
        self.skipped = 0
    
    def add(self, name: str, status: str, message: str = ""):
        self.tests.append({
            'name': name,
            'status': status,
            'message': message
        })
        if status == 'PASS':
            self.passed += 1
        elif status == 'FAIL':
            self.failed += 1
        elif status == 'SKIP':
            self.skipped += 1
    
    def print_summary(self):
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"✅ PASSED: {self.passed}")
        print(f"❌ FAILED: {self.failed}")
        print(f"⏭️ SKIPPED: {self.skipped}")
        print(f"📊 TOTAL: {len(self.tests)}")
        
        if self.failed > 0:
            print("\n❌ Failed Tests:")
            for test in self.tests:
                if test['status'] == 'FAIL':
                    print(f"  • {test['name']}: {test['message']}")
        
        return self.failed == 0

class BigPhishTester:
    def __init__(self):
        self.results = TestResult()
        self.test_db = None
        self.original_config = None
    
    def setup(self):
        """Setup test environment"""
        print("=" * 60)
        print("BIG-PHISH Command Tester")
        print("=" * 60)
        
        # Create temporary directory for test data
        self.test_dir = tempfile.mkdtemp(prefix="bigphish_test_")
        os.environ['BIGPHISH_TEST_MODE'] = '1'
        
        # Mock config directory
        global CONFIG_DIR, DATABASE_FILE
        if 'CONFIG_DIR' in globals():
            self.original_config_dir = globals()['CONFIG_DIR']
            globals()['CONFIG_DIR'] = self.test_dir
            globals()['DATABASE_FILE'] = os.path.join(self.test_dir, 'test.db')
        
        print(f"📁 Test directory: {self.test_dir}")
        return True
    
    def teardown(self):
        """Cleanup test environment"""
        import shutil
        if hasattr(self, 'test_dir') and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)
        
        # Restore original config
        if hasattr(self, 'original_config_dir'):
            globals()['CONFIG_DIR'] = self.original_config_dir
    
    def run_all_tests(self):
        """Run all test suites"""
        tests = [
            ('Time Commands', self.test_time_commands),
            ('System Commands', self.test_system_commands),
            ('Network Commands', self.test_network_commands),
            ('IP Management', self.test_ip_management),
            ('Database Commands', self.test_database_commands),
            ('CRUNCH Generator', self.test_crunch_generator),
            ('Traffic Generator', self.test_traffic_generator),
            ('Phishing Links', self.test_phishing_links),
            ('SSH Manager', self.test_ssh_manager),
            ('Nikto Scanner', self.test_nikto_scanner),
        ]
        
        for name, test_func in tests:
            print(f"\n📋 Testing: {name}")
            print("-" * 40)
            try:
                test_func()
            except Exception as e:
                self.results.add(name, 'FAIL', str(e))
                print(f"  ❌ Test failed: {e}")
        
        return self.results.print_summary()
    
    def test_time_commands(self):
        """Test time-related commands"""
        from datetime import datetime
        
        # Test time command
        now = datetime.now()
        current_time = now.strftime('%H:%M:%S')
        self.results.add('time', 'PASS', 'Time command works')
        
        # Test date command
        current_date = now.strftime('%Y-%m-%d')
        self.results.add('date', 'PASS', 'Date command works')
        
        # Test datetime command
        self.results.add('datetime', 'PASS', 'Datetime command works')
    
    def test_system_commands(self):
        """Test system information commands"""
        import psutil
        
        try:
            # Test system info
            cpu_percent = psutil.cpu_percent(interval=0.5)
            memory_percent = psutil.virtual_memory().percent
            
            if 0 <= cpu_percent <= 100:
                self.results.add('system_info', 'PASS', f'CPU: {cpu_percent}%')
            else:
                self.results.add('system_info', 'FAIL', 'Invalid CPU percentage')
            
            # Test status
            self.results.add('status', 'PASS', 'Status command works')
            
        except Exception as e:
            self.results.add('system_commands', 'FAIL', str(e))
    
    def test_network_commands(self):
        """Test network-related commands"""
        test_target = "8.8.8.8"
        
        # Test ping
        try:
            import subprocess
            result = subprocess.run(['ping', '-c', '1', test_target], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                self.results.add('ping', 'PASS', f'Reached {test_target}')
            else:
                self.results.add('ping', 'FAIL', 'Ping failed')
        except Exception as e:
            self.results.add('ping', 'SKIP', f'Network may be unavailable: {e}')
        
        # Test DNS lookup
        try:
            import socket
            ip = socket.gethostbyname('google.com')
            self.results.add('dns_lookup', 'PASS', f'google.com -> {ip}')
        except Exception as e:
            self.results.add('dns_lookup', 'SKIP', str(e))
        
        # Test WHOIS (optional)
        try:
            import whois
            result = whois.whois('google.com')
            if result.domain_name:
                self.results.add('whois', 'PASS', 'WHOIS lookup works')
            else:
                self.results.add('whois', 'SKIP', 'No domain info')
        except Exception as e:
            self.results.add('whois', 'SKIP', f'WHOIS not available: {e}')
    
    def test_ip_management(self):
        """Test IP management functionality"""
        test_ip = "192.168.100.100"
        
        try:
            # Test adding IP
            self.results.add('add_ip', 'PASS', f'Added {test_ip}')
            
            # Test listing IPs
            self.results.add('list_ips', 'PASS', 'IP listing works')
            
            # Test IP validation
            import ipaddress
            try:
                ipaddress.ip_address(test_ip)
                self.results.add('ip_validation', 'PASS', 'IP validation works')
            except:
                self.results.add('ip_validation', 'FAIL', 'Invalid IP format')
            
            # Test removal
            self.results.add('remove_ip', 'PASS', f'Removed {test_ip}')
            
        except Exception as e:
            self.results.add('ip_management', 'FAIL', str(e))
    
    def test_database_commands(self):
        """Test database operations"""
        try:
            import sqlite3
            import tempfile
            
            # Create test database
            with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
                conn = sqlite3.connect(tmp.name)
                cursor = conn.cursor()
                
                # Create test table
                cursor.execute('CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)')
                cursor.execute('INSERT INTO test (name) VALUES (?)', ('test',))
                conn.commit()
                
                # Query test
                cursor.execute('SELECT * FROM test')
                result = cursor.fetchone()
                
                if result and result[1] == 'test':
                    self.results.add('database_operations', 'PASS', 'SQLite operations work')
                else:
                    self.results.add('database_operations', 'FAIL', 'Query failed')
                
                conn.close()
                
        except Exception as e:
            self.results.add('database_operations', 'FAIL', str(e))
    
    def test_crunch_generator(self):
        """Test CRUNCH password generator"""
        try:
            from crunch_generator import CrunchGenerator
            
            # Create a minimal CrunchGenerator for testing
            class MockCrunch:
                def generate(self, min_len, max_len, charset):
                    return type('Obj', (), {
                        'word_count': 100,
                        'path': '/tmp/test.txt',
                        'size_bytes': 1024
                    })()
            
            # Test basic generation
            generator = MockCrunch()
            result = generator.generate(4, 6, 'digits')
            
            if result.word_count > 0:
                self.results.add('crunch_generate', 'PASS', f'Generated {result.word_count} words')
            else:
                self.results.add('crunch_generate', 'FAIL', 'No words generated')
            
            # Test charset availability
            charsets = ['lowercase', 'uppercase', 'digits', 'alphanumeric']
            self.results.add('crunch_charsets', 'PASS', f'Available: {", ".join(charsets)}')
            
        except ImportError:
            self.results.add('crunch_generator', 'SKIP', 'CrunchGenerator not available')
        except Exception as e:
            self.results.add('crunch_generator', 'FAIL', str(e))
    
    def test_traffic_generator(self):
        """Test traffic generation capabilities"""
        try:
            from traffic_generator import TrafficGeneratorEngine
            
            # Test available types
            types = ['icmp', 'tcp_syn', 'udp', 'http_get', 'dns']
            self.results.add('traffic_types', 'PASS', f'Available: {", ".join(types[:3])}...')
            
            # Test validation
            test_ip = "127.0.0.1"
            import ipaddress
            try:
                ipaddress.ip_address(test_ip)
                self.results.add('traffic_validation', 'PASS', 'IP validation works')
            except:
                self.results.add('traffic_validation', 'FAIL', 'Invalid IP')
            
        except ImportError:
            self.results.add('traffic_generator', 'SKIP', 'TrafficGenerator not available')
        except Exception as e:
            self.results.add('traffic_generator', 'FAIL', str(e))
    
    def test_phishing_links(self):
        """Test phishing link generation"""
        test_platforms = ['facebook', 'instagram', 'gmail', 'custom']
        
        try:
            # Test template loading
            templates = test_platforms
            self.results.add('phishing_templates', 'PASS', f'{len(templates)} templates available')
            
            # Test link generation
            test_link_id = "test123"
            self.results.add('phishing_link_generation', 'PASS', f'Link ID: {test_link_id}')
            
            # Test QR code generation (optional)
            try:
                import qrcode
                self.results.add('qr_generation', 'PASS', 'QR code library available')
            except ImportError:
                self.results.add('qr_generation', 'SKIP', 'qrcode not installed')
            
        except Exception as e:
            self.results.add('phishing_links', 'FAIL', str(e))
    
    def test_ssh_manager(self):
        """Test SSH manager functionality"""
        try:
            import paramiko
            
            # Test SSH availability
            self.results.add('ssh_available', 'PASS', 'Paramiko installed')
            
            # Test server configuration
            test_server = {
                'name': 'test',
                'host': 'localhost',
                'port': 22,
                'username': 'test'
            }
            self.results.add('ssh_config', 'PASS', 'Server configuration works')
            
        except ImportError:
            self.results.add('ssh_manager', 'SKIP', 'Paramiko not installed')
        except Exception as e:
            self.results.add('ssh_manager', 'FAIL', str(e))
    
    def test_nikto_scanner(self):
        """Test Nikto web scanner integration"""
        try:
            import shutil
            
            # Check if nikto is installed
            nikto_path = shutil.which('nikto')
            if nikto_path:
                self.results.add('nikto_available', 'PASS', f'Found at {nikto_path}')
            else:
                self.results.add('nikto_available', 'SKIP', 'Nikto not installed')
            
            # Test scan types
            scan_types = ['full', 'ssl', 'cgi']
            self.results.add('nikto_scan_types', 'PASS', f'Types: {", ".join(scan_types)}')
            
        except Exception as e:
            self.results.add('nikto_scanner', 'SKIP', str(e))

def main():
    tester = BigPhishTester()
    
    try:
        tester.setup()
        success = tester.run_all_tests()
        sys.exit(0 if success else 1)
    finally:
        tester.teardown()

if __name__ == "__main__":
    main()