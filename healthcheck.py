#!/usr/bin/env python3
"""Health check script for BIG-PHISH Docker container"""

import sys
import sqlite3
import os
import socket

def check_database():
    """Check database connectivity"""
    try:
        conn = sqlite3.connect('.bigphish/bigphish.db')
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        cursor.fetchone()
        conn.close()
        return True
    except Exception as e:
        print(f"Database error: {e}")
        return False

def check_config():
    """Check configuration file"""
    config_path = 'config/config.json'
    if os.path.exists(config_path):
        return True
    print("Config file missing")
    return False

def check_directories():
    """Check required directories"""
    required_dirs = ['.bigphish', 'reports', 'logs', 'config']
    for d in required_dirs:
        if not os.path.exists(d):
            print(f"Missing directory: {d}")
            return False
    return True

def check_port(port):
    """Check if port is available"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0

def main():
    """Run health checks"""
    checks = [
        check_database(),
        check_config(),
        check_directories(),
    ]
    
    if all(checks):
        print("✅ BIG-PHISH is healthy")
        sys.exit(0)
    else:
        print("❌ BIG-PHISH is unhealthy")
        sys.exit(1)

if __name__ == '__main__':
    main()