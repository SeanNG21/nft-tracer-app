#!/usr/bin/env python3
"""
Network Traffic Generator for NFT Tracer Testing
Generates TCP, UDP, ICMP and other network traffic
"""

import socket
import struct
import time
import random
import sys
import logging
from threading import Thread

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class NetworkTrafficGenerator:
    """Generates various network traffic patterns"""

    def __init__(self, target_host='localhost'):
        self.target_host = target_host

    def generate_tcp_traffic(self, port=8080, num_connections=10):
        """Generate TCP connection traffic"""
        logging.info(f"Generating {num_connections} TCP connections to {self.target_host}:{port}")

        for i in range(num_connections):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target_host, port))

                # Send some data
                message = f"TCP Test Message {i+1}\n".encode()
                sock.send(message)

                # Try to receive response
                try:
                    data = sock.recv(1024)
                    logging.info(f"TCP Connection {i+1}: Sent {len(message)} bytes, received {len(data)} bytes")
                except socket.timeout:
                    logging.info(f"TCP Connection {i+1}: Sent {len(message)} bytes, no response")

                sock.close()
                time.sleep(random.uniform(0.1, 0.5))

            except Exception as e:
                logging.error(f"TCP connection {i+1} failed: {e}")

        logging.info("TCP traffic generation completed")

    def generate_udp_traffic(self, port=8082, num_packets=50):
        """Generate UDP packet traffic"""
        logging.info(f"Generating {num_packets} UDP packets to {self.target_host}:{port}")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            for i in range(num_packets):
                message = f"UDP Test Packet {i+1} - {random.randint(1000, 9999)}".encode()
                sock.sendto(message, (self.target_host, port))
                logging.info(f"UDP Packet {i+1}: Sent {len(message)} bytes")
                time.sleep(random.uniform(0.05, 0.2))

            sock.close()
            logging.info("UDP traffic generation completed")

        except Exception as e:
            logging.error(f"UDP traffic generation failed: {e}")

    def generate_icmp_traffic(self, num_pings=10):
        """Generate ICMP ping traffic (requires root)"""
        logging.info(f"Generating {num_pings} ICMP pings to {self.target_host}")

        try:
            import subprocess
            for i in range(num_pings):
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', self.target_host],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    logging.info(f"ICMP Ping {i+1}: Success")
                else:
                    logging.warning(f"ICMP Ping {i+1}: Failed")

                time.sleep(1)

            logging.info("ICMP traffic generation completed")

        except Exception as e:
            logging.error(f"ICMP traffic generation failed: {e}")

    def generate_dns_traffic(self, num_queries=20):
        """Generate DNS query traffic"""
        logging.info(f"Generating {num_queries} DNS queries")

        domains = [
            'google.com', 'github.com', 'example.com',
            'test.local', 'api.test.com', 'db.local'
        ]

        try:
            for i in range(num_queries):
                domain = random.choice(domains)
                try:
                    result = socket.gethostbyname(domain)
                    logging.info(f"DNS Query {i+1}: {domain} -> {result}")
                except socket.gaierror as e:
                    logging.warning(f"DNS Query {i+1}: {domain} -> Failed ({e})")

                time.sleep(random.uniform(0.2, 1))

            logging.info("DNS traffic generation completed")

        except Exception as e:
            logging.error(f"DNS traffic generation failed: {e}")

    def generate_port_scan(self, start_port=8000, end_port=8100):
        """Simulate port scanning activity"""
        logging.info(f"Simulating port scan on {self.target_host}:{start_port}-{end_port}")

        open_ports = []

        for port in range(start_port, end_port + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target_host, port))

                if result == 0:
                    open_ports.append(port)
                    logging.info(f"Port {port}: OPEN")
                else:
                    logging.debug(f"Port {port}: CLOSED")

                sock.close()
                time.sleep(0.01)  # Small delay to avoid overwhelming

            except Exception as e:
                logging.error(f"Error scanning port {port}: {e}")

        logging.info(f"Port scan completed. Found {len(open_ports)} open ports: {open_ports}")

    def generate_connection_flood(self, port=8080, connections=100, threads=10):
        """Generate connection flood (for testing load)"""
        logging.info(f"Generating connection flood: {connections} connections with {threads} threads")

        def make_connections(num):
            for i in range(num):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((self.target_host, port))
                    sock.send(b"FLOOD TEST\n")
                    time.sleep(0.1)
                    sock.close()
                except Exception as e:
                    logging.debug(f"Connection failed: {e}")

        threads_list = []
        connections_per_thread = connections // threads

        for i in range(threads):
            thread = Thread(target=make_connections, args=(connections_per_thread,))
            thread.start()
            threads_list.append(thread)

        for thread in threads_list:
            thread.join()

        logging.info("Connection flood completed")

    def generate_large_transfer(self, port=8080, size_mb=10):
        """Generate large data transfer"""
        logging.info(f"Generating large data transfer: {size_mb}MB to {self.target_host}:{port}")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.target_host, port))

            chunk_size = 1024 * 1024  # 1MB chunks
            total_sent = 0
            target_size = size_mb * 1024 * 1024

            while total_sent < target_size:
                data = b'X' * min(chunk_size, target_size - total_sent)
                sock.send(data)
                total_sent += len(data)
                logging.info(f"Sent: {total_sent / (1024*1024):.2f}MB / {size_mb}MB")
                time.sleep(0.1)

            sock.close()
            logging.info("Large transfer completed")

        except Exception as e:
            logging.error(f"Large transfer failed: {e}")

    def generate_mixed_traffic(self, duration=60):
        """Generate mixed protocol traffic"""
        logging.info(f"Generating mixed traffic for {duration} seconds")

        start_time = time.time()

        while time.time() - start_time < duration:
            # Random traffic type
            traffic_type = random.choice(['tcp', 'udp', 'dns'])

            try:
                if traffic_type == 'tcp':
                    self.generate_tcp_traffic(num_connections=5)
                elif traffic_type == 'udp':
                    self.generate_udp_traffic(num_packets=10)
                elif traffic_type == 'dns':
                    self.generate_dns_traffic(num_queries=5)

                time.sleep(random.uniform(1, 3))

            except Exception as e:
                logging.error(f"Error generating {traffic_type} traffic: {e}")

        logging.info("Mixed traffic generation completed")

def main():
    """Main function"""
    print("🌐 Network Traffic Generator")
    print("=" * 50)

    if len(sys.argv) < 2:
        print("Usage: python network-traffic-generator.py <pattern> [target_host]")
        print("\nPatterns:")
        print("  tcp        - TCP connection traffic")
        print("  udp        - UDP packet traffic")
        print("  icmp       - ICMP ping traffic (requires root)")
        print("  dns        - DNS query traffic")
        print("  portscan   - Port scanning simulation")
        print("  flood      - Connection flood")
        print("  large      - Large data transfer")
        print("  mixed      - Mixed protocol traffic")
        print("  all        - Run all patterns")
        sys.exit(1)

    pattern = sys.argv[1]
    target_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'

    generator = NetworkTrafficGenerator(target_host)

    try:
        if pattern == 'tcp':
            generator.generate_tcp_traffic()
        elif pattern == 'udp':
            generator.generate_udp_traffic()
        elif pattern == 'icmp':
            generator.generate_icmp_traffic()
        elif pattern == 'dns':
            generator.generate_dns_traffic()
        elif pattern == 'portscan':
            generator.generate_port_scan()
        elif pattern == 'flood':
            generator.generate_connection_flood()
        elif pattern == 'large':
            generator.generate_large_transfer()
        elif pattern == 'mixed':
            generator.generate_mixed_traffic()
        elif pattern == 'all':
            print("\n1. TCP traffic...")
            generator.generate_tcp_traffic(num_connections=10)
            print("\n2. UDP traffic...")
            generator.generate_udp_traffic(num_packets=20)
            print("\n3. DNS traffic...")
            generator.generate_dns_traffic(num_queries=10)
            print("\n4. Port scan...")
            generator.generate_port_scan(8000, 8010)
        else:
            print(f"Unknown pattern: {pattern}")
            sys.exit(1)

        print("\n✅ Traffic generation completed!")

    except KeyboardInterrupt:
        print("\n\nTraffic generation stopped by user")

if __name__ == '__main__':
    main()
