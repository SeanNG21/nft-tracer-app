#!/usr/bin/env python3
"""
Mock Database Client for NFT Tracer Testing
Simulates database connections and queries
"""

import socket
import time
import random
import json
import logging
from threading import Thread

logging.basicConfig(level=logging.INFO)

class MockDatabaseClient:
    """Simulates database client making connections"""

    def __init__(self, host='localhost', port=3306):
        self.host = host
        self.port = port
        self.running = False

    def simulate_mysql_traffic(self):
        """Simulate MySQL connection patterns"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            logging.info(f"Connected to MySQL-like service at {self.host}:{self.port}")

            # Simulate queries
            queries = [
                b"SELECT * FROM users WHERE id = 1",
                b"INSERT INTO logs (message, timestamp) VALUES ('test', NOW())",
                b"UPDATE users SET last_login = NOW() WHERE id = 1",
                b"SELECT COUNT(*) FROM transactions",
                b"DELETE FROM temp_data WHERE created_at < NOW() - INTERVAL 1 DAY"
            ]

            for query in queries:
                sock.send(query)
                time.sleep(random.uniform(0.1, 0.5))

            sock.close()
            logging.info("MySQL simulation completed")

        except Exception as e:
            logging.error(f"MySQL simulation error: {e}")

    def simulate_redis_traffic(self):
        """Simulate Redis connection patterns"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, 6379))
            logging.info(f"Connected to Redis-like service at {self.host}:6379")

            # Redis commands
            commands = [
                b"*2\r\n$3\r\nGET\r\n$4\r\ntest\r\n",
                b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n",
                b"*2\r\n$4\r\nINCR\r\n$7\r\ncounter\r\n"
            ]

            for cmd in commands:
                sock.send(cmd)
                time.sleep(random.uniform(0.05, 0.2))

            sock.close()
            logging.info("Redis simulation completed")

        except Exception as e:
            logging.error(f"Redis simulation error: {e}")

    def simulate_postgres_traffic(self):
        """Simulate PostgreSQL connection patterns"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, 5432))
            logging.info(f"Connected to PostgreSQL-like service at {self.host}:5432")

            # Simulate protocol messages
            time.sleep(random.uniform(0.1, 0.3))
            sock.send(b"SELECT version();")

            sock.close()
            logging.info("PostgreSQL simulation completed")

        except Exception as e:
            logging.error(f"PostgreSQL simulation error: {e}")

    def run_continuous(self):
        """Run continuous database simulations"""
        self.running = True
        logging.info("Starting continuous database traffic simulation")

        while self.running:
            # Randomly choose a database type to simulate
            db_type = random.choice(['mysql', 'redis', 'postgres'])

            try:
                if db_type == 'mysql':
                    self.simulate_mysql_traffic()
                elif db_type == 'redis':
                    self.simulate_redis_traffic()
                elif db_type == 'postgres':
                    self.simulate_postgres_traffic()
            except Exception as e:
                logging.error(f"Error in {db_type} simulation: {e}")

            # Wait before next simulation
            time.sleep(random.uniform(2, 5))

    def stop(self):
        """Stop simulation"""
        self.running = False

def main():
    """Main function"""
    print("💾 Mock Database Client")
    print("=" * 50)
    print("Simulating database connections for NFT Tracer testing")
    print()

    client = MockDatabaseClient()

    try:
        client.run_continuous()
    except KeyboardInterrupt:
        print("\n\nStopping database client...")
        client.stop()

if __name__ == '__main__':
    main()
