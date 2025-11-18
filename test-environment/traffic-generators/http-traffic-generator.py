#!/usr/bin/env python3
"""
HTTP Traffic Generator for NFT Tracer Testing
Generates various HTTP traffic patterns
"""

import requests
import time
import random
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class HTTPTrafficGenerator:
    """Generates HTTP traffic to mock services"""

    def __init__(self, base_url='http://localhost:8080'):
        self.base_url = base_url
        self.session = requests.Session()

    def make_request(self, method='GET', endpoint='/', data=None):
        """Make HTTP request"""
        url = f"{self.base_url}{endpoint}"

        try:
            if method == 'GET':
                response = self.session.get(url, timeout=5)
            elif method == 'POST':
                response = self.session.post(url, json=data, timeout=5)
            elif method == 'PUT':
                response = self.session.put(url, json=data, timeout=5)
            elif method == 'DELETE':
                response = self.session.delete(url, timeout=5)
            else:
                return None

            logging.info(f"{method} {endpoint} - Status: {response.status_code} - Size: {len(response.content)} bytes")
            return response

        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            return None

    def generate_normal_traffic(self, duration=60, requests_per_second=2):
        """Generate normal HTTP traffic pattern"""
        logging.info(f"Generating normal traffic for {duration} seconds at {requests_per_second} req/s")

        endpoints = [
            '/',
            '/api/data',
            '/api/health',
            '/health'
        ]

        start_time = time.time()
        request_count = 0

        while time.time() - start_time < duration:
            endpoint = random.choice(endpoints)
            self.make_request('GET', endpoint)
            request_count += 1

            time.sleep(1 / requests_per_second)

        logging.info(f"Normal traffic completed: {request_count} requests")

    def generate_burst_traffic(self, num_requests=100, threads=10):
        """Generate burst of concurrent requests"""
        logging.info(f"Generating burst traffic: {num_requests} requests with {threads} threads")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []

            for i in range(num_requests):
                endpoint = random.choice(['/api/data', '/api/slow', '/api/large'])
                future = executor.submit(self.make_request, 'GET', endpoint)
                futures.append(future)

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Request failed: {e}")

        logging.info("Burst traffic completed")

    def generate_api_crud_traffic(self, duration=30):
        """Generate CRUD API traffic"""
        logging.info(f"Generating CRUD API traffic for {duration} seconds")

        start_time = time.time()

        while time.time() - start_time < duration:
            # Create
            user_data = {
                'name': f'User{random.randint(1, 1000)}',
                'email': f'user{random.randint(1, 1000)}@test.com'
            }
            response = self.make_request('POST', '/api/v1/users', data=user_data)

            if response and response.status_code == 201:
                # Read
                time.sleep(0.5)
                self.make_request('GET', '/api/v1/users')

                # Update (if we got user ID)
                time.sleep(0.5)
                update_data = {'name': f'Updated{random.randint(1, 1000)}'}
                # Note: We'd need to parse user_id from create response

            time.sleep(1)

        logging.info("CRUD traffic completed")

    def generate_slow_requests(self, num_requests=10):
        """Generate slow/heavy requests"""
        logging.info(f"Generating {num_requests} slow requests")

        for i in range(num_requests):
            logging.info(f"Slow request {i+1}/{num_requests}")
            self.make_request('GET', '/api/slow')
            self.make_request('GET', '/api/large')
            time.sleep(2)

        logging.info("Slow requests completed")

    def generate_mixed_traffic(self, duration=60):
        """Generate mixed traffic pattern"""
        logging.info(f"Generating mixed traffic for {duration} seconds")

        start_time = time.time()

        while time.time() - start_time < duration:
            # Random pattern selection
            pattern = random.choice([
                ('GET', '/'),
                ('GET', '/api/data'),
                ('GET', '/api/random'),
                ('POST', '/api/upload', {'data': 'test'}),
                ('GET', '/api/large'),
                ('GET', '/api/slow')
            ])

            if len(pattern) == 3:
                method, endpoint, data = pattern
                self.make_request(method, endpoint, data)
            else:
                method, endpoint = pattern
                self.make_request(method, endpoint)

            # Variable delay
            time.sleep(random.uniform(0.1, 2))

        logging.info("Mixed traffic completed")

def main():
    """Main function"""
    print("🌐 HTTP Traffic Generator")
    print("=" * 50)

    if len(sys.argv) < 2:
        print("Usage: python http-traffic-generator.py <pattern> [options]")
        print("\nPatterns:")
        print("  normal     - Normal traffic pattern")
        print("  burst      - Burst of concurrent requests")
        print("  crud       - CRUD API operations")
        print("  slow       - Slow/heavy requests")
        print("  mixed      - Mixed traffic pattern")
        print("  all        - Run all patterns")
        sys.exit(1)

    pattern = sys.argv[1]

    # Get target URL from environment or use default
    base_url = 'http://localhost:8080'
    if len(sys.argv) > 2:
        base_url = sys.argv[2]

    generator = HTTPTrafficGenerator(base_url)

    try:
        if pattern == 'normal':
            generator.generate_normal_traffic(duration=60)
        elif pattern == 'burst':
            generator.generate_burst_traffic(num_requests=100)
        elif pattern == 'crud':
            generator.generate_api_crud_traffic(duration=30)
        elif pattern == 'slow':
            generator.generate_slow_requests(num_requests=10)
        elif pattern == 'mixed':
            generator.generate_mixed_traffic(duration=60)
        elif pattern == 'all':
            print("\n1. Normal traffic...")
            generator.generate_normal_traffic(duration=30)
            print("\n2. Burst traffic...")
            generator.generate_burst_traffic(num_requests=50)
            print("\n3. Slow requests...")
            generator.generate_slow_requests(num_requests=5)
            print("\n4. Mixed traffic...")
            generator.generate_mixed_traffic(duration=30)
        else:
            print(f"Unknown pattern: {pattern}")
            sys.exit(1)

        print("\n✅ Traffic generation completed!")

    except KeyboardInterrupt:
        print("\n\nTraffic generation stopped by user")

if __name__ == '__main__':
    main()
