#!/usr/bin/env python3
"""
Scenario Runner for NFT Tracer Testing
Orchestrates various traffic generation scenarios
"""

import sys
import os
import time
import logging
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, '/app')

from traffic_generators.http_traffic_generator import HTTPTrafficGenerator
from traffic_generators.network_traffic_generator import NetworkTrafficGenerator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class ScenarioRunner:
    """Runs predefined test scenarios"""

    def __init__(self):
        self.web_url = os.getenv('WEB_SERVER_URL', 'http://localhost:8080')
        self.api_url = os.getenv('API_SERVER_URL', 'http://localhost:8081')
        self.duration = int(os.getenv('DURATION', '3600'))  # Default 1 hour

    def run_normal_user_scenario(self):
        """Simulate normal user behavior"""
        logging.info("=" * 60)
        logging.info("SCENARIO: Normal User Behavior")
        logging.info("=" * 60)

        http_gen = HTTPTrafficGenerator(self.web_url)

        # Simulate browsing
        logging.info("Phase 1: Browsing website...")
        http_gen.generate_normal_traffic(duration=60, requests_per_second=1)

        # API interactions
        logging.info("Phase 2: API interactions...")
        http_api = HTTPTrafficGenerator(self.api_url)
        http_api.generate_api_crud_traffic(duration=30)

        logging.info("Normal user scenario completed")

    def run_heavy_load_scenario(self):
        """Simulate heavy load"""
        logging.info("=" * 60)
        logging.info("SCENARIO: Heavy Load")
        logging.info("=" * 60)

        http_gen = HTTPTrafficGenerator(self.web_url)

        logging.info("Generating burst traffic...")
        http_gen.generate_burst_traffic(num_requests=200, threads=20)

        logging.info("Heavy load scenario completed")

    def run_api_testing_scenario(self):
        """Test API endpoints extensively"""
        logging.info("=" * 60)
        logging.info("SCENARIO: API Testing")
        logging.info("=" * 60)

        http_gen = HTTPTrafficGenerator(self.api_url)

        logging.info("Running CRUD operations...")
        http_gen.generate_api_crud_traffic(duration=120)

        logging.info("API testing scenario completed")

    def run_mixed_traffic_scenario(self):
        """Generate mixed traffic patterns"""
        logging.info("=" * 60)
        logging.info("SCENARIO: Mixed Traffic")
        logging.info("=" * 60)

        http_web = HTTPTrafficGenerator(self.web_url)
        http_api = HTTPTrafficGenerator(self.api_url)

        logging.info("Generating mixed HTTP traffic...")
        http_web.generate_mixed_traffic(duration=120)

        logging.info("Mixed traffic scenario completed")

    def run_database_traffic_scenario(self):
        """Simulate database connections"""
        logging.info("=" * 60)
        logging.info("SCENARIO: Database Traffic")
        logging.info("=" * 60)

        # Network traffic to databases
        net_gen = NetworkTrafficGenerator('mock-postgres')

        logging.info("Simulating database connections...")
        net_gen.generate_tcp_traffic(port=5432, num_connections=20)
        net_gen.generate_tcp_traffic(port=3306, num_connections=20)  # MySQL

        logging.info("Database traffic scenario completed")

    def run_continuous_monitoring_scenario(self):
        """Continuous traffic for long-term monitoring"""
        logging.info("=" * 60)
        logging.info("SCENARIO: Continuous Monitoring")
        logging.info(f"Duration: {self.duration} seconds")
        logging.info("=" * 60)

        http_web = HTTPTrafficGenerator(self.web_url)
        http_api = HTTPTrafficGenerator(self.api_url)

        start_time = time.time()
        iteration = 0

        while time.time() - start_time < self.duration:
            iteration += 1
            logging.info(f"\nIteration {iteration} - Elapsed: {int(time.time() - start_time)}s / {self.duration}s")

            # Cycle through different patterns
            patterns = [
                lambda: http_web.generate_normal_traffic(duration=30, requests_per_second=2),
                lambda: http_api.generate_api_crud_traffic(duration=30),
                lambda: http_web.generate_burst_traffic(num_requests=50, threads=5),
            ]

            pattern = patterns[iteration % len(patterns)]
            pattern()

            time.sleep(10)  # Short break between iterations

        logging.info("Continuous monitoring scenario completed")

    def run_all_scenarios(self):
        """Run all scenarios sequentially"""
        logging.info("=" * 60)
        logging.info("RUNNING ALL SCENARIOS")
        logging.info("=" * 60)

        scenarios = [
            self.run_normal_user_scenario,
            self.run_api_testing_scenario,
            self.run_heavy_load_scenario,
            self.run_database_traffic_scenario,
            self.run_mixed_traffic_scenario,
        ]

        for i, scenario in enumerate(scenarios, 1):
            logging.info(f"\n{'='*60}")
            logging.info(f"Scenario {i}/{len(scenarios)}")
            logging.info(f"{'='*60}\n")

            try:
                scenario()
            except Exception as e:
                logging.error(f"Scenario failed: {e}")

            time.sleep(5)  # Break between scenarios

        logging.info("\n" + "=" * 60)
        logging.info("ALL SCENARIOS COMPLETED")
        logging.info("=" * 60)

def main():
    """Main function"""
    print("🎬 NFT Tracer Test Scenario Runner")
    print("=" * 60)
    print(f"Started at: {datetime.now()}")
    print()

    # Wait for services to be ready
    logging.info("Waiting for services to be ready...")
    time.sleep(10)

    scenario = os.getenv('SCENARIO', 'mixed').lower()
    runner = ScenarioRunner()

    try:
        if scenario == 'normal':
            runner.run_normal_user_scenario()
        elif scenario == 'heavy':
            runner.run_heavy_load_scenario()
        elif scenario == 'api':
            runner.run_api_testing_scenario()
        elif scenario == 'mixed':
            runner.run_mixed_traffic_scenario()
        elif scenario == 'database':
            runner.run_database_traffic_scenario()
        elif scenario == 'continuous':
            runner.run_continuous_monitoring_scenario()
        elif scenario == 'all':
            runner.run_all_scenarios()
        else:
            logging.error(f"Unknown scenario: {scenario}")
            sys.exit(1)

        logging.info("\n✅ Scenario execution completed successfully!")

    except KeyboardInterrupt:
        logging.info("\n\nScenario execution stopped by user")
    except Exception as e:
        logging.error(f"\n❌ Scenario execution failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
