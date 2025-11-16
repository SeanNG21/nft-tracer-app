#!/usr/bin/env python3
"""
Automated test to verify rule_eval events are captured correctly
"""

import os
import sys
import time
import json
import socket
import subprocess
import requests
from pathlib import Path

# Colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_success(msg):
    print(f"{GREEN}✓{RESET} {msg}")

def print_error(msg):
    print(f"{RED}✗{RESET} {msg}")

def print_info(msg):
    print(f"{BLUE}ℹ{RESET} {msg}")

def print_warning(msg):
    print(f"{YELLOW}⚠{RESET} {msg}")

class RuleEvalTester:
    def __init__(self):
        self.backend_url = "http://localhost:5000"
        self.session_id = f"test_rule_eval_{int(time.time())}"
        self.trace_file = None

    def check_backend_running(self):
        """Check if backend server is running"""
        print_info("Checking if backend server is running...")
        try:
            response = requests.get(f"{self.backend_url}/api/health", timeout=2)
            if response.status_code == 200:
                print_success("Backend server is running")
                return True
        except:
            pass

        print_error("Backend server is NOT running!")
        print_info("Please start backend with: sudo python3 backend/app.py")
        return False

    def check_rules_loaded(self):
        """Check if nftables rules are loaded"""
        print_info("Checking if nftables rules are loaded...")
        try:
            result = subprocess.run(['sudo', 'nft', '-a', 'list', 'table', 'ip', 'filter'],
                                   capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'handle 4100' in result.stdout:
                print_success("Rules are loaded (found handle 4100)")
                return True
        except:
            pass

        print_error("Rules are NOT loaded!")
        print_info("Please load rules with: sudo python3 backend/load_example_ruleset.py")
        return False

    def start_trace_session(self):
        """Start a trace session"""
        print_info(f"Starting trace session: {self.session_id}")
        try:
            response = requests.post(
                f"{self.backend_url}/api/sessions",
                json={
                    "session_id": self.session_id,
                    "mode": "nft"
                },
                timeout=5
            )

            if response.status_code == 201:
                print_success(f"Trace session started: {self.session_id}")
                return True
            else:
                print_error(f"Failed to start session: {response.text}")
                return False
        except Exception as e:
            print_error(f"Failed to start session: {e}")
            return False

    def generate_test_traffic(self):
        """Generate traffic to trigger rules"""
        print_info("Generating test traffic to trigger rules...")

        tests = [
            {
                'name': 'SSH (port 22) - should trigger rule handle 4100',
                'cmd': ['timeout', '1', 'nc', '-z', 'localhost', '22'],
                'expected_rule': 4100
            },
            {
                'name': 'HTTP (port 80) - should trigger rule handle 4101',
                'cmd': ['timeout', '1', 'nc', '-z', 'localhost', '80'],
                'expected_rule': 4101
            },
            {
                'name': 'ICMP ping - should trigger rule handle 4102 (drop)',
                'cmd': ['ping', '-c', '2', '-W', '1', 'localhost'],
                'expected_rule': 4102
            }
        ]

        for test in tests:
            print_info(f"  Testing: {test['name']}")
            try:
                result = subprocess.run(test['cmd'], capture_output=True, timeout=3)
                # Don't care about exit code, just that traffic was generated
                time.sleep(0.5)  # Give eBPF time to process
                print_success(f"    Traffic generated")
            except subprocess.TimeoutExpired:
                print_success(f"    Traffic generated (timeout expected)")
            except Exception as e:
                print_warning(f"    Could not generate traffic: {e}")

        # Wait a bit for all events to be processed
        print_info("Waiting 2 seconds for events to be processed...")
        time.sleep(2)

    def stop_trace_session(self):
        """Stop the trace session"""
        print_info(f"Stopping trace session: {self.session_id}")
        try:
            response = requests.delete(
                f"{self.backend_url}/api/sessions/{self.session_id}",
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()
                self.trace_file = data.get('output_file')
                print_success(f"Session stopped. Trace file: {self.trace_file}")
                return True
            else:
                print_error(f"Failed to stop session: {response.text}")
                return False
        except Exception as e:
            print_error(f"Failed to stop session: {e}")
            return False

    def analyze_trace_file(self):
        """Analyze the trace file for rule_eval events"""
        if not self.trace_file:
            print_error("No trace file to analyze")
            return False

        print_info(f"Analyzing trace file: {self.trace_file}")

        try:
            # Download trace file
            response = requests.get(
                f"{self.backend_url}/api/download/{self.trace_file}",
                timeout=5
            )

            if response.status_code != 200:
                print_error(f"Failed to download trace file: {response.status_code}")
                return False

            trace_data = response.json()

            # Analyze
            print_info("\n" + "="*60)
            print_info("TRACE ANALYSIS RESULTS")
            print_info("="*60)

            traces = trace_data.get('traces', [])
            total_packets = len(traces)

            print_info(f"Total packets traced: {total_packets}")

            if total_packets == 0:
                print_error("❌ NO PACKETS CAPTURED!")
                print_warning("Possible reasons:")
                print_warning("  1. No traffic was generated")
                print_warning("  2. eBPF program not attached")
                print_warning("  3. Kernel doesn't support required kprobes")
                return False

            # Count events by type
            rule_eval_count = 0
            chain_exit_count = 0
            hook_exit_count = 0

            rule_handles_seen = set()

            for trace in traces:
                events = trace.get('important_events', [])
                for event in events:
                    trace_type = event.get('trace_type')

                    if trace_type == 'rule_eval':
                        rule_eval_count += 1
                        rule_handle = event.get('rule_handle')
                        if rule_handle:
                            rule_handles_seen.add(rule_handle)
                    elif trace_type == 'chain_exit':
                        chain_exit_count += 1
                    elif trace_type == 'hook_exit':
                        hook_exit_count += 1

            print_info(f"\nEvent counts:")
            print_info(f"  chain_exit events: {chain_exit_count}")
            print_info(f"  rule_eval events:  {rule_eval_count}")
            print_info(f"  hook_exit events:  {hook_exit_count}")

            print_info(f"\nRule handles captured:")
            if rule_handles_seen:
                for handle in sorted(rule_handles_seen):
                    print_info(f"  - Handle {handle}")
            else:
                print_warning("  No rule handles captured")

            # Success criteria
            success = True

            if rule_eval_count == 0:
                print_error("\n❌ NO rule_eval EVENTS CAPTURED!")
                print_warning("\nThis means:")
                print_warning("  - nft_immediate_eval kprobe might not be triggering")
                print_warning("  - OR no rules with verdict expressions were hit")
                print_warning("  - OR all events were deduplicated")
                success = False
            else:
                print_success(f"\n✅ SUCCESS: Captured {rule_eval_count} rule_eval events!")

            if len(rule_handles_seen) == 0:
                print_warning("\n⚠ No rule handles were extracted")
                print_warning("  This might indicate an issue with extract_rule_handle()")

            # Show sample rule_eval events
            if rule_eval_count > 0:
                print_info("\n" + "-"*60)
                print_info("Sample rule_eval events:")
                print_info("-"*60)

                samples_shown = 0
                for trace in traces:
                    if samples_shown >= 3:
                        break

                    events = trace.get('important_events', [])
                    for event in events:
                        if event.get('trace_type') == 'rule_eval':
                            print_info(json.dumps(event, indent=2))
                            samples_shown += 1
                            if samples_shown >= 3:
                                break

            print_info("="*60)

            return success

        except Exception as e:
            print_error(f"Failed to analyze trace: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_full_test(self):
        """Run complete test workflow"""
        print_info("\n" + "="*60)
        print_info("RULE_EVAL EVENT CAPTURE TEST")
        print_info("="*60 + "\n")

        # Pre-checks
        if not self.check_backend_running():
            return False

        if not self.check_rules_loaded():
            return False

        # Run test
        if not self.start_trace_session():
            return False

        try:
            self.generate_test_traffic()
        finally:
            self.stop_trace_session()

        # Analyze results
        success = self.analyze_trace_file()

        print_info("\n" + "="*60)
        if success:
            print_success("TEST PASSED ✅")
        else:
            print_error("TEST FAILED ❌")
        print_info("="*60 + "\n")

        return success

def main():
    if os.geteuid() != 0:
        print_error("This script requires root privileges")
        print_info("Please run with: sudo python3 test_rule_eval_capture.py")
        sys.exit(1)

    tester = RuleEvalTester()
    success = tester.run_full_test()

    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
