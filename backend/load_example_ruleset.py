#!/usr/bin/env python3
"""
Quick helper to load example ruleset into cache

Usage: python3 load_example_ruleset.py
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nft_ruleset_parser import get_parser

def main():
    parser = get_parser()

    # Load from example file
    example_file = os.path.join(os.path.dirname(__file__), 'example_ruleset.json')

    if not os.path.exists(example_file):
        print(f"ERROR: {example_file} not found!")
        print("Make sure you're running this from the backend directory")
        return 1

    print(f"Loading ruleset from {example_file}...")
    num_rules = parser.load_from_json_file(example_file)

    if num_rules > 0:
        print(f"✓ Successfully loaded {num_rules} rules")
        print(f"  Cache: {parser.cache_file}")
        print("")
        print("Rules loaded:")
        for handle, rule in sorted(parser.rules.items()):
            print(f"  {rule}")
        print("")
        print("Now you can start a trace session and rule_text will be populated!")
        return 0
    else:
        print("✗ Failed to load rules")
        return 1

if __name__ == '__main__':
    sys.exit(main())
