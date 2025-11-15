#!/usr/bin/env python3
"""
Test script for NFT Ruleset Parser
Run this to debug rule parsing
"""

import sys
import json
from nft_ruleset_parser import get_ruleset_parser

def main():
    print("=" * 80)
    print("NFT Ruleset Parser Test")
    print("=" * 80)

    # Get parser instance
    parser = get_ruleset_parser()

    # Check if loaded successfully
    if not parser._loaded:
        print("[!] Parser failed to load ruleset")
        return 1

    print(f"[✓] Loaded {len(parser.rules)} rules")
    print(f"[✓] Loaded {len(parser.tables)} tables")
    print(f"[✓] Loaded {len(parser.chains)} chains")
    print()

    # Print all tables
    print("=" * 80)
    print("TABLES:")
    print("=" * 80)
    for key, table in parser.tables.items():
        print(f"  {key}")
    print()

    # Print all chains
    print("=" * 80)
    print("CHAINS:")
    print("=" * 80)
    for key, chain in parser.chains.items():
        print(f"  {key}")
        hook = chain.get('hook')
        if hook:
            print(f"    Hook: {hook}")
    print()

    # Print all rules with details
    print("=" * 80)
    print("RULES:")
    print("=" * 80)
    for handle, rule in sorted(parser.rules.items()):
        print(f"\nHandle {handle}:")
        print(f"  Family: {rule.family}")
        print(f"  Table:  {rule.table}")
        print(f"  Chain:  {rule.chain}")
        print(f"  Text:   {rule.rule_text}")

        # Show expression list for debugging
        if len(rule.expr_list) > 0:
            print(f"  Expressions ({len(rule.expr_list)}):")
            for i, expr in enumerate(rule.expr_list):
                print(f"    [{i}] {json.dumps(expr, indent=8)}")
    print()

    # Test lookup by handle
    print("=" * 80)
    print("TESTING LOOKUPS:")
    print("=" * 80)

    if len(parser.rules) > 0:
        # Test first rule
        first_handle = next(iter(parser.rules.keys()))
        print(f"\nLooking up handle {first_handle}:")
        rule_text = parser.get_rule_text(first_handle)
        print(f"  Result: {rule_text}")

        # Test non-existent handle
        print(f"\nLooking up non-existent handle 99999:")
        rule_text = parser.get_rule_text(99999)
        print(f"  Result: {rule_text}")
    else:
        print("[!] No rules found to test")

    print()
    print("=" * 80)
    print("Test completed!")
    print("=" * 80)

    return 0

if __name__ == '__main__':
    sys.exit(main())
