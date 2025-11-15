#!/usr/bin/env python3
"""
Test Backend Startup Sequence
Mimics what app.py does on startup to diagnose parser loading
"""

import sys

print("=" * 70)
print("TESTING BACKEND STARTUP SEQUENCE")
print("=" * 70)

# Test 1: Import check
print("\n[Test 1] Checking NFT parser import...")
try:
    from nft_ruleset_parser import get_ruleset_parser
    NFT_PARSER_AVAILABLE = True
    print("✓ NFT parser imported successfully")
except ImportError as e:
    NFT_PARSER_AVAILABLE = False
    print(f"✗ Failed to import NFT parser: {e}")
    sys.exit(1)

# Test 2: Parser initialization
print("\n[Test 2] Initializing NFT parser...")
if NFT_PARSER_AVAILABLE:
    try:
        print("[*] Preloading NFT ruleset parser...")
        parser = get_ruleset_parser()

        if parser._loaded:
            print(f"[✓] NFT Parser ready: {len(parser.rules)} rules loaded")
            print(f"    - Tables: {len(parser.tables)}")
            print(f"    - Chains: {len(parser.chains)}")

            # Show sample rules
            if len(parser.rules) > 0:
                print("\n    Sample rules:")
                for i, (handle, rule) in enumerate(list(parser.rules.items())[:3]):
                    print(f"      Handle {handle}: {rule.rule_text}")
                if len(parser.rules) > 3:
                    print(f"      ... and {len(parser.rules) - 3} more rules")
        else:
            print("[!] NFT Parser failed to load ruleset")
            sys.exit(1)

    except Exception as e:
        print(f"[!] Error preloading NFT parser: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

# Test 3: Rule lookup
print("\n[Test 3] Testing rule lookup...")
if len(parser.rules) > 0:
    # Test with first available handle
    test_handle = next(iter(parser.rules.keys()))
    print(f"    Looking up handle {test_handle}...")
    rule = parser.get_rule_by_handle(test_handle)
    if rule:
        print(f"    ✓ Found: {rule.rule_text}")
    else:
        print(f"    ✗ Failed to lookup handle {test_handle}")

    # Test with handle from user's trace (4100)
    print(f"\n    Looking up handle 4100 (from trace file)...")
    rule = parser.get_rule_by_handle(4100)
    if rule:
        print(f"    ✓ Found: {rule.rule_text}")
    else:
        print(f"    ⚠ Handle 4100 not found in current ruleset")
        print(f"    → This means rules changed since trace was captured")
        print(f"    → Current handles: {sorted(parser.rules.keys())[:10]}...")
else:
    print("    ⚠ No rules loaded, skipping lookup test")

print("\n" + "=" * 70)
print("STARTUP SEQUENCE TEST COMPLETE")
print("=" * 70)
print("\nConclusion:")
if NFT_PARSER_AVAILABLE and parser._loaded:
    print("✓ Backend startup should work correctly")
    print("✓ Parser is ready to enrich events")
    print("\nIf backend still doesn't show these logs, the issue is:")
    print("  1. Backend is not starting from this directory")
    print("  2. Backend is using a different Python environment")
    print("  3. Backend code has not been reloaded")
else:
    print("✗ Parser failed to initialize")
    print("✗ Backend will not show rule definitions")

sys.exit(0)
