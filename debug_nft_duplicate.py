#!/usr/bin/env python3
"""
Debug Script: Analyze nft_immediate_eval duplicate calls
Helps verify if duplicate is real or just multiple rules being evaluated
"""

import json
import sys
from collections import defaultdict

def analyze_trace_file(filepath):
    """Analyze trace JSON file to detect duplicate nft_immediate_eval calls"""

    with open(filepath, 'r') as f:
        data = json.load(f)

    print("=" * 80)
    print("NFT_IMMEDIATE_EVAL DUPLICATE ANALYSIS")
    print("=" * 80)
    print(f"File: {filepath}\n")

    traces = data.get('traces', [])
    print(f"Total packet traces: {len(traces)}\n")

    for idx, trace in enumerate(traces):
        print(f"--- TRACE #{idx + 1} ---")
        print(f"SKB: {trace.get('skb_addr')}")
        print(f"Protocol: {trace.get('protocol_name')} ({trace.get('protocol')})")
        print(f"{trace.get('src_ip')}:{trace.get('src_port')} → "
              f"{trace.get('dst_ip')}:{trace.get('dst_port')}")
        print(f"Final verdict: {trace.get('final_verdict')}")
        print(f"Total rules evaluated: {trace.get('total_rules_evaluated')}")
        print()

        # Extract rule_eval events
        all_events = trace.get('important_events', [])
        rule_evals = [e for e in all_events if e.get('trace_type') == 'rule_eval']

        if len(rule_evals) == 0:
            print("  [!] No rule_eval events found")
            continue

        print(f"  Rule evaluations: {len(rule_evals)}")
        print()

        # Group by expr_addr to detect true duplicates
        by_expr = defaultdict(list)
        by_rule_handle = defaultdict(list)
        by_rule_seq = defaultdict(list)

        for event in rule_evals:
            expr_addr = event.get('expr_addr', 'N/A')
            rule_handle = event.get('rule_handle', 'N/A')
            rule_seq = event.get('rule_seq', 'N/A')

            by_expr[expr_addr].append(event)
            by_rule_handle[rule_handle].append(event)
            by_rule_seq[rule_seq].append(event)

        # Print detailed analysis
        print("  Event Details:")
        print("  " + "-" * 76)
        print(f"  {'#':<4} {'rule_seq':<10} {'expr_addr':<18} {'rule_handle':<12} "
              f"{'verdict':<10} {'verdict_raw':<12}")
        print("  " + "-" * 76)

        for i, event in enumerate(rule_evals):
            print(f"  {i+1:<4} "
                  f"{event.get('rule_seq', 'N/A'):<10} "
                  f"{str(event.get('expr_addr', 'N/A')):<18} "
                  f"{str(event.get('rule_handle', 'N/A')):<12} "
                  f"{event.get('verdict', 'N/A'):<10} "
                  f"{str(event.get('verdict_raw', 'N/A')):<12}")

        print()

        # Detect duplicates
        duplicates_found = False

        # Check for same expr_addr (TRUE duplicate)
        for expr_addr, events in by_expr.items():
            if expr_addr != 'N/A' and len(events) > 1:
                duplicates_found = True
                print(f"  [!] DUPLICATE DETECTED: Same expr_addr {expr_addr} "
                      f"evaluated {len(events)} times!")
                print(f"      This is a TRUE DUPLICATE - same expression called multiple times")
                print(f"      Timestamps:")
                for e in events:
                    print(f"        - {e.get('timestamp')} (rule_seq={e.get('rule_seq')})")
                print()

        # Check for same rule_handle (potentially same rule)
        for rule_handle, events in by_rule_handle.items():
            if rule_handle not in [None, 'N/A', 0] and len(events) > 1:
                print(f"  [?] POTENTIAL DUPLICATE: Same rule_handle {rule_handle} "
                      f"evaluated {len(events)} times")
                print(f"      This could be the same rule with different expressions")
                print(f"      rule_seq values: {[e.get('rule_seq') for e in events]}")
                print()

        # Check for different expr_addr (NORMAL - different rules)
        unique_expr = [e for e in by_expr.keys() if e != 'N/A']
        if len(unique_expr) == len(rule_evals):
            print(f"  [✓] All {len(rule_evals)} rule_eval events have DIFFERENT expr_addr")
            print(f"      This is NORMAL - packet evaluated by {len(rule_evals)} different rules")
            print()

        # Analyze verdict progression
        print("  Verdict Progression:")
        for i, event in enumerate(rule_evals):
            verdict = event.get('verdict', 'UNKNOWN')
            verdict_raw = event.get('verdict_raw', 'N/A')
            print(f"    Rule {i+1} (seq={event.get('rule_seq')}): "
                  f"{verdict} (raw={verdict_raw})")

        # Check if terminal verdict followed by more evals (SUSPICIOUS)
        for i, event in enumerate(rule_evals[:-1]):  # All except last
            verdict = event.get('verdict', 'UNKNOWN')
            if verdict in ['DROP', 'ACCEPT']:
                print(f"\n  [!] WARNING: Rule {i+1} has terminal verdict '{verdict}' "
                      f"but {len(rule_evals) - i - 1} more rules were evaluated!")
                print(f"      This could indicate:")
                print(f"      - Verdict is actually CONTINUE (check verdict_raw)")
                print(f"      - Jump/Goto logic in ruleset")
                print(f"      - Bug in verdict decoding")

        print("\n" + "=" * 80 + "\n")

    # Summary
    print("SUMMARY:")
    print("-" * 80)

    total_rule_evals = 0
    total_duplicates = 0

    for trace in traces:
        all_events = trace.get('important_events', [])
        rule_evals = [e for e in all_events if e.get('trace_type') == 'rule_eval']
        total_rule_evals += len(rule_evals)

        # Check duplicates
        by_expr = defaultdict(int)
        for event in rule_evals:
            expr_addr = event.get('expr_addr', 'N/A')
            if expr_addr != 'N/A':
                by_expr[expr_addr] += 1

        for expr_addr, count in by_expr.items():
            if count > 1:
                total_duplicates += count

    print(f"Total rule_eval events: {total_rule_evals}")
    print(f"Total TRUE duplicates (same expr_addr): {total_duplicates}")
    print()

    if total_duplicates == 0:
        print("[✓] NO TRUE DUPLICATES FOUND")
        print("    All nft_immediate_eval calls are for different expressions/rules")
        print("    This is NORMAL behavior - packet evaluated by multiple rules")
    else:
        print(f"[!] {total_duplicates} TRUE DUPLICATES FOUND")
        print("    Same expression was evaluated multiple times")
        print("    This indicates a BUG in the tracer")

    print("=" * 80)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 debug_nft_duplicate.py <trace_file.json>")
        print()
        print("Example:")
        print("  python3 debug_nft_duplicate.py backend/output/trace_full_*.json")
        sys.exit(1)

    filepath = sys.argv[1]

    try:
        analyze_trace_file(filepath)
    except FileNotFoundError:
        print(f"[!] Error: File not found: {filepath}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Error: Invalid JSON file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
