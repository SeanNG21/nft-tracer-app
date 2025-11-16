#!/usr/bin/env python3
"""
NFT Ruleset Parser - Maps rule_handle to rule_text

This module parses nftables ruleset and creates a mapping between
rule handles and their corresponding rule text for enriching trace events.
"""

import subprocess
import json
import re
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass


@dataclass
class RuleInfo:
    """Information about an nftables rule"""
    handle: int
    table: str
    chain: str
    family: str
    rule_text: str
    position: int  # Position in chain (0-indexed)

    def __str__(self):
        return f"[{self.family}:{self.table}:{self.chain}#{self.position}] handle {self.handle}: {self.rule_text}"


class NFTRulesetParser:
    """Parser for nftables ruleset to extract rule handle -> text mappings"""

    def __init__(self):
        self.rules: Dict[int, RuleInfo] = {}
        self._last_update = 0

    def parse_ruleset(self) -> Dict[int, RuleInfo]:
        """
        Parse nftables ruleset and return mapping of handle -> RuleInfo

        Returns:
            Dict mapping rule_handle to RuleInfo objects
        """
        try:
            # Try JSON format first (more reliable)
            result = subprocess.run(
                ['nft', '-j', 'list', 'ruleset'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                return self._parse_json_ruleset(result.stdout)
            else:
                # Fallback to text format with handles
                return self._parse_text_ruleset()

        except subprocess.TimeoutExpired:
            print("Warning: nft command timed out")
            return {}
        except Exception as e:
            print(f"Error parsing ruleset: {e}")
            return {}

    def _parse_json_ruleset(self, json_output: str) -> Dict[int, RuleInfo]:
        """Parse JSON format ruleset"""
        rules = {}

        try:
            data = json.loads(json_output)
            nftables_data = data.get('nftables', [])

            # Track position per chain
            chain_positions: Dict[Tuple[str, str, str], int] = {}

            for item in nftables_data:
                if 'rule' in item:
                    rule = item['rule']

                    # Extract basic info
                    handle = rule.get('handle')
                    if not handle:
                        continue

                    family = rule.get('family', 'unknown')
                    table = rule.get('table', 'unknown')
                    chain = rule.get('chain', 'unknown')

                    # Get position for this chain
                    chain_key = (family, table, chain)
                    position = chain_positions.get(chain_key, 0)
                    chain_positions[chain_key] = position + 1

                    # Build rule text from expr
                    rule_text = self._build_rule_text_from_expr(rule.get('expr', []))

                    rules[handle] = RuleInfo(
                        handle=handle,
                        table=table,
                        chain=chain,
                        family=family,
                        rule_text=rule_text,
                        position=position
                    )

        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            return {}

        return rules

    def _build_rule_text_from_expr(self, expr_list: List) -> str:
        """Build human-readable rule text from expression list"""
        parts = []

        for expr in expr_list:
            if isinstance(expr, dict):
                # Handle different expression types
                if 'match' in expr:
                    match = expr['match']
                    left = self._expr_to_text(match.get('left', {}))
                    op = match.get('op', '==')
                    right = self._expr_to_text(match.get('right', {}))
                    parts.append(f"{left} {op} {right}")

                elif 'counter' in expr:
                    parts.append("counter")

                elif 'drop' in expr:
                    parts.append("drop")

                elif 'accept' in expr:
                    parts.append("accept")

                elif 'reject' in expr:
                    parts.append("reject")

                elif 'jump' in expr:
                    parts.append(f"jump {expr['jump'].get('target', '?')}")

                elif 'goto' in expr:
                    parts.append(f"goto {expr['goto'].get('target', '?')}")

                elif 'log' in expr:
                    log_info = expr['log']
                    prefix = log_info.get('prefix', '')
                    if prefix:
                        parts.append(f'log prefix "{prefix}"')
                    else:
                        parts.append("log")

        return ' '.join(parts) if parts else "(no expressions)"

    def _expr_to_text(self, expr: dict) -> str:
        """Convert an expression object to text"""
        if not expr:
            return "?"

        if 'payload' in expr:
            payload = expr['payload']
            protocol = payload.get('protocol', '')
            field = payload.get('field', '')
            return f"{protocol} {field}"

        elif 'prefix' in expr:
            prefix = expr['prefix']
            addr = prefix.get('addr', '')
            length = prefix.get('len', 0)
            return f"{addr}/{length}"

        elif isinstance(expr, (str, int)):
            return str(expr)

        return str(expr)

    def _parse_text_ruleset(self) -> Dict[int, RuleInfo]:
        """Parse text format ruleset with handles (-a flag)"""
        rules = {}

        try:
            result = subprocess.run(
                ['nft', '-a', 'list', 'ruleset'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                return {}

            current_table = None
            current_chain = None
            current_family = None
            position = 0

            for line in result.stdout.split('\n'):
                line = line.strip()

                # Match table declaration
                table_match = re.match(r'table\s+(\w+)\s+(\w+)', line)
                if table_match:
                    current_family = table_match.group(1)
                    current_table = table_match.group(2)
                    continue

                # Match chain declaration
                chain_match = re.match(r'chain\s+(\w+)', line)
                if chain_match:
                    current_chain = chain_match.group(1)
                    position = 0  # Reset position for new chain
                    continue

                # Match rule with handle
                # Example: "tcp dport 22 counter packets 10 bytes 520 accept # handle 5"
                handle_match = re.search(r'#\s*handle\s+(\d+)', line)
                if handle_match and current_table and current_chain:
                    handle = int(handle_match.group(1))
                    # Remove the handle comment from rule text
                    rule_text = re.sub(r'\s*#\s*handle\s+\d+\s*$', '', line).strip()

                    rules[handle] = RuleInfo(
                        handle=handle,
                        table=current_table,
                        chain=current_chain,
                        family=current_family or 'ip',
                        rule_text=rule_text,
                        position=position
                    )
                    position += 1

        except subprocess.TimeoutExpired:
            print("Warning: nft command timed out")
        except Exception as e:
            print(f"Error in text parsing: {e}")

        return rules

    def get_rule_text(self, handle: int) -> Optional[str]:
        """Get rule text for a given handle"""
        rule = self.rules.get(handle)
        return rule.rule_text if rule else None

    def get_rule_info(self, handle: int) -> Optional[RuleInfo]:
        """Get full rule info for a given handle"""
        return self.rules.get(handle)

    def get_rule_position(self, handle: int) -> Optional[int]:
        """Get position of rule in its chain (0-indexed)"""
        rule = self.rules.get(handle)
        return rule.position if rule else None

    def refresh(self):
        """Refresh ruleset from nftables"""
        self.rules = self.parse_ruleset()
        import time
        self._last_update = time.time()
        return len(self.rules)

    def get_rules_by_chain(self, family: str, table: str, chain: str) -> List[RuleInfo]:
        """Get all rules for a specific chain, sorted by position"""
        chain_rules = [
            rule for rule in self.rules.values()
            if rule.family == family and rule.table == table and rule.chain == chain
        ]
        return sorted(chain_rules, key=lambda r: r.position)


# Singleton instance
_parser_instance = None

def get_parser() -> NFTRulesetParser:
    """Get singleton parser instance"""
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = NFTRulesetParser()
        _parser_instance.refresh()
    return _parser_instance


if __name__ == "__main__":
    # Test the parser
    parser = NFTRulesetParser()
    rules = parser.parse_ruleset()

    print(f"Found {len(rules)} rules:")
    for handle, rule in sorted(rules.items()):
        print(f"  {rule}")

    # Test getting rule by handle
    if rules:
        first_handle = next(iter(rules))
        print(f"\nRule lookup test (handle {first_handle}):")
        print(f"  Text: {parser.get_rule_text(first_handle)}")
        print(f"  Position: {parser.get_rule_position(first_handle)}")
