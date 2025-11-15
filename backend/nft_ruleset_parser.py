#!/usr/bin/env python3
"""
NFTables Ruleset Parser
Parse nftables ruleset và tạo mapping rule_handle -> rule definition
"""

import subprocess
import json
from typing import Dict, Optional, List
from dataclasses import dataclass


@dataclass
class NFTRule:
    """NFTables Rule Information"""
    handle: int
    table: str
    chain: str
    family: str
    expr_list: List[Dict]
    rule_text: str

    def __init__(self, handle: int, table: str, chain: str, family: str, expr_list: List[Dict]):
        self.handle = handle
        self.table = table
        self.chain = chain
        self.family = family
        self.expr_list = expr_list
        self.rule_text = self._generate_rule_text(expr_list)

    @staticmethod
    def _generate_rule_text(expr_list: List[Dict]) -> str:
        """Generate human-readable rule text from expression list"""
        parts = []

        for expr in expr_list:
            if 'match' in expr:
                match = expr['match']
                # Match expressions: tcp dport 8888
                left = match.get('left', {})
                right = match.get('right', {})
                op = match.get('op', '==')

                left_str = NFTRule._format_expr(left)
                right_str = NFTRule._format_expr(right)

                if op == '==':
                    parts.append(f"{left_str} {right_str}")
                else:
                    parts.append(f"{left_str} {op} {right_str}")

            elif 'counter' in expr:
                # Counter expression
                counter = expr['counter']
                packets = counter.get('packets', 0)
                bytes_count = counter.get('bytes', 0)
                parts.append(f"counter packets {packets} bytes {bytes_count}")

            elif 'immediate' in expr:
                # Immediate verdict: accept, drop, continue, etc.
                immediate = expr['immediate']
                if 'accept' in immediate:
                    parts.append("accept")
                elif 'drop' in immediate:
                    parts.append("drop")
                elif 'continue' in immediate:
                    parts.append("continue")
                elif 'return' in immediate:
                    parts.append("return")
                elif 'jump' in immediate:
                    target = immediate['jump'].get('target', 'unknown')
                    parts.append(f"jump {target}")
                elif 'goto' in immediate:
                    target = immediate['goto'].get('target', 'unknown')
                    parts.append(f"goto {target}")
                elif 'queue' in immediate:
                    queue_data = immediate['queue']
                    if isinstance(queue_data, dict):
                        num = queue_data.get('num', 0)
                        parts.append(f"queue num {num}")
                    else:
                        parts.append("queue")

            elif 'log' in expr:
                # Log expression
                log = expr['log']
                prefix = log.get('prefix', '')
                if prefix:
                    parts.append(f'log prefix "{prefix}"')
                else:
                    parts.append("log")

            elif 'reject' in expr:
                # Reject expression
                parts.append("reject")

            elif 'ct' in expr:
                # Connection tracking
                ct = expr['ct']
                key = ct.get('key', 'state')
                parts.append(f"ct {key}")

            elif 'limit' in expr:
                # Rate limiting
                limit = expr['limit']
                rate = limit.get('rate', 0)
                per = limit.get('per', 'second')
                parts.append(f"limit rate {rate}/{per}")

            elif 'nat' in expr:
                # NAT expression
                nat = expr['nat']
                nat_type = nat.get('type', 'snat')
                parts.append(f"{nat_type}")

            elif 'masquerade' in expr:
                parts.append("masquerade")

            elif 'set' in expr:
                # Set expression
                set_expr = expr['set']
                op = set_expr.get('op', 'add')
                elem = NFTRule._format_expr(set_expr.get('elem', {}))
                parts.append(f"set {op} {elem}")

        return ' '.join(parts) if parts else '(no expressions)'

    @staticmethod
    def _format_expr(expr) -> str:
        """Format expression component"""
        # Handle primitive types first (before checking dict keys)
        if isinstance(expr, (int, str)):
            return str(expr)

        elif isinstance(expr, list):
            # List of values: { 80, 443 }
            return "{ " + ", ".join(str(v) for v in expr) + " }"

        # Now check if expr is a dict
        if not isinstance(expr, dict):
            return str(expr)

        # Handle dict-based expressions
        if 'payload' in expr:
            # Payload: tcp dport, ip saddr, etc.
            payload = expr['payload']
            protocol = payload.get('protocol', '')
            field = payload.get('field', '')
            return f"{protocol} {field}".strip()

        elif 'meta' in expr:
            # Meta: iifname, oifname, etc.
            meta = expr['meta']
            key = meta.get('key', '')
            return f"meta {key}"

        elif 'ct' in expr:
            # CT: ct state
            ct = expr['ct']
            key = ct.get('key', '')
            return f"ct {key}"

        elif 'set' in expr:
            # Set reference
            return f"@{expr['set']}"

        elif 'prefix' in expr:
            # IP prefix
            prefix = expr['prefix']
            addr = prefix.get('addr', '')
            length = prefix.get('len', 0)
            return f"{addr}/{length}"

        elif 'range' in expr:
            # Range: 1000-2000
            range_expr = expr['range']
            return f"{range_expr[0]}-{range_expr[1]}"

        elif 'concat' in expr:
            # Concatenation
            concat = expr['concat']
            parts = [NFTRule._format_expr(e) for e in concat]
            return ". ".join(parts)

        else:
            # Fallback: try to extract value
            return str(expr.get('value', expr.get('data', str(expr))))


class NFTRulesetParser:
    """Parse nftables ruleset và cache rule definitions"""

    def __init__(self):
        self.rules: Dict[int, NFTRule] = {}  # handle -> NFTRule
        self.tables: Dict[str, Dict] = {}     # family:table -> table info
        self.chains: Dict[str, Dict] = {}     # family:table:chain -> chain info
        self._loaded = False

    def load_ruleset(self) -> bool:
        """Load nftables ruleset using 'nft -j list ruleset'"""
        try:
            # Execute nft command to get JSON ruleset
            result = subprocess.run(
                ['nft', '-j', 'list', 'ruleset'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                print(f"[!] Failed to load nftables ruleset: {result.stderr}")
                return False

            # Parse JSON output
            ruleset_data = json.loads(result.stdout)

            # Process nftables objects
            for item in ruleset_data.get('nftables', []):
                if 'table' in item:
                    self._process_table(item['table'])
                elif 'chain' in item:
                    self._process_chain(item['chain'])
                elif 'rule' in item:
                    self._process_rule(item['rule'])

            self._loaded = True
            print(f"[✓] Loaded {len(self.rules)} nftables rules")
            return True

        except FileNotFoundError:
            print("[!] 'nft' command not found - Install nftables")
            return False
        except subprocess.TimeoutExpired:
            print("[!] nft command timeout")
            return False
        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse nft JSON output: {e}")
            return False
        except Exception as e:
            print(f"[!] Error loading ruleset: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _process_table(self, table: Dict):
        """Process table definition"""
        family = table.get('family', 'ip')
        name = table.get('name', '')
        key = f"{family}:{name}"
        self.tables[key] = table

    def _process_chain(self, chain: Dict):
        """Process chain definition"""
        family = chain.get('family', 'ip')
        table = chain.get('table', '')
        name = chain.get('name', '')
        key = f"{family}:{table}:{name}"
        self.chains[key] = chain

    def _process_rule(self, rule: Dict):
        """Process rule definition"""
        family = rule.get('family', 'ip')
        table = rule.get('table', '')
        chain = rule.get('chain', '')
        handle = rule.get('handle')
        expr_list = rule.get('expr', [])

        if handle is not None:
            nft_rule = NFTRule(
                handle=handle,
                table=table,
                chain=chain,
                family=family,
                expr_list=expr_list
            )
            self.rules[handle] = nft_rule

    def get_rule_by_handle(self, handle: int) -> Optional[NFTRule]:
        """Get rule by handle"""
        if not self._loaded:
            self.load_ruleset()
        return self.rules.get(handle)

    def get_rule_text(self, handle: int) -> str:
        """Get rule text by handle"""
        rule = self.get_rule_by_handle(handle)
        if rule:
            return rule.rule_text
        return f"(rule handle {handle} not found)"

    def get_chain_info(self, family: str, table: str, chain: str) -> Optional[Dict]:
        """Get chain information"""
        key = f"{family}:{table}:{chain}"
        return self.chains.get(key)

    def reload(self) -> bool:
        """Reload ruleset from nftables"""
        self.rules.clear()
        self.tables.clear()
        self.chains.clear()
        self._loaded = False
        return self.load_ruleset()


# Global instance
_parser_instance: Optional[NFTRulesetParser] = None


def get_ruleset_parser() -> NFTRulesetParser:
    """Get global ruleset parser instance"""
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = NFTRulesetParser()
        _parser_instance.load_ruleset()
    return _parser_instance
