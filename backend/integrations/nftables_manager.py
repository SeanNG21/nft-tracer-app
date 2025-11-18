#!/usr/bin/env python3
"""
NFTables Manager Module
Provides API functions for managing nftables rules
"""

import subprocess
import json
import re
from typing import Dict, List, Optional, Tuple


class NFTablesManager:
    """Manager for nftables operations"""

    @staticmethod
    def check_nft_available() -> Tuple[bool, str]:
        """Check if nft command is available and accessible"""
        try:
            result = subprocess.run(
                ['which', 'nft'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Check if we can run nft (may need sudo)
                version_result = subprocess.run(
                    ['nft', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if version_result.returncode == 0:
                    return True, "nft available"
                else:
                    # Try with sudo
                    sudo_result = subprocess.run(
                        ['sudo', '-n', 'nft', '--version'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if sudo_result.returncode == 0:
                        return True, "nft available (requires sudo)"
                    else:
                        return False, "nft requires sudo privileges"
            else:
                return False, "nft command not found"
        except Exception as e:
            return False, f"Error checking nft: {str(e)}"

    @staticmethod
    def get_ruleset() -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Get complete nftables ruleset in JSON format
        Returns: (success, data, error_message)
        """
        try:
            # Try without sudo first
            result = subprocess.run(
                ['nft', '--json', 'list', 'ruleset'],
                capture_output=True,
                text=True,
                timeout=10
            )

            # If permission denied, try with sudo
            if result.returncode != 0:
                result = subprocess.run(
                    ['sudo', 'nft', '--json', 'list', 'ruleset'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

            if result.returncode == 0:
                try:
                    ruleset = json.loads(result.stdout)
                    return True, ruleset, None
                except json.JSONDecodeError as e:
                    return False, None, f"Failed to parse JSON: {str(e)}"
            else:
                return False, None, result.stderr or "Failed to get ruleset"

        except subprocess.TimeoutExpired:
            return False, None, "Command timeout"
        except Exception as e:
            return False, None, f"Error: {str(e)}"

    @staticmethod
    def get_tables() -> Tuple[bool, Optional[List[Dict]], Optional[str]]:
        """
        Get list of all tables
        Returns: (success, tables_list, error_message)
        """
        success, ruleset, error = NFTablesManager.get_ruleset()
        if not success:
            return False, None, error

        tables = []
        nftables = ruleset.get('nftables', [])

        for item in nftables:
            if 'table' in item:
                table_info = item['table']
                tables.append({
                    'family': table_info.get('family', 'unknown'),
                    'name': table_info.get('name', 'unknown'),
                    'handle': table_info.get('handle')
                })

        return True, tables, None

    @staticmethod
    def get_chains(family: str, table: str) -> Tuple[bool, Optional[List[Dict]], Optional[str]]:
        """
        Get chains for a specific table
        Returns: (success, chains_list, error_message)
        """
        success, ruleset, error = NFTablesManager.get_ruleset()
        if not success:
            return False, None, error

        chains = []
        nftables = ruleset.get('nftables', [])

        for item in nftables:
            if 'chain' in item:
                chain_info = item['chain']
                if chain_info.get('family') == family and chain_info.get('table') == table:
                    chains.append({
                        'name': chain_info.get('name', 'unknown'),
                        'handle': chain_info.get('handle'),
                        'type': chain_info.get('type'),
                        'hook': chain_info.get('hook'),
                        'prio': chain_info.get('prio'),
                        'policy': chain_info.get('policy')
                    })

        return True, chains, None

    @staticmethod
    def add_rule(family: str, table: str, chain: str, rule_text: str) -> Tuple[bool, Optional[str]]:
        """
        Add a new rule to specified chain
        Returns: (success, error_message)
        """
        try:
            # Validate inputs
            if not all([family, table, chain, rule_text]):
                return False, "Missing required parameters"

            # Build command
            cmd = [
                'sudo', 'nft', 'add', 'rule',
                family, table, chain, rule_text
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return True, None
            else:
                error_msg = result.stderr or "Failed to add rule"
                return False, error_msg

        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, f"Error: {str(e)}"

    @staticmethod
    def delete_rule(family: str, table: str, chain: str, handle: int) -> Tuple[bool, Optional[str]]:
        """
        Delete a rule by handle
        Returns: (success, error_message)
        """
        try:
            # Validate inputs
            if not all([family, table, chain]) or handle is None:
                return False, "Missing required parameters"

            # Build command
            cmd = [
                'sudo', 'nft', 'delete', 'rule',
                family, table, chain, 'handle', str(handle)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return True, None
            else:
                error_msg = result.stderr or "Failed to delete rule"
                return False, error_msg

        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, f"Error: {str(e)}"

    @staticmethod
    def update_rule(family: str, table: str, chain: str, handle: int, new_rule_text: str) -> Tuple[bool, Optional[str]]:
        """
        Update a rule by deleting and re-adding it
        Returns: (success, error_message)
        """
        # Delete old rule
        success, error = NFTablesManager.delete_rule(family, table, chain, handle)
        if not success:
            return False, f"Failed to delete old rule: {error}"

        # Add new rule
        success, error = NFTablesManager.add_rule(family, table, chain, new_rule_text)
        if not success:
            return False, f"Failed to add new rule: {error}"

        return True, None

    @staticmethod
    def get_ruleset_with_handles() -> Tuple[bool, Optional[Dict[int, str]], Optional[str]]:
        """
        Get ruleset with exact rule text mapped by handle
        Returns: (success, handle_to_text_map, error_message)

        This method ensures 100% accuracy by:
        1. Getting JSON ruleset with handles
        2. Getting text ruleset
        3. Mapping handles to exact rule text
        """
        try:
            # Get JSON ruleset with handles
            result_json = subprocess.run(
                ['sudo', 'nft', '--json', '--handle', 'list', 'ruleset'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result_json.returncode != 0:
                # Try without sudo
                result_json = subprocess.run(
                    ['nft', '--json', '--handle', 'list', 'ruleset'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

            if result_json.returncode != 0:
                return False, None, result_json.stderr or "Failed to get JSON ruleset"

            # Get text ruleset with handles
            result_text = subprocess.run(
                ['sudo', 'nft', '--handle', 'list', 'ruleset'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result_text.returncode != 0:
                # Try without sudo
                result_text = subprocess.run(
                    ['nft', '--handle', 'list', 'ruleset'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

            if result_text.returncode != 0:
                return False, None, result_text.stderr or "Failed to get text ruleset"

            # Parse JSON to get handles
            try:
                ruleset_json = json.loads(result_json.stdout)
            except json.JSONDecodeError as e:
                return False, None, f"Failed to parse JSON: {str(e)}"

            # Parse text ruleset to extract rule text by handle
            handle_to_text = NFTablesManager._parse_text_ruleset(result_text.stdout, ruleset_json)

            return True, handle_to_text, None

        except subprocess.TimeoutExpired:
            return False, None, "Command timeout"
        except Exception as e:
            return False, None, f"Error: {str(e)}"

    @staticmethod
    def _parse_text_ruleset(text_output: str, json_ruleset: Dict) -> Dict[int, str]:
        """
        Parse text ruleset and map handles to exact rule text

        Strategy:
        1. Extract all handles from JSON (with metadata: family, table, chain)
        2. Parse text output line by line
        3. Match rules with handles using context (family, table, chain)
        4. Store exact rule text (everything before '# handle X')
        """
        handle_map = {}

        # Build handle metadata from JSON
        handle_metadata = {}  # handle -> {family, table, chain, index}
        nftables = json_ruleset.get('nftables', [])

        current_family = None
        current_table = None
        current_chain = None
        rule_index_in_chain = {}  # (family, table, chain) -> index

        for item in nftables:
            if 'table' in item:
                current_family = item['table'].get('family')
                current_table = item['table'].get('name')
            elif 'chain' in item:
                current_chain = item['chain'].get('name')
                rule_index_in_chain[(current_family, current_table, current_chain)] = 0
            elif 'rule' in item:
                rule = item['rule']
                handle = rule.get('handle')
                if handle and current_family and current_table and current_chain:
                    key = (current_family, current_table, current_chain)
                    index = rule_index_in_chain.get(key, 0)
                    handle_metadata[handle] = {
                        'family': current_family,
                        'table': current_table,
                        'chain': current_chain,
                        'index': index
                    }
                    rule_index_in_chain[key] = index + 1

        # Parse text output
        lines = text_output.split('\n')
        current_family = None
        current_table = None
        current_chain = None
        rule_index = 0

        for line in lines:
            stripped = line.strip()

            # Detect family context (e.g., "table ip filter {")
            if stripped.startswith('table '):
                parts = stripped.split()
                if len(parts) >= 3:
                    current_family = parts[1]
                    current_table = parts[2].rstrip(' {')

            # Detect chain context (e.g., "chain input {")
            elif stripped.startswith('chain '):
                parts = stripped.split()
                if len(parts) >= 2:
                    current_chain = parts[1].rstrip(' {')
                    rule_index = 0

            # Detect rule with handle (e.g., "ip saddr 1.2.3.4 accept # handle 5")
            elif '# handle ' in stripped and current_family and current_table and current_chain:
                # Extract handle number
                handle_match = re.search(r'# handle (\d+)', stripped)
                if handle_match:
                    handle = int(handle_match.group(1))
                    # Extract rule text (everything before '# handle')
                    rule_text = stripped.split('# handle')[0].strip()

                    # Verify this handle matches expected context
                    metadata = handle_metadata.get(handle)
                    if metadata:
                        if (metadata['family'] == current_family and
                            metadata['table'] == current_table and
                            metadata['chain'] == current_chain and
                            metadata['index'] == rule_index):
                            handle_map[handle] = rule_text
                            rule_index += 1
                    else:
                        # Fallback: store anyway if handle not in metadata
                        handle_map[handle] = rule_text
                        rule_index += 1

        return handle_map

    @staticmethod
    def parse_ruleset_to_tree(ruleset: Dict) -> Dict:
        """
        Parse ruleset JSON into a tree structure organized by family -> table -> chain -> rules
        """
        tree = {}
        nftables = ruleset.get('nftables', [])

        # First pass: collect tables and chains
        for item in nftables:
            if 'table' in item:
                table_info = item['table']
                family = table_info.get('family', 'unknown')
                table_name = table_info.get('name', 'unknown')

                if family not in tree:
                    tree[family] = {}

                if table_name not in tree[family]:
                    tree[family][table_name] = {
                        'handle': table_info.get('handle'),
                        'chains': {}
                    }

            elif 'chain' in item:
                chain_info = item['chain']
                family = chain_info.get('family', 'unknown')
                table_name = chain_info.get('table', 'unknown')
                chain_name = chain_info.get('name', 'unknown')

                if family not in tree:
                    tree[family] = {}
                if table_name not in tree[family]:
                    tree[family][table_name] = {'chains': {}}

                tree[family][table_name]['chains'][chain_name] = {
                    'handle': chain_info.get('handle'),
                    'type': chain_info.get('type'),
                    'hook': chain_info.get('hook'),
                    'prio': chain_info.get('prio'),
                    'policy': chain_info.get('policy'),
                    'rules': []
                }

        # Second pass: collect rules
        for item in nftables:
            if 'rule' in item:
                rule_info = item['rule']
                family = rule_info.get('family', 'unknown')
                table_name = rule_info.get('table', 'unknown')
                chain_name = rule_info.get('chain', 'unknown')

                if (family in tree and
                    table_name in tree[family] and
                    chain_name in tree[family][table_name]['chains']):

                    # Parse rule expression to readable text
                    rule_text = NFTablesManager.parse_rule_expr(rule_info.get('expr', []))

                    rule_data = {
                        'handle': rule_info.get('handle'),
                        'expr': rule_info.get('expr', []),
                        'rule_text': rule_text,
                        'comment': rule_info.get('comment')
                    }

                    tree[family][table_name]['chains'][chain_name]['rules'].append(rule_data)

        return tree

    @staticmethod
    def parse_rule_expr(expr_list: List[Dict]) -> str:
        """
        Parse nftables rule expression to human-readable text
        This is a simplified parser - can be extended for more complex rules
        """
        parts = []

        for expr in expr_list:
            if 'match' in expr:
                match = expr['match']
                left = match.get('left', {})
                right = match.get('right', {})
                op = match.get('op', '==')

                # Parse left side (field)
                left_str = NFTablesManager.parse_expr_value(left)
                right_str = NFTablesManager.parse_expr_value(right)

                if op == '==':
                    parts.append(f"{left_str} {right_str}")
                else:
                    parts.append(f"{left_str} {op} {right_str}")

            elif 'counter' in expr:
                counter = expr['counter']
                packets = counter.get('packets', 0)
                bytes_val = counter.get('bytes', 0)
                parts.append(f"counter packets {packets} bytes {bytes_val}")

            elif 'accept' in expr:
                parts.append('accept')
            elif 'drop' in expr:
                parts.append('drop')
            elif 'reject' in expr:
                parts.append('reject')
            elif 'return' in expr:
                parts.append('return')
            elif 'jump' in expr:
                target = expr['jump'].get('target', '')
                parts.append(f"jump {target}")
            elif 'goto' in expr:
                target = expr['goto'].get('target', '')
                parts.append(f"goto {target}")
            elif 'log' in expr:
                log_info = expr['log']
                prefix = log_info.get('prefix', '')
                parts.append(f'log prefix "{prefix}"')

        return ' '.join(parts) if parts else '<empty rule>'

    @staticmethod
    def parse_expr_value(value_dict: Dict) -> str:
        """Parse expression value to string"""
        if isinstance(value_dict, dict):
            if 'payload' in value_dict:
                payload = value_dict['payload']
                protocol = payload.get('protocol', '')
                field = payload.get('field', '')
                return f"{protocol} {field}" if protocol and field else str(value_dict)
            elif 'prefix' in value_dict:
                prefix = value_dict['prefix']
                addr = prefix.get('addr', '')
                length = prefix.get('len', '')
                return f"{addr}/{length}"
            elif 'set' in value_dict:
                return str(value_dict['set'])
            elif 'range' in value_dict:
                rng = value_dict['range']
                return f"{rng[0]}-{rng[1]}"
            else:
                # Try to get first value
                for key, val in value_dict.items():
                    return str(val)

        return str(value_dict)
