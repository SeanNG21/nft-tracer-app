# NFTables Manager - User Guide

## Overview

NFTables Manager is a web-based interface for managing nftables rules integrated into the NFT Tracer App.

**Features:**
- View ruleset in tree structure
- Filter and search rules
- Add, edit, and delete rules
- Export ruleset to JSON

## Architecture

### Backend APIs

File: `/backend/nftables_manager.py`

**Endpoints:**
1. `GET /api/nft/health` - Check nft command availability
2. `GET /api/nft/rules` - Get complete ruleset
3. `GET /api/nft/tables` - Get tables list
4. `GET /api/nft/chains/<family>/<table>` - Get chains for a table
5. `POST /api/nft/rule/add` - Add new rule
6. `POST /api/nft/rule/delete` - Delete rule by handle
7. `POST /api/nft/rule/update` - Update rule (delete + add)

### Frontend Components

File: `/frontend/src/NFTablesManager.jsx`
CSS: `/frontend/src/NFTablesManager.css`

**State Management:**
- `activeTab`: 'view' or 'manage'
- `ruleTree`: Rules tree (family → table → chain → rules)
- `filters`: Filters (family, chain, verdict, handle, text)
- `ruleForm`: Form data for add/edit operations
- `expandedItems`: Track expanded items in tree view

## Tab 1: View Rules

### Features

1. **Load Ruleset** - Load all rules from the system organized by Family → Table → Chain → Rules
2. **Tree Display** - Click headers to expand/collapse, showing chain type, hook, priority, policy, rule handle, and expression
3. **Filters**:
   - Family: ip, ip6, inet, arp, bridge
   - Chain Name: Text search
   - Verdict: accept, drop, reject, return, jump, goto
   - Rule Handle: Filter by specific handle
   - Text Search: Search in rule text
4. **Actions**:
   - Edit: Open rule in Manage tab
   - Delete: Remove rule with confirmation
   - Export to JSON: Export complete ruleset

## Tab 2: Manage Rules

### Add Rule Form

**Target (Required):**
- Family: ip, ip6, inet, arp, bridge
- Table: Dropdown from nft list tables
- Chain: Dropdown from selected table

**Match Conditions:**
- Protocol: tcp, udp, icmp, icmpv6
- TCP/UDP Ports: Destination/Source ports (e.g., 80, 8000-9000)
- IP Addresses: Source/Destination IP (e.g., 192.168.1.0/24)
- Interfaces: Input/Output interface (e.g., eth0, wlan0)
- Connection Tracking: CT State (new, established, related, invalid)

**Actions (Verdict):**
- accept: Accept packet
- drop: Drop packet silently
- reject: Reject with ICMP response
- return: Return to parent chain
- jump: Jump to another chain
- goto: Goto another chain
- log: Log packet with prefix

**Options:**
- Enable counter: Count packets/bytes

### Edit Rule

1. Click "Edit" on a rule in View Rules tab
2. Tab switches to Manage Rules in Edit mode
3. Form is pre-filled with current rule information
4. Modify fields as needed
5. Click "Update Rule"
6. Backend deletes old rule and adds new rule in same position

Note: Family/Table/Chain are disabled in Edit mode. Click "Switch to Add Mode" to add new rules.

### Delete Rule

1. Click "Delete" on a rule in View Rules tab
2. Confirm deletion
3. Rule is removed from chain

## Rule Examples

### Allow HTTP traffic
```
Family: ip
Table: filter
Chain: input
Match: tcp dport 80
Action: accept
Counter: yes

Rule: tcp dport 80 counter accept
```

### Drop packets from specific IP
```
Family: ip
Table: filter
Chain: input
Match: ip saddr 10.0.0.100
Action: drop
Counter: yes

Rule: ip saddr 10.0.0.100 counter drop
```

### Allow established connections
```
Family: inet
Table: filter
Chain: input
Match: ct state established,related
Action: accept

Rule: ct state established,related accept
```

## Requirements

**Backend:**
- Python 3.x
- Flask
- nftables installed
- sudo privileges for nft commands

**Frontend:**
- React 18.x
- axios
- Modern browser

## Security Notes

**IMPORTANT:**
1. Backend requires sudo access to run nft commands
2. Input validation is performed on both frontend and backend
3. All changes should be logged for audit purposes
4. Backup ruleset before making changes

## Troubleshooting

### Backend cannot find nft command
```bash
sudo apt-get install nftables
nft --version
sudo nft list ruleset
```

### Permission denied errors
```bash
# Configure sudo without password (optional)
sudo visudo
# Add: your_user ALL=(ALL) NOPASSWD: /usr/sbin/nft
```

### Frontend cannot connect to backend
```bash
# Check backend is running
curl http://localhost:5000/api/nft/health

# Ensure Flask-CORS is enabled in app.py
```

### Rules do not load
```bash
# Check nftables service
sudo systemctl status nftables

# Check ruleset manually
sudo nft list ruleset
```

## API Examples

### Get all rules
```bash
curl http://localhost:5000/api/nft/rules
```

### Add a rule
```bash
curl -X POST http://localhost:5000/api/nft/rule/add \
  -H "Content-Type: application/json" \
  -d '{
    "family": "ip",
    "table": "filter",
    "chain": "input",
    "rule_text": "tcp dport 8888 counter accept"
  }'
```

### Delete a rule
```bash
curl -X POST http://localhost:5000/api/nft/rule/delete \
  -H "Content-Type: application/json" \
  -d '{
    "family": "ip",
    "table": "filter",
    "chain": "input",
    "handle": 5
  }'
```

### Update a rule
```bash
curl -X POST http://localhost:5000/api/nft/rule/update \
  -H "Content-Type: application/json" \
  -d '{
    "family": "ip",
    "table": "filter",
    "chain": "input",
    "handle": 5,
    "new_rule_text": "tcp dport 9999 counter accept"
  }'
```
