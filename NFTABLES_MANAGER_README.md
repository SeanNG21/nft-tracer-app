# NFTables Manager - User Guide

## Tổng quan

Trang **NFTables Manager** là một công cụ quản lý rules của nftables với giao diện đồ họa thân thiện. Trang này được tích hợp vào NFT Tracer App và cho phép:

- ✅ Xem toàn bộ hệ thống ruleset dạng cây
- ✅ Lọc và tìm kiếm rules
- ✅ Thêm rules mới bằng form builder
- ✅ Sửa rules hiện có
- ✅ Xóa rules
- ✅ Xuất ruleset ra JSON

---

## Kiến trúc

### Backend APIs

File: `/backend/nftables_manager.py`

**Endpoints:**

1. **GET** `/api/nft/health` - Kiểm tra nft command có sẵn không
2. **GET** `/api/nft/rules` - Lấy toàn bộ ruleset (raw + tree structure)
3. **GET** `/api/nft/tables` - Lấy danh sách tables
4. **GET** `/api/nft/chains/<family>/<table>` - Lấy chains của table
5. **POST** `/api/nft/rule/add` - Thêm rule mới
6. **POST** `/api/nft/rule/delete` - Xóa rule theo handle
7. **POST** `/api/nft/rule/update` - Cập nhật rule (delete + add)

**Cấu trúc dữ liệu:**

```json
{
  "tree": {
    "ip": {
      "filter": {
        "handle": 1,
        "chains": {
          "input": {
            "type": "filter",
            "hook": "input",
            "prio": 0,
            "policy": "accept",
            "rules": [
              {
                "handle": 2,
                "rule_text": "tcp dport 80 counter accept",
                "expr": [...]
              }
            ]
          }
        }
      }
    }
  }
}
```

### Frontend Components

File: `/frontend/src/NFTablesManager.jsx`
CSS: `/frontend/src/NFTablesManager.css`

**State Management:**
- `activeTab`: 'view' hoặc 'manage'
- `ruleTree`: Cây rules (family → table → chain → rules)
- `filters`: Bộ lọc (family, chain, verdict, handle, text)
- `ruleForm`: Form data cho add/edit rule
- `expandedItems`: Track các items đã mở trong tree view

---

## Tab 1: View Rules (Danh sách Rules)

### Chức năng:

1. **Load Ruleset**
   - Click "Load Ruleset" để tải toàn bộ rules từ hệ thống
   - Rules được tổ chức theo cấu trúc: Family → Table → Chain → Rules

2. **Hiển thị dạng cây**
   - Click vào header để expand/collapse
   - Hiển thị đầy đủ:
     - Chain type (filter, nat, route)
     - Hook (input, forward, output, prerouting, postrouting)
     - Priority
     - Policy (accept, drop)
     - Rule handle
     - Rule expression (human-readable)

3. **Filters (Bộ lọc)**
   - **Family**: ip, ip6, inet, arp, bridge
   - **Chain Name**: Filter theo tên chain (text search)
   - **Verdict**: Filter theo action (accept, drop, reject, return, jump, goto)
   - **Rule Handle**: Filter theo số handle cụ thể
   - **Text Search**: Tìm kiếm trong rule text

4. **Actions**
   - **Edit**: Mở rule trong tab Manage để sửa
   - **Delete**: Xóa rule (có confirmation)
   - **Export to JSON**: Xuất toàn bộ ruleset ra file JSON

### Ví dụ sử dụng:

```
1. Click "Load Ruleset"
2. Expand "ip" → "filter" → "input"
3. Filter by "Verdict: accept"
4. Click "Edit" trên rule muốn sửa
5. Hoặc click "Delete" để xóa
```

---

## Tab 2: Manage Rules (Quản lý Rules)

### Phần 1: Add Rule

**Form fields:**

#### Target (Bắt buộc)
- **Family**: ip, ip6, inet, arp, bridge
- **Table**: Dropdown load từ nft list tables
- **Chain**: Dropdown load từ table đã chọn

#### Match Conditions (Điều kiện khớp)

**Protocol:**
- tcp, udp, icmp, icmpv6

**TCP/UDP Ports:**
- TCP Destination Port (e.g., 80, 443, 8000-9000)
- TCP Source Port
- UDP Destination Port (e.g., 53, 123)
- UDP Source Port

**IP Addresses:**
- Source IP (e.g., 192.168.1.0/24)
- Destination IP (e.g., 10.0.0.1)

**Interfaces:**
- Input Interface (e.g., eth0, wlan0)
- Output Interface

**Connection Tracking:**
- CT State: new, established, related, invalid, established,related

#### Action (Verdict)

- **accept**: Chấp nhận packet
- **drop**: Drop packet (silent)
- **reject**: Reject packet (với ICMP response)
- **return**: Trở về chain cha
- **jump**: Nhảy sang chain khác (cần chọn target chain)
- **goto**: Goto chain khác (cần chọn target chain)
- **log**: Log packet (cần nhập log prefix)

**Options:**
- ☑ Enable counter: Đếm packets/bytes

### Workflow Add Rule:

```
1. Chọn Family, Table, Chain
2. Điền Match Conditions (optional)
   Example:
   - Protocol: tcp
   - TCP Destination Port: 8888
   - Source IP: 1.2.3.4
3. Chọn Action: accept
4. Check "Enable counter"
5. Click "Generate Preview"
   → Preview: tcp dport 8888 ip saddr 1.2.3.4 counter accept
6. Click "Add Rule"
7. Rule được thêm vào chain
```

### Phần 2: Edit Rule

**Workflow:**

```
1. Từ Tab 1 (View Rules), click "Edit" trên rule muốn sửa
2. Tab tự động chuyển sang "Manage Rules" ở chế độ Edit
3. Form được pre-fill với thông tin rule hiện tại
4. Sửa các field cần thiết
5. Click "Generate Preview" để xem rule mới
6. Click "Update Rule"
7. Backend sẽ:
   - Delete rule cũ (theo handle)
   - Add rule mới vào cùng vị trí
```

**Lưu ý:**
- Khi ở Edit mode, Family/Table/Chain bị disabled (không đổi được)
- Để thêm rule mới, click "Switch to Add Mode"

### Phần 3: Delete Rule

**Workflow:**

```
1. Từ Tab 1 (View Rules), click "Delete" trên rule muốn xóa
2. Confirm deletion
3. Rule bị xóa khỏi chain
```

---

## Ví dụ Rules

### 1. Allow HTTP traffic

```
Family: ip
Table: filter
Chain: input
Match: tcp dport 80
Action: accept
Counter: yes

→ Rule: tcp dport 80 counter accept
```

### 2. Drop packets from specific IP

```
Family: ip
Table: filter
Chain: input
Match: ip saddr 10.0.0.100
Action: drop
Counter: yes

→ Rule: ip saddr 10.0.0.100 counter drop
```

### 3. Allow established connections

```
Family: inet
Table: filter
Chain: input
Match: ct state established,related
Action: accept

→ Rule: ct state established,related accept
```

### 4. Log and accept SSH

```
Family: ip
Table: filter
Chain: input
Match: tcp dport 22
Action: log
Log Prefix: "SSH-ACCEPT: "
Counter: yes

→ Rule: tcp dport 22 counter log prefix "SSH-ACCEPT: " accept
```

### 5. Jump to custom chain

```
Family: ip
Table: filter
Chain: input
Match: tcp dport 8000-9000
Action: jump
Target Chain: custom_chain

→ Rule: tcp dport 8000-9000 jump custom_chain
```

---

## UI Features

### Design
- **Color scheme**: Purple gradient primary (#667eea, #764ba2), Cyan accents (#00bcd4)
- **Layout**: Card-based, responsive
- **Tree view**: Collapsible với expand/collapse animation
- **Form**: Grid layout, responsive trên mobile

### User Experience
- Auto-refresh sau khi add/edit/delete
- Confirmation trước khi delete
- Error handling với error banner
- Loading states cho tất cả async operations
- Preview rule trước khi add/update

### Responsive
- Desktop: Multi-column grid layout
- Tablet: 2 columns
- Mobile: Single column, full-width buttons

---

## Requirements

### Backend
- Python 3.x
- Flask
- nftables installed
- sudo privileges (cho nft commands)

### Frontend
- React 18.x
- axios
- Modern browser (Chrome, Firefox, Safari, Edge)

---

## Security Notes

⚠️ **QUAN TRỌNG:**

1. **Sudo Access**: Backend cần quyền sudo để chạy `nft` commands
2. **Input Validation**: Frontend validate inputs, nhưng backend cũng phải validate
3. **Error Messages**: Backend trả về error messages chi tiết để debug
4. **Audit**: Mọi thay đổi nên được log lại
5. **Backup**: Nên backup ruleset trước khi sửa/xóa rules

---

## Troubleshooting

### Backend không thấy nft command

```bash
# Install nftables
sudo apt-get install nftables

# Check version
nft --version

# Check sudo access
sudo nft list ruleset
```

### Backend trả về "Permission denied"

```bash
# Configure sudo without password for nft (OPTIONAL)
sudo visudo
# Add line:
# your_user ALL=(ALL) NOPASSWD: /usr/sbin/nft

# Or run backend with sudo (NOT RECOMMENDED)
```

### Frontend không connect được backend

```bash
# Check backend đang chạy
curl http://localhost:5000/api/nft/health

# Check CORS
# Đảm bảo Flask-CORS enabled trong app.py
```

### Rules không load

```bash
# Check nftables service
sudo systemctl status nftables

# Check ruleset manually
sudo nft list ruleset

# Check backend logs
# Xem error messages từ Python
```

---

## Future Enhancements

Các tính năng có thể thêm vào trong tương lai:

1. **Rule Templates**: Pre-defined templates cho common use cases
2. **Bulk Import/Export**: Import rules từ file nft script
3. **Rule Validation**: Syntax checking trước khi add
4. **Rule Reordering**: Drag-and-drop để sắp xếp rules
5. **Chain Management**: Add/delete/modify chains
6. **Table Management**: Add/delete tables
7. **Rule Statistics**: Hiển thị counter realtime
8. **Rule Comments**: Thêm comment cho rules
9. **Diff View**: So sánh trước/sau khi sửa
10. **Rule History**: Track changes over time
11. **Backup/Restore**: Backup và restore toàn bộ ruleset
12. **Rule Testing**: Test rule trước khi apply

---

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

---

## Credits

Developed as part of the NFT Tracer App project.

**Components:**
- Backend: Python + Flask + nftables
- Frontend: React + axios
- Styling: Custom CSS with gradients

**Version**: 1.0.0
**Date**: 2025-11-16
