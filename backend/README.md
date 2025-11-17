# NFT Tracer Backend

Backend server cho ứng dụng NFT Tracer - công cụ trace và phân tích packet qua kernel Linux và nftables.

## Cấu trúc thư mục

```
backend/
├── app.py                          # Main Flask application (entry point)
├── multi_function_backend.py       # Multi-function tracer logic
├── realtime_extension.py           # Realtime WebSocket extension
├── requirements.txt                # Python dependencies
│
├── discovery/                      # Kernel function discovery modules
│   ├── __init__.py
│   ├── btf_skb_discoverer.py      # BTF-based SKB function discoverer
│   └── enhanced_skb_discoverer.py # Enhanced discoverer with layer classification
│
├── ebpf/                           # eBPF kernel programs
│   ├── __init__.py
│   ├── nft_tracer.bpf.c           # Legacy NFT tracer
│   ├── full_tracer.bpf.c          # Full packet path tracer
│   └── multi_function_nft_trace_v2.bpf.c  # Multi-function tracer (active)
│
├── integrations/                   # External integrations
│   ├── __init__.py
│   ├── nftables_manager.py        # NFTables API integration
│   └── multifunction_integration.py # Multi-function tracer integration
│
├── data/                           # Runtime data
│   ├── output/                    # Trace output files
│   └── cache/                     # Cache files (skb_functions.json, etc.)
│
├── docs/                           # Documentation
│   ├── FIXES_AND_IMPROVEMENTS.md
│   ├── MULTI_FUNCTION_INTEGRATION_README.md
│   └── MULTI_FUNCTION_TRACE_README.md
│
├── scripts/                        # Helper scripts
│   └── quick_start_multi_trace.sh
│
└── tests/                          # Test files
    └── test_socketio_server.py
```

## Modules chính

### Core Application
- **app.py** (1,932 lines): Main Flask server với các API endpoints cho tracing, session management, và packet analysis
- **multi_function_backend.py** (377 lines): Logic xử lý multi-function tracing
- **realtime_extension.py** (1,369 lines): WebSocket extension cho realtime visualization

### Discovery
- **btf_skb_discoverer.py**: Tự động phát hiện kernel functions xử lý sk_buff thông qua BTF
- **enhanced_skb_discoverer.py**: Phiên bản nâng cao với phân loại theo network layers (Device, GRO, Netfilter, IPv4, IPv6, TCP, UDP, Routing, Xmit, SoftIRQ)

### eBPF Programs
- **nft_tracer.bpf.c**: Legacy NFT tracer
- **full_tracer.bpf.c**: Full packet path tracer
- **multi_function_nft_trace_v2.bpf.c**: Active multi-function tracer (recommended)

### Integrations
- **nftables_manager.py**: Quản lý và tương tác với nftables rules
- **multifunction_integration.py**: Integration layer cho multi-function tracing mode

## API Endpoints

### Trace Management
- `POST /api/trace/start` - Bắt đầu trace session
- `POST /api/trace/stop` - Dừng trace session
- `GET /api/trace/status` - Lấy trạng thái trace
- `GET /api/traces` - Liệt kê tất cả traces đã lưu
- `GET /api/trace/<trace_id>` - Lấy chi tiết một trace

### Realtime WebSocket
- `ws://localhost:5000/socket.io` - WebSocket endpoint cho realtime events

### NFTables
- `GET /api/nftables/tables` - Lấy danh sách tables
- `GET /api/nftables/chains` - Lấy danh sách chains
- `GET /api/nftables/rules` - Lấy danh sách rules

### Function Discovery
- `POST /api/discover` - Discover kernel functions

### System Info
- `GET /api/status` - System status và capabilities

## Yêu cầu hệ thống

- Python 3.8+
- Linux kernel với BPF/BTF support
- BCC (BPF Compiler Collection)
- Root privileges (để load eBPF programs)

## Cài đặt

```bash
# Install system dependencies
sudo apt-get install bpfcc-tools python3-bpfcc

# Install Python dependencies
pip3 install -r requirements.txt

# Run server
sudo python3 app.py
```

## Development Notes

- Backend sử dụng Flask với CORS enabled cho frontend React
- WebSocket mode sử dụng flask-socketio với threading async mode
- eBPF programs được compile và load runtime qua BCC
- Cache files được lưu trong `data/cache/` để tăng performance
- Output traces được lưu trong `data/output/`

## Cleaned Up Files

Các file sau đã được xóa trong quá trình tái cấu trúc:
- ✗ app.py.backup
- ✗ requirements.txt.backup
- ✗ multi_function_nft_tracer.py (v1, deprecated)
- ✗ multi_function_nft_trace.bpf.c (v1, deprecated)
- ✗ universal_skb_tracer.py (unused)
- ✗ multi_function_nft_tracer_v2.py (not imported)

## Recent Changes

**2025-11-17: Backend Restructuring**
- Tổ chức lại cấu trúc thư mục theo chức năng
- Di chuyển eBPF programs vào `ebpf/`
- Di chuyển discovery modules vào `discovery/`
- Di chuyển integrations vào `integrations/`
- Di chuyển docs, scripts, tests vào thư mục riêng
- Cập nhật import paths và file paths
- Thêm BCC vào requirements.txt
- Xóa các file deprecated và backup
