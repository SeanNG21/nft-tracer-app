# NFT Tracer Backend

Backend server for NFT Tracer - a packet tracing and analysis tool using Linux kernel and nftables.

## Directory Structure

```
backend/
├── app.py                          # Main Flask application
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
│   └── multi_function_nft_trace_v2.bpf.c  # Multi-function tracer
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
│   ├── MULTI_FUNCTION_INTEGRATION_README.md
│   └── MULTI_FUNCTION_TRACE_README.md
│
├── scripts/                        # Helper scripts
│   └── quick_start_multi_trace.sh
│
└── tests/                          # Test files
    └── test_socketio_server.py
```

## Core Modules

### Application
- **app.py**: Main Flask server with API endpoints for tracing, session management, and packet analysis
- **multi_function_backend.py**: Multi-function tracing logic
- **realtime_extension.py**: WebSocket extension for realtime visualization

### Discovery
- **btf_skb_discoverer.py**: Auto-discover kernel functions processing sk_buff via BTF
- **enhanced_skb_discoverer.py**: Enhanced version with network layer classification (Device, GRO, Netfilter, IPv4, IPv6, TCP, UDP, Routing, Xmit, SoftIRQ)

### eBPF Programs
- **nft_tracer.bpf.c**: Legacy NFT tracer
- **full_tracer.bpf.c**: Full packet path tracer
- **multi_function_nft_trace_v2.bpf.c**: Multi-function tracer

### Integrations
- **nftables_manager.py**: Manage and interact with nftables rules
- **multifunction_integration.py**: Integration layer for multi-function tracing

## API Endpoints

### Trace Management
- `POST /api/trace/start` - Start trace session
- `POST /api/trace/stop` - Stop trace session
- `GET /api/trace/status` - Get trace status
- `GET /api/traces` - List all saved traces
- `GET /api/trace/<trace_id>` - Get trace details

### Realtime WebSocket
- `ws://localhost:5000/socket.io` - WebSocket endpoint for realtime events

### NFTables
- `GET /api/nftables/tables` - Get tables list
- `GET /api/nftables/chains` - Get chains list
- `GET /api/nftables/rules` - Get rules list

### Function Discovery
- `POST /api/discover` - Discover kernel functions

### System Info
- `GET /api/status` - System status and capabilities

## System Requirements

- Python 3.8+
- Linux kernel with BPF/BTF support
- BCC (BPF Compiler Collection)
- Root privileges (to load eBPF programs)

## Installation

```bash
# Install system dependencies
sudo apt-get install bpfcc-tools python3-bpfcc

# Install Python dependencies
pip3 install -r requirements.txt

# Run server
sudo python3 app.py
```

## Development Notes

- Flask with CORS enabled for React frontend
- WebSocket uses flask-socketio with threading async mode
- eBPF programs are compiled and loaded at runtime via BCC
- Cache files stored in `data/cache/` for performance
- Output traces stored in `data/output/`

## Recent Changes

**2025-11-17: Backend Restructuring**
- Reorganized directory structure by function
- Moved eBPF programs to `ebpf/`
- Moved discovery modules to `discovery/`
- Moved integrations to `integrations/`
- Separated docs, scripts, and tests into dedicated directories
- Updated import paths and file paths
- Added BCC to requirements.txt
- Removed deprecated and backup files
