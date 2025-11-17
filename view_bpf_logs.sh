#!/bin/bash
# View BPF debug logs from trace_pipe
# Usage: sudo ./view_bpf_logs.sh [filter]
#
# Examples:
#   sudo ./view_bpf_logs.sh              # Show all logs
#   sudo ./view_bpf_logs.sh ERROR        # Show only errors
#   sudo ./view_bpf_logs.sh "DEBUG|SUCCESS"  # Show debug and success

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root (sudo)"
    exit 1
fi

FILTER="${1:-ERROR|DEBUG|WARN|SUCCESS}"

echo "[*] Monitoring BPF trace logs (filter: $FILTER)"
echo "[*] Press Ctrl+C to stop"
echo ""

cat /sys/kernel/debug/tracing/trace_pipe | grep -E "$FILTER"
