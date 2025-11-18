"""
pytest configuration and fixtures for NFT Tracer tests
"""

import pytest
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import TestingConfig


@pytest.fixture(scope='session')
def test_config():
    """Provide test configuration"""
    return TestingConfig


@pytest.fixture
def mock_ebpf():
    """Mock eBPF functionality for testing"""
    class MockBPF:
        def __init__(self, *args, **kwargs):
            pass

        def __getitem__(self, key):
            return []

        def perf_buffer_poll(self, *args, **kwargs):
            pass

    return MockBPF


@pytest.fixture
def sample_packet_data():
    """Provide sample packet data for testing"""
    return {
        'timestamp': 1234567890.123,
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 54321,
        'dst_port': 80,
        'protocol': 6,  # TCP
        'verdict': 'accept',
        'hook': 'input',
    }


@pytest.fixture
def sample_trace():
    """Provide sample trace data for testing"""
    return {
        'trace_id': 'test-trace-001',
        'packets': [
            {
                'timestamp': 1234567890.123,
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'verdict': 'accept',
            }
        ],
        'summary': {
            'total_packets': 1,
            'accepted': 1,
            'dropped': 0,
        }
    }
