#!/usr/bin/env python3
"""
Multi-Function Tracer Integration cho app.py
Thêm routes và WebSocket support cho multi-function mode
"""

import os
import json
import threading
import time
from flask import jsonify, request
from multi_function_backend import MultiFunctionBackendTracer, MultiFunctionEvent

# Global tracer instance
multi_tracer = None
multi_tracer_thread = None
multi_tracer_lock = threading.Lock()


def add_multi_function_routes(app, socketio=None):
    """
    Add multi-function tracer routes to Flask app

    Args:
        app: Flask application
        socketio: SocketIO instance (optional, for realtime)
    """

    @app.route('/api/multi-function/start', methods=['POST'])
    def start_multi_function():
        """
        Start multi-function tracer
        AUTO-DISCOVERY: If no config file, will auto-scan BTF (PWru style)
        """
        global multi_tracer, multi_tracer_thread

        with multi_tracer_lock:
            if multi_tracer and multi_tracer.running:
                return jsonify({'error': 'Multi-function tracer already running'}), 400

            try:
                # Get config from request
                data = request.get_json() or {}
                config_file = data.get('config', None)  # None = auto-discovery
                max_functions = data.get('max_functions', 50)

                # Check if auto-discovery mode
                auto_discovery = (config_file is None or not os.path.exists(config_file))
                if auto_discovery:
                    print(f"[*] AUTO-DISCOVERY MODE (no config file)")
                else:
                    print(f"[*] CONFIG MODE: {config_file}")

                # Event callback: emit via WebSocket
                def event_callback(evt: MultiFunctionEvent):
                    if socketio:
                        socketio.emit('multi_function_event', evt.to_dict())

                # Stats callback: emit stats via WebSocket
                def stats_callback(stats: dict):
                    if socketio:
                        socketio.emit('multi_function_stats', stats)

                # Create tracer
                multi_tracer = MultiFunctionBackendTracer(
                    config_file=config_file,
                    max_functions=max_functions,
                    event_callback=event_callback,
                    stats_callback=stats_callback
                )

                # Load functions
                multi_tracer.load_functions()

                # Start tracer
                if not multi_tracer.start():
                    return jsonify({'error': 'Failed to start tracer'}), 500

                # Start polling thread
                def poll_loop():
                    while multi_tracer and multi_tracer.running:
                        multi_tracer.poll()
                        time.sleep(0.01)

                multi_tracer_thread = threading.Thread(target=poll_loop, daemon=True)
                multi_tracer_thread.start()

                # Emit status
                if socketio:
                    socketio.emit('multi_function_status', {
                        'running': True,
                        'functions_count': len(multi_tracer.functions_to_trace),
                        'auto_discovery': auto_discovery
                    })

                return jsonify({
                    'status': 'started',
                    'functions_count': len(multi_tracer.functions_to_trace),
                    'config': config_file if not auto_discovery else 'AUTO-DISCOVERY (BTF)',
                    'auto_discovery': auto_discovery,
                    'mode': 'auto-btf' if auto_discovery else 'config'
                })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

    @app.route('/api/multi-function/stop', methods=['POST'])
    def stop_multi_function():
        """Stop multi-function tracer"""
        global multi_tracer, multi_tracer_thread

        with multi_tracer_lock:
            if not multi_tracer:
                return jsonify({'error': 'No tracer running'}), 400

            try:
                # Stop tracer
                multi_tracer.stop()

                # Get final stats
                final_stats = multi_tracer.get_stats()

                # Cleanup
                multi_tracer = None
                multi_tracer_thread = None

                # Emit status
                if socketio:
                    socketio.emit('multi_function_status', {'running': False})

                return jsonify({
                    'status': 'stopped',
                    'final_stats': final_stats
                })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

    @app.route('/api/multi-function/status', methods=['GET'])
    def multi_function_status():
        """Get multi-function tracer status"""
        with multi_tracer_lock:
            if multi_tracer and multi_tracer.running:
                stats = multi_tracer.get_stats()
                # Detect if using auto-discovery (no config_file or doesn't exist)
                auto_discovery = (not multi_tracer.config_file or
                                not os.path.exists(multi_tracer.config_file))
                return jsonify({
                    'running': True,
                    'stats': stats,
                    'functions_count': len(multi_tracer.functions_to_trace),
                    'auto_discovery': auto_discovery,
                    'mode': 'auto-btf' if auto_discovery else 'config'
                })
            else:
                return jsonify({
                    'running': False
                })

    @app.route('/api/multi-function/stats', methods=['GET'])
    def multi_function_stats():
        """Get current statistics"""
        with multi_tracer_lock:
            if not multi_tracer:
                return jsonify({'error': 'No tracer running'}), 400

            stats = multi_tracer.get_stats()
            return jsonify(stats)

    @app.route('/api/multi-function/config', methods=['GET'])
    def get_multi_function_config():
        """Get available trace configurations"""
        configs = []

        # Check for trace_config.json
        if os.path.exists('trace_config.json'):
            with open('trace_config.json', 'r') as f:
                config = json.load(f)
                configs.append({
                    'file': 'trace_config.json',
                    'total_functions': len(config.get('functions', [])),
                    'description': config.get('description', 'Default trace config')
                })

        # Check for enhanced_skb_functions.json
        if os.path.exists('enhanced_skb_functions.json'):
            with open('enhanced_skb_functions.json', 'r') as f:
                data = json.load(f)
                configs.append({
                    'file': 'enhanced_skb_functions.json',
                    'total_functions': data.get('total', 0),
                    'description': 'Full SKB function list'
                })

        return jsonify({
            'configs': configs,
            'default': 'trace_config.json' if os.path.exists('trace_config.json') else None
        })

    @app.route('/api/multi-function/discover', methods=['POST'])
    def multi_function_discover():
        """Trigger function discovery for multi-function tracer"""
        try:
            data = request.get_json() or {}
            max_trace = data.get('max_trace', 50)
            priority = data.get('priority', 2)

            # Run discovery script
            import subprocess
            result = subprocess.run([
                'python3',
                'enhanced_skb_discoverer.py',
                '--output', 'enhanced_skb_functions.json',
                '--config', 'trace_config.json',
                '--max-trace', str(max_trace),
                '--priority', str(priority)
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Load generated config
                with open('trace_config.json', 'r') as f:
                    config = json.load(f)

                return jsonify({
                    'status': 'success',
                    'functions_discovered': len(config.get('functions', [])),
                    'output': result.stdout
                })
            else:
                return jsonify({
                    'status': 'error',
                    'error': result.stderr
                }), 500

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    print("[✓] Multi-function routes added:")
    print("    POST   /api/multi-function/start")
    print("    POST   /api/multi-function/stop")
    print("    GET    /api/multi-function/status")
    print("    GET    /api/multi-function/stats")
    print("    GET    /api/multi-function/config")
    print("    POST   /api/multi-function/discover")

    # WebSocket events (if socketio available):
    if socketio:
        print("[✓] Multi-function WebSocket events:")
        print("    Emit: multi_function_event")
        print("    Emit: multi_function_stats")
        print("    Emit: multi_function_status")


# Helper function to cleanup on app shutdown
def cleanup_multi_function():
    """Cleanup multi-function tracer on shutdown"""
    global multi_tracer
    with multi_tracer_lock:
        if multi_tracer:
            multi_tracer.stop()
            multi_tracer = None
