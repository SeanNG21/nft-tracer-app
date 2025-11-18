#!/usr/bin/env python3
"""
Mock Web Server for NFT Tracer Testing
Generates HTTP traffic for testing packet tracing
"""

from flask import Flask, jsonify, request, render_template_string
import random
import time
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Simple HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Mock Web Server</title>
    <style>
        body { font-family: Arial; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .endpoint { padding: 10px; margin: 10px 0; background: #f0f0f0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Mock Web Server</h1>
        <p>This server generates various HTTP traffic patterns for NFT Tracer testing.</p>

        <h2>Available Endpoints:</h2>
        <div class="endpoint">
            <strong>GET /</strong> - This page
        </div>
        <div class="endpoint">
            <strong>GET /api/data</strong> - Returns JSON data
        </div>
        <div class="endpoint">
            <strong>GET /api/slow</strong> - Slow response (simulates heavy processing)
        </div>
        <div class="endpoint">
            <strong>POST /api/upload</strong> - Accepts POST data
        </div>
        <div class="endpoint">
            <strong>GET /api/random</strong> - Random status codes
        </div>
        <div class="endpoint">
            <strong>GET /api/large</strong> - Large response payload
        </div>
        <div class="endpoint">
            <strong>GET /health</strong> - Health check
        </div>

        <h2>Statistics:</h2>
        <p>Requests served: <strong id="count">{{ request_count }}</strong></p>
    </div>
</body>
</html>
"""

# Track requests
request_count = 0

@app.before_request
def before_request():
    global request_count
    request_count += 1
    logging.info(f"Request {request_count}: {request.method} {request.path} from {request.remote_addr}")

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, request_count=request_count)

@app.route('/api/data')
def api_data():
    """Returns simple JSON data"""
    return jsonify({
        'status': 'success',
        'timestamp': time.time(),
        'data': {
            'message': 'Hello from mock server',
            'request_count': request_count,
            'random_value': random.randint(1, 1000)
        }
    })

@app.route('/api/slow')
def api_slow():
    """Simulates slow endpoint"""
    delay = random.uniform(1, 3)
    time.sleep(delay)
    return jsonify({
        'status': 'success',
        'message': f'Processed after {delay:.2f} seconds',
        'timestamp': time.time()
    })

@app.route('/api/upload', methods=['POST'])
def api_upload():
    """Accepts POST data"""
    data = request.get_json() or {}
    return jsonify({
        'status': 'success',
        'message': 'Data received',
        'received_data': data,
        'size': len(str(data))
    }), 201

@app.route('/api/random')
def api_random():
    """Returns random status codes"""
    status_codes = [200, 200, 200, 400, 404, 500, 503]  # More 200s
    status = random.choice(status_codes)
    return jsonify({
        'status': status,
        'message': f'Random status code: {status}'
    }), status

@app.route('/api/large')
def api_large():
    """Returns large payload"""
    large_data = {
        'items': [
            {
                'id': i,
                'name': f'Item {i}',
                'description': f'This is a description for item {i}' * 10,
                'data': [random.random() for _ in range(100)]
            }
            for i in range(100)
        ]
    }
    return jsonify(large_data)

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'uptime': time.time(),
        'requests': request_count
    })

@app.route('/api/error')
def api_error():
    """Simulates server error"""
    return jsonify({
        'status': 'error',
        'message': 'Simulated server error'
    }), 500

if __name__ == '__main__':
    print("🌐 Starting Mock Web Server on port 8080")
    print("📊 This server will generate HTTP traffic for NFT Tracer testing")
    app.run(host='0.0.0.0', port=8080, debug=False)
