#!/usr/bin/env python3
"""
Mock API Service for NFT Tracer Testing
Simulates a RESTful API service with various endpoints
"""

from flask import Flask, jsonify, request
import random
import time
import uuid

app = Flask(__name__)

# In-memory storage
users = {}
posts = {}

@app.route('/api/v1/users', methods=['GET'])
def get_users():
    """Get all users"""
    return jsonify({
        'status': 'success',
        'count': len(users),
        'users': list(users.values())
    })

@app.route('/api/v1/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """Get specific user"""
    if user_id not in users:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'status': 'success',
        'user': users[user_id]
    })

@app.route('/api/v1/users', methods=['POST'])
def create_user():
    """Create new user"""
    data = request.get_json()
    user_id = str(uuid.uuid4())

    user = {
        'id': user_id,
        'name': data.get('name', f'User{len(users)}'),
        'email': data.get('email', f'user{len(users)}@test.com'),
        'created_at': time.time()
    }

    users[user_id] = user

    return jsonify({
        'status': 'success',
        'user': user
    }), 201

@app.route('/api/v1/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    """Update user"""
    if user_id not in users:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    users[user_id].update(data)
    users[user_id]['updated_at'] = time.time()

    return jsonify({
        'status': 'success',
        'user': users[user_id]
    })

@app.route('/api/v1/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete user"""
    if user_id not in users:
        return jsonify({'error': 'User not found'}), 404

    del users[user_id]

    return jsonify({
        'status': 'success',
        'message': 'User deleted'
    }), 204

@app.route('/api/v1/posts', methods=['GET'])
def get_posts():
    """Get all posts"""
    return jsonify({
        'status': 'success',
        'count': len(posts),
        'posts': list(posts.values())
    })

@app.route('/api/v1/posts', methods=['POST'])
def create_post():
    """Create new post"""
    data = request.get_json()
    post_id = str(uuid.uuid4())

    post = {
        'id': post_id,
        'title': data.get('title', f'Post {len(posts)}'),
        'content': data.get('content', 'Sample content'),
        'author': data.get('author', 'Anonymous'),
        'created_at': time.time()
    }

    posts[post_id] = post

    return jsonify({
        'status': 'success',
        'post': post
    }), 201

@app.route('/api/v1/search')
def search():
    """Search endpoint"""
    query = request.args.get('q', '')
    category = request.args.get('category', 'all')

    # Simulate search delay
    time.sleep(random.uniform(0.1, 0.5))

    results = [
        {
            'id': i,
            'title': f'Result {i} for "{query}"',
            'category': category,
            'relevance': random.uniform(0.5, 1.0)
        }
        for i in range(random.randint(0, 20))
    ]

    return jsonify({
        'status': 'success',
        'query': query,
        'results': results
    })

@app.route('/api/v1/stats')
def stats():
    """System statistics"""
    return jsonify({
        'status': 'success',
        'stats': {
            'users': len(users),
            'posts': len(posts),
            'uptime': time.time(),
            'memory_usage': random.randint(100, 500),
            'cpu_usage': random.uniform(10, 80)
        }
    })

@app.route('/health')
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'service': 'mock-api',
        'timestamp': time.time()
    })

if __name__ == '__main__':
    print("🚀 Starting Mock API Service on port 8081")
    print("📡 RESTful API endpoints ready for testing")
    app.run(host='0.0.0.0', port=8081, debug=False)
