"""
Authentication utilities for NFT Tracer
"""
from functools import wraps
from datetime import datetime, timedelta
from flask import request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from models import User, db


def register_user(username: str, email: str, password: str) -> tuple:
    """
    Register a new user

    Args:
        username: Username
        email: Email address
        password: Plain text password

    Returns:
        tuple: (user, error_message) where error_message is None if successful
    """
    # Validate input
    if not username or not email or not password:
        return None, "Username, email and password are required"

    if len(username) < 3:
        return None, "Username must be at least 3 characters"

    if len(password) < 6:
        return None, "Password must be at least 6 characters"

    # Check if user already exists
    if User.query.filter_by(username=username).first():
        return None, "Username already exists"

    if User.query.filter_by(email=email).first():
        return None, "Email already exists"

    # Create new user
    try:
        user = User(username=username, email=email)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        return user, None
    except Exception as e:
        db.session.rollback()
        return None, f"Database error: {str(e)}"


def authenticate_user(username: str, password: str) -> tuple:
    """
    Authenticate user credentials

    Args:
        username: Username
        password: Plain text password

    Returns:
        tuple: (user, error_message) where error_message is None if successful
    """
    user = User.query.filter_by(username=username).first()

    if not user:
        return None, "Invalid username or password"

    if not user.is_active:
        return None, "User account is inactive"

    if not user.check_password(password):
        return None, "Invalid username or password"

    # Update last login
    try:
        user.last_login = datetime.utcnow()
        db.session.commit()
    except:
        db.session.rollback()

    return user, None


def create_tokens(user_id: int) -> dict:
    """
    Create JWT access and refresh tokens

    Args:
        user_id: User ID

    Returns:
        dict: {access_token, refresh_token}
    """
    access_token = create_access_token(
        identity=user_id,
        expires_delta=timedelta(hours=24)
    )
    refresh_token = create_refresh_token(
        identity=user_id,
        expires_delta=timedelta(days=30)
    )

    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': 86400  # 24 hours in seconds
    }


def token_required(fn):
    """
    Decorator to require JWT token for route
    """
    @wraps(fn)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 401

        # Add user to kwargs
        return fn(*args, user=user, **kwargs)

    return decorated_function


def optional_token(fn):
    """
    Decorator for optional JWT token (allow anonymous but provide user if token valid)
    """
    @wraps(fn)
    def decorated_function(*args, **kwargs):
        # Check for token in header
        auth_header = request.headers.get('Authorization', '')
        user = None

        if auth_header.startswith('Bearer '):
            try:
                from flask_jwt_extended import verify_jwt_in_request
                verify_jwt_in_request()
                current_user_id = get_jwt_identity()
                user = User.query.get(current_user_id)
            except:
                pass  # Token is invalid or missing, continue as anonymous

        return fn(*args, user=user, **kwargs)

    return decorated_function
