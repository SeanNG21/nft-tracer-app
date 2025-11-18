"""
NFT Tracer Configuration Module
Loads configuration from environment variables
"""

import os
from typing import Optional
from pathlib import Path


class Config:
    """Base configuration class"""

    # Application
    ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')

    # Backend
    BACKEND_HOST = os.getenv('BACKEND_HOST', '0.0.0.0')
    BACKEND_PORT = int(os.getenv('BACKEND_PORT', '5000'))
    DATABASE_PATH = os.getenv('DATABASE_PATH', './nft_tracer.db')

    # eBPF and Tracing
    ENABLE_EBPF = os.getenv('ENABLE_EBPF', 'True').lower() in ('true', '1', 't')
    ENABLE_REALTIME = os.getenv('ENABLE_REALTIME', 'True').lower() in ('true', '1', 't')
    TRACE_BUFFER_SIZE = int(os.getenv('TRACE_BUFFER_SIZE', '1024'))

    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', './logs/nft-tracer.log')

    # Security
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*')
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-change-in-production')

    # Performance
    MAX_PACKET_BUFFER = int(os.getenv('MAX_PACKET_BUFFER', '10000'))
    CLEANUP_INTERVAL = int(os.getenv('CLEANUP_INTERVAL', '300'))

    @classmethod
    def is_development(cls) -> bool:
        """Check if running in development mode"""
        return cls.ENV == 'development'

    @classmethod
    def is_testing(cls) -> bool:
        """Check if running in testing mode"""
        return cls.ENV in ('testing', 'test')

    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production mode"""
        return cls.ENV == 'production'

    @classmethod
    def get_log_file_path(cls) -> Path:
        """Get absolute path for log file"""
        log_file = Path(cls.LOG_FILE)
        if not log_file.is_absolute():
            log_file = Path.cwd() / log_file

        # Create log directory if it doesn't exist
        log_file.parent.mkdir(parents=True, exist_ok=True)

        return log_file

    @classmethod
    def get_database_path(cls) -> Path:
        """Get absolute path for database file"""
        db_path = Path(cls.DATABASE_PATH)
        if not db_path.is_absolute():
            db_path = Path.cwd() / db_path

        # Create database directory if it doesn't exist
        db_path.parent.mkdir(parents=True, exist_ok=True)

        return db_path

    @classmethod
    def validate(cls) -> bool:
        """Validate configuration"""
        errors = []

        # Check port range
        if not (1 <= cls.BACKEND_PORT <= 65535):
            errors.append(f"Invalid BACKEND_PORT: {cls.BACKEND_PORT}")

        # Check buffer sizes
        if cls.TRACE_BUFFER_SIZE < 1:
            errors.append(f"Invalid TRACE_BUFFER_SIZE: {cls.TRACE_BUFFER_SIZE}")

        if cls.MAX_PACKET_BUFFER < 1:
            errors.append(f"Invalid MAX_PACKET_BUFFER: {cls.MAX_PACKET_BUFFER}")

        # Warn if using default secret key in production
        if cls.is_production() and 'change' in cls.SECRET_KEY.lower():
            errors.append("WARNING: Using default SECRET_KEY in production!")

        if errors:
            for error in errors:
                print(f"[CONFIG ERROR] {error}")
            return False

        return True

    @classmethod
    def print_config(cls):
        """Print current configuration (for debugging)"""
        print("=" * 50)
        print("NFT Tracer Configuration")
        print("=" * 50)
        print(f"Environment:     {cls.ENV}")
        print(f"Debug Mode:      {cls.DEBUG}")
        print(f"Backend Host:    {cls.BACKEND_HOST}")
        print(f"Backend Port:    {cls.BACKEND_PORT}")
        print(f"Database:        {cls.get_database_path()}")
        print(f"eBPF Enabled:    {cls.ENABLE_EBPF}")
        print(f"Realtime:        {cls.ENABLE_REALTIME}")
        print(f"Log Level:       {cls.LOG_LEVEL}")
        print(f"Log File:        {cls.get_log_file_path()}")
        print("=" * 50)


class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'


class TestingConfig(Config):
    """Testing environment configuration"""
    ENV = 'testing'
    DEBUG = False
    ENABLE_EBPF = False
    MOCK_EBPF = True
    DATABASE_PATH = ':memory:'  # Use in-memory database for tests


class StagingConfig(Config):
    """Staging environment configuration"""
    ENV = 'production'
    DEBUG = False
    LOG_LEVEL = 'INFO'


# Configuration dictionary
config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'production': StagingConfig,  # Use staging config for production
}


def get_config(env_name: Optional[str] = None) -> Config:
    """Get configuration object based on environment name"""
    if env_name is None:
        env_name = os.getenv('FLASK_ENV', 'development')

    config_class = config_by_name.get(env_name, DevelopmentConfig)
    return config_class


if __name__ == '__main__':
    # Test configuration loading
    config = get_config()
    config.print_config()
    config.validate()
