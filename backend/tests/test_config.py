"""
Tests for configuration module
"""

import pytest
import os
from config import Config, DevelopmentConfig, TestingConfig, StagingConfig, get_config


class TestConfig:
    """Test configuration loading and validation"""

    def test_default_config(self):
        """Test default configuration values"""
        config = Config()
        assert config.BACKEND_PORT == 5000
        assert config.TRACE_BUFFER_SIZE > 0

    def test_development_config(self):
        """Test development configuration"""
        config = DevelopmentConfig()
        assert config.DEBUG is True
        assert config.LOG_LEVEL == 'DEBUG'
        assert config.is_development() is True

    def test_testing_config(self):
        """Test testing configuration"""
        config = TestingConfig()
        assert config.DEBUG is False
        assert config.ENABLE_EBPF is False
        assert config.MOCK_EBPF is True
        assert config.is_testing() is True

    def test_staging_config(self):
        """Test staging configuration"""
        config = StagingConfig()
        assert config.DEBUG is False
        assert config.is_production() is True

    def test_get_config_by_name(self):
        """Test getting config by environment name"""
        dev_config = get_config('development')
        assert isinstance(dev_config, type)
        assert issubclass(dev_config, Config)

        test_config = get_config('testing')
        assert issubclass(test_config, Config)

    def test_config_validation(self):
        """Test configuration validation"""
        config = Config()
        assert config.validate() is True

    def test_invalid_port(self, monkeypatch):
        """Test validation with invalid port"""
        monkeypatch.setenv('BACKEND_PORT', '99999')
        config = Config()
        assert config.validate() is False

    def test_database_path(self):
        """Test database path resolution"""
        config = Config()
        db_path = config.get_database_path()
        assert db_path.parent.exists()

    def test_log_file_path(self):
        """Test log file path resolution"""
        config = Config()
        log_path = config.get_log_file_path()
        assert log_path.parent.exists()
