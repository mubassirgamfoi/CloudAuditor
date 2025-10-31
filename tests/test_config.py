"""
Tests for config command.
"""

import pytest
import tempfile
from pathlib import Path
from typer.testing import CliRunner
from cloudauditor.main import app
from cloudauditor.utils.fileio import load_config, save_config

runner = CliRunner()


def test_config_show_empty():
    """Test showing config when no config exists."""
    # First reset config
    runner.invoke(app, ["config", "--reset"])

    result = runner.invoke(app, ["config", "--show"])
    assert result.exit_code == 0
    assert "No configuration found" in result.stdout or "Configuration" in result.stdout


def test_config_set_aws():
    """Test setting AWS configuration."""
    result = runner.invoke(
        app,
        ["config", "--provider", "aws", "--profile", "test-profile", "--region", "us-west-2"]
    )
    assert result.exit_code == 0
    assert "test-profile" in result.stdout
    assert "us-west-2" in result.stdout


def test_config_set_gcp():
    """Test setting GCP configuration."""
    result = runner.invoke(
        app,
        ["config", "--provider", "gcp", "--profile", "test-project", "--region", "us-central1"]
    )
    assert result.exit_code == 0
    assert "test-project" in result.stdout
    assert "us-central1" in result.stdout


def test_config_set_custom_key():
    """Test setting custom configuration key."""
    result = runner.invoke(
        app,
        ["config", "--set", "test_key=test_value"]
    )
    assert result.exit_code == 0

    # Verify it was saved
    config = load_config()
    assert "test_key" in config
    assert config["test_key"] == "test_value"


def test_config_set_invalid_key_format():
    """Test setting config with invalid key format."""
    result = runner.invoke(
        app,
        ["config", "--set", "invalid_format"]
    )
    assert result.exit_code == 1
    assert "Invalid format" in result.stdout


def test_config_invalid_provider():
    """Test config with invalid provider."""
    result = runner.invoke(
        app,
        ["config", "--provider", "azure"]
    )
    assert result.exit_code == 1
    assert "Unsupported provider" in result.stdout


def test_config_show_after_set():
    """Test showing config after setting values."""
    # Set some config
    runner.invoke(
        app,
        ["config", "--provider", "aws", "--profile", "test", "--region", "us-east-1"]
    )

    # Show config
    result = runner.invoke(app, ["config", "--show"])
    assert result.exit_code == 0
    assert "Configuration" in result.stdout or "AWS" in result.stdout


def test_config_reset():
    """Test resetting configuration."""
    # Set some config first
    runner.invoke(
        app,
        ["config", "--provider", "aws", "--profile", "test"]
    )

    # Reset
    result = runner.invoke(app, ["config", "--reset"])
    assert result.exit_code == 0

    # Verify it's empty
    config = load_config()
    assert config == {}


def test_config_file_operations():
    """Test config file save and load operations."""
    test_config = {
        "aws": {
            "profile": "test-profile",
            "region": "us-east-1"
        }
    }

    # Save config
    save_config(test_config)

    # Load config
    loaded_config = load_config()

    assert "aws" in loaded_config
    assert loaded_config["aws"]["profile"] == "test-profile"
    assert loaded_config["aws"]["region"] == "us-east-1"
