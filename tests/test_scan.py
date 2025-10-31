"""
Tests for scan command.
"""

import pytest
from typer.testing import CliRunner
from cloudauditor.main import app
from cloudauditor.providers import AWSScanner, GCPScanner

runner = CliRunner()


def test_scan_aws_mock():
    """Test AWS scan with mock data."""
    result = runner.invoke(app, ["scan", "aws", "--output", "json"])
    assert result.exit_code in [0, 1]  # May exit with 1 if findings exist
    assert "AWS" in result.stdout or "aws" in result.stdout


def test_scan_gcp_mock():
    """Test GCP scan with mock data."""
    result = runner.invoke(app, ["scan", "gcp", "--output", "json"])
    assert result.exit_code in [0, 1]
    assert "GCP" in result.stdout or "gcp" in result.stdout


def test_scan_invalid_provider():
    """Test scan with invalid provider."""
    result = runner.invoke(app, ["scan", "azure"])
    assert result.exit_code == 1
    assert "Unsupported provider" in result.stdout


def test_scan_invalid_output_format():
    """Test scan with invalid output format."""
    result = runner.invoke(app, ["scan", "aws", "--output", "xml"])
    assert result.exit_code == 1
    assert "Unsupported output format" in result.stdout


def test_aws_scanner_initialization():
    """Test AWS scanner initialization."""
    scanner = AWSScanner(profile="test", region="us-west-2", use_mock=True)
    assert scanner.profile == "test"
    assert scanner.region == "us-west-2"
    assert scanner.use_mock is True


def test_aws_scanner_scan():
    """Test AWS scanner scan method."""
    scanner = AWSScanner(use_mock=True)
    results = scanner.scan()

    assert "provider" in results
    assert results["provider"] == "aws"
    assert "findings" in results
    assert "summary" in results
    assert isinstance(results["findings"], list)


def test_gcp_scanner_initialization():
    """Test GCP scanner initialization."""
    scanner = GCPScanner(profile="test-project", region="us-central1", use_mock=True)
    assert scanner.profile == "test-project"
    assert scanner.region == "us-central1"
    assert scanner.use_mock is True


def test_gcp_scanner_scan():
    """Test GCP scanner scan method."""
    scanner = GCPScanner(use_mock=True)
    results = scanner.scan()

    assert "provider" in results
    assert results["provider"] == "gcp"
    assert "findings" in results
    assert "summary" in results
    assert isinstance(results["findings"], list)


def test_scan_with_verbose():
    """Test scan command with verbose flag."""
    result = runner.invoke(app, ["scan", "aws", "--verbose"])
    assert result.exit_code in [0, 1]


def test_scan_summary_calculation():
    """Test that scan summary is calculated correctly."""
    scanner = AWSScanner(use_mock=True)
    results = scanner.scan()

    summary = results["summary"]
    findings = results["findings"]

    assert summary["total_checks"] == len(findings)

    # Count manually
    passed = sum(1 for f in findings if f.get("status") == "PASSED")
    failed = sum(1 for f in findings if f.get("status") == "FAILED")

    assert summary["passed"] == passed
    assert summary["failed"] == failed
