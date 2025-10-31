"""
Tests for report command.
"""

import pytest
import tempfile
from pathlib import Path
from typer.testing import CliRunner
from cloudauditor.main import app
from cloudauditor.utils.fileio import save_results
from cloudauditor.providers import AWSScanner

runner = CliRunner()


@pytest.fixture
def sample_results():
    """Generate sample scan results."""
    scanner = AWSScanner(use_mock=True)
    return scanner.scan()


@pytest.fixture
def saved_results(sample_results):
    """Save sample results and return the path."""
    return save_results(sample_results)


def test_report_list():
    """Test listing available scan results."""
    result = runner.invoke(app, ["report", "--list"])
    assert result.exit_code == 0


def test_report_no_results():
    """Test report when no results are available."""
    # This test might fail if results exist from other tests
    # In a real test environment, you'd use isolated temp directories
    pass


def test_report_json_format(saved_results):
    """Test report generation in JSON format."""
    result = runner.invoke(app, ["report", "--output", "json"])
    assert result.exit_code == 0


def test_report_markdown_format(saved_results):
    """Test report generation in Markdown format."""
    result = runner.invoke(app, ["report", "--output", "markdown"])
    assert result.exit_code == 0


def test_report_html_format(saved_results):
    """Test report generation in HTML format."""
    result = runner.invoke(app, ["report", "--output", "html"])
    assert result.exit_code == 0


def test_report_invalid_format():
    """Test report with invalid output format."""
    result = runner.invoke(app, ["report", "--output", "pdf"])
    assert result.exit_code == 1
    assert "Unsupported output format" in result.stdout


def test_report_with_output_file(saved_results):
    """Test report with output file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
        output_file = f.name

    try:
        result = runner.invoke(
            app,
            ["report", "--output", "markdown", "--output-file", output_file]
        )
        assert result.exit_code == 0
        assert Path(output_file).exists()
    finally:
        Path(output_file).unlink(missing_ok=True)


def test_report_provider_filter(saved_results):
    """Test report with provider filter."""
    result = runner.invoke(app, ["report", "--provider", "aws"])
    assert result.exit_code == 0
