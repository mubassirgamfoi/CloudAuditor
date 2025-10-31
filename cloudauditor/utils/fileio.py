"""
File I/O utilities for CloudAuditor.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime


def get_config_dir() -> Path:
    """
    Get the CloudAuditor configuration directory.

    Returns:
        Path to ~/.cloudauditor directory
    """
    config_dir = Path.home() / ".cloudauditor"
    config_dir.mkdir(exist_ok=True)
    return config_dir


def get_results_dir() -> Path:
    """
    Get the directory for storing scan results.

    Returns:
        Path to ~/.cloudauditor/results directory
    """
    results_dir = get_config_dir() / "results"
    results_dir.mkdir(exist_ok=True)
    return results_dir


def save_results(data: Dict[str, Any], filename: Optional[str] = None) -> Path:
    """
    Save scan results to a JSON file.

    Args:
        data: Scan results to save
        filename: Optional custom filename

    Returns:
        Path to the saved file
    """
    results_dir = get_results_dir()

    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        provider = data.get('provider', 'unknown')
        filename = f"scan_{provider}_{timestamp}.json"

    filepath = results_dir / filename

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)

    # Also save as "latest.json" for easy access
    latest_path = results_dir / f"latest_{data.get('provider', 'unknown')}.json"
    with open(latest_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)

    return filepath


def load_results(filename: Optional[str] = None, provider: Optional[str] = None) -> Dict[str, Any]:
    """
    Load scan results from a JSON file.

    Args:
        filename: Optional specific filename to load
        provider: If filename not provided, load latest results for this provider

    Returns:
        Scan results dictionary

    Raises:
        FileNotFoundError: If the specified file doesn't exist
    """
    results_dir = get_results_dir()

    if filename:
        filepath = results_dir / filename
    elif provider:
        filepath = results_dir / f"latest_{provider}.json"
    else:
        # Find the most recent results file
        json_files = list(results_dir.glob("scan_*.json"))
        if not json_files:
            raise FileNotFoundError("No scan results found")
        filepath = max(json_files, key=lambda p: p.stat().st_mtime)

    if not filepath.exists():
        raise FileNotFoundError(f"Results file not found: {filepath}")

    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_config(config: Dict[str, Any]) -> None:
    """
    Save configuration to ~/.cloudauditor/config.yaml

    Args:
        config: Configuration dictionary to save
    """
    config_file = get_config_dir() / "config.yaml"

    with open(config_file, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, default_flow_style=False)


def load_config() -> Dict[str, Any]:
    """
    Load configuration from ~/.cloudauditor/config.yaml

    Returns:
        Configuration dictionary (empty dict if file doesn't exist)
    """
    config_file = get_config_dir() / "config.yaml"

    if not config_file.exists():
        return {}

    with open(config_file, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
        return config if config else {}


def save_output(content: str, filepath: Path, output_format: str) -> Path:
    """
    Save formatted output to a file. If no extension is provided, append one
    based on output_format.

    Args:
        content: Content to save
        filepath: Path where to save the file
        output_format: Format type (json, markdown, html)

    Returns:
        Final file path written to (with extension applied if missing)
    """
    # Ensure extension exists
    if not filepath.suffix:
        ext = {
            'json': '.json',
            'markdown': '.md',
            'html': '.html',
        }.get(output_format.lower(), '')
        if ext:
            filepath = filepath.with_suffix(ext)

    # Ensure parent directory exists
    filepath.parent.mkdir(parents=True, exist_ok=True)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    return filepath


def list_results(provider: Optional[str] = None) -> list:
    """
    List all available scan results.

    Args:
        provider: Optional filter by provider

    Returns:
        List of result file paths
    """
    results_dir = get_results_dir()

    if provider:
        pattern = f"scan_{provider}_*.json"
    else:
        pattern = "scan_*.json"

    files = list(results_dir.glob(pattern))
    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)
