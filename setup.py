"""
Setup script for CloudAuditor CLI.

For modern installations, prefer using pyproject.toml:
    pip install .

This setup.py is provided for backwards compatibility.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="cloudauditor",
    version="1.0.0",
    author="CloudAuditor Team",
    author_email="team@cloudauditor.example.com",
    description="Production-ready CLI tool for scanning AWS and GCP environments for CIS benchmark compliance",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cloudauditor",
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={
        "cloudauditor": ["data/*.json"],
    },
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "typer>=0.9.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "aws": ["boto3>=1.26.0"],
        "gcp": [
            "google-cloud-storage>=2.10.0",
            "google-cloud-compute>=1.14.0",
            "google-cloud-logging>=3.5.0",
            "google-cloud-iam>=2.12.0",
        ],
        "ai": [
            "openai>=1.0.0",
            "python-dotenv>=1.0.0",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cloudauditor=cloudauditor.main:app",
        ],
    },
)
