#!/bin/bash

echo "CloudAuditor Linux Setup Script"
echo "==============================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed"
    echo "Please install Python3:"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
    echo "  CentOS/RHEL: sudo yum install python3 python3-pip"
    echo "  Fedora: sudo dnf install python3 python3-pip"
    exit 1
fi

echo "Python found: $(python3 --version)"

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "ERROR: pip3 is not available"
    echo "Please install pip3:"
    echo "  Ubuntu/Debian: sudo apt install python3-pip"
    echo "  CentOS/RHEL: sudo yum install python3-pip"
    echo "  Fedora: sudo dnf install python3-pip"
    exit 1
fi

echo "pip found: $(pip3 --version)"

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv venv
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to create virtual environment"
    exit 1
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
python -m pip install --upgrade pip

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies"
    exit 1
fi

# Install CloudAuditor package in development mode
echo ""
echo "Installing CloudAuditor package..."
pip install -e .
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install CloudAuditor package"
    exit 1
fi

# Install GCP dependencies
echo ""
echo "Installing GCP dependencies..."
pip install google-cloud-storage google-cloud-compute google-cloud-logging google-cloud-iam google-cloud-bigquery google-cloud-dataproc

# Install AWS dependencies (optional)
echo ""
echo "Installing AWS dependencies..."
pip install boto3

# Test installation
echo ""
echo "Testing installation..."
python cloudauditor/main.py --version
if [ $? -ne 0 ]; then
    echo "ERROR: Installation test failed"
    exit 1
fi

echo ""
echo "================================"
echo "Setup completed successfully!"
echo "================================"
echo ""
echo "To use CloudAuditor:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Run scans: python cloudauditor/main.py scan gcp --profile your-project-id"
echo ""
echo "For GCP setup:"
echo "1. Set GOOGLE_APPLICATION_CREDENTIALS environment variable"
echo "2. Set GOOGLE_CLOUD_PROJECT environment variable"
echo "3. Use --real flag for actual GCP API calls"
echo ""
echo "Example:"
echo "  export GOOGLE_APPLICATION_CREDENTIALS=\"/path/to/service-account-key.json\""
echo "  export GOOGLE_CLOUD_PROJECT=\"your-project-id\""
echo "  python cloudauditor/main.py scan gcp --profile your-project-id --real"
