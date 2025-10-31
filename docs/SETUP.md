# CloudAuditor Setup Guide

This guide provides step-by-step instructions for setting up CloudAuditor CLI on Windows and Linux environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Windows Setup](#windows-setup)
- [Linux Setup](#linux-setup)
- [GCP Configuration](#gcp-configuration)
- [AWS Configuration](#aws-configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Python**: 3.8 or higher
- **Operating System**: Windows 10/11, Ubuntu 18.04+, CentOS 7+, or macOS 10.14+
- **Memory**: Minimum 2GB RAM
- **Disk Space**: At least 500MB free space

### Cloud Provider Access

- **GCP**: Service account with appropriate permissions
- **AWS**: IAM user with necessary policies (optional)

## Windows Setup

### 1. Install Python

#### Option A: Python.org Installer (Recommended)
1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run the installer and **check "Add Python to PATH"**
3. Verify installation:
   ```cmd
   python --version
   pip --version
   ```

#### Option B: Microsoft Store
1. Open Microsoft Store
2. Search for "Python 3.11" or latest version
3. Click "Install"

#### Option C: Chocolatey
```powershell
# Install Chocolatey (if not already installed)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Python
choco install python
```

### 2. Clone the Repository

```cmd
git clone https://github.com/your-org/cloudauditor-cli.git
cd cloudauditor-cli
```

### 3. Create Virtual Environment

```cmd
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Verify activation (you should see (venv) in your prompt)
```

### 4. Install Dependencies

```cmd
# Upgrade pip
python -m pip install --upgrade pip

# Install core dependencies
pip install -r requirements.txt

# Install GCP dependencies (if not already in requirements.txt)
pip install google-cloud-storage google-cloud-compute google-cloud-logging google-cloud-iam google-cloud-bigquery google-cloud-dataproc

# Install AWS dependencies (optional)
pip install boto3
```

### 5. Verify Installation

```cmd
# Test the installation
python cloudauditor/main.py --version

# Test GCP scanner with mock data
python cloudauditor/main.py scan gcp --profile test-project --output json

# Test AWS scanner with mock data
python cloudauditor/main.py scan aws --profile test-profile --output json
```

## Linux Setup

### 1. Install Python

#### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip python3-venv

# Verify installation
python3 --version
pip3 --version
```

#### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL 8+
sudo dnf install python3 python3-pip

# CentOS/RHEL 7
sudo yum install python3 python3-pip

# Verify installation
python3 --version
pip3 --version
```

#### Arch Linux
```bash
sudo pacman -S python python-pip
```

### 2. Clone the Repository

```bash
git clone https://github.com/your-org/cloudauditor-cli.git
cd cloudauditor-cli
```

### 3. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Verify activation (you should see (venv) in your prompt)
```

### 4. Install Dependencies

```bash
# Upgrade pip
python -m pip install --upgrade pip

# Install core dependencies
pip install -r requirements.txt

# Install GCP dependencies
pip install google-cloud-storage google-cloud-compute google-cloud-logging google-cloud-iam google-cloud-bigquery google-cloud-dataproc

# Install AWS dependencies (optional)
pip install boto3
```

### 5. Verify Installation

```bash
# Test the installation
python cloudauditor/main.py --version

# Test GCP scanner with mock data
python cloudauditor/main.py scan gcp --profile test-project --output json

# Test AWS scanner with mock data
python cloudauditor/main.py scan aws --profile test-profile --output json
```

## GCP Configuration

### 1. Create Service Account

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to **IAM & Admin** > **Service Accounts**
3. Click **Create Service Account**
4. Fill in details:
   - **Name**: `cloudauditor-service-account`
   - **Description**: `Service account for CloudAuditor security scanning`
5. Click **Create and Continue**

### 2. Assign Required Roles

Assign these roles to your service account:

- **Viewer** (basic read access)
- **Security Center Admin** (for security findings)
- **Logging Viewer** (for audit logs)
- **Monitoring Viewer** (for metrics)
- **Storage Object Viewer** (for bucket analysis)
- **BigQuery Data Viewer** (for dataset analysis)
- **Compute Instance Admin** (for VM analysis)

### 3. Create and Download Key

1. Click on your service account
2. Go to **Keys** tab
3. Click **Add Key** > **Create new key**
4. Choose **JSON** format
5. Download the key file
6. **Important**: Keep this file secure and never commit it to version control

### 4. Set Environment Variables

#### Windows (Command Prompt)
```cmd
set GOOGLE_APPLICATION_CREDENTIALS=C:\path\to\your\service-account-key.json
set GOOGLE_CLOUD_PROJECT=your-project-id
```

#### Windows (PowerShell)
```powershell
$env:GOOGLE_APPLICATION_CREDENTIALS="C:\path\to\your\service-account-key.json"
$env:GOOGLE_CLOUD_PROJECT="your-project-id"
```

#### Linux/macOS
```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/service-account-key.json"
export GOOGLE_CLOUD_PROJECT="your-project-id"

# Add to ~/.bashrc or ~/.zshrc for persistence
echo 'export GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/service-account-key.json"' >> ~/.bashrc
echo 'export GOOGLE_CLOUD_PROJECT="your-project-id"' >> ~/.bashrc
source ~/.bashrc
```

### 5. Test GCP Connection

```bash
# Test with real GCP APIs
python cloudauditor/main.py scan gcp --profile your-project-id --real --output json
```

## AWS Configuration (Optional)

### 1. Configure AWS Credentials

#### Option A: AWS CLI
```bash
# Install AWS CLI
pip install awscli

# Configure credentials
aws configure
```

#### Option B: Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

#### Option C: Credentials File
Create `~/.aws/credentials`:
```ini
[default]
aws_access_key_id = your-access-key
aws_secret_access_key = your-secret-key
region = us-east-1
```

### 2. Test AWS Connection

```bash
# Test with real AWS APIs
python cloudauditor/main.py scan aws --profile default --real --output json
```

## Verification

### 1. Run Mock Scans

```bash
# GCP mock scan
python cloudauditor/main.py scan gcp --profile test-project --output json

# AWS mock scan
python cloudauditor/main.py scan aws --profile test-profile --output json
```

### 2. Run Real Scans (with credentials)

```bash
# GCP real scan
python cloudauditor/main.py scan gcp --profile your-project-id --real --output json

# AWS real scan
python cloudauditor/main.py scan aws --profile your-profile --real --output json
```

### 3. Check Output Formats

```bash
# JSON output
python cloudauditor/main.py scan gcp --profile test-project --output json --output-file results.json

# Markdown output
python cloudauditor/main.py scan gcp --profile test-project --output markdown --output-file results.md

# HTML output
python cloudauditor/main.py scan gcp --profile test-project --output html --output-file results.html
```

## Troubleshooting

### Common Issues

#### 1. Python Not Found
```bash
# Windows
python --version
# If not found, reinstall Python with "Add to PATH" checked

# Linux
python3 --version
# If not found, install python3
sudo apt install python3  # Ubuntu/Debian
```

#### 2. Permission Denied (Linux/macOS)
```bash
# Make scripts executable
chmod +x cloudauditor/main.py

# Or run with python
python cloudauditor/main.py --version
```

#### 3. Module Not Found
```bash
# Ensure virtual environment is activated
# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

#### 4. GCP Authentication Issues
```bash
# Check environment variables
echo $GOOGLE_APPLICATION_CREDENTIALS
echo $GOOGLE_CLOUD_PROJECT

# Test GCP authentication
gcloud auth application-default print-access-token
```

#### 5. AWS Authentication Issues
```bash
# Check AWS configuration
aws sts get-caller-identity

# Verify credentials file
cat ~/.aws/credentials
```

### Logging and Debugging

```bash
# Enable verbose logging
python cloudauditor/main.py scan gcp --profile test-project --verbose

# Check log files
# Windows
type %USERPROFILE%\.cloudauditor\logs\*.log

# Linux/macOS
cat ~/.cloudauditor/logs/*.log
```

### Performance Issues

```bash
# Run with limited scope
python cloudauditor/main.py scan gcp --profile test-project --region us-east1

# Use mock data for testing
python cloudauditor/main.py scan gcp --profile test-project
```

## Next Steps

1. **Configure Notifications**: Set up email or Slack notifications for critical findings
2. **Schedule Scans**: Use cron (Linux) or Task Scheduler (Windows) for regular scans
3. **Customize Checks**: Modify checker classes to add organization-specific rules
4. **Integration**: Integrate with CI/CD pipelines for automated security scanning

## Support

For additional help:
- Check the [README.md](README.md) for usage examples
- Review the [API documentation](docs/API.md)
- Open an issue on GitHub for bugs or feature requests
