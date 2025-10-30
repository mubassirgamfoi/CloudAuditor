# CloudAuditor CLI

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A production-ready command-line tool for scanning AWS, GCP, and Azure environments for CIS benchmark compliance issues and security misconfigurations.

## 🚀 Quick Setup

### Windows
```cmd
# Run the automated setup script
scripts\setup_windows.bat

# Or use PowerShell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
```

### Linux/macOS
```bash
# Run the automated setup script
chmod +x scripts/setup_linux.sh
./scripts/setup_linux.sh
```

### Manual Setup
See [docs/SETUP.md](docs/SETUP.md) for detailed setup instructions for both Windows and Linux environments.

## Features

- **Multi-Cloud Support**: Scan AWS, GCP, Azure, and DigitalOcean environments
- **CIS Benchmark Compliance**:
  - **CIS Google Cloud Platform Foundation Benchmark v3.0.0** (8 service areas)
    - Identity and Access Management (IAM)
    - Logging and Monitoring (Cloud Audit Logging, Sinks, Metric Filters)
    - Networking (Default Network, Legacy Networks, DNSSEC, VPC Flow Logs)
    - Virtual Machines (Default Service Account, SSH Keys, OS Login, Shielded VM)
    - Storage (Cloud Storage Bucket Access, Uniform Bucket-Level Access)
    - Cloud SQL Database Services (MySQL, PostgreSQL, SQL Server configurations)
    - BigQuery (Dataset Access, CMEK, Data Classification)
    - Dataproc (CMEK, Cluster Security)
  - Full implementation of **CIS AWS Foundations Benchmark v6.0.0** (24 critical checks)
    - IAM security (root access, MFA, password policies, access key rotation)
    - Storage security (S3, RDS, EFS encryption and access controls)
    - Logging (CloudTrail, VPC Flow Logs, KMS key rotation)
    - Monitoring (AWS Security Hub)
    - Networking (Security Groups, IMDSv2)
  - Full implementation of **CIS AWS Compute Services Benchmark v1.1.0** (47 checks)
    - EC2 (AMI security, EBS encryption, instance hardening)
    - ECS (container security, privileged mode, secrets management)
    - Lambda (IAM permissions, code signing, runtime versions)
  - Full implementation of **CIS AWS Database Services Benchmark v1.0.0** (28 checks)
    - Aurora (encryption, SSL/TLS, audit logging, backups)
    - RDS (encryption, VPC, patching, monitoring)
    - DynamoDB (encryption, VPC endpoints, CloudTrail logging)
    - ElastiCache (encryption, VPC, authentication)
    - DocumentDB (encryption, TLS, audit logging)
    - Neptune (encryption, SSL/TLS, IAM authentication)
  - Full implementation of **CIS AWS End User Compute Services Benchmark v1.2.0** (6 checks)
    - WorkSpaces (IAM administration, MFA, volume encryption)
    - WorkSpaces Web (authentication, network restrictions)
    - WorkDocs (access controls, encryption at rest)
    - AppStream 2.0 (security groups, encryption, user access)
  - Full implementation of **CIS AWS Storage Services Benchmark v1.0.0** (56 checks)
    - AWS Backup (backup configuration, security, IAM policies)
    - Amazon EBS (volume encryption, snapshots, security groups, IAM)
    - Amazon EFS (file system encryption, VPC integration, access controls)
    - Amazon FSx (file cache encryption, S3 integration, Lustre client)
    - Amazon S3 (bucket security, storage classes, access controls)
    - AWS Elastic Disaster Recovery (configuration, replication, failover)
  - **CIS Microsoft Azure Foundations Benchmark v5.0.0** (7 service areas)
    - Analytics Services (Azure Databricks security, encryption, access controls)
    - Virtual Machines (encryption, network security, access controls, monitoring)
    - Identity and Access Management (security defaults, MFA, conditional access)
    - Logging and Monitoring (diagnostic settings, activity logs, Application Insights)
    - Networking (RDP/SSH access, NSG flow logs, Network Watcher, public IPs)
    - Security Services (Microsoft Defender for Cloud, Key Vault, Azure Bastion)
    - Storage Services (Azure Files, Blob Storage, encryption, secure transfer)
  - **CIS Microsoft Azure Storage Services Benchmark v1.0.0** (selected storage services)
    - Storage Accounts (public network access, default deny, secure transfer, TLS 1.2, shared key access, infra encryption)
    - Azure Blob Storage (soft delete for blobs/containers, versioning, immutability, anonymous access)
    - Azure Files (soft delete, SMB 3.1.1, AES-256-GCM channel encryption)
    - Queue Storage (SAS HTTPS-only, short expiry, stored access policies)
    - Backup vaults (soft delete, immutability, CMK, infra encryption, CRR/CSR)
    - Recovery Services vaults (soft delete, immutability, CMK, infra encryption, networking, CRR/CSR)
    - Elastic SAN (public network access, CMK on volume groups)
    - Azure NetApp Files (encryption key source set to CMK)
  - **CIS Microsoft Azure Database Services Benchmark v1.0.0** (selected database services)
  - **CIS DigitalOcean Foundations Benchmark v1.0.0** (foundational controls)
    - Account Access (Secure Sign-In, 2FA, SSH Keys audit, Team contact email)
    - API (Replace legacy tokens, least-privilege scopes, OAuth/Authorized apps)
    - Principle of Least Privilege (RBAC roles implemented)
    - Security History (regular reviews)
  - **CIS DigitalOcean Services Benchmark v1.0.0** (selected services)
    - Droplet (backups, firewall present/attached, OS upgrade/update, auditd, SSH key auth, unused keys)
    - Kubernetes (log forwarding, upgrade window, HA control plane)
    - Logging & Monitoring (security history monitored, metrics agent installed)
    - Spaces (access controls, keys, lifecycle policy, file listing, CDN, CORS, bucket destruction)
    - Volumes (LUKS on block storage)
    - Cosmos DB (selected networks, private endpoints, Entra/RBAC)
    - MySQL (enforce SSL, TLS 1.2+, audit logging)
    - PostgreSQL (SSL, logging params, throttling, retention, network restrictions)
    - Azure SQL / SQL DB (auditing on, ingress restrictions, TDE CMK, Entra admin, TDE on DBs, audit retention, public access)
  - See [CIS_FOUNDATIONS_BENCHMARK.md](CIS_FOUNDATIONS_BENCHMARK.md) for detailed foundations coverage
  - **CIS Microsoft Azure Compute Services Benchmark v2.0.0** (selected compute services)
    - App Service (HTTPS-only, FTPS only, min TLS)
    - Function Apps (HTTPS-only, managed identity)
    - Azure Kubernetes Service (RBAC enabled, disable local accounts, Azure Policy add-on)
    - Virtual Machines / Scale Sets (CMK disk encryption, encryption at host)
    - Azure Container Instances (no public IP exposure)
    - Azure Virtual Desktop (MFA via Conditional Access)
  
  - See [CIS_COMPUTE_AZURE_BENCHMARK.md](CIS_COMPUTE_AZURE_BENCHMARK.md) for detailed Azure compute coverage
  - See [CIS_COMPUTE_BENCHMARK.md](CIS_COMPUTE_BENCHMARK.md) for detailed compute coverage
  - See [CIS_DATABASE_BENCHMARK.md](CIS_DATABASE_BENCHMARK.md) for detailed database services coverage
  - See [CIS_ENDUSER_BENCHMARK.md](CIS_ENDUSER_BENCHMARK.md) for detailed end user compute coverage
  - See [CIS_STORAGE_BENCHMARK.md](CIS_STORAGE_BENCHMARK.md) for detailed storage services coverage
- **Rich CLI Experience**: Colorful output, progress bars, and intuitive interface using `rich` and `typer`
- **Multiple Output Formats**: Export reports in JSON, Markdown, or HTML
- **Configuration Management**: Store and manage default settings
- **AI-Powered Explanations**: Get natural language explanations of findings using OpenAI (optional)
- **Mock Mode**: Test without cloud credentials using realistic mock data
- **Modular Architecture**: Easy to extend with new providers and checks
- **Production-Ready**: Type-hinted, documented, tested, and error-handled

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [scan](#scan-command)
  - [report](#report-command)
  - [config](#config-command)
  - [explain](#explain-command)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Testing](#testing)
- [Development](#development)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cloudauditor.git
cd cloudauditor

# Install the package
pip install .
```

### Installation with Optional Dependencies

```bash
# Install with AWS support
pip install ".[aws]"

# Install with GCP support
pip install ".[gcp]"

# Install with AI features
pip install ".[ai]"

# Install everything (including dev tools)
pip install ".[all]"
```

### Install from requirements.txt

```bash
pip install -r requirements.txt
```

### Verify Installation

**Windows:**
```cmd
# Use the provided batch file (recommended)
.\run_cloudauditor.bat --version

# Or use virtual environment directly
venv\Scripts\python.exe -m cloudauditor.main --version
```

**Linux/macOS:**
```bash
# Activate virtual environment first
source venv/bin/activate

# Then run CloudAuditor
cloudauditor --version
cloudauditor --help
```

## Quick Start

### 1. Scan an AWS Environment (Mock Mode)

**Windows:**
```cmd
# Use the provided batch file
.\run_cloudauditor.bat scan aws

# With specific options
.\run_cloudauditor.bat scan aws --profile prod --region us-east-1 --output json
```

**Linux/macOS:**
```bash
# Activate virtual environment first
source venv/bin/activate

# Scan AWS using mock data (no credentials required)
cloudauditor scan aws

# With specific options
cloudauditor scan aws --profile prod --region us-east-1 --output json
```

### 2. Scan a GCP Environment (Mock Mode)

**Windows:**
```cmd
# Use the provided batch file
.\run_cloudauditor.bat scan gcp

# With specific options
.\run_cloudauditor.bat scan gcp --profile my-project --region us-central1 --output markdown
```

**Linux/macOS:**
```bash
# Scan GCP using mock data
cloudauditor scan gcp

# With specific options
cloudauditor scan gcp --profile my-project --region us-central1 --output markdown
```

### 3. Scan an Azure Environment (Mock Mode)

**Windows:**
```cmd
# Use the provided batch file
.\run_cloudauditor.bat scan azure

# With specific options
.\run_cloudauditor.bat scan azure --profile subscription-id --tenant tenant-id --output markdown
```

**Linux/macOS:**
```bash
# Scan Azure using mock data
cloudauditor scan azure

# With specific options
cloudauditor scan azure --profile subscription-id --tenant tenant-id --output markdown
```

### 4. Scan a DigitalOcean Environment (Mock Mode)

**Windows:**
```cmd
# Use the provided batch file
.\run_cloudauditor.bat scan digitalocean

# With specific options (account label)
.\run_cloudauditor.bat scan digitalocean --profile my-team --output markdown
```

**Linux/macOS:**
```bash
# Scan DigitalOcean using mock data
cloudauditor scan digitalocean

# With specific options
cloudauditor scan digitalocean --profile my-team --output markdown
```

### 5. Generate a Report

**Windows:**
```cmd
# Generate a report from the latest scan
.\run_cloudauditor.bat report --output markdown --output-file report.md

# List available scan results
.\run_cloudauditor.bat report --list

# Generate HTML report
.\run_cloudauditor.bat report --output html --output-file report.html
```

**Linux/macOS:**
```bash
# Generate a report from the latest scan
cloudauditor report --output markdown --output-file report.md

# List available scan results
cloudauditor report --list

# Generate HTML report
cloudauditor report --output html --output-file report.html
```

### 6. Configure Default Settings

```bash
# Set AWS defaults
cloudauditor config --provider aws --profile production --region us-east-1

# Set GCP defaults
cloudauditor config --provider gcp --profile my-project --region us-central1

# View current configuration
cloudauditor config --show
```

### 5. Get AI Explanations (Requires OpenAI API Key)

```bash
# Set your OpenAI API key
cloudauditor config --set openai_api_key=sk-your-key-here

# Explain all findings
cloudauditor explain --provider aws

# Explain a specific finding
cloudauditor explain --finding 1
```

## Commands

### `scan` Command

Scan cloud environments for security compliance issues.

```bash
cloudauditor scan <provider> [OPTIONS]
```

**Arguments:**
- `provider`: Cloud provider to scan (`aws`, `gcp`, or `azure`)

**Options:**
- `--profile, -p TEXT`: Cloud provider profile/project/subscription name
- `--region, -r TEXT`: Cloud provider region
- `--tenant, -t TEXT`: Azure tenant ID (Azure only)
- `--output, -o TEXT`: Output format (`json`, `markdown`, `html`) [default: json]
- `--output-file, -f PATH`: Save output to file
- `--verbose, -v`: Enable verbose logging
- `--real`: Use real cloud APIs instead of mock data

**Examples:**

```bash
# Basic scan
cloudauditor scan aws

# Scan with custom profile and region
cloudauditor scan aws --profile prod --region us-west-2

# Scan GCP and save to file
cloudauditor scan gcp --output markdown --output-file gcp-scan.md

# Scan Azure with subscription and tenant
cloudauditor scan azure --profile subscription-id --tenant tenant-id

# Scan with real AWS credentials (requires boto3 and AWS credentials)
cloudauditor scan aws --real --profile my-aws-profile

# Verbose output for debugging
cloudauditor scan aws --verbose
```

### `report` Command

Generate compliance reports from scan results.

```bash
cloudauditor report [OPTIONS]
```

**Options:**
- `--provider, -p TEXT`: Filter by provider (`aws`, `gcp`, or `azure`)
- `--output, -o TEXT`: Output format (`json`, `markdown`, `html`) [default: json]
- `--output-file, -f PATH`: Save output to file
- `--input-file, -i PATH`: Load specific results file
- `--list, -l`: List available scan results
- `--verbose, -v`: Enable verbose logging

**Examples:**

```bash
# Generate report from latest scan
cloudauditor report

# List all available scans
cloudauditor report --list

# Generate Markdown report
cloudauditor report --output markdown --output-file compliance-report.md

# Generate HTML report for specific provider
cloudauditor report --provider aws --output html --output-file aws-report.html

# Generate report from specific scan file
cloudauditor report --input-file scan_aws_20231215_143022.json --output markdown
```

### `config` Command

Manage CloudAuditor configuration settings.

```bash
cloudauditor config [OPTIONS]
```

**Options:**
- `--show, -s`: Show current configuration
- `--provider TEXT`: Provider to configure (`aws` or `gcp`)
- `--profile TEXT`: Set default profile/project
- `--region TEXT`: Set default region
- `--set TEXT`: Set custom config key (format: `key=value`)
- `--reset`: Reset configuration to defaults
- `--verbose, -v`: Enable verbose logging

**Configuration Location:** `~/.cloudauditor/config.yaml`

**Examples:**

```bash
# Show current configuration
cloudauditor config --show

# Configure AWS defaults
cloudauditor config --provider aws --profile production --region us-east-1

# Configure GCP defaults
cloudauditor config --provider gcp --profile my-project --region us-central1

# Set custom configuration
cloudauditor config --set openai_api_key=sk-...
cloudauditor config --set custom_setting=value

# Reset all configuration
cloudauditor config --reset
```

### `explain` Command

Use AI to explain compliance findings in natural language.

```bash
cloudauditor explain [OPTIONS]
```

**Requirements:** OpenAI API key (set via environment variable, .env file, or config)

**Options:**
- `--provider, -p TEXT`: Filter by provider (`aws`, `gcp`, or `azure`)
- `--input-file, -i PATH`: Load specific results file
- `--finding, -f INTEGER`: Explain specific finding by ID
- `--verbose, -v`: Enable verbose logging

**Examples:**

```bash
# Set OpenAI API key first
export OPENAI_API_KEY=sk-your-key-here
# or
cloudauditor config --set openai_api_key=sk-your-key-here

# Explain summary of all findings
cloudauditor explain --provider aws

# Explain a specific finding
cloudauditor explain --finding 1

# Explain findings from a specific scan
cloudauditor explain --input-file scan_gcp_20231215_143022.json
```

## Configuration

### Configuration File

CloudAuditor stores configuration in `~/.cloudauditor/config.yaml`:

```yaml
aws:
  profile: production
  region: us-east-1

gcp:
  project: my-project
  region: us-central1

openai_api_key: sk-...
```

### Environment Variables

You can also use environment variables:

```bash
# AWS
export AWS_PROFILE=production
export AWS_REGION=us-east-1

# GCP
export GCP_PROJECT=my-project
export GCP_REGION=us-central1

# OpenAI
export OPENAI_API_KEY=sk-...
```

### .env File

Create a `.env` file in your project directory:

```bash
cp .env.example .env
# Edit .env with your configuration
```

## Output Formats

### JSON

Structured data format, ideal for programmatic consumption:

```json
{
  "provider": "aws",
  "region": "us-east-1",
  "timestamp": "2023-12-15T14:30:22",
  "summary": {
    "total_checks": 10,
    "passed": 3,
    "failed": 7,
    "warnings": 0
  },
  "findings": [...]
}
```

### Markdown

Human-readable format, great for documentation:

```markdown
# CloudAuditor Compliance Report

**Provider:** AWS
**Region:** us-east-1

## Summary
- Total Checks: 10
- Passed: 3
- Failed: 7

## Findings
### 1. S3 Bucket Encryption Not Enabled
**Severity:** HIGH
...
```

### HTML

Rich formatted report with styling, perfect for sharing:

```html
<!DOCTYPE html>
<html>
  <head><title>CloudAuditor Report</title></head>
  <body>
    <!-- Styled report content -->
  </body>
</html>
```

## Testing

### Run Tests

```bash
# Install dev dependencies
pip install ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=cloudauditor --cov-report=html

# Run specific test file
pytest tests/test_scan.py

# Run with verbose output
pytest -v
```

### Test Structure

```
tests/
├── __init__.py
├── test_scan.py      # Tests for scan command
├── test_report.py    # Tests for report command
└── test_config.py    # Tests for config command
```

## Development

### Project Structure

```
cloudauditor/
├── __init__.py           # Package initialization
├── main.py               # Main CLI entry point
├── commands/             # Command implementations
│   ├── __init__.py
│   ├── scan.py          # Scan command
│   ├── report.py        # Report command
│   ├── config.py        # Config command
│   └── explain.py       # Explain command (AI)
├── providers/            # Cloud provider scanners
│   ├── __init__.py
│   ├── aws.py           # AWS scanner
│   └── gcp.py           # GCP scanner
├── utils/                # Utility modules
│   ├── __init__.py
│   ├── logger.py        # Logging utilities
│   ├── formatter.py     # Output formatting
│   └── fileio.py        # File I/O operations
└── data/                 # Mock data
    └── mock_results.json
```

### Code Style

```bash
# Format code with black
black cloudauditor/ tests/

# Check code style
flake8 cloudauditor/ tests/

# Type checking
mypy cloudauditor/
```

### Adding New Providers

1. Create a new scanner class in `cloudauditor/providers/`:

```python
class AzureScanner:
    def __init__(self, profile=None, region=None, use_mock=True):
        # Initialize scanner
        pass

    def scan(self) -> Dict[str, Any]:
        # Implement scan logic
        pass
```

2. Register the provider in `cloudauditor/providers/__init__.py`
3. Update the scan command to support the new provider

### Adding New Checks

Extend the scanner classes with new check methods:

```python
def _check_new_security_feature(self, session) -> List[Dict[str, Any]]:
    findings = []
    # Implement check logic
    return findings
```

## Architecture

### Design Principles

- **Modularity**: Each component is independent and can be extended
- **Type Safety**: Full type hints throughout the codebase
- **Error Handling**: Comprehensive error handling and user feedback
- **Testing**: Unit tests for all major components
- **Documentation**: Inline documentation and clear code structure

### Key Components

1. **CLI Layer** (`main.py`, `commands/`): User interface using Typer
2. **Scanner Layer** (`providers/`): Cloud provider-specific logic
3. **Utility Layer** (`utils/`): Shared functionality (logging, formatting, file I/O)
4. **Data Layer** (`data/`): Mock data and test fixtures

## Real Cloud Provider Integration

### AWS Setup

```bash
# Install AWS support
pip install ".[aws]"

# Configure AWS credentials
aws configure

# Scan with real AWS API
cloudauditor scan aws --real --profile my-profile
```

### GCP Setup

```bash
# Install GCP support
pip install ".[gcp]"

# Authenticate with GCP
gcloud auth application-default login

# Set project
gcloud config set project my-project

# Scan with real GCP API
cloudauditor scan gcp --real --profile my-project
```

## Troubleshooting

### Common Issues

**Issue: Command not found after installation**
```bash
# Ensure pip bin directory is in PATH
python -m cloudauditor.main --help
```

**Issue: Import errors**
```bash
# Reinstall with dependencies
pip install --force-reinstall ".[all]"
```

**Issue: Permission errors on config file**
```bash
# Fix permissions
chmod 600 ~/.cloudauditor/config.yaml
```

**Issue: OpenAI API errors**
```bash
# Verify API key is set
cloudauditor config --show
# Check API key validity at platform.openai.com
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [Typer](https://typer.tiangolo.com/) and [Rich](https://rich.readthedocs.io/)
- CIS Benchmarks from the [Center for Internet Security](https://www.cisecurity.org/)
- Cloud provider SDKs: [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) (AWS) and [Google Cloud Python](https://cloud.google.com/python/docs/reference)

## Support

- Report bugs: [GitHub Issues](https://github.com/yourusername/cloudauditor/issues)
- Documentation: [README.md](README.md)
- Questions: Open a GitHub Discussion

---

**Made with ❤️ by the CloudAuditor Team**
"# CloudAuditor" 
