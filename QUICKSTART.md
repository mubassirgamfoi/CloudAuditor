# CloudAuditor CLI - Quick Start Guide

Get started with CloudAuditor in 5 minutes!

## Installation

```bash
cd CloudAuditor_CLI
pip install .
```

## Basic Usage

### 1. Run Your First Scan

```bash
# Scan AWS (using mock data - no credentials needed!)
cloudauditor scan aws

# Scan GCP
cloudauditor scan gcp
```

You'll see a colorful output showing:
- Summary statistics (passed/failed checks)
- Detailed findings table
- Severity levels and affected resources

### 2. Generate a Report

```bash
# Create a Markdown report
cloudauditor report --output markdown --output-file my-report.md

# Create an HTML report
cloudauditor report --output html --output-file my-report.html

# List all available scans
cloudauditor report --list
```

### 3. Save Your Settings

```bash
# Configure AWS defaults
cloudauditor config --provider aws --profile production --region us-east-1

# View your configuration
cloudauditor config --show
```

### 4. Get AI Explanations (Optional)

```bash
# Set your OpenAI API key
cloudauditor config --set openai_api_key=sk-your-key-here

# Get AI explanation of findings
cloudauditor explain --provider aws

# Explain a specific finding
cloudauditor explain --finding 1
```

## Example Commands

```bash
# Scan with custom settings
cloudauditor scan aws --profile prod --region us-west-2 --output json

# Generate and save a report
cloudauditor scan gcp --output-file gcp-scan.md --output markdown

# Verbose mode for debugging
cloudauditor scan aws --verbose

# Export report in different format
cloudauditor report --provider aws --output html --output-file aws-compliance.html
```

## File Locations

- **Configuration**: `~/.cloudauditor/config.yaml`
- **Scan Results**: `~/.cloudauditor/results/`
- **Latest Results**: `~/.cloudauditor/results/latest_<provider>.json`

## What's Next?

1. **Use with Real Cloud APIs**:
   ```bash
   # Install AWS support
   pip install ".[aws]"

   # Configure AWS credentials
   aws configure

   # Scan with real API
   cloudauditor scan aws --real
   ```

2. **Explore All Features**: Check out [README.md](README.md) for complete documentation

3. **Run Tests**:
   ```bash
   pip install ".[dev]"
   pytest
   ```

4. **Try Programmatic Usage**: See [examples/example_usage.py](examples/example_usage.py)

## Need Help?

```bash
# General help
cloudauditor --help

# Command-specific help
cloudauditor scan --help
cloudauditor report --help
cloudauditor config --help
cloudauditor explain --help

# Check version
cloudauditor --version
```

## Common Use Cases

### Daily Security Scan
```bash
#!/bin/bash
# Save as: daily-scan.sh
cloudauditor scan aws --output json
cloudauditor scan gcp --output json
cloudauditor report --output html --output-file daily-report.html
```

### Weekly Compliance Report
```bash
#!/bin/bash
# Save as: weekly-report.sh
cloudauditor scan aws --real
cloudauditor report --provider aws --output markdown --output-file weekly-aws-report.md
```

### Quick Security Check
```bash
# Just scan and show critical issues
cloudauditor scan aws | grep CRITICAL
```

---

That's it! You're ready to audit your cloud infrastructure. For detailed documentation, see [README.md](README.md).
