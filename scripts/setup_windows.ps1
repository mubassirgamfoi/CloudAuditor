# CloudAuditor Windows PowerShell Setup Script
Write-Host "CloudAuditor Windows Setup Script" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python not found"
    }
    Write-Host "Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "Make sure to check 'Add Python to PATH' during installation" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if pip is available
try {
    $pipVersion = pip --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "pip not found"
    }
    Write-Host "pip found: $pipVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: pip is not available" -ForegroundColor Red
    Write-Host "Please reinstall Python with pip included" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Create virtual environment
Write-Host "`nCreating virtual environment..." -ForegroundColor Yellow
python -m venv venv
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to create virtual environment" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"

# Verify virtual environment is active
Write-Host "Verifying virtual environment..." -ForegroundColor Yellow
Get-Command python | Select-Object Source

# Upgrade pip
Write-Host "`nUpgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# Install dependencies
Write-Host "`nInstalling dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install dependencies" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Install CloudAuditor package in development mode
Write-Host "`nInstalling CloudAuditor package..." -ForegroundColor Yellow
pip install -e .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install CloudAuditor package" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Install GCP dependencies
Write-Host "`nInstalling GCP dependencies..." -ForegroundColor Yellow
pip install google-cloud-storage google-cloud-compute google-cloud-logging google-cloud-iam google-cloud-bigquery google-cloud-dataproc

# Install AWS dependencies (optional)
Write-Host "`nInstalling AWS dependencies..." -ForegroundColor Yellow
pip install boto3

# Test installation
Write-Host "`nTesting installation..." -ForegroundColor Yellow
python cloudauditor/main.py --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Installation test failed" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "`n=================================" -ForegroundColor Green
Write-Host "Setup completed successfully!" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green
Write-Host ""
Write-Host "To use CloudAuditor:" -ForegroundColor Cyan
Write-Host "1. Activate the virtual environment: venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "2. Run scans: python cloudauditor/main.py scan gcp --profile your-project-id" -ForegroundColor White
Write-Host ""
Write-Host "For GCP setup:" -ForegroundColor Cyan
Write-Host "1. Set GOOGLE_APPLICATION_CREDENTIALS environment variable" -ForegroundColor White
Write-Host "2. Set GOOGLE_CLOUD_PROJECT environment variable" -ForegroundColor White
Write-Host "3. Use --real flag for actual GCP API calls" -ForegroundColor White
Write-Host ""
Write-Host "Example:" -ForegroundColor Cyan
Write-Host '  $env:GOOGLE_APPLICATION_CREDENTIALS="C:\path\to\service-account-key.json"' -ForegroundColor White
Write-Host '  $env:GOOGLE_CLOUD_PROJECT="your-project-id"' -ForegroundColor White
Write-Host '  python cloudauditor/main.py scan gcp --profile your-project-id --real' -ForegroundColor White
Write-Host ""
Read-Host "Press Enter to exit"
