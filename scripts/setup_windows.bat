@echo off
echo CloudAuditor Windows Setup Script
echo ================================

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Python found: 
python --version

REM Check if pip is available
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: pip is not available
    echo Please reinstall Python with pip included
    pause
    exit /b 1
)

echo pip found:
pip --version

REM Create virtual environment
echo.
echo Creating virtual environment...
python -m venv venv
if %errorlevel% neq 0 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Verify virtual environment is active
echo Verifying virtual environment...
where python

REM Upgrade pip
echo.
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo.
echo Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

REM Install CloudAuditor package in development mode
echo.
echo Installing CloudAuditor package...
pip install -e .
if %errorlevel% neq 0 (
    echo ERROR: Failed to install CloudAuditor package
    pause
    exit /b 1
)

REM Install GCP dependencies
echo.
echo Installing GCP dependencies...
pip install google-cloud-storage google-cloud-compute google-cloud-logging google-cloud-iam google-cloud-bigquery google-cloud-dataproc

REM Install AWS dependencies (optional)
echo.
echo Installing AWS dependencies...
pip install boto3

REM Test installation
echo.
echo Testing installation...
python cloudauditor/main.py --version
if %errorlevel% neq 0 (
    echo ERROR: Installation test failed
    pause
    exit /b 1
)

echo.
echo ================================
echo Setup completed successfully!
echo ================================
echo.
echo To use CloudAuditor:
echo 1. Activate the virtual environment: venv\Scripts\activate.bat
echo 2. Run scans: python cloudauditor/main.py scan gcp --profile your-project-id
echo.
echo For GCP setup:
echo 1. Set GOOGLE_APPLICATION_CREDENTIALS environment variable
echo 2. Set GOOGLE_CLOUD_PROJECT environment variable
echo 3. Use --real flag for actual GCP API calls
echo.
pause
