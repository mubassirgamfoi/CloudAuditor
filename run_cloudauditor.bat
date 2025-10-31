@echo off
echo CloudAuditor CLI
echo ================

REM Check if virtual environment exists
if not exist "venv\Scripts\python.exe" (
    echo ERROR: Virtual environment not found!
    echo Please run the setup script first: scripts\setup_windows.bat
    pause
    exit /b 1
)

REM Activate virtual environment and run CloudAuditor
call venv\Scripts\activate.bat
python -m cloudauditor.main %*
