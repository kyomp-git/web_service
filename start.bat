@echo off
cd /d "%~dp0"

python --version > nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python first.
    pause
    exit /b 1
)

if not exist ".venv" (
    echo [Setup] Creating virtual environment...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    echo [Setup] Installing packages...
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

echo [Start] http://localhost:5000
python app.py
pause
