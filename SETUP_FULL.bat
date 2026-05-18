@echo off
REM Setup SentinelX with Npcap and full packet capture support
REM Run as Administrator

setlocal enabledelayedexpansion

cd /d "%~dp0"

echo.
echo ========================================
echo    SentinelX Full Setup (with Npcap)
echo ========================================
echo.

REM Check admin rights
openfiles >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: This script requires administrator privileges!
    echo Please run as Administrator (right-click and select "Run as administrator")
    echo.
    pause
    exit /b 1
)

REM Step 1: Create virtual environment
echo [STEP 1] Creating Python virtual environment...
if exist env (
    echo Removing existing virtual environment...
    rmdir /s /q env
)

python -m venv env
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

echo Virtual environment created successfully!
echo.

REM Step 2: Activate venv and upgrade pip
echo [STEP 2] Upgrading pip...
call env\Scripts\activate.bat
python -m pip install --upgrade pip setuptools wheel
if errorlevel 1 (
    echo WARNING: pip upgrade had issues but continuing...
)
echo.

REM Step 3: Install requirements
echo [STEP 3] Installing Python requirements from requirements.txt...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install requirements
    pause
    exit /b 1
)
echo.

REM Step 4: Install Npcap
echo [STEP 4] Installing Npcap for packet capture...
echo Running PowerShell to install Npcap...
powershell -NoProfile -ExecutionPolicy Bypass -File "install_npcap.ps1"
if errorlevel 1 (
    echo WARNING: Npcap installation had issues, but continuing...
    echo You can manually install from https://npcap.com/download.html
)
echo.

REM Step 5: Test Scapy + Npcap integration
echo [STEP 5] Testing Scapy and Npcap integration...
python -c "from scapy.all import get_if_list; interfaces=get_if_list(); print(f'Found {len(interfaces)} interfaces'); exit(0 if len(interfaces) > 0 else 1)"
if errorlevel 1 (
    echo WARNING: Scapy could not detect network interfaces
    echo This usually means Npcap is not installed or not working
    echo Please install Npcap from https://npcap.com/download.html
) else (
    echo SUCCESS: Scapy and Npcap are working!
)
echo.

echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo To run SentinelX now: .\SentinelX.bat
echo.
pause
