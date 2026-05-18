@echo off
REM SentinelX Antivirus - Main Launcher
REM Launches the SentinelX malware detection system with GUI

setlocal enabledelayedexpansion

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"

REM Check for admin privileges using a more reliable method
openfiles >nul 2>&1
if errorlevel 1 (
    echo.
    echo Requesting administrator privileges...
    echo.
    
    REM Re-launch with administrator privileges - only happens once
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" && exit /b
)

REM We have admin rights, proceed
cd /d "%SCRIPT_DIR%"

REM Verify Python environment exists
if not exist "%SCRIPT_DIR%env\Scripts\activate.bat" (
    echo.
    echo [ERROR] Python virtual environment not found at: %SCRIPT_DIR%env
    echo.
    pause
    exit /b 1
)

REM Activate the virtual environment first
call "%SCRIPT_DIR%env\Scripts\activate.bat"

REM Check if main GUI script exists
if not exist "%SCRIPT_DIR%run_gui.py" (
    echo.
    echo [ERROR] run_gui.py not found!
    echo.
    pause
    exit /b 1
)

REM Display startup message
cls
echo.
echo ============================================================
echo           SentinelX Antivirus System
echo ============================================================
echo.
echo 15-Layer Firewall Protection
echo 10-Layer File Scanning Engine
echo.

REM Run the GUI in the virtual environment
python "%SCRIPT_DIR%run_dashboard.py"

REM Capture exit code
set "EXIT_CODE=%errorLevel%"

:exit_handler
if %EXIT_CODE% neq 0 (
    echo.
    echo [ERROR] SentinelX exited with code: %EXIT_CODE%
    echo.
    pause
)

endlocal
exit /b %EXIT_CODE%
