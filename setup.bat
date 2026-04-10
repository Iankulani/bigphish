@echo off
title BIG-PHISH Installer
color 0A

echo ========================================
echo 🐋 BIG-PHISH v1.0.0 Installer
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.7+
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set pyver=%%i
echo [OK] Python %pyver% detected

REM Create virtual environment
echo [INFO] Creating virtual environment...
if not exist "venv" (
    python -m venv venv
)

REM Activate and install requirements
echo [INFO] Installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-full.txt

REM Create directories
echo [INFO] Creating directories...
mkdir .bigphish 2>nul
mkdir reports 2>nul
mkdir logs 2>nul
mkdir config 2>nul
mkdir wordlists 2>nul
mkdir phishing_templates 2>nul
mkdir captured_credentials 2>nul
mkdir ssh_keys 2>nul
mkdir traffic_logs 2>nul
mkdir nikto_results 2>nul

REM Create config if not exists
if not exist "config\config.json" (
    copy config.example.json config\config.json 2>nul
    if errorlevel 1 (
        echo [WARN] No config.example.json found, creating default...
        (
            echo {
            echo     "monitoring": {"enabled": true, "port_scan_threshold": 10},
            echo     "scanning": {"default_ports": "1-1000", "timeout": 30},
            echo     "security": {"auto_block": false, "log_level": "INFO"},
            echo     "nikto": {"enabled": true, "timeout": 300},
            echo     "traffic_generation": {"enabled": true, "max_duration": 300, "allow_floods": false},
            echo     "social_engineering": {"enabled": true, "default_port": 8080, "capture_credentials": true},
            echo     "crunch": {"enabled": true, "max_file_size_mb": 1024, "default_output_dir": "wordlists"},
            echo     "ssh": {"enabled": true, "default_timeout": 30, "max_connections": 5}
            echo }
        ) > config\config.json
    )
)

REM Create run script
echo [INFO] Creating run script...
(
echo @echo off
echo call venv\Scripts\activate.bat
echo python bigphish.py %%*
) > run.bat

echo.
echo ========================================
echo ✅ BIG-PHISH Installation Complete!
echo ========================================
echo.
echo Run with: run.bat
echo.
pause