@echo off

echo ================================
echo Setting up JavaScator environment
echo ================================

python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo Python is not installed or not in PATH.
    pause
    exit /b 1
)

python -m venv venv

call venv\Scripts\activate.bat

python -m pip install --upgrade pip

pip install --upgrade colorama

if not exist JavaDist (
    mkdir JavaDist
)

echo =====================================
echo Setup complete! You can now run:
echo python main.py your_script.js
echo =====================================

pause>nul
