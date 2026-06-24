@echo off
REM AI Shield Guardian - Quick Setup Script for Windows

echo.
echo ========================================================
echo      AI Shield Guardian Setup Script
echo ========================================================
echo.

REM Check Python
echo Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python not found. Install Python 3.9+ first.
    exit /b 1
)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Python %PYTHON_VERSION% found

REM Setup Backend
echo.
echo Installing backend dependencies...
cd backend
pip install -r requirements.txt
cd ..

REM Setup Frontend
echo.
echo Installing frontend dependencies...
cd frontend
call npm install
cd ..

REM Train model
echo.
echo Training AI model...
cd models
python train_model.py
cd ..

echo.
echo ========================================================
echo Setup complete!
echo.
echo Start the system:
echo   Terminal 1: python backend/app.py
echo   Terminal 2: cd frontend ^& npm start
echo.
echo Dashboard: http://localhost:3000
echo API Server: http://localhost:8000
echo ========================================================
echo.
pause
