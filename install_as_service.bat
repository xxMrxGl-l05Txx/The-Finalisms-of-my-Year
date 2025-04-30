@echo off
echo Installing Security Monitoring System as a Windows service...

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Administrative privileges required.
    echo Please run this script as an administrator.
    pause
    exit /b 1
)

:: Set paths
set "SCRIPT_DIR=%~dp0"
set "PYTHON_EXE=python"
set "SERVICE_SCRIPT=%SCRIPT_DIR%backend\utils\service_runner.py"
set "SERVICE_NAME=SecurityMonitoringService"
set "SERVICE_DISPLAY_NAME=Security Monitoring and Alerting System"
set "SERVICE_DESCRIPTION=Monitors system resources and detects potential security incidents"

:: Check if Python is installed
%PYTHON_EXE% --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Python is not installed or not in PATH.
    pause
    exit /b 1
)

:: Install NSSM if needed
if not exist "%SCRIPT_DIR%\nssm.exe" (
    echo Downloading NSSM (Non-Sucking Service Manager)...
    powershell -Command "(New-Object Net.WebClient).DownloadFile('https://nssm.cc/release/nssm-2.24.zip', '%TEMP%\nssm.zip')"
    powershell -Command "Expand-Archive -Path '%TEMP%\nssm.zip' -DestinationPath '%TEMP%\nssm'"
    copy "%TEMP%\nssm\nssm-2.24\win64\nssm.exe" "%SCRIPT_DIR%"
    del /q "%TEMP%\nssm.zip"
    rmdir /s /q "%TEMP%\nssm"
)

:: Check if service already exists
sc query %SERVICE_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    echo Service already exists. Removing...
    sc stop %SERVICE_NAME% >nul 2>&1
    sc delete %SERVICE_NAME% >nul 2>&1
    timeout /t 2 >nul
)

:: Install service using NSSM
echo Installing service using NSSM...
"%SCRIPT_DIR%\nssm.exe" install %SERVICE_NAME% "%PYTHON_EXE%" "%SERVICE_SCRIPT% --daemon"
"%SCRIPT_DIR%\nssm.exe" set %SERVICE_NAME% DisplayName "%SERVICE_DISPLAY_NAME%"
"%SCRIPT_DIR%\nssm.exe" set %SERVICE_NAME% Description "%SERVICE_DESCRIPTION%"
"%SCRIPT_DIR%\nssm.exe" set %SERVICE_NAME% AppDirectory "%SCRIPT_DIR%"
"%SCRIPT_DIR%\nssm.exe" set %SERVICE_NAME% AppStdout "%SCRIPT_DIR%\logs\service.log"
"%SCRIPT_DIR%\nssm.exe" set %SERVICE_NAME% AppStderr "%SCRIPT_DIR%\logs\service_error.log"
"%SCRIPT_DIR%\nssm.exe" set %SERVICE_NAME% AppRotateFiles 1
"%SCRIPT_DIR%\nssm.exe" set %SERVICE_NAME% AppRotateOnline 1
"%SCRIPT_DIR%\nssm.exe" set %SERVICE_NAME% AppRotateSeconds 86400
"%SCRIPT_DIR%\nssm.exe" set %SERVICE_NAME% Start SERVICE_AUTO_START

:: Create logs directory
if not exist "%SCRIPT_DIR%\logs" mkdir "%SCRIPT_DIR%\logs"

:: Install dependencies
echo Installing required Python packages...
%PYTHON_EXE% -m pip install -r "%SCRIPT_DIR%\backend\requirements.txt"

:: Start the service
echo Starting the service...
sc start %SERVICE_NAME%

echo.
echo Security Monitoring Service installed successfully!
echo Service Name: %SERVICE_NAME%
echo Logs: %SCRIPT_DIR%\logs\
echo.
echo To uninstall, run: sc delete %SERVICE_NAME%
echo.

pause
