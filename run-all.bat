@echo off
echo ========================================
echo TurbineAero Application Launcher
echo ========================================
echo.
echo This will start both the API and Web applications.
echo Make sure you have run the database migration first!
echo.
echo Press any key to continue or Ctrl+C to cancel...
pause >nul

echo.
echo Starting API Server on https://localhost:7003...
start "TurbineAero API" cmd /k "cd src\TurbineAero.API && dotnet run"

timeout /t 3 /nobreak >nul

echo.
echo Starting Web Application on https://localhost:7001...
start "TurbineAero Web" cmd /k "cd src\TurbineAero.Web && dotnet run"

echo.
echo ========================================
echo Both applications are starting...
echo ========================================
echo.
echo API: https://localhost:7003
echo Web: https://localhost:7001
echo.
echo Press any key to exit this window (applications will continue running)...
pause >nul
