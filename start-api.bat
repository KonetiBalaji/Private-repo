@echo off
echo Starting TurbineAero API Server...
cd src\TurbineAero.API
dotnet run --urls "https://localhost:7003"
pause
