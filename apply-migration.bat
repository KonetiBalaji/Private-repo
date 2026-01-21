@echo off
echo ========================================
echo Applying Database Migration
echo ========================================
echo.
echo This will create the UserFiles table in your database.
echo.
echo Press any key to continue or Ctrl+C to cancel...
pause >nul

echo.
echo Navigating to Web project...
cd src\TurbineAero.Web

echo.
echo Applying migration...
dotnet ef database update

echo.
echo ========================================
if %ERRORLEVEL% EQU 0 (
    echo Migration applied successfully!
    echo.
    echo You can now run the application.
) else (
    echo Migration failed. Please check the error above.
)
echo ========================================
echo.
pause
