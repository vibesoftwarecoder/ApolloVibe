@echo off
REM Assemble the complete ApolloVibe portable release zip from build\.
REM Usage: package_apollovibe.bat <version>   e.g. package_apollovibe.bat 2026.6.1-multiseat.1
if "%~1"=="" (
    echo Usage: package_apollovibe.bat ^<version^>   e.g. 2026.6.1-multiseat.1
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0package_apollovibe.ps1" -Version "%~1"
exit /b %ERRORLEVEL%
