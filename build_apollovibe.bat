@echo off
REM Build sunshine.exe via MSYS2/UCRT64 into build\.
REM Paths derive from this script's own location, so the repo can live anywhere.
REM Set MSYS2_ROOT if MSYS2 is not at C:\msys64.
setlocal

if not defined MSYS2_ROOT set "MSYS2_ROOT=C:\msys64"

set MSYSTEM=UCRT64
set CHERE_INVOKING=1

REM Repo root = this script's directory, minus the trailing backslash.
set "REPO=%~dp0"
if "%REPO:~-1%"=="\" set "REPO=%REPO:~0,-1%"

REM C:\path\to\repo  ->  /C/path/to/repo  for MSYS bash.
set "MSYSREPO=%REPO:\=/%"
set "MSYSREPO=/%MSYSREPO::=%"

"%MSYS2_ROOT%\usr\bin\bash.exe" --login -c "cd %MSYSREPO%/build && ninja -j4 sunshine 2>&1" > "%REPO%\build_apollovibe.log" 2>&1
echo EXIT_CODE=%ERRORLEVEL% >> "%REPO%\build_apollovibe.log"
