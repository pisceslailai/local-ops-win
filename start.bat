@echo off
rem Windows launcher: prefer the Python launcher, then fall back to python.
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 server.py --launcher %*
) else (
  python server.py --launcher %*
)
