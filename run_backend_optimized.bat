@echo off
REM Optimized backend for load testing: no reload, multiple workers
pushd "%~dp0"

echo Starting backend in OPTIMIZED mode (auto workers by CPU cores)...
cd /d %~dp0backend
py -m pip install -q -r requirements.txt
set HOST=127.0.0.1
set PORT=8000
set MIN_WORKERS=2
set MAX_WORKERS=8
py start_backend.py
