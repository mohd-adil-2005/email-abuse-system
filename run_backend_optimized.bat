@echo off
REM Optimized backend for load testing: no reload, multiple workers
pushd "%~dp0"

echo Starting backend in OPTIMIZED mode (no reload, 4 workers)...
cd /d %~dp0backend
py -m pip install -q -r requirements.txt
py -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 4
