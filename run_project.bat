@echo off
echo Project Start kar raha hoon...

:: Hamesha uss folder mein chalo jahan yeh script rakha hai
:: Isse "The system cannot find the path specified" wala error nahi aayega
pushd "%~dp0"

:: Backend ko nayi window mein start karein
echo Backend start ho raha hai...
start "backend" cmd /k "cd /d backend && python -m pip install -r requirements.txt && python -m uvicorn app.main:app --reload"

:: Thoda wait karein taaki backend start ho jaye
timeout /t 5 >nul

:: Frontend ko nayi window mein start karein
echo Frontend start ho raha hai...
start "frontend" cmd /k "cd /d frontend && python -m pip install -r requirements.txt && python -m streamlit run dashboard.py"

echo Sab kuch start ho gaya hai! Alag windows check karein.

:: Wapas original folder mein aa jao
popd

pause