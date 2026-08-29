@echo off
chcp 65001 >nul
cd /d %~dp0
if not exist .venv (
    py -m venv .venv
)
call .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python run.py
pause
