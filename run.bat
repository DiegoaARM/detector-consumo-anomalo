@echo off
setlocal
cd /d "%~dp0"
if not defined DETECTOR_LLM_URL set DETECTOR_LLM_URL=http://127.0.0.1:11434
if not defined DETECTOR_LLM_MODEL set DETECTOR_LLM_MODEL=llama3.2:3b
if not defined DETECTOR_LLM_TIMEOUT set DETECTOR_LLM_TIMEOUT=30
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
