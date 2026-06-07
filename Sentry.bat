@echo off
REM Sentry - La sentinella della tua rete
title Sentry
cd /d "%~dp0"
python app.py
if errorlevel 1 (
    echo.
    echo Errore nell'avvio. Assicurati che Python sia installato e nel PATH.
    pause
)
