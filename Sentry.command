#!/bin/bash
# Lanciatore per macOS: doppio click per avviare Sentry.
# Si posiziona nella cartella dello script e avvia l'app con python3.
cd "$(dirname "$0")" || exit 1

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 non trovato. Installalo da https://www.python.org/downloads/ (o 'brew install python')."
  read -r -p "Premi Invio per chiudere."
  exit 1
fi

if ! python3 -c "import tkinter" >/dev/null 2>&1; then
  echo "Tkinter non disponibile in questo Python. Installalo con: brew install python-tk"
  read -r -p "Premi Invio per chiudere."
  exit 1
fi

python3 app.py
