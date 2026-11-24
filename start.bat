@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py) || (set PY=python)
%PY% --version >nul 2>nul
if errorlevel 1 (
  echo Python is not installed. Install it from python.org and tick "Add python.exe to PATH".
  pause
  exit /b 1
)
if not exist .venv\Scripts\activate.bat (
  echo First run: setting things up, this takes a few minutes...
  %PY% -m venv .venv
)
call .venv\Scripts\activate.bat
python -c "import flask, playwright, keyring, cryptography" >nul 2>nul
if errorlevel 1 (
  echo Installing requirements...
  python -m pip install -r requirements.txt flask playwright
  if errorlevel 1 (
    echo Install failed. Check your internet connection and try again.
    pause
    exit /b 1
  )
  python -m playwright install chromium
)
if not exist "%APPDATA%\job-autofill\.shortcut_asked" (
  if not exist "%APPDATA%\job-autofill" mkdir "%APPDATA%\job-autofill"
  echo asked> "%APPDATA%\job-autofill\.shortcut_asked"
  choice /c YN /m "Create a desktop shortcut with the app icon"
  if not errorlevel 2 (
    powershell -NoProfile -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('Desktop')+'\Job Autofill.lnk');$s.TargetPath='%~dp0start.bat';$s.WorkingDirectory='%~dp0';$s.IconLocation='%~dp0icon.ico';$s.Save()"
    echo Shortcut created on your Desktop.
  )
)
python job_autofill.py
pause
