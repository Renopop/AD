@echo off
REM Construction des executables Windows. Prerequis : pip install pyinstaller
cd /d "%~dp0"
where pyinstaller >nul 2>nul || (echo PyInstaller introuvable : lancez  pip install pyinstaller & exit /b 1)
pyinstaller --noconfirm --clean --onefile --noconsole --name RechercheMails --hidden-import recherche_mails_gui recherche_mails.py
if errorlevel 1 exit /b 1
pyinstaller --noconfirm --clean --onefile --console --name recherche_mails_cli --hidden-import recherche_mails_gui recherche_mails.py
echo Termine : dist\RechercheMails.exe  et  dist\recherche_mails_cli.exe
