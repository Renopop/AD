@echo off
REM Construction des executables Windows avec PyInstaller.
REM Prerequis (une seule fois) :  pip install pyinstaller
REM Resultat : dist\AdGuardAnalyse.exe (interface graphique, sans console)
REM            dist\adguard_analyse_cli.exe (ligne de commande)
REM Le dossier "listes" est copie a cote des .exe pour rester modifiable.

cd /d "%~dp0"
where pyinstaller >nul 2>nul || (echo PyInstaller introuvable : lancez  pip install pyinstaller & exit /b 1)

pyinstaller --noconfirm --clean --onefile --noconsole --name AdGuardAnalyse ^
    --hidden-import adguard_gui --add-data "listes;listes" adguard_analyse.py
if errorlevel 1 exit /b 1

pyinstaller --noconfirm --clean --onefile --console --name adguard_analyse_cli ^
    --hidden-import adguard_gui --add-data "listes;listes" adguard_analyse.py
if errorlevel 1 exit /b 1

xcopy /E /I /Y listes dist\listes >nul
echo.
echo Termine : dist\AdGuardAnalyse.exe  et  dist\adguard_analyse_cli.exe  (+ dist\listes)
