@echo off
setlocal
cd /d "%~dp0\.."

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando permissao de Administrador para ativar bloqueio nos pacotes do Windows...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

if not exist "data\windivert\WinDivert.dll" (
    echo [Qproxy] Instalando driver oficial WinDivert 2.2.2 com verificacao SHA-256...
    python main.py --install-windivert
)

echo [Qproxy] Iniciando bloqueio em nivel de pacotes do Windows (WinDivert/WFP)...
python main.py --mode auto
pause
