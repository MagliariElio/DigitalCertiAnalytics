@echo off
rem Double-click this file to install DigitalCertiAnalytics on Windows. No administrator rights are needed.
rem If Windows says "Windows protected your PC", click "More info" and then "Run anyway".
rem Options are passed on to install.ps1, for example:  install.bat --skip mongodb    or    install.bat --check
rem This file must stay ASCII with CRLF line endings.
setlocal
set "DCA_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%DCA_POWERSHELL%" set "DCA_POWERSHELL=powershell.exe"
rem -ExecutionPolicy Bypass applies to this run only: no setting of the computer is changed
"%DCA_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
set "DCA_STATUS=%ERRORLEVEL%"
echo.
if "%DCA_STATUS%"=="0" goto :done
echo The installation did not finish: read the messages above to see what to do, then run install.bat again.
goto :end
:done
echo Done. You can close this window.
:end
if not defined DCA_NO_PAUSE pause
exit /b %DCA_STATUS%
