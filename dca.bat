@echo off
rem Starts DigitalCertiAnalytics with the project's own Python, from any folder.
rem   dca.bat --help                show all the options (also when started without options)
rem   dca.bat --leaf_analysis       analyse the leaf certificates of res\certs_polito.json
rem   dca.bat --plot_all_results    create the charts
rem Double-clicked, it shows the options, asks which ones to run and keeps the window open.
rem Install the project first with install.bat. This file must stay ASCII with CRLF line endings.
setlocal
set "DCA_ROOT=%~dp0"
set "DCA_ROOT=%DCA_ROOT:~0,-1%"
set "DCA_PYTHON=%DCA_ROOT%\.venv\Scripts\python.exe"
set "DCA_SELF=%~nx0"
set "DCA_INTERACTIVE="
if "%~1"=="" call :detect_double_click
if not exist "%DCA_PYTHON%" goto :not_installed

rem The .venv programs (sslyze) come first; the caches stay inside the project
set "PATH=%DCA_ROOT%\.venv\Scripts;%PATH%"
set "VIRTUAL_ENV=%DCA_ROOT%\.venv"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "MPLCONFIGDIR=%DCA_ROOT%\.tools\cache\matplotlib"
set "PYTHONPYCACHEPREFIX=%DCA_ROOT%\.tools\cache\pycache"
set "PYTHONHOME="
set "PYTHONPATH="
rem After the project folder is moved, python.exe is still there but cannot find its Python
"%DCA_PYTHON%" -c "" >nul 2>&1 || goto :not_installed
cd /d "%DCA_ROOT%\src"
if defined DCA_INTERACTIVE goto :interactive
if "%~1"=="" goto :help
rem Keep the program last, so that its exit code (130 after Ctrl+C) is returned
"%DCA_PYTHON%" -m analysis.main %*
exit /b %ERRORLEVEL%

:help
"%DCA_PYTHON%" -m analysis.main --help
exit /b %ERRORLEVEL%

:interactive
"%DCA_PYTHON%" -m analysis.main --help
echo.
echo Type the options to run, for example:  --leaf_analysis --plot_leaf_results
:ask
set "DCA_OPTIONS="
set /p "DCA_OPTIONS=Options (or just press Enter to close): "
if not defined DCA_OPTIONS exit /b 0
"%DCA_PYTHON%" -m analysis.main %DCA_OPTIONS%
set "DCA_STATUS=%ERRORLEVEL%"
rem 2: the program did not understand the options and ran nothing, so ask again instead of closing the window
if not "%DCA_STATUS%"=="2" goto :finish
echo.
echo Those options were not understood. Every option starts with two dashes, for example:  --leaf_analysis
echo The list of the options is above.
goto :ask
:finish
echo.
pause
exit /b %DCA_STATUS%

:not_installed
echo DigitalCertiAnalytics is not installed yet, or the project folder was moved.
echo Run install.bat in the folder "%DCA_ROOT%" first.
if defined DCA_INTERACTIVE pause
exit /b 1

:detect_double_click
rem A double-clicked file is started as: cmd.exe /c ""C:\...\dca.bat" "
rem Delayed expansion, so that characters such as & in the folder name are not run as commands
setlocal EnableDelayedExpansion
set "DCA_FOUND="
set "DCA_LINE=!CMDCMDLINE!"
if /i not "!DCA_LINE:/c=!"=="!DCA_LINE!" if /i not "!DCA_LINE:%DCA_SELF%=!"=="!DCA_LINE!" set "DCA_FOUND=1"
endlocal & set "DCA_INTERACTIVE=%DCA_FOUND%"
exit /b 0
