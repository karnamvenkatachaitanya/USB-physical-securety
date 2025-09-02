@echo off
:: This batch file will run the USB Physical Security Python script with administrator privileges.
:: It automatically finds the script in the same directory, so you can move the project folder.

:: Get the directory where this batch file is located
set "batch_dir=%~dp0"

::----------------------------------------------------------------------
:: Part 1: Request Administrator Privileges
::----------------------------------------------------------------------
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

::----------------------------------------------------------------------
:: Part 2: Run the Python Script from the Correct Directory
::----------------------------------------------------------------------
:gotAdmin
    echo Setting current directory to the script location...
    :: This is the critical fix: Change directory to the script's folder first!
    cd /d "%batch_dir%"

    if exist "USB Physical Security.py" (
        echo Found script. Running with administrator rights...
        python "USB Physical Security.py"
    ) else (
        echo ERROR: "USB Physical Security.py" not found.
        pause
    )
    
echo Script has finished.
pause

