@echo off
setlocal EnableDelayedExpansion
title Odyssey V1 PRE ALPHA - 2025 Edition
echo.
color 2

:: Check for Administrator Privileges
>nul 2>&1 "%SystemRoot%\system32\cacls.exe" "%SystemRoot%\system32\config\system"
if %errorlevel% NEQ 0 (
    echo [ERROR] Please run this script as Administrator.
    pause
    exit /b
)

:MENU
cls
echo ============================
echo   Windows Setup Main Menu
echo ============================
echo 1. Start Main Setup
echo 2. Administration Menu
echo 3. Utils Menu
echo 4. Hot Fixes Menu
echo 0. Exit
echo.
set /p choice=Enter your choice [0-4]: 

if "%choice%"=="1" goto STARTMAIN
if "%choice%"=="2" goto ADMIN_MENU
if "%choice%"=="3" goto UTILS_MENU
if "%choice%"=="4" goto HOTFIXES_MENU

if "%choice%"=="0" exit /b
goto MENU

:HOTFIXES_MENU
cls
echo ============================
echo   Windows Hot Fixes Menu
echo ============================
echo 1. Fix BitLocker Encryption Error Code 0x8004100e
echo 0. Back to Main Menu
echo.
set /p hotfix_choice=Enter your choice [0-1]:

if "%hotfix_choice%"=="1" goto FIX_BITLOCKER
if "%hotfix_choice%"=="0" goto MENU
echo [ERROR] Invalid choice. Please try again.
pause
goto HOTFIXES_MENU

:FIX_BITLOCKER
cls
echo [INFO] Fixing BitLocker Encryption Error Code 0x8004100e...
mofcomp.exe c:\windows\system32\wbem\win32_encryptablevolume.mof
pause
goto HOTFIXES_MENU

:ADMIN_MENU
cls
echo ============================
echo   Windows Administration Menu
echo ============================
echo 1.  Disable BitLocker
echo 2.  Create New User
echo 3.  Gamco Registry Setup Fix
echo 4.  Enable BitLocker
echo 5.  Change Computer Name
echo 6.  Set Local Administrator Password
echo 7.  Join Domain / Workgroup
echo 8.  Enable/Disable Remote Desktop
echo 9.  Enable/Disable Windows Firewall
echo 10. Clear Windows Event Logs
echo 11. Manage Windows Services
echo 12. View Windows Update History
echo 13. Enable/Disable UAC
echo 14. Export/Import Local Group Policy
echo 0.  Back to Main Menu
echo.
set /p admin_choice=Enter your choice [0-14]:

if "%admin_choice%"=="1" goto DISABLE_BITLOCKER
if "%admin_choice%"=="2" goto CREATE_USER
if "%admin_choice%"=="3" goto GAMCO
if "%admin_choice%"=="4" goto ENABLE_BITLOCKER
if "%admin_choice%"=="5" goto RENAME_PC
if "%admin_choice%"=="6" goto SET_ADMIN_PASS
if "%admin_choice%"=="7" goto JOIN_DOMAIN
if "%admin_choice%"=="8" goto REMOTE_DESKTOP
if "%admin_choice%"=="9" goto FIREWALL
if "%admin_choice%"=="10" goto CLEAR_EVENT_LOGS
if "%admin_choice%"=="11" goto MANAGE_SERVICES
if "%admin_choice%"=="12" goto UPDATE_HISTORY
if "%admin_choice%"=="13" goto TOGGLE_UAC
if "%admin_choice%"=="14" goto GPO_BACKUP
if "%admin_choice%"=="0" goto MENU
echo [ERROR] Invalid choice. Please try again.
pause
goto ADMIN_MENU

:UTILS_MENU
cls
echo ============================
echo   Windows Utilities Menu
echo ============================
echo 1.  MassGrave
echo 2.  MassGrave Alternative
echo 3.  System Information Report
echo 4.  Disk Cleanup
echo 5.  Check for Windows Updates
echo 6.  Network Troubleshooter
echo 7.  Open Device Manager
echo 8.  Open Task Manager
echo 9.  Open Control Panel
echo 10. Backup User Data
echo 11. Restore System from Restore Point
echo 12. Run SFC / DISM for System Health
echo 13. Open Windows Explorer to Documents
echo 14. About / Credits
echo 15. Reboot / Shutdown Options
echo 0.  Back to Main Menu
echo.

set /p utils_choice=Enter your choice [0-15]:
if "%utils_choice%"=="1" goto MASSGRAVE
if "%utils_choice%"=="2" goto MASSGRAVEALT
if "%utils_choice%"=="3" goto INFO
if "%utils_choice%"=="4" goto DISK_CLEANUP
if "%utils_choice%"=="5" goto WIN_UPDATES
if "%utils_choice%"=="6" goto NET_TROUBLE
if "%utils_choice%"=="7" goto DEVICE_MANAGER
if "%utils_choice%"=="8" goto TASK_MANAGER
if "%utils_choice%"=="9" goto CONTROL_PANEL
if "%utils_choice%"=="10" goto BACKUP_USERDATA
if "%utils_choice%"=="11" goto RESTORE_POINT
if "%utils_choice%"=="12" goto SFC_DISM
if "%utils_choice%"=="13" goto OPEN_DOCS
if "%utils_choice%"=="14" goto ABOUT
if "%utils_choice%"=="15" goto REBOOT_SHUTDOWN
if "%utils_choice%"=="0" goto MENU
echo [ERROR] Invalid choice. Please try again.
pause
goto UTILS_MENU





:CLEAR_EVENT_LOGS
echo [INFO] Clearing all Windows Event Logs...
for /F "tokens=*" %%G in ('wevtutil.exe el') DO wevtutil.exe cl "%%G"
echo [OK] Event logs cleared.
pause
goto ADMIN_MENU

:MANAGE_SERVICES
echo [INFO] Example: Restarting Print Spooler...
net stop spooler
net start spooler
pause
goto ADMIN_MENU

:UPDATE_HISTORY
echo [INFO] Opening Windows Update History...
start ms-settings:windowsupdate-history
pause
goto ADMIN_MENU

:TOGGLE_UAC
echo [INFO] Toggling UAC...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
pause
goto ADMIN_MENU

:GPO_BACKUP
echo [INFO] Exporting Local Group Policy...
mkdir "%USERPROFILE%\Desktop\GPO-Backup"
xcopy "%SystemRoot%\System32\GroupPolicy" "%USERPROFILE%\Desktop\GPO-Backup\GroupPolicy" /E /I /Y
echo [OK] GPO exported to Desktop\GPO-Backup.
pause
goto ADMIN_MENU

:BACKUP_USERDATA
echo [INFO] Backing up user data (Documents, Desktop, Pictures)...
set /p backupdest=Enter backup destination folder:
xcopy "%USERPROFILE%\Documents" "%backupdest%\Documents" /E /I /Y
xcopy "%USERPROFILE%\Desktop" "%backupdest%\Desktop" /E /I /Y
xcopy "%USERPROFILE%\Pictures" "%backupdest%\Pictures" /E /I /Y
echo [OK] Backup complete.
pause
goto UTILS_MENU

:RESTORE_POINT
echo [INFO] Opening System Restore...
start rstrui.exe
pause
goto UTILS_MENU

:SFC_DISM
echo [INFO] Running SFC and DISM...
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth
pause
goto UTILS_MENU

:OPEN_DOCS
echo [INFO] Opening Documents folder...
start explorer "%USERPROFILE%\Documents"
pause
goto UTILS_MENU

:ABOUT
cls
echo ==================================================
echo           Odyssey Batch Utility Script v1.0
echo --------------------------------------------------
echo   Created by Colin
echo   For support, contact me on Teams
echo --------------------------------------------------
echo   This script automates Windows setup, tweaks,
echo   and administration for rapid deployment.
echo --------------------------------------------------
echo   Thank you for using Odyssey!
echo ==================================================
pause
goto UTILS_MENU

:REBOOT_SHUTDOWN
echo 1. Reboot
echo 2. Shutdown
echo 0. Cancel
set /p poweropt=Choose an option [0-2]:
if "%poweropt%"=="1" shutdown /r /t 0
if "%poweropt%"=="2" shutdown /s /t 0
goto UTILS_MENU

:ENABLE_BITLOCKER
echo [INFO] Enabling BitLocker on C: drive...
manage-bde -on C:
if %errorlevel% neq 0 (
    echo [ERROR] Failed to start BitLocker encryption.
    pause
    goto ADMIN_MENU
)

echo.
echo [INFO] Monitoring BitLocker encryption progress. Press Ctrl+C to stop monitoring.
:BITLOCKER_ENCRYPT_PROGRESS
manage-bde -status C: | find /i "Percentage Encrypted" >nul
if %errorlevel% neq 0 (
    echo [OK] BitLocker encryption completed or not enabled.
    pause
    goto ADMIN_MENU
)
for /f "tokens=3" %%a in ('manage-bde -status C: ^| find "Percentage Encrypted"') do (
    set "progress=%%a"
    setlocal enabledelayedexpansion
    echo [PROGRESS] Encryption: !progress!
    endlocal
)
timeout /t 5 >nul
goto BITLOCKER_ENCRYPT_PROGRESS
pause
goto ADMIN_MENU

:RENAME_PC
set /p NewName=Enter the new PC name:
echo Renaming PC to %NewName%...
powershell -Command "Rename-Computer -NewName '%NewName%' -Force -Restart"
pause
goto ADMIN_MENU

:SET_ADMIN_PASS
set /p adminuser=Enter admin username:
net user %adminuser% *
pause
goto ADMIN_MENU

:JOIN_DOMAIN
set /p domain=Enter domain name (or leave blank for workgroup):
if "%domain%"=="" (
    set /p workgroup=Enter workgroup name:
    netdom join %COMPUTERNAME% /domain:%workgroup%
) else (
    netdom join %COMPUTERNAME% /domain:%domain%
)
pause
goto ADMIN_MENU

:REMOTE_DESKTOP
echo [INFO] Toggling Remote Desktop...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
echo [OK] Remote Desktop enabled.
pause
goto ADMIN_MENU

:FIREWALL
echo [INFO] Toggling Windows Firewall...
netsh advfirewall set allprofiles state off
echo [OK] Windows Firewall disabled.
pause
goto ADMIN_MENU

:DISK_CLEANUP
echo [INFO] Running Disk Cleanup...
cleanmgr
pause
goto UTILS_MENU

:WIN_UPDATES
echo [INFO] Checking for Windows Updates...
start ms-settings:windowsupdate
pause
goto UTILS_MENU

:NET_TROUBLE
echo [INFO] Running Network Troubleshooter...
msdt.exe /id NetworkDiagnosticsNetworkAdapter
pause
goto UTILS_MENU

:DEVICE_MANAGER
echo [INFO] Opening Device Manager...
start devmgmt.msc
pause
goto UTILS_MENU

:TASK_MANAGER
echo [INFO] Opening Task Manager...
start taskmgr
pause
goto UTILS_MENU

:CONTROL_PANEL
echo [INFO] Opening Control Panel...
start control
pause
goto UTILS_MENU

:DISABLE_BITLOCKER
:: Disable BitLocker and show live progress
echo [INFO] Checking BitLocker status...
manage-bde -status C:

echo.
echo [INFO] Disabling BitLocker on C: drive...
manage-bde -off C:

echo.
echo [INFO] Monitoring BitLocker decryption progress. Press Ctrl+C to stop monitoring.
:BITLOCKER_PROGRESS
for /f "tokens=3" %%a in ('manage-bde -status C: ^| find "Percentage"') do (
    set "progress=%%a"
    setlocal enabledelayedexpansion
    echo [PROGRESS] Decryption: !progress!
    endlocal
)
timeout /t 5 >nul
manage-bde -status C: | find "Percentage" >nul
if %errorlevel%==0 goto BITLOCKER_PROGRESS

echo [OK] BitLocker decryption completed or not enabled.
pause
goto MENU

:INFO
echo [INFO] Generating system information report...
systeminfo > "%USERPROFILE%\Desktop\SystemInfo.txt" 2>nul
if %errorlevel% neq 0 (
    echo [WARN] systeminfo failed. Trying MSINFO32...
    msinfo32 /report "%USERPROFILE%\Desktop\SystemInfo.txt"
    if %errorlevel% neq 0 (
        echo [ERROR] Both systeminfo and msinfo32 failed to generate a report.
        pause
        goto MENU
    )
)
echo [OK] Report saved to Desktop.
echo [INFO] You can view the report by opening SystemInfo.txt on your Desktop.
echo [NOTE] This report includes system configuration, network adapter details, and more.
echo [NOTE] If you need to share this report, please ensure it does not contain sensitive information.
echo [NOTE] You can also use this report for troubleshooting purposes.
echo [NOTE] If you can not find the report, go to this location in explorer: 'C:\Users\username\Desktop'
pause
goto MENU

:CREATE_USER
set /p newuser=Enter new username:
net user %newuser% /add
set /p usertype=Should this user be an Administrator? (Y/N): 

if /i "%usertype%"=="Y" (
    net localgroup administrators %newuser% /add
    echo [OK] User %newuser% created and added to Administrators.
) else (
    echo [OK] Standard user %newuser% created.
)

pause
goto MENU

:GAMCO
echo [INFO] Adding Registry Files For Autodiscovery...
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeExplicitO365Endpoint" /t REG_DWORD /d 1 /f
pause
goto MENU

:MASSGRAVE
echo [INFO] Starting MassGrave...
powershell -NoProfile -Command "irm https://get.activated.win | iex"
pause
goto MENU

:MASSGRAVEALT
echo [INFO] Starting MassGrave Alternative...
powershell -NoProfile -Command "irm https://massgrave.dev/get | iex"
pause
goto MENU

:STARTMAIN
echo [INFO] Starting Main Setup...
timeout /t 5 /nobreak >nul

::=================================================
:: Check for Administrator Privileges
::=================================================
>nul 2>&1 "%SystemRoot%\system32\cacls.exe" "%SystemRoot%\system32\config\system"
if %errorlevel% NEQ 0 (
    echo [ERROR] Please run this script as Administrator.
    pause
    exit /b
)

::=================================================
:: Uninstall Bloatware via Winget
::=================================================
echo [INFO] Uninstalling default bloatware...
powershell -NoProfile -Command "winget uninstall --id 'McAfee.wps'"
powershell -NoProfile -Command "winget uninstall --id 'Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe'"
echo [OK] Bloatware removed (check Control Panel to verify).
echo [INFO] You may need to log off/log back in for changes to take effect.
timeout /t 5 /nobreak >nul


::=================================================
:: Create Installation Directory
::=================================================
set "installDir=C:\_install"
if not exist "%installDir%" (
    echo [INFO] Creating directory %installDir%...
    mkdir "%installDir%"
    echo [OK] Directory created.
) else (
    echo [INFO] Directory already exists: %installDir%
)

echo [INFO] If you run into a problem, please reboot your computer and run this script again.
echo [INFO] After reboot, run this script again to continue installation.

::=================================================
:: Winget Actions (Update/Import) This is commented due to testing at the monent (but this code does work)
::=================================================

::=========================================
:: Check if winget is installed
::=========================================
:: Ensure installed-apps.json exists in script folder; download from GitHub raw if missing
if not exist "%~dp0installed-apps.json" (
    echo [INFO] installed-apps.json not found locally -- attempting download...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/CS-Colin/Odyssey/refs/heads/master/Dependencies/installed-apps.json' -OutFile '%~dp0installed-apps.json' -UseBasicParsing; exit 0 } catch { exit 1 }"
    if not exist "%~dp0installed-apps.json" (
        echo [WARN] Could not download installed-apps.json; winget import may fail.
    ) else (
        echo [OK] installed-apps.json downloaded.
    )
)

echo [INFO] Starting Winget import...
powershell -NoProfile -Command "winget import -i 'installed-apps.json'"
echo [OK] Import complete.

set /p updateChoice=Do you want to check for updates with winget? (Y/N):
if /I "%updateChoice%"=="Y" (
    where winget >nul 2>&1
    if %errorlevel%==0 (
        echo [INFO] Running winget update...
        powershell -NoProfile -ExecutionPolicy Bypass -Command "winget update --all --accept-source-agreements --accept-package-agreements"
    ) else (
        echo [WARN] winget not found. Skipping update.
    )
) else (
    echo [INFO] Skipping winget update.
)

::=================================================
:: File Associations (Manual Registry Method)
::=================================================
:: Adobe Acrobat for PDFs
echo [INFO] Setting default apps for PDF...

set "adobePath=C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
set "progId=AcroExch.Document"

if not exist "%adobePath%" (
    echo [ERROR] Adobe Reader not found at: %adobePath%
    pause
    exit /b
)

reg add "HKCU\Software\Classes\.pdf" /ve /d "%progId%" /f
reg add "HKCU\Software\Classes\%progId%\shell\open\command" /ve /d "\"%adobePath%\" \"%%1\"" /f
reg add "HKCU\Software\Classes\%progId%\DefaultIcon" /ve /d "\"%adobePath%\",1" /f
echo [OK] Default app for PDF set to Adobe Acrobat.
timeout /t 5 /nobreak >nul


:: Outlook for MAILTO and .MSG
echo [INFO] Setting Outlook as default for MAILTO and MSG files...

set "outlookPath=C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"

if not exist "%outlookPath%" (
    echo [ERROR] Outlook not found at: %outlookPath%
    pause
    exit /b
)

:: MAILTO
reg add "HKCU\Software\Classes\mailto" /ve /d "Outlook.URL.mailto.15" /f
reg add "HKCU\Software\Classes\mailto\shell\open\command" /ve /d "\"%outlookPath%\" /c ipm.note /m \"%%1\"" /f

:: .MSG
reg add "HKCU\Software\Classes\.msg" /ve /d "Outlook.File.msg" /f
reg add "HKCU\Software\Classes\Outlook.File.msg\shell\open\command" /ve /d "\"%outlookPath%\" \"%%1\"" /f
reg add "HKCU\Software\Classes\Outlook.File.msg\DefaultIcon" /ve /d "\"%outlookPath%\",1" /f

echo [OK] Registry entries for default apps have been set.
echo [INFO] You may need to log off/log back in for changes to take effect.
timeout /t 5 /nobreak >nul


::=================================================
:: Enforce File Type Associations with SetUserFTA
::=================================================
echo [INFO] Enforcing file type associations with SetUserFTA...
:: Ensure SetUserFTA.exe exists in script folder; download from GitHub raw if missing
if not exist "%~dp0SetUserFTA.exe" (
    echo [INFO] SetUserFTA.exe not found locally -- attempting download...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/CS-Colin/Odyssey/refs/heads/master/Dependencies/SetUserFTA.exe' -OutFile '%~dp0SetUserFTA.exe' -UseBasicParsing; exit 0 } catch { exit 1 }"
    if not exist "%~dp0SetUserFTA.exe" (
        echo [WARN] Could not download SetUserFTA.exe; SetUserFTA steps may fail.
    ) else (
        echo [OK] SetUserFTA.exe downloaded.
    )
)

:: Adobe Acrobat
powershell -NoProfile -Command ".\SetUserFTA.exe .pdf AcroExch.Document.DC"

:: Outlook
powershell -NoProfile -Command ".\SetUserFTA.exe .msg Outlook.File.msg"
powershell -NoProfile -Command ".\SetUserFTA.exe mailto Outlook.URL.mailto.15"
powershell -NoProfile -Command ".\SetUserFTA.exe .eml Outlook.File.eml"
powershell -NoProfile -Command ".\SetUserFTA.exe .emlx Outlook.File.emlx"

:: Chrome
powershell -NoProfile -Command ".\SetUserFTA.exe .http Google.Chrome"
powershell -NoProfile -Command ".\SetUserFTA.exe .https Google.Chrome"
powershell -NoProfile -Command ".\SetUserFTA.exe .url Google.Chrome"
powershell -NoProfile -Command ".\SetUserFTA.exe .htm ChromeHTML"
powershell -NoProfile -Command ".\SetUserFTA.exe .html ChromeHTML"

echo [OK] File type associations have been set.
echo [INFO] You may need to log off/log back in for changes to take effect.
echo [NOTE] For enforcement issues, consult SetUserFTA documentation.
timeout /t 5 /nobreak >nul


::=================================================
:: Set Time Zone to South Africa Standard Time (SAST)
::=================================================
echo [INFO] Setting time zone to South Africa Standard Time...
tzutil /s "South Africa Standard Time"
echo [OK] Time zone set to SAST (UTC+2).
echo [INFO] You may need to log off/log back in for changes to take effect.
timeout /t 5 /nobreak >nul


::=================================================
:: Display Current Time Zone
::=================================================
echo [INFO] Displaying current time zone...
for /f "tokens=*" %%a in ('tzutil /g') do set timezone=%%a
echo [INFO] Current system time zone: %timezone%
echo [OK] Time zone displayed.
echo [INFO] You may need to log off/log back in for changes to take effect.
timeout /t 5 /nobreak >nul


::=================================================
:: Disable Fast Startup (Hiberboot)
::=================================================
echo [INFO] Disabling Fast Startup...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f
echo [OK] Fast Startup has been disabled.
timeout /t 5 /nobreak >nul


::=================================================
:: Set Power Plan to Balanced
::=================================================
echo [INFO] Setting power plan to Balanced...
powercfg -setactive SCHEME_BALANCED

:: Optional: Uncomment for High Performance or Ultimate Performance
:: powercfg -setactive SCHEME_MIN
:: powercfg -setactive SCHEME_MAX

echo [OK] Power plan set.
timeout /t 5 /nobreak >nul

::=================================================
:: Disable Suggested Apps in Start Menu
::=================================================
echo [INFO] Disabling suggested apps in Start Menu...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
echo [OK] Suggested apps disabled.

::=================================================
:: Disable Sticky Keys Shortcut Prompts
::=================================================
echo [INFO] Disabling Sticky Keys shortcut prompts...
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f
echo [OK] Sticky Keys prompts disabled.

::=================================================
:: Disable Windows Telemetry
::=================================================
echo [INFO] Disabling Windows Telemetry...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
timeout /t 5 /nobreak >nul

echo [OK] Windows Telemetry disabled.
echo [INFO] You may need to log off/log back in for changes to take effect.
timeout /t 5 /nobreak >nul


::=================================================
:: Disable Cortana
::=================================================
echo [INFO] Disabling Cortana...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
echo [OK] Cortana disabled.
timeout /t 5 /nobreak >nul


::=================================================
:: Disable Windows Spotlight    
::=================================================
echo [INFO] Disabling Windows Spotlight...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
echo [OK] Windows Spotlight disabled.
timeout /t 5 /nobreak >nul


::=================================================
:: Set Explorer to open "This PC" instead of Quick Access
::=================================================
echo [INFO] Setting Explorer to open "This PC" instead of Quick Access...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
echo [OK] Explorer settings updated.
timeout /t 5 /nobreak >nul


::=================================================
:: Show Hidden Files and File Extensions
::=================================================
echo [INFO] Showing hidden files and file extensions...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
echo [OK] Hidden files and file extensions are now visible.
timeout /t 5 /nobreak >nul

::=================================================
:: Disable Xbox Game Bar and Game DVR
::=================================================
:: Note: This may affect gaming performance and features.
:: If you are a gamer, consider keeping these features enabled.
::=================================================
echo [INFO] Disabling Xbox Game Bar and Game DVR...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
echo [OK] Xbox Game Bar and Game DVR disabled.

::=================================================
:: Enable .NET Framework 3.5 (if not already enabled)
::=================================================
::echo [INFO] Checking for .NET Framework 3.5...
::dism /online /get-feature /featurename:NetFx3 /format:table | findstr "Enabled"
::if %errorlevel% neq 0 (
::    echo [INFO] .NET Framework 3.5 not enabled. Enabling now...
::) else (
::    echo [OK] .NET Framework 3.5 is already enabled.
::    exit /b
::)
:: Enable .NET Framework 3.5
::echo [INFO] Enabling .NET Framework 3.5...
::dism /online /enable-feature /featurename:NetFx3 /all /norestart
::echo [OK] .NET Framework 3.5 enabled.


::=================================================
:: Disable Windows Defender
::=================================================
::echo [INFO] Disabling Windows Defender...

:: Disable Real-Time Protection
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f

:: Disable Windows Defender Service
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

:: Disable Tamper Protection (requires manual confirmation in some cases)
::reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f

::echo [OK] Windows Defender has been disabled.
::timeout /t 5 /nobreak >nul

::=================================================
:: Enable Clipboard History (Windows 10/11)
::=================================================
:: Note: This feature allows you to access your clipboard history.
:: It is recommended to enable this feature for better productivity.
::=================================================
echo [INFO] Checking for Clipboard History feature...

reg query "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=2*" %%a in ('reg query "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory 2^>nul') do set "clipboardHistory=%%b"
    if "%clipboardHistory%"=="0x1" (
        echo [OK] Clipboard History is already enabled.
    ) else (
        echo [INFO] Clipboard History is disabled. Enabling now...
        reg add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 1 /f
        echo [OK] Clipboard History enabled.
    )
) else (
    echo [INFO] Clipboard History feature not found. Enabling now...
    reg add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 1 /f
    echo [OK] Clipboard History enabled.
)

::=================================================
:: Set Windows to Dark Mode (Uncomment to enable)
::=================================================
::echo [INFO] Setting Windows to Dark Mode...
::reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f
::reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f
::echo [OK] Windows set to Dark Mode.
::timeout /t 5 /nobreak >nul

setlocal EnableDelayedExpansion

::=================================================
:: Create Shortcuts on Desktop and Pin to Start/Taskbar
::=================================================
echo [INFO] Creating shortcuts on desktop and pinning to Start/Taskbar...

:: Get current user's desktop path
for /f "tokens=2,*" %%a in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v Desktop 2^>nul') do set "desktop=%%b"
if not defined desktop set "desktop=%USERPROFILE%\Desktop"

:: Define Office App Paths (adjust if Office is installed elsewhere)
set "wordPath=%ProgramFiles%\Microsoft Office\root\Office16\WINWORD.EXE"
set "excelPath=%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE"
set "outlookPath=%ProgramFiles%\Microsoft Office\root\Office16\OUTLOOK.EXE"

:: Special folder paths
set "thisPCPath=explorer.exe"
set "thisPCArgs=::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
set "userFolderPath=explorer.exe"
set "userFolderArgs=%USERPROFILE%"

:: Create shortcuts on desktop
call :CreateShortcut "Word" "!wordPath!"
call :CreateShortcut "Excel" "!excelPath!"
call :CreateShortcut "Outlook" "!outlookPath!"
call :CreateShortcutWithArgs "This PC" "!thisPCPath!" "!thisPCArgs!"
call :CreateShortcutWithArgs "User Folder" "!userFolderPath!" "!userFolderArgs!"

:: Pin shortcuts to Start and Taskbar (attempts only, may not always work)
powershell -ExecutionPolicy Bypass -Command ^
"& {
    $apps = @('Word', 'Excel', 'Outlook', 'This PC', 'User Folder')
    foreach ($app in $apps) {
        $shortcut = \"$env:USERPROFILE\Desktop\$app.lnk\"
        if (Test-Path $shortcut) {
            $shell = New-Object -ComObject Shell.Application
            $folder = $shell.Namespace((Split-Path $shortcut))
            $item = $folder.ParseName((Split-Path $shortcut -Leaf))
            $verbs = $item.Verbs()
            foreach ($verb in $verbs) {
                if ($verb.Name -match 'Pin to Start') { $verb.DoIt() }
                if ($verb.Name -match 'Pin to taskbar') { $verb.DoIt() }
            }
        }
    }
}"

if %errorlevel% neq 0 (
    echo [ERROR] Pinning may have failed or was partially successful.
    pause
    exit /b 1
) else (
    echo [OK] Shortcuts created. Pinning attempt completed.
)

pause


::=================================================
:: Function: CreateShortcut
::=================================================
:CreateShortcut
set "shortcutName=%~1"
set "targetPath=%~2"

powershell -ExecutionPolicy Bypass -Command ^
"$desktop = [Environment]::GetFolderPath('Desktop'); ^
 $WshShell = New-Object -ComObject WScript.Shell; ^
 $Shortcut = $WshShell.CreateShortcut(\"$desktop\\%shortcutName%.lnk\"); ^
 $Shortcut.TargetPath = \"%targetPath%\"; ^
 $Shortcut.Save()"
 

::=================================================
:: Function: CreateShortcutWithArgs
::=================================================
:CreateShortcutWithArgs
set "shortcutName=%~1"
set "targetPath=%~2"
set "arguments=%~3"

powershell -ExecutionPolicy Bypass -Command ^
"$desktop = [Environment]::GetFolderPath('Desktop'); ^
 $WshShell = New-Object -ComObject WScript.Shell; ^
 $Shortcut = $WshShell.CreateShortcut(\"$desktop\\%shortcutName%.lnk\"); ^
 $Shortcut.TargetPath = \"%targetPath%\"; ^
 $Shortcut.Arguments = \"%arguments%\"; ^
 $Shortcut.Save()"


::=========================================
:: Check if OS is Windows 11 (required for Widgets, etc.)
::=========================================
for /f "tokens=4-5 delims=. " %%i in ('ver') do set "ver_major=%%i" & set "ver_minor=%%j"
if %ver_major% LSS 10 (
    echo [INFO] This script is intended for Windows 10/11 only...
    pause
    exit /b
)

::=========================================
:: Disable Task View Button
::=========================================
echo [INFO] Disabling Task View button...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f

::=========================================
:: Disable Task View Button
::=========================================
echo [INFO] Disabling Widgets button...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f

::=========================================
:: Set Taskbar Search to "Search Box Only"
:: Values:
::   0 = Hidden
::   1 = Search icon only
::   2 = Search box
::   3 = Search (depends on Windows version)
::=========================================
echo [INFO] Setting Search to 'Search Box Only'...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 1 /f

::=========================================
:: Align Taskbar to Center (Windows 11)
:: Values:
::   0 = Left
::   1 = Center
::=========================================
echo [INFO] Aligning Taskbar to Center...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f

::=========================================
:: Restart Explorer to apply changes
::=========================================
echo [INFO] Restarting Explorer to apply changes...
taskkill /f /im explorer.exe >nul 2>&1
timeout /t 2 /nobreak >nul
start explorer.exe

echo [OK] Taskbar tweaks applied successfully.


::=================================================
:: Open Windows Update Settings, Start Windows Update service
::=================================================
setlocal EnableDelayedExpansion

:: ================================
:: Advanced Windows Update Script (No Logging)
:: ================================
:: List of necessary services
set "services=wuauserv bits cryptsvc"

:: Start required services
for %%S in (%services%) do (
    sc query %%S | find /i "RUNNING" >nul
    if errorlevel 1 (
        echo [INFO] Starting service: %%S
        net start %%S >nul 2>&1
    ) else (
        echo [INFO] Service %%S is already running
    )
)

:: Trigger Windows Update scan (Windows 10/11)
where usoclient >nul 2>&1
if %errorlevel%==0 (
    echo [INFO] Triggering Windows Update scan...
    usoclient StartScan >nul 2>&1
) else (
    echo [INFO] Usoclient not found. Manual check may be required.
)

:: Open Windows Update settings
start ms-settings:windowsupdate

echo [INFO] Windows Update process started.

::=================================================
:: Set Computer Name
::=================================================
:: Prompt for the new PC name
set /p NewName=Enter the new PC name: 

:: Show current name
for /f %%i in ('hostname') do set CurrentName=%%i

echo.
echo Current PC Name: %CurrentName%
echo New PC Name: %NewName%

:: Confirm
set /p confirm=Do you want to rename the PC to "%NewName%" and restart? (Y/N): 
if /i not "%confirm%"=="Y" (
    echo Operation cancelled.
    exit /b
)

:: Rename using PowerShell
powershell -Command "Rename-Computer -NewName '%NewName%' -Force -Restart"

if %errorlevel%==0 (
    echo Rename command issued. Restarting...
) else (
    echo [ERROR] Failed to issue rename command.
    echo [INFO] Make sure you are running as Administrator.
)

pause
goto MENU