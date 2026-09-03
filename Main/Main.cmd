@echo off
setlocal EnableDelayedExpansion
title Odyssey V1 ALPHA - 2025 Edition

:: Runtime configuration, logging, and setup state
set "ODYSSEY_VERSION=1.1"
set "DRY_RUN=0"
set "REBOOT_REQUIRED=0"
set "SUCCESS_COUNT=0"
set "FAIL_COUNT=0"
set "SKIP_COUNT=0"
set "RESUME_MODE=0"
set "LOG_DIR=C:\_install\Logs"
set "CONFIG_FILE=%~dp0Odyssey.conf"
if /i "%~1"=="/resume" set "RESUME_MODE=1"
if not exist "C:\_install" mkdir "C:\_install" >nul 2>&1
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%" >nul 2>&1
for /f %%I in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "RUN_ID=%%I"
set "LOG_FILE=%LOG_DIR%\Odyssey-%RUN_ID%.log"
if exist "%CONFIG_FILE%" for /f "usebackq tokens=1,* delims==" %%A in ("%CONFIG_FILE%") do if not "%%A"=="" if not "%%A:~0,1"=="#" set "%%A=%%B"
if exist "%CONFIG_FILE%" for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%CONFIG_FILE%") do if not "%%A"=="" set "%%A=%%B"
call :LOG INFO "Odyssey %ODYSSEY_VERSION% started."
if "%RESUME_MODE%"=="1" call :LOG INFO "Resuming after restart."

:: Check for Administrator Privileges
>nul 2>&1 "%SystemRoot%\system32\cacls.exe" "%SystemRoot%\system32\config\system"
if %errorlevel% NEQ 0 (
>nul 2>&1 "%SystemRoot%\system32\cacls.exe" "%SystemRoot%\system32\config\system"
if errorlevel 1 (
    echo [ERROR] Please run this script as Administrator.
    pause
    exit /b
)

FOR /F "tokens=*" %%A IN ('powershell -NoProfile -ExecutionPolicy Bypass -Command "winget --version 2>$null"') DO SET "VER=%%A"

echo [INFO] Checking for winget...

if "%VER%"=="" (
    echo [ERR] winget NOT installed
    timeout /t 2 /nobreak >nul
    echo [INFO] Will attempt to install...
    timeout /t 2 /nobreak >nul
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile getwinget.ps1; .\getwinget.ps1; Remove-Item getwinget.ps1"
    powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $bundle=Join-Path $env:TEMP 'Microsoft.DesktopAppInstaller.msixbundle'; Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -OutFile $bundle -UseBasicParsing; Add-AppxPackage -Path $bundle; Remove-Item -LiteralPath $bundle -Force; exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"
    if errorlevel 1 echo [WARN] Automatic Winget installation failed. Install App Installer from Microsoft Store.
) else (
    echo [OK] Winget current version: %VER%
    echo.
    timeout /t 3 /nobreak >nul
    echo Checking for updates to winget...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "winget upgrade --id Microsoft.AppInstaller"
)
timeout /t 5 /nobreak >nul
if "%RESUME_MODE%"=="1" goto RESUME_AFTER_RESTART

:MENU
cls
echo:            ______________________________________________________
echo:                          Winget Version: %ver%
echo:          
echo:                        =============================
echo:                              Odyssey Main Menu       
echo:                        =============================
echo:        
echo:                           [1] Start Main Setup  
echo:                           [2] Administration Menu
echo:                           [3] Utilities Menu
echo:                           [4] Windows Hot Fixes Menu
echo:                           [5] Windows Debloater Menu
echo:                           [6] Deployment Tools
echo:                 ______________________________________________      
echo:                                                                         
echo:                           [0] Go to Main Menu
echo:            ______________________________________________________
echo:
echo.
echo Enter your choice [0-6]:
set "choice="
set /p choice= 

if "%choice%"=="0" exit 
if "%choice%"=="1" goto STARTMAIN
if "%choice%"=="2" goto ADMIN_MENU
if "%choice%"=="3" goto UTILS_MENU
if "%choice%"=="4" goto HOTFIXES_MENU
if "%choice%"=="5" goto DEBLOATER_MENU
if "%choice%"=="6" goto DEPLOYMENT_TOOLS
set /p choice= 

if "!choice!"=="0" exit /b
if "!choice!"=="1" goto STARTMAIN
if "!choice!"=="2" goto ADMIN_MENU
if "!choice!"=="3" goto UTILS_MENU
if "!choice!"=="4" goto HOTFIXES_MENU
if "!choice!"=="5" goto DEBLOATER_MENU
if "!choice!"=="6" goto DEPLOYMENT_TOOLS
echo [ERROR] Invalid choice. Please try again.
pause
goto MENU

:DEBLOATER_MENU
cls
echo:            ______________________________________________________
echo:
echo:                        ============================
echo:                          Windows Debloater Menu
echo:                        ============================
echo:
echo:                   [1] Debloat Windows (GitHub Script - Sycnex)
echo:                    [2] Debloat Windows (Chiris Titus Script)
echo:
echo:               ________________________________________________
echo:
echo:                           [0] Go to Main Menu
echo:            ______________________________________________________
echo:
echo.
echo Enter your choice [0-2]:
set /p debloat_choice=
if "%debloat_choice%"=="1" goto DEBLOAT_WINDOWS
if "%debloat_choice%"=="2" goto CHRIS_TITUS_DEBLOAT
if "%debloat_choice%"=="0" goto MENU
echo Enter your choice [0-2]:
set "debloat_choice="
set /p debloat_choice=
if "!debloat_choice!"=="1" goto DEBLOAT_WINDOWS
if "!debloat_choice!"=="2" goto CHRIS_TITUS_DEBLOAT
if "!debloat_choice!"=="0" goto MENU

echo [ERROR] Invalid choice. Please try again.
pause
goto DEBLOATER_MENU

:DEBLOAT_WINDOWS
set "confirm="
set /p "confirm=This runs a third-party debloat script. Continue? (Y/N): "
if /i not "%confirm%"=="Y" goto DEBLOATER_MENU
if /i not "!confirm!"=="Y" goto DEBLOATER_MENU
call :CREATE_RESTORE_POINT
echo [INFO] Starting Windows Debloater...
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://git.io/debloat | iex"
if errorlevel 1 (echo [ERROR] Debloat script failed.& call :RESULT FAIL) else (echo [OK] Debloat script executed.& call :RESULT OK)
pause
goto DEBLOATER_MENU

:CHRIS_TITUS_DEBLOAT
set "confirm="
set /p "confirm=This runs a third-party utility from the Internet. Continue? (Y/N): "
if /i not "%confirm%"=="Y" goto DEBLOATER_MENU
if /i not "!confirm!"=="Y" goto DEBLOATER_MENU
call :CREATE_RESTORE_POINT
echo [INFO] Starting Chris Titus Windows Debloater...
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://christitus.com/win | iex"
if errorlevel 1 (echo [ERROR] Chris Titus script failed.& call :RESULT FAIL) else (echo [OK] Chris Titus debloat script executed.& call :RESULT OK)
pause
goto DEBLOATER_MENU


:HOTFIXES_MENU
cls
echo:            ______________________________________________________
echo:          
echo:                        ============================
echo:                            Windows Hot Fixes Menu
echo:                        ============================
echo:                 
echo:              [1] Fix BitLocker Encryption Error Code 0x8004100e
echo:              [2] Disable UDP for RDP
echo:                 ______________________________________________      
echo:                                                                         
echo:                           [0] Go to Main Menu
echo:            ______________________________________________________
echo:
echo.
echo Enter your choice [0-1]:
set /p hotfix_choice=

if "%hotfix_choice%"=="1" goto FIX_BITLOCKER
if "%hotfix_choice%"=="2" goto DISABLE_UDP_RDP
if "%hotfix_choice%"=="0" goto MENU
echo Enter your choice [0-1]:
set "hotfix_choice="
set /p hotfix_choice=

if "!hotfix_choice!"=="1" goto FIX_BITLOCKER
if "!hotfix_choice!"=="2" goto DISABLE_UDP_RDP
if "!hotfix_choice!"=="0" goto MENU
echo [ERROR] Invalid choice. Please try again.
pause
goto HOTFIXES_MENU

:FIX_BITLOCKER
cls
echo [INFO] Fixing BitLocker Encryption Error Code 0x8004100e...
mofcomp.exe c:\windows\system32\wbem\win32_encryptablevolume.mof
echo [OK] MOF file recompiled. Please try enabling BitLocker again.
echo [NOTE] If the issue persists, consider running SFC / DISM or checking for Windows Updates.
pause
goto HOTFIXES_MENU

:DISABLE_UDP_RDP
cls
echo [INFO] Disabling UDP for RDP to improve stability on some networks...
reg add "HKLM\software\policies\microsoft\windows nt\Terminal Services\Client" /v fClientDisableUDP /d 1 /t REG_DWORD
echo [OK] UDP for RDP has been disabled. You may need to reboot for changes to take effect.
pause
goto HOTFIXES_MENU

:ADMIN_MENU
cls
echo:            ______________________________________________________
echo:
echo:                        ============================
echo:                         Windows Administration Menu
echo:                        ============================
echo:
echo:              [1]  Disable BitLocker
echo:              [2]  Create New User
echo:              [3]  Gamco Registry Setup Fix
echo:              [4]  Enable BitLocker
echo:              [5]  Change Computer Name
echo:              [6]  Set Local Administrator Password
echo:              [7]  Join Domain / Workgroup
echo:              [8]  Enable / Disable Remote Desktop
echo:              [9]  Enable / Disable Windows Firewall
echo:              [10] Clear Windows Event Logs
echo:              [11] Manage Windows Services
echo:              [12] View Windows Update History
echo:              [13] Enable / Disable UAC
echo:              [14] Export / Import Local Group Policy
echo:
echo:               ________________________________________________
echo:
echo:                           [0] Go to Main Menu
echo:            ______________________________________________________
echo:
echo.
echo Enter your choice [0-14]:
set /p admin_choice=
echo Enter your choice [0-14]:
set "admin_choice="
set /p admin_choice=

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
if "!admin_choice!"=="1" goto DISABLE_BITLOCKER
if "!admin_choice!"=="2" goto CREATE_USER
if "!admin_choice!"=="3" goto GAMCO
if "!admin_choice!"=="4" goto ENABLE_BITLOCKER
if "!admin_choice!"=="5" goto RENAME_PC
if "!admin_choice!"=="6" goto SET_ADMIN_PASS
if "!admin_choice!"=="7" goto JOIN_DOMAIN
if "!admin_choice!"=="8" goto REMOTE_DESKTOP
if "!admin_choice!"=="9" goto FIREWALL
if "!admin_choice!"=="10" goto CLEAR_EVENT_LOGS
if "!admin_choice!"=="11" goto MANAGE_SERVICES
if "!admin_choice!"=="12" goto UPDATE_HISTORY
if "!admin_choice!"=="13" goto TOGGLE_UAC
if "!admin_choice!"=="14" goto GPO_BACKUP
if "!admin_choice!"=="0" goto MENU
echo [ERROR] Invalid choice. Please try again.
pause
goto ADMIN_MENU

:UTILS_MENU
cls
echo:            ______________________________________________________
echo:
echo:                        ============================
echo:                          Windows Utilities Menu
echo:                        ============================
echo:
echo:              [1]  MassGrave
echo:              [2]  MassGrave Alternative
echo:              [3]  System Information Report
echo:              [4]  Disk Cleanup
echo:              [5]  Check for Windows Updates
echo:              [6]  Network Troubleshooter
echo:              [7]  Open Device Manager
echo:              [8]  Open Task Manager
echo:              [9]  Open Control Panel
echo:              [10] Backup User Data
echo:              [11] Restore System from Restore Point
echo:              [12] Run SFC / DISM for System Health
echo:              [13] Open Windows Explorer to Documents
echo:              [14] About / Credits
echo:              [15] Reboot / Shutdown Options
echo:
echo:            ______________________________________________________
echo:
echo:                           [0] Go to Main Menu
echo:            ______________________________________________________
echo:
echo.
echo Enter your choice [0-15]:
set /p utils_choice=
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
echo Enter your choice [0-15]:
set "utils_choice="
set /p utils_choice=
if "!utils_choice!"=="1" goto MASSGRAVE
if "!utils_choice!"=="2" goto MASSGRAVEALT
if "!utils_choice!"=="3" goto INFO
if "!utils_choice!"=="4" goto DISK_CLEANUP
if "!utils_choice!"=="5" goto WIN_UPDATES
if "!utils_choice!"=="6" goto NET_TROUBLE
if "!utils_choice!"=="7" goto DEVICE_MANAGER
if "!utils_choice!"=="8" goto TASK_MANAGER
if "!utils_choice!"=="9" goto CONTROL_PANEL
if "!utils_choice!"=="10" goto BACKUP_USERDATA
if "!utils_choice!"=="11" goto RESTORE_POINT
if "!utils_choice!"=="12" goto SFC_DISM
if "!utils_choice!"=="13" goto OPEN_DOCS
if "!utils_choice!"=="14" goto ABOUT
if "!utils_choice!"=="15" goto REBOOT_SHUTDOWN
if "!utils_choice!"=="0" goto MENU
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
:BACKUP_USERDATA
echo [INFO] Backing up user data (Documents, Desktop, Pictures)...
set "backupdest="
set /p "backupdest=Enter backup destination folder: "
if not defined backupdest (
    echo [ERROR] A backup destination is required.
    pause
    goto UTILS_MENU
)
if not exist "%backupdest%" mkdir "%backupdest%" >nul 2>&1
if not exist "%backupdest%" (
    echo [ERROR] The backup destination could not be created.
    pause
    goto UTILS_MENU
)
robocopy "%USERPROFILE%\Documents" "%backupdest%\Documents" /E /R:1 /W:1
robocopy "%USERPROFILE%\Desktop" "%backupdest%\Desktop" /E /R:1 /W:1
robocopy "%USERPROFILE%\Pictures" "%backupdest%\Pictures" /E /R:1 /W:1
echo [OK] Backup finished. Review any Robocopy warnings above.
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
echo:
echo:   ================================================================
echo:                         ODYSSEY
echo:                 Batch Utility Script  v1.0
echo:   ================================================================
echo:
echo:        Created by Colin
echo:        Support: https://github.com/CS-Colin/Odyssey/
echo:
echo:   ----------------------------------------------------------------
echo:        Automated Windows Setup • Tweaks • Administration
echo:        Designed for Fast, Clean Deployment
echo:   ----------------------------------------------------------------
echo:
echo:                 Thank you for using Odyssey
echo:   ================================================================
echo:
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
:BITLOCKER_ENCRYPT_PROGRESS
set "progress="
for /f %%a in ('powershell -NoProfile -Command "try { (Get-BitLockerVolume -MountPoint 'C:').EncryptionPercentage } catch { exit 1 }"') do set "progress=%%a"
if not defined progress (
    echo [WARN] Unable to read BitLocker progress.
    pause
    goto ADMIN_MENU
)
echo [PROGRESS] Encryption: !progress!%%
if !progress! GEQ 100 (
    echo [OK] BitLocker encryption completed.
    pause
    goto ADMIN_MENU
)
timeout /t 5 >nul
goto BITLOCKER_ENCRYPT_PROGRESS

:RENAME_PC
set "NewName="
set /p "NewName=Enter the new PC name: "
echo(%NewName%| findstr /r /x "[A-Za-z0-9][A-Za-z0-9-]*" >nul
echo(!NewName!| findstr /r /x "[A-Za-z0-9][A-Za-z0-9-]*" >nul
if errorlevel 1 (
    echo [ERROR] Use only letters, numbers, and hyphens.
    pause
    goto ADMIN_MENU
)
echo Renaming PC to %NewName%...
powershell -NoProfile -Command "Rename-Computer -NewName '%NewName%' -Force"
echo Renaming PC to !NewName!...
powershell -NoProfile -Command "Rename-Computer -NewName '!NewName!' -Force"
if errorlevel 1 (echo [ERROR] Computer rename failed.& call :RESULT FAIL) else (echo [OK] Rename scheduled.& set "REBOOT_REQUIRED=1"& call :RESULT OK)
pause
goto ADMIN_MENU

:SET_ADMIN_PASS
set /p adminuser=Enter admin username:
net user "%adminuser%" *
pause
goto ADMIN_MENU

:JOIN_DOMAIN
set /p domain=Enter domain name (or leave blank for workgroup):
if "%domain%"=="" (
    set /p workgroup=Enter workgroup name:
    powershell -NoProfile -Command "Add-Computer -WorkGroupName '!workgroup!'"
) else (
    powershell -NoProfile -Command "Add-Computer -DomainName '%domain%' -Credential (Get-Credential)"
)
if errorlevel 1 (echo [ERROR] Domain or workgroup change failed.& call :RESULT FAIL) else (set "REBOOT_REQUIRED=1"& call :RESULT OK)
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
:BITLOCKER_PROGRESS
set "progress="
for /f %%a in ('powershell -NoProfile -Command "try { (Get-BitLockerVolume -MountPoint 'C:').EncryptionPercentage } catch { exit 1 }"') do set "progress=%%a"
if not defined progress (
    echo [WARN] Unable to read BitLocker progress.
    pause
    goto MENU
)
echo [PROGRESS] Decryption: !progress!%%
if !progress! LEQ 0 goto BITLOCKER_DECRYPTED
timeout /t 5 >nul
goto BITLOCKER_PROGRESS

:BITLOCKER_DECRYPTED
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
    if errorlevel 1 (
        echo [ERROR] Both systeminfo and msinfo32 failed to generate a report.
        pause
        goto MENU
    )
)
echo [OK] Report saved to Desktop.
echo [INFO] You can view the report by opening SystemInfo.txt on Desktop.
echo [NOTE] This report includes system configuration and network details.
echo [NOTE] If you need to share, ensure it does not contain sensitive information.
echo [NOTE] You can also use this report for troubleshooting purposes.
echo [NOTE] If not found in usual location, check C:\Users\username\Desktop
pause
goto MENU

:CREATE_USER
set /p "newuser=Enter the user's full name (for example, John Smith): "
:CREATE_USER
set "newuser="
set /p "newuser=Enter the user's full name (for example, John Smith): "
if not defined newuser (
    echo [ERROR] A username is required.
    pause
    goto ADMIN_MENU
)
echo.
echo [NOTE] Set a password for this user when prompted. Your password will not be displayed.
net user "%newuser%" * /add
if errorlevel 1 (
    echo [ERROR] The user could not be created. Check the name and try again.
    pause
    goto ADMIN_MENU
)
set "usertype="
set /p usertype=Should this user be an Administrator? (Y/N): 
set /p usertype=Should this user be an Administrator? (Y/N): 

if /i "%usertype%"=="Y" (
    net localgroup administrators "%newuser%" /add
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

call :PREFLIGHT
if errorlevel 1 (
    pause
    goto MENU
)
set "dryChoice="
set /p "dryChoice=Preview only without making changes? (Y/N): "
if /i "%dryChoice%"=="Y" set "DRY_RUN=1"
if "%DRY_RUN%"=="1" (
if /i "!dryChoice!"=="Y" set "DRY_RUN=1"
if "!DRY_RUN!"=="1" (
    echo [DRY RUN] Would remove configured bloatware, import applications, apply registry and taskbar settings, create shortcuts, prompt for a PC name and user, and start Windows Update.
    call :LOG INFO "Dry run completed; no setup changes were made."
    set /a SKIP_COUNT+=1
    goto SETUP_SUMMARY
)
call :CREATE_RESTORE_POINT

::=================================================
:: Check for Administrator Privileges
::=================================================
>nul 2>&1 "%SystemRoot%\system32\cacls.exe" "%SystemRoot%\system32\config\system"
if %errorlevel% NEQ 0 (
    echo [ERROR] Please run this script as Administrator.
    pause
    exit /b
>nul 2>&1 "%SystemRoot%\system32\cacls.exe" "%SystemRoot%\system32\config\system"
if errorlevel 1 (
    echo [ERROR] Please run this script as Administrator.
    pause
    goto MENU
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

::=========================================
:: Check if winget is installed
::=========================================
:: Ensure installed-apps.json exists in C:\_install; download from GitHub raw if missing
if not exist "C:\_install\installed-apps.json" (
    echo [INFO] installed-apps.json not found locally -- attempting download...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/CS-Colin/Odyssey/refs/heads/master/Dependencies/installed-apps.json' -OutFile 'C:\_install\installed-apps.json' -UseBasicParsing; exit 0 } catch { exit 1 }"
    if not exist "C:\_install\installed-apps.json" (
        echo [WARN] Could not download installed-apps.json; winget import may fail.
    ) else (
        echo [OK] installed-apps.json downloaded.
    )
)

echo [INFO] Starting Winget import...
powershell -NoProfile -Command "winget import -i 'C:\_install\installed-apps.json'"
echo [OK] Import complete.
echo [INFO] Starting Winget import...
if exist "C:\_install\installed-apps.json" (
    powershell -NoProfile -Command "winget import -i 'C:\_install\installed-apps.json' --accept-source-agreements --accept-package-agreements"
    if errorlevel 1 (echo [WARN] Winget import completed with errors.& call :RESULT FAIL) else (echo [OK] Import complete.& call :RESULT OK)
) else (
    echo [SKIP] Winget import skipped because installed-apps.json is unavailable.
    call :RESULT SKIP
)

set /p installoffice=Would you like to install Microsoft Office? (Y/N):
if /I "%installoffice%"=="Y" (
    winget list --id Microsoft.Office -e >nul 2>&1
    if not errorlevel 1 (
        echo [SKIP] Microsoft Office is already installed.
        call :RESULT SKIP
    ) else (
        echo [INFO] Installing Microsoft Office via winget...
        powershell -NoProfile -Command "winget install --id Microsoft.Office -e --accept-source-agreements --accept-package-agreements"
        if errorlevel 1 (call :RESULT FAIL) else (call :RESULT OK)
    )
) else (
    echo [INFO] Skipping Microsoft Office installation.
    call :RESULT SKIP
)

set /p updateChoice=Do you want to check for updates with winget? (Y/N):
if /I "%updateChoice%"=="Y" (
    where winget >nul 2>&1
    if %errorlevel%==0 (
    where winget >nul 2>&1
    if not errorlevel 1 (
        echo [INFO] Running winget update...
        powershell -NoProfile -ExecutionPolicy Bypass -Command "winget update --all --accept-source-agreements --accept-package-agreements"
    ) else (
        echo [WARN] winget not found. Skipping update.
    )
) else (
    echo [INFO] Skipping winget update.
)

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
echo [INFO] Setting Explorer to open This PC instead of Quick Access...
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
    if not errorlevel 1 (
    for /f "tokens=2*" %%a in ('reg query "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory 2^>nul') do set "clipboardHistory=%%b"
    if "%clipboardHistory%"=="0x1" (
    if "!clipboardHistory!"=="0x1" (
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
:: Create shortcuts on desktop
if exist "!wordPath!" (call :CreateShortcut "Word" "!wordPath!") else (echo [SKIP] Word is not installed.& call :RESULT SKIP)
if exist "!excelPath!" (call :CreateShortcut "Excel" "!excelPath!") else (echo [SKIP] Excel is not installed.& call :RESULT SKIP)
if exist "!outlookPath!" (call :CreateShortcut "Outlook" "!outlookPath!") else (echo [SKIP] Outlook is not installed.& call :RESULT SKIP)
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
:: Pin shortcuts to Start and Taskbar (best effort; Windows may block programmatic pinning)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$apps=@('Word','Excel','Outlook','This PC','User Folder'); $shell=New-Object -ComObject Shell.Application; foreach($app in $apps){ $shortcut=Join-Path ([Environment]::GetFolderPath('Desktop')) ($app+'.lnk'); if(Test-Path -LiteralPath $shortcut){ $folder=$shell.Namespace((Split-Path -LiteralPath $shortcut)); $item=$folder.ParseName((Split-Path -Leaf $shortcut)); foreach($verb in $item.Verbs()){ if($verb.Name -match 'Pin to Start|Pin to taskbar'){ $verb.DoIt() } } } }"

if %errorlevel% neq 0 (
    echo [ERROR] Pinning may have failed or was partially successful.
    pause
    exit /b 1
) else (
    echo [OK] Shortcuts created. Pinning attempt completed.
)
if %errorlevel% neq 0 (
    echo [WARN] Shortcut pinning was unavailable. Setup will continue.
    call :LOG WARN "Shortcut pinning was unavailable or partially successful."
    call :RESULT SKIP
) else (
    echo [OK] Shortcuts created. Pinning attempt completed.
    call :RESULT OK
)

pause
goto AFTER_SHORTCUT_FUNCTIONS


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
exit /b
:CreateShortcut
set "shortcutName=%~1"
set "targetPath=%~2"
echo [INFO] Creating %shortcutName% shortcut...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$desktop=[Environment]::GetFolderPath('Desktop'); $shortcut=(New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $desktop '%shortcutName%.lnk')); $shortcut.TargetPath='%targetPath%'; $shortcut.Save()"
if errorlevel 1 (
    echo [WARN] Could not create the %shortcutName% shortcut. Setup will continue.
    call :LOG WARN "Could not create %shortcutName% shortcut."
    call :RESULT SKIP
) else (
    call :RESULT OK
)
exit /b 0

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
exit /b
set "targetPath=%~2"
set "arguments=%~3"
echo [INFO] Creating %shortcutName% shortcut...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$desktop=[Environment]::GetFolderPath('Desktop'); $shortcut=(New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $desktop '%shortcutName%.lnk')); $shortcut.TargetPath='%targetPath%'; $shortcut.Arguments='%arguments%'; $shortcut.Save()"
if errorlevel 1 (
    echo [WARN] Could not create the %shortcutName% shortcut. Setup will continue.
    call :LOG WARN "Could not create %shortcutName% shortcut."
    call :RESULT SKIP
) else (
    call :RESULT OK
)
exit /b 0

:AFTER_SHORTCUT_FUNCTIONS

::=========================================
:: Check if OS is Windows 11 (required for Widgets, etc.)
::=========================================
for /f "tokens=4-5 delims=. " %%i in ('ver') do set "ver_major=%%i" & set "ver_minor=%%j"
if %ver_major% LSS 10 (
    echo [INFO] This script is intended for Windows 10/11 only...
    pause
    exit /b
for /f %%i in ('powershell -NoProfile -Command "[Environment]::OSVersion.Version.Major"') do set "ver_major=%%i"
if not defined ver_major (
    echo [WARN] Unable to determine the Windows version. Setup will continue.
) else if !ver_major! LSS 10 (
    echo [INFO] This script is intended for Windows 10/11 only...
    pause
    goto MENU
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
:: Set Computer Name
::=================================================
:: Prompt for the new PC name
set "NewName="
set /p "NewName=Enter the new PC name (leave blank to keep current name): "

:: Show current name
for /f %%i in ('hostname') do set CurrentName=%%i

echo.
echo Current PC Name: %CurrentName%
echo New PC Name: %NewName%
echo New PC Name: !NewName!

:: Confirm
if not defined NewName (
    echo [SKIP] Computer rename skipped.
    call :RESULT SKIP
    goto AFTER_MAIN_RENAME
)
echo(%NewName%| findstr /r /x "[A-Za-z0-9][A-Za-z0-9-]*" >nul
echo(!NewName!| findstr /r /x "[A-Za-z0-9][A-Za-z0-9-]*" >nul
if errorlevel 1 (
    echo [ERROR] PC names may contain only letters, numbers, and hyphens.
    call :RESULT FAIL
    goto AFTER_MAIN_RENAME
)
set "confirm="
set /p confirm=Do you want to rename the PC to "%NewName%" (Y/N): 
if /i "%confirm%"=="Y" (
set /p confirm=Do you want to rename the PC to "!NewName!" (Y/N): 
if /i "!confirm!"=="Y" (
    echo [INFO] Rename command issued. Will require a restart to take effect.
    powershell -NoProfile -Command "Rename-Computer -NewName '%NewName%'"
    powershell -NoProfile -Command "Rename-Computer -NewName '!NewName!'"
    if errorlevel 1 (
        echo [ERROR] Computer rename failed.
        call :RESULT FAIL
    ) else (
        set "REBOOT_REQUIRED=1"
        call :RESULT OK
        call :REGISTER_RESUME
    )
)
if /i "%confirm%"=="N" (
if /i "!confirm!"=="N" (
    echo Cancelled by user.
    call :RESULT SKIP
)
:AFTER_MAIN_RENAME

::Make new user an administrator

echo [INFO] Creating new user account...
echo [INFO] Creating new user account...
echo [NOTE] Please enter the name of the new user when prompted. You will also be asked if this user should have Administrator privileges. (THIS IS MANDATORY)

set /p "newuser=Enter the user's full name (for example, John Smith): "
if not defined newuser (
    echo [ERROR] A username is required.
    pause
    goto MENU
set "newuser="
set /p "newuser=Enter the user's full name, or leave blank to skip: "
if not defined newuser (
    echo [SKIP] User creation skipped.
    call :RESULT SKIP
    goto AFTER_USER_CREATION
)
echo.
echo [NOTE] Set a password for this user when prompted. Your password will not be displayed.
net user "%newuser%" * /add
if errorlevel 1 (
    echo [ERROR] The user could not be created. Check the name and try again.
    pause
    goto MENU
)
set /p usertype=Should this user be an Administrator? (Y/N): 
    echo [ERROR] The user could not be created. Check the name and try again.
    call :RESULT FAIL
    goto AFTER_USER_CREATION
)
set "usertype="
set /p usertype=Should this user be an Administrator? (Y/N): 

if /i "%usertype%"=="Y" (
    net localgroup administrators "%newuser%" /add
    echo [OK] User %newuser% created and added to Administrators.
) else (
    echo [OK] Standard user %newuser% created.
)


::=================================================
)

:AFTER_USER_CREATION

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

echo [INFO] Windows Update process started.

:: Open Windows Update settings
start ms-settings:windowsupdate

echo [DONE] The setup script has completed. Please check Windows Update for any pending updates and install them as necessary.
echo [INFO] You may need to reboot for some changes to take effect.
goto SETUP_SUMMARY

::=================================================
:: Deployment, backup, diagnostic, and helper tools
::=================================================
:DEPLOYMENT_TOOLS
cls
echo:                        ============================
echo:                            Deployment Tools
echo:                        ============================
echo:
echo:              [1] Backup Wi-Fi, printers, and browser bookmarks
echo:              [2] Create a system restore point
echo:              [3] Check drivers, firmware, and Windows Update
echo:              [4] Run Internet and system compatibility checks
echo:              [5] Create or view Odyssey configuration
echo:              [6] View current session summary
echo:              [0] Go to Main Menu
echo:
set "deploy_choice="
set /p "deploy_choice=Enter your choice [0-6]: "
if "%deploy_choice%"=="1" goto DEPLOYMENT_BACKUP
if "%deploy_choice%"=="2" goto DEPLOYMENT_RESTORE
if "%deploy_choice%"=="3" goto DEPLOYMENT_UPDATES
if "%deploy_choice%"=="4" goto DEPLOYMENT_CHECKS
if "%deploy_choice%"=="5" goto DEPLOYMENT_CONFIG
if "%deploy_choice%"=="6" goto SETUP_SUMMARY
if "%deploy_choice%"=="0" goto MENU
if "!deploy_choice!"=="1" goto DEPLOYMENT_BACKUP
if "!deploy_choice!"=="2" goto DEPLOYMENT_RESTORE
if "!deploy_choice!"=="3" goto DEPLOYMENT_UPDATES
if "!deploy_choice!"=="4" goto DEPLOYMENT_CHECKS
if "!deploy_choice!"=="5" goto DEPLOYMENT_CONFIG
if "!deploy_choice!"=="6" goto SETUP_SUMMARY
if "!deploy_choice!"=="0" goto MENU
echo [ERROR] Invalid choice.
pause
goto DEPLOYMENT_TOOLS

:DEPLOYMENT_BACKUP
echo [NOTE] The Wi-Fi backup contains readable wireless passwords. Store it securely.
set "confirm="
set /p "confirm=Continue with the backup? (Y/N): "
if /i not "%confirm%"=="Y" goto DEPLOYMENT_TOOLS
if /i not "!confirm!"=="Y" goto DEPLOYMENT_TOOLS
set "BACKUP_ROOT=%USERPROFILE%\Desktop\Odyssey-Backup-%RUN_ID%"
mkdir "%BACKUP_ROOT%\WiFi" >nul 2>&1
mkdir "%BACKUP_ROOT%\Bookmarks" >nul 2>&1
echo [INFO] Exporting Wi-Fi profiles...
netsh wlan export profile key=clear folder="%BACKUP_ROOT%\WiFi" >nul 2>&1
echo [INFO] Exporting printers...
if exist "%WINDIR%\System32\spool\tools\PrintBrm.exe" "%WINDIR%\System32\spool\tools\PrintBrm.exe" -b -f "%BACKUP_ROOT%\Printers.printerExport" >nul 2>&1
if exist "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Bookmarks" copy /y "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Bookmarks" "%BACKUP_ROOT%\Bookmarks\Chrome-Bookmarks" >nul
if exist "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Bookmarks" copy /y "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Bookmarks" "%BACKUP_ROOT%\Bookmarks\Edge-Bookmarks" >nul
if exist "%APPDATA%\Mozilla\Firefox\Profiles" xcopy "%APPDATA%\Mozilla\Firefox\Profiles" "%BACKUP_ROOT%\Bookmarks\Firefox-Profiles" /e /i /y >nul
echo [OK] Backup saved to %BACKUP_ROOT%
call :LOG INFO "Deployment backup saved to %BACKUP_ROOT%."
call :RESULT OK
pause
goto DEPLOYMENT_TOOLS

:DEPLOYMENT_RESTORE
call :CREATE_RESTORE_POINT
pause
goto DEPLOYMENT_TOOLS

:DEPLOYMENT_UPDATES
echo [INFO] Scanning Plug and Play devices...
pnputil /scan-devices
echo [INFO] Installed firmware devices:
powershell -NoProfile -Command "Get-PnpDevice -Class Firmware -ErrorAction SilentlyContinue | Format-Table Status,FriendlyName -AutoSize"
echo [INFO] Triggering Windows Update scan and opening Optional Updates...
usoclient StartScan >nul 2>&1
start ms-settings:windowsupdate-optionalupdates
call :LOG INFO "Driver, firmware, and Windows Update check started."
call :RESULT OK
pause
goto DEPLOYMENT_TOOLS

:DEPLOYMENT_CHECKS
call :PREFLIGHT
if errorlevel 1 (call :RESULT FAIL) else (call :RESULT OK)
pause
goto DEPLOYMENT_TOOLS

:DEPLOYMENT_CONFIG
if not exist "%CONFIG_FILE%" (
    >"%CONFIG_FILE%" echo # Odyssey configuration - use NAME=VALUE
    >>"%CONFIG_FILE%" echo DRY_RUN=0
    >>"%CONFIG_FILE%" echo CREATE_RESTORE_POINT=1
    echo [OK] Configuration created at %CONFIG_FILE%
) else (
    echo [INFO] Current configuration:
    type "%CONFIG_FILE%"
)
pause
goto DEPLOYMENT_TOOLS

:SETUP_SUMMARY
echo.
echo ================================================================
echo                         SESSION SUMMARY
echo ================================================================
echo Successful: %SUCCESS_COUNT%
echo Failed:     %FAIL_COUNT%
echo Skipped:    %SKIP_COUNT%
echo Log file:   %LOG_FILE%
if "%REBOOT_REQUIRED%"=="1" (
    echo Restart required: YES
    set /p "restartChoice=Restart now? (Y/N): "
    if /i "!restartChoice!"=="Y" shutdown /r /t 0
) else (
    echo Restart required: NO
)
pause
goto MENU

:RESUME_AFTER_RESTART
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v OdysseyResume /f >nul 2>&1
echo [OK] Odyssey resumed after the restart.
echo [INFO] The previous setup run completed before restarting. Review Windows Update and the latest log in %LOG_DIR%.
call :LOG INFO "Post-restart resume completed."
pause
goto MENU

:PREFLIGHT
echo [INFO] Running preflight checks...
powershell -NoProfile -Command "if ([Environment]::OSVersion.Version.Major -lt 10) { exit 1 }"
if errorlevel 1 (
    echo [ERROR] Windows 10 or Windows 11 is required.
    call :LOG ERROR "Unsupported Windows version."
    exit /b 1
)
powershell -NoProfile -Command "try { $null=Invoke-WebRequest -Uri 'https://www.microsoft.com' -Method Head -TimeoutSec 8 -UseBasicParsing; exit 0 } catch { exit 1 }"
if errorlevel 1 (
    echo [ERROR] No working Internet connection was detected.
    call :LOG ERROR "Internet connectivity check failed."
    exit /b 1
)
where winget >nul 2>&1
if errorlevel 1 echo [WARN] winget is unavailable; application steps may be skipped.
echo [OK] Preflight checks passed.
call :LOG INFO "Preflight checks passed."
exit /b 0

:CREATE_RESTORE_POINT
if /i "%CREATE_RESTORE_POINT%"=="0" (
    echo [SKIP] Restore-point creation disabled by configuration.
    call :RESULT SKIP
    exit /b 0
)
echo [INFO] Creating a system restore point...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction SilentlyContinue; Checkpoint-Computer -Description 'Odyssey before changes' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop; exit 0 } catch { exit 1 }"
if errorlevel 1 (
    echo [WARN] Restore point could not be created. System Protection may be disabled or Windows may be rate-limiting restore points.
    call :LOG WARN "Restore point creation failed."
    call :RESULT FAIL
) else (
    echo [OK] Restore point created.
    call :LOG INFO "Restore point created."
    call :RESULT OK
)
exit /b 0

:REGISTER_RESUME
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v OdysseyResume /t REG_SZ /d "\"%~f0\" /resume" /f >nul 2>&1
if errorlevel 1 (
    call :LOG WARN "Could not register restart resume."
) else (
    call :LOG INFO "Restart resume registered."
)
exit /b

:RESULT
if /i "%~1"=="OK" set /a SUCCESS_COUNT+=1
if /i "%~1"=="FAIL" set /a FAIL_COUNT+=1
if /i "%~1"=="SKIP" set /a SKIP_COUNT+=1
call :LOG INFO "Result recorded: %~1"
exit /b

:LOG
>>"%LOG_FILE%" echo [%date% %time%] [%~1] %~2
exit /b