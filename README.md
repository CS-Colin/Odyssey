# Odyssey V1 Pre-Alpha

This repository contains a Windows batch script (`Main.cmd`) that provides a text-based menu system for performing a wide variety of administrative, utility, and system maintenance tasks on a Windows machine. The script is intended for use in an IT or support environment where quick access to common fixes and tools is required.

> **⚠️ Administrator privileges are required.** The script checks for elevated rights on startup and will exit if not run as an administrator.

---

## Features

The main menu of the script is organized into several submenus:

### Main Setup
- Placeholder for future setup routines (not currently implemented).

### Administration Menu
- Disable/enable BitLocker
- Create new local user accounts
- Apply Gamco registry setup fix
- Change computer name
- Set local administrator password
- Join a domain or workgroup
- Enable/disable Remote Desktop and Windows Firewall
- Clear Windows event logs
- Manage Windows services
- View Windows Update history
- Enable/disable User Account Control (UAC)
- Export/import local group policy

### Utilities Menu
- Launch tools such as MassGrave (and an alternative), system information report, disk cleanup
- Check and install Windows updates
- Network troubleshooter, Device/Task Manager, Control Panel
- Backup user data or restore the system from a restore point
- Run SFC/DISM for system health
- Quick navigation to Documents folder
- About/credits information and reboot/shutdown options

### Windows Hot Fixes Menu
- Fix BitLocker encryption error code `0x8004100e`
- Disable UDP for Remote Desktop Protocol (RDP) for network stability

### Windows Debloater Menu
- Run community debloat scripts (Sycnex or Chris Titus)

---

## Getting Started

1. **Clone or download** the repository to a Windows machine.
2. Open an elevated command prompt ("Run as administrator").
3. Navigate to the `Main` directory:
   ```batch
   cd \path\to\Oddssey\Master
   ```
4. Execute the script:
   ```batch
   Main.cmd
   ```

   Alternatively you can run the script directly from PowerShell with an internet download:
   ```powershell
   irm get.bhnetworks.co.za | iex
   ```

5. Follow the on-screen prompts to select the desired action.

---

## Notes & Troubleshooting

- The `Main.cmd` script uses `setlocal EnableDelayedExpansion` and relies on standard Windows command-line tools (`reg`, `mofcomp`, `powershell`, etc.).
- When invoking external debloat scripts or other PowerShell commands, ensure there is network connectivity.
- Some actions (e.g., disabling UDP for RDP, changing the computer name) may require a system reboot to take effect.
- Always review the output of any automated fixes before closing the session to verify success.

---

## License

This project is provided "as-is" with no warranty. Feel free to adapt or redistribute the script according to your needs.

---

*Created on February 24, 2026.*
