# Java Uninstaller Script

A PowerShell script for automatically uninstalling Java versions from Windows systems.

## Features

- Automatically detects installed Java versions
- Uninstalls Java from Windows systems
- Handles both 32-bit and 64-bit Java installations
- Runs with elevated privileges for proper uninstallation

## Requirements

- Windows operating system
- PowerShell 5.1 or higher
- Administrator privileges

## Usage

### Method 1: Direct Execution (Fastest)
Open PowerShell as Administrator and run:
```powershell
irm https://raw.githubusercontent.com/RezoxP/java-vanisher/main/JavaUninstaller.ps1 | iex
```


## Common Issues and Solutions

### Execution Policy Error
If you get an execution policy error, run PowerShell as Administrator and try:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\JavaUninstaller.ps1
```

### Access Denied
- Make sure you're running PowerShell as Administrator
- Right-click the script → Properties → Check "Unblock" if present
- Ensure you have full permissions to the script directory

## Note

- This script may not clear all java installings if you had changed the default installation directory. 
- Always backup important data before running uninstallation scripts.
- The script requires administrator privileges.
- Some Java-dependent applications might stop working after uninstallation.

## Donate
- If you like my script and helped you, pls give a **STAR** as it helps people to find this script
