# Java Uninstaller Script
A PowerShell script for completely uninstalling Java versions from Windows systems.

## ✨ Features

- Automatically detects installed Java versions (Oracle, OpenJDK, Adoptium)
- Uninstalls Java from Windows systems with vendor-specific handling
- Handles both 32-bit and 64-bit Java installations
- Removes registry entries and environment variables
- Stops Java services and processes
- Verifies complete removal
- Detailed logging of all operations
- Force removal option for stubborn installations

## 📋 Requirements

- Windows operating system
- PowerShell 5.1 or higher
- Administrator privileges

## 🚀 Usage

### Download the latest 'JavaUninstaller.ps1' script from [Releases](../../releases) section and run it in PowerShell:

```powershell
# Normal usage with confirmation
.\JavaUninstaller.ps1

# Skip confirmation
.\JavaUninstaller.ps1 -Force

# Specify custom log path
.\JavaUninstaller.ps1 -LogPath "C:\Logs\java_removal.log"
```

## 🔧 Common Issues and Solutions

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

### Java Still Present After Uninstallation
- Check if Java was installed in a non-default location
- Run the script with `-Force` parameter
- Check the log file for any error messages
- Manually remove any remaining directories after script completion

## ⚠️ Important Notes

- This script may not clear Java installations if you changed the default installation directory
- Always backup important data before running uninstallation scripts
- The script requires administrator privileges
- Some Java-dependent applications might stop working after uninstallation
- Check the log file (JavaRemoval_[timestamp].log) for detailed operation information

## Supported Java Distributions

- Oracle Java
- OpenJDK
- Eclipse Adoptium
- Microsoft OpenJDK
- AdoptOpenJDK

## 🌟 Support

If this script helped you, please give it a **STAR** ⭐ as it helps others find this script.
