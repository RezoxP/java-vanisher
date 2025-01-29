# Java Uninstaller Script - Simple Version
# This script can be run with: irm <url> | iex

# Security protocol settings
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Self-elevate if not running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/RezoxP/java-vanisher/main/JavaUninstaller.ps1'))`"" -Wait
        exit
    }
    catch {
        Write-Warning "Failed to elevate privileges. Some features may not work correctly."
    }
}

# Download and execute the main script
$mainScript = (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/RezoxP/java-vanisher/main/JavaUninstaller.ps1')
if ($mainScript) {
    Invoke-Expression $mainScript
} else {
    Write-Error "Failed to download the main script"
    exit 1
}
