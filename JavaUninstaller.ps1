# Java Uninstaller Script
# Run this script as Administrator to completely remove Java and all its traces from Windows
# Compatible with PowerShell 5.1 and 7.x

# Version check and compatibility settings
$PSVersionTable.PSVersion | Out-Null
$script:isPSCore = $PSVersionTable.PSEdition -eq 'Core'
$script:runningOnWindows = if ($isPSCore) { $IsWindows } else { $true }

if (-not $script:runningOnWindows) {
    Write-Error "This script must be run on Windows."
    exit 1
}

# Set error action preference to stop on any error
$ErrorActionPreference = "Stop"

# Initialize logging
$scriptPath = $PSScriptRoot
if (-not $scriptPath) {
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$logFile = Join-Path -Path $scriptPath -ChildPath "JavaRemoval_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$global:removedItems = @()
$global:foundItems = @()

function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Type = "INFO"  # INFO, WARNING, ERROR, SUCCESS, FOUND, REMOVED
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] $Type - $Message"
    
    # Add color to console output
    switch ($Type) {
        "WARNING" { 
            if ($script:isPSCore) {
                Write-Warning $logMessage
            } else {
                $host.UI.WriteWarningLine($logMessage)
            }
        }
        "ERROR" { 
            if ($script:isPSCore) {
                Write-Error $logMessage -ErrorAction Continue
            } else {
                $host.UI.WriteErrorLine($logMessage)
            }
        }
        "SUCCESS" { 
            Write-Host $logMessage -ForegroundColor Green
        }
        "FOUND" { 
            Write-Host $logMessage -ForegroundColor Cyan
        }
        "REMOVED" { 
            Write-Host $logMessage -ForegroundColor Magenta
        }
        default { 
            Write-Host $logMessage
        }
    }
    
    # Write to log file
    try {
        $logMessage | Out-File -FilePath $logFile -Append -Encoding utf8 -ErrorAction Stop
    }
    catch {
        $errorMsg = "Failed to write to log file: $_"
        if ($script:isPSCore) {
            Write-Error $errorMsg -ErrorAction Continue
        } else {
            $host.UI.WriteErrorLine($errorMsg)
        }
    }
    
    # Store items based on type
    if ($Type -eq "FOUND") {
        $global:foundItems += $Message
    }
    elseif ($Type -eq "REMOVED") {
        $global:removedItems += $Message
    }
}

function Test-AdminPrivileges {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
        return $principal.IsInRole($adminRole)
    }
    catch {
        Write-LogMessage "Error checking admin privileges: $_" -Type "ERROR"
        return $false
    }
}

function Test-IsJavaRelated {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    
    $javaPatterns = @(
        '^java',
        '^jdk',
        '^jre',
        'oracle.*java',
        'java.*oracle',
        'hotspot',
        'javaw?\.exe$',
        'javac\.exe$',
        'javaws\.exe$',
        'javaupdate',
        'jusched',
        'java.*update',
        'java.*web.*start',
        'java.*cache',
        'java.*control.*panel'
    )

    foreach ($pattern in $javaPatterns) {
        if ($Name -match $pattern) {
            return $true
        }
    }
    return $false
}

function Find-JavaInstallations {
    Write-LogMessage "Scanning for Java installations..."
    
    $javaInstalls = @()
    
    # Check both 32-bit and 64-bit registry locations
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $regPaths) {
        try {
            if (Test-Path -Path $path) {
                $items = Get-ItemProperty -Path $path -ErrorAction Stop
                foreach ($item in $items) {
                    if (($item.DisplayName -like "*Java*" -or 
                         $item.DisplayName -like "*JDK*" -or 
                         $item.DisplayName -like "*JRE*") -and
                        ($item.Publisher -like "*Oracle*" -or 
                         $item.Publisher -like "*Sun Microsystems*" -or
                         $item.Publisher -like "*Eclipse Adoptium*" -or
                         $item.Publisher -like "*Eclipse Foundation*")) {
                        
                        $javaInstalls += $item
                        Write-LogMessage "Found Java installation: $($item.DisplayName) - $($item.DisplayVersion)" -Type "FOUND"
                    }
                }
            }
        }
        catch {
            Write-LogMessage "Error accessing registry path $path`: $_" -Type "ERROR"
        }
    }
    
    return $javaInstalls
}

function Find-JavaTraces {
    Write-LogMessage "Scanning for Java traces..."
    $traces = @()
    
    # Common Java installation directories
    $commonPaths = @(
        (Join-Path -Path $env:ProgramFiles -ChildPath "Java"),
        (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Java"),
        (Join-Path -Path $env:ProgramFiles -ChildPath "Common Files\Oracle\Java"),
        (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Common Files\Oracle\Java"),
        (Join-Path -Path $env:SystemDrive -ChildPath "Program Files\Eclipse Adoptium"),
        (Join-Path -Path $env:SystemDrive -ChildPath "Program Files\Eclipse Foundation"),
        (Join-Path -Path $env:LOCALAPPDATA -ChildPath "Programs\Common\Oracle\Java"),
        (Join-Path -Path $env:APPDATA -ChildPath "Sun\Java"),
        (Join-Path -Path $env:LOCALAPPDATA -ChildPath "Sun\Java"),
        (Join-Path -Path $env:USERPROFILE -ChildPath ".java"),
        (Join-Path -Path $env:ALLUSERSPROFILE -ChildPath "Oracle\Java")
    )
    
    # Scan directories
    foreach ($path in $commonPaths) {
        try {
            if (Test-Path -Path $path) {
                Write-LogMessage "Found Java-related directory: $path" -Type "FOUND"
                $traces += $path
            }
        }
        catch {
            Write-LogMessage "Error accessing path $path`: $_" -Type "ERROR"
        }
    }
    
    # Scan environment variables
    $envVars = @('JAVA_HOME', 'JDK_HOME', 'JRE_HOME')
    foreach ($var in $envVars) {
        try {
            $machineVal = [Environment]::GetEnvironmentVariable($var, 'Machine')
            $userVal = [Environment]::GetEnvironmentVariable($var, 'User')
            if ($machineVal -or $userVal) {
                Write-LogMessage "Found Java environment variable: $var" -Type "FOUND"
                $traces += "ENV:$var"
            }
        }
        catch {
            Write-LogMessage "Error checking environment variable $var`: $_" -Type "ERROR"
        }
    }
    
    # Check PATH for Java entries
    try {
        $machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
        $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
        
        if ($machinePath) {
            $pathEntries = $machinePath.Split(';')
            foreach ($entry in $pathEntries) {
                if ($entry -and (Test-IsJavaRelated $entry)) {
                    Write-LogMessage "Found Java PATH entry (Machine): $entry" -Type "FOUND"
                    $traces += "PATH:$entry"
                }
            }
        }
        
        if ($userPath) {
            $pathEntries = $userPath.Split(';')
            foreach ($entry in $pathEntries) {
                if ($entry -and (Test-IsJavaRelated $entry)) {
                    Write-LogMessage "Found Java PATH entry (User): $entry" -Type "FOUND"
                    $traces += "PATH:$entry"
                }
            }
        }
    }
    catch {
        Write-LogMessage "Error checking PATH entries: $_" -Type "ERROR"
    }
    
    return $traces
}

function Remove-JavaInstallation {
    param(
        [Parameter(Mandatory=$true)]
        $Installation
    )
    
    try {
        $uninstallString = $Installation.UninstallString
        $displayName = $Installation.DisplayName
        
        if ([string]::IsNullOrEmpty($uninstallString)) {
            Write-LogMessage "No uninstall string found for $displayName" -Type "WARNING"
            return
        }
        
        Write-LogMessage "Uninstalling $displayName..."
        
        if ($uninstallString -like "*msiexec*") {
            $productCode = [regex]::Match($uninstallString, "{[0-9A-F-]+}").Value
            if ($productCode) {
                $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $productCode /qn /norestart" -Wait -PassThru -WindowStyle Hidden
            }
            else {
                Write-LogMessage "Could not extract product code from uninstall string: $uninstallString" -Type "ERROR"
                return
            }
        }
        else {
            # Handle non-MSI uninstallers
            $process = Start-Process -FilePath $uninstallString -ArgumentList "/s" -Wait -PassThru -WindowStyle Hidden
        }
        
        if ($process.ExitCode -eq 0) {
            Write-LogMessage "Successfully uninstalled $displayName" -Type "SUCCESS"
            Write-LogMessage $displayName -Type "REMOVED"
        }
        else {
            Write-LogMessage "Failed to uninstall $displayName (Exit code: $($process.ExitCode))" -Type "ERROR"
        }
    }
    catch {
        Write-LogMessage "Error uninstalling $($Installation.DisplayName): $_" -Type "ERROR"
    }
}

function Clear-JavaTraces {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [array]$Traces
    )
    
    if ($null -eq $Traces) {
        Write-LogMessage "No Java traces found to remove." -Type "INFO"
        return
    }
    
    foreach ($trace in $Traces) {
        try {
            if ($null -eq $trace) { continue }
            
            if ($trace.StartsWith("ENV:")) {
                $varName = $trace.Substring(4)
                [Environment]::SetEnvironmentVariable($varName, $null, 'Machine')
                [Environment]::SetEnvironmentVariable($varName, $null, 'User')
                Write-LogMessage "Removed environment variable: $varName" -Type "SUCCESS"
                Write-LogMessage $trace -Type "REMOVED"
            }
            elseif ($trace.StartsWith("PATH:")) {
                $pathEntry = $trace.Substring(5)
                $machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
                $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
                
                if ($machinePath) {
                    $newMachinePath = ($machinePath.Split(';') | Where-Object { $_ -ne $pathEntry -and $_ }) -join ';'
                    [Environment]::SetEnvironmentVariable('PATH', $newMachinePath, 'Machine')
                }
                
                if ($userPath) {
                    $newUserPath = ($userPath.Split(';') | Where-Object { $_ -ne $pathEntry -and $_ }) -join ';'
                    [Environment]::SetEnvironmentVariable('PATH', $newUserPath, 'User')
                }
                
                Write-LogMessage "Removed PATH entry: $pathEntry" -Type "SUCCESS"
                Write-LogMessage $trace -Type "REMOVED"
            }
            else {
                if (Test-Path -Path $trace) {
                    Remove-Item -Path $trace -Recurse -Force -ErrorAction Stop
                    Write-LogMessage "Removed directory: $trace" -Type "SUCCESS"
                    Write-LogMessage $trace -Type "REMOVED"
                }
            }
        }
        catch {
            Write-LogMessage "Error removing trace $trace`: $_" -Type "ERROR"
        }
    }
}

function Clear-JavaBrowserPlugins {
    Write-LogMessage "Cleaning Java browser plugins..."
    
    # Browser plugin directories
    $browserLocations = @{
        Chrome = @(
            (Join-Path -Path $env:LOCALAPPDATA -ChildPath "Google\Chrome\User Data\Default\Extensions"),
            (Join-Path -Path $env:LOCALAPPDATA -ChildPath "Google\Chrome\User Data\Default\Local Extension Settings")
        )
        Firefox = @(
            (Join-Path -Path $env:APPDATA -ChildPath "Mozilla\Firefox\Profiles"),
            (Join-Path -Path $env:PROGRAMFILES -ChildPath "Mozilla Firefox\browser\extensions"),
            (Join-Path -Path ${env:PROGRAMFILES(x86)} -ChildPath "Mozilla Firefox\browser\extensions")
        )
        Edge = @(
            (Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Edge\User Data\Default\Extensions"),
            (Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Edge\User Data\Default\Local Extension Settings")
        )
    }
    
    foreach ($browser in $browserLocations.Keys) {
        foreach ($location in $browserLocations[$browser]) {
            try {
                if (Test-Path -Path $location) {
                    $items = Get-ChildItem -Path $location -Recurse -ErrorAction Stop
                    foreach ($item in $items) {
                        if (Test-IsJavaRelated $item.Name) {
                            try {
                                Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                                Write-LogMessage "Removed $browser plugin: $($item.FullName)" -Type "SUCCESS"
                                Write-LogMessage $item.FullName -Type "REMOVED"
                            }
                            catch {
                                Write-LogMessage "Error removing $browser plugin $($item.FullName): $_" -Type "ERROR"
                            }
                        }
                    }
                }
            }
            catch {
                Write-LogMessage "Error accessing $browser plugins in $location`: $_" -Type "ERROR"
            }
        }
    }
}

function Clear-JavaRegistry {
    Write-LogMessage "Cleaning Java registry entries..." -Type "INFO"
    
    $registryPaths = @(
        # Main Java registry keys
        "HKLM:\SOFTWARE\JavaSoft",
        "HKLM:\SOFTWARE\WOW6432Node\JavaSoft",
        
        # Java Update registry keys
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SunJavaUpdateSched",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\SunJavaUpdateSched",
        
        # Java deployment registry keys
        "HKCU:\Software\JavaSoft",
        "HKCU:\Software\AppDataLow\Software\JavaSoft",
        
        # Java Runtime registry keys
        "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{08B0E5C0-4FCB-11CF-AAA5-00401C608500}",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\{08B0E5C0-4FCB-11CF-AAA5-00401C608500}"
    )
    
    # Add these paths to the traces for user confirmation
    $registryPaths | ForEach-Object {
        if (Test-Path -Path $_) {
            $global:foundItems += "Registry: $_"
            Write-LogMessage "Found Java registry key: $_" -Type "FOUND"
        }
    }
    
    # Remove registry keys
    foreach ($path in $registryPaths) {
        try {
            if (Test-Path -Path $path) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-LogMessage "Removed registry key: $path" -Type "SUCCESS"
                Write-LogMessage "Registry: $path" -Type "REMOVED"
            }
        }
        catch {
            Write-LogMessage "Error removing registry key $path`: $_" -Type "ERROR"
        }
    }
    
    # Clean Java-related environment variables from registry
    $envRegPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        "HKCU:\Environment"
    )
    
    foreach ($envPath in $envRegPaths) {
        try {
            $envRegKey = Get-Item -Path $envPath -ErrorAction Stop
            $envRegKey.GetValueNames() | ForEach-Object {
                if ($_ -like "*JAVA*" -or $_ -like "*JDK*" -or $_ -like "*JRE*") {
                    Write-LogMessage "Found Java environment variable in registry: $_" -Type "FOUND"
                    $global:foundItems += "Registry ENV: $_"
                    try {
                        Remove-ItemProperty -Path $envPath -Name $_ -ErrorAction Stop
                        Write-LogMessage "Removed environment variable from registry: $_" -Type "SUCCESS"
                        Write-LogMessage "Registry ENV: $_" -Type "REMOVED"
                    }
                    catch {
                        Write-LogMessage "Error removing environment variable $_ from registry: $_" -Type "ERROR"
                    }
                }
            }
        }
        catch {
            Write-LogMessage "Error accessing registry path $envPath`: $_" -Type "ERROR"
        }
    }
}

function Get-UserConfirmation {
    param (
        [array]$Installations,
        [array]$Traces
    )
    
    Write-Host "`n=== Items to be Removed ===" -ForegroundColor Yellow
    
    if ($Installations.Count -gt 0) {
        Write-Host "`nJava Installations:" -ForegroundColor Cyan
        foreach ($install in $Installations) {
            Write-Host "  - $($install.DisplayName) - $($install.DisplayVersion)" -ForegroundColor White
        }
    }
    
    if ($Traces.Count -gt 0) {
        Write-Host "`nJava Traces (Files and Directories):" -ForegroundColor Cyan
        foreach ($trace in $Traces) {
            if (-not $trace.StartsWith("Registry")) {
                Write-Host "  - $trace" -ForegroundColor White
            }
        }
    }
    
    if ($global:foundItems.Count -gt 0) {
        Write-Host "`nRegistry Items:" -ForegroundColor Cyan
        $global:foundItems | Where-Object { $_.StartsWith("Registry") } | ForEach-Object {
            Write-Host "  - $_" -ForegroundColor White
        }
    }
    
    $totalItems = $Installations.Count + $Traces.Count + ($global:foundItems | Where-Object { $_.StartsWith("Registry") }).Count
    Write-Host "`nTotal items to remove: $totalItems" -ForegroundColor Yellow
    
    do {
        $response = Read-Host "`nDo you want to proceed with removal? (Y/N)"
        $response = $response.Trim().ToUpper()
    } while ($response -notin @('Y', 'N'))
    
    return $response -eq 'Y'
}

# Main execution
try {
    Write-LogMessage "=== Java Uninstaller Script Started ===" -Type "INFO"
    
    # Check for admin privileges
    if (-not (Test-AdminPrivileges)) {
        Write-LogMessage "This script requires administrator privileges. Please run as administrator." -Type "ERROR"
        exit 1
    }
    
    # Find Java installations and traces first
    $installations = @(Find-JavaInstallations)
    $traces = @(Find-JavaTraces)
    
    if ($installations.Count -eq 0 -and $traces.Count -eq 0) {
        Write-LogMessage "No Java components found to remove." -Type "INFO"
        exit 0
    }
    
    # Get user confirmation
    if (-not (Get-UserConfirmation -Installations $installations -Traces $traces)) {
        Write-LogMessage "Operation cancelled by user." -Type "WARNING"
        exit 0
    }
    
    Write-LogMessage "Starting removal process..." -Type "INFO"
    
    # Stop Java-related processes
    Get-Process | Where-Object { Test-IsJavaRelated $_.Name } | ForEach-Object {
        try {
            $_ | Stop-Process -Force -ErrorAction Stop
            Write-LogMessage "Stopped process: $($_.Name)" -Type "SUCCESS"
        }
        catch {
            Write-LogMessage "Failed to stop process $($_.Name): $_" -Type "WARNING"
        }
    }
    
    # Remove Java installations
    if ($installations.Count -gt 0) {
        foreach ($install in $installations) {
            Remove-JavaInstallation $install
        }
    } else {
        Write-LogMessage "No Java installations found." -Type "INFO"
    }
    
    # Clear Java traces
    if ($traces.Count -gt 0) {
        Clear-JavaTraces -Traces $traces
    } else {
        Write-LogMessage "No Java traces found." -Type "INFO"
    }
    
    # Clean browser plugins
    Clear-JavaBrowserPlugins
    
    # Clean registry
    Clear-JavaRegistry
    
    Write-LogMessage "=== Java Uninstaller Script Completed ===" -Type "SUCCESS"
    Write-LogMessage "Total items removed: $($global:removedItems.Count)" -Type "SUCCESS"
    
    # Display summary
    if ($global:removedItems.Count -gt 0) {
        Write-LogMessage "=== Removal Summary ===" -Type "INFO"
        $global:removedItems | ForEach-Object {
            Write-LogMessage $_ -Type "REMOVED"
        }
    } else {
        Write-LogMessage "No items were removed." -Type "INFO"
    }
    
    Write-LogMessage "Log file created at: $logFile" -Type "INFO"
}
catch {
    $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_ }
    Write-LogMessage "Fatal error: $errorMessage" -Type "ERROR"
    exit 1
}
