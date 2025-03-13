## Script to fully restore Windows Update functionality
## Run as Administrator

# Script name: Restore-Windows-Updates.ps1
# Author: Claude
# Description: Completely restores Windows Update functionality by reversing all blocking measures

# Check for administrator rights
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please restart with elevated privileges." -ForegroundColor Red
    exit
}

Write-Host "Windows Update Restoration Tool" -ForegroundColor Cyan
Write-Host "==============================`n" -ForegroundColor Cyan

# Function to create a restore point before making changes
function Create-RestorePoint {
    Write-Host "Creating system restore point..." -ForegroundColor Yellow
    Enable-ComputerRestore -Drive "$env:SystemDrive"
    Checkpoint-Computer -Description "Before Windows Update Restoration" -RestorePointType "MODIFY_SETTINGS"
}

# Function to restore Windows Update service
function Restore-WindowsUpdateService {
    Write-Host "Restoring Windows Update service..." -ForegroundColor Yellow
    
    # Reset Windows Update service
    Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "wuauserv" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    
    # Re-enable other related services
    $updateServices = @("BITS", "DoSvc", "UsoSvc")
    foreach ($service in $updateServices) {
        Set-Service -Name $service -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name $service -ErrorAction SilentlyContinue
    }
    
    $serviceStatus = @()
    foreach ($service in (@("wuauserv") + $updateServices)) {
        $status = Get-Service -Name $service -ErrorAction SilentlyContinue
        $serviceStatus += [PSCustomObject]@{
            Service = $service
            Status = if ($status) { $status.Status } else { "Not Found" }
            StartType = if ($status) { $status.StartType } else { "N/A" }
        }
    }
    
    Write-Host "`nUpdate Services Status:" -ForegroundColor Cyan
    $serviceStatus | Format-Table -AutoSize
}

# Function to restore Windows Update registry settings
function Restore-WindowsUpdateRegistry {
    Write-Host "Restoring Windows Update registry settings..." -ForegroundColor Yellow
    
    $WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $AUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    
    # Remove registry keys that disable updates
    if (Test-Path $AUPath) {
        # Reset AU settings to defaults
        $registryKeys = @(
            "NoAutoUpdate",
            "AUOptions",
            "EnableFeaturedSoftware",
            "IncludeRecommendedUpdates"
        )
        
        foreach ($key in $registryKeys) {
            Remove-ItemProperty -Path $AUPath -Name $key -ErrorAction SilentlyContinue
        }
    }
    
    # Also check and remove blocking settings in the parent WindowsUpdate key
    if (Test-Path $WUPath) {
        $parentKeys = @(
            "DisableWindowsUpdateAccess",
            "SetUpdateNotificationLevel",
            "ElevateNonAdmins"
        )
        
        foreach ($key in $parentKeys) {
            Remove-ItemProperty -Path $WUPath -Name $key -ErrorAction SilentlyContinue
        }
    }
    
    # Reset metered connection settings
    Write-Host "Restoring network connection settings..." -ForegroundColor Yellow
    
    # For Ethernet
    # For the Ethernet metered connection section in Restore-WindowsUpdateRegistry function:

# Reset metered connection settings
Write-Host "Restoring network connection settings..." -ForegroundColor Yellow

# For Ethernet
$ethernetPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost"
if (Test-Path $ethernetPath) {
    Write-Host "Attempting to reset Ethernet metered connection setting..." -ForegroundColor Yellow
    
    try {
        # First try direct modification
        Set-ItemProperty -Path $ethernetPath -Name "Ethernet" -Value 1 -Type DWord -Force -ErrorAction Stop
        Write-Host "Successfully reset Ethernet metered connection." -ForegroundColor Green
    } 
    catch {
        Write-Host "Standard method failed, trying alternative approach..." -ForegroundColor Yellow
        
        try {
            # Try using reg.exe command instead (sometimes works when PowerShell fails)
            $regResult = Start-Process -FilePath "reg.exe" -ArgumentList "add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost`" /v Ethernet /t REG_DWORD /d 1 /f" -Wait -PassThru -Verb RunAs -ErrorAction Stop
            
            if ($regResult.ExitCode -eq 0) {
                Write-Host "Successfully reset Ethernet metered connection using reg.exe." -ForegroundColor Green
            } else {
                throw "reg.exe returned exit code $($regResult.ExitCode)"
            }
        }
        catch {
            Write-Host "Could not reset Ethernet metered connection setting." -ForegroundColor Yellow
            Write-Host "This setting may need to be manually changed after script completion:" -ForegroundColor Yellow
            Write-Host "1. Open Registry Editor (regedit.exe)" -ForegroundColor Cyan
            Write-Host "2. Navigate to: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" -ForegroundColor Cyan
            Write-Host "3. Change the 'Ethernet' value to 1" -ForegroundColor Cyan
        }
    }
} else {
    Write-Host "Ethernet metered connection registry path not found, this is unusual but not critical." -ForegroundColor Yellow
}
    
    # For Wi-Fi
    try {
        $networkInterfaces = Get-NetConnectionProfile
        foreach ($interface in $networkInterfaces) {
            $interfaceName = $interface.InterfaceAlias
            # For Wi-Fi
            if (Get-NetAdapter -Name $interfaceName -ErrorAction SilentlyContinue | Where-Object { $_.MediaType -eq "802.11" }) {
                $registryPath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\$interfaceName"
                if (Test-Path $registryPath) {
                    Remove-ItemProperty -Path $registryPath -Name "Cost" -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {
        Write-Host "Failed to reset Wi-Fi metered connection settings: $_" -ForegroundColor Yellow
    }
}

# Function to restore hosts file
function Restore-HostsFile {
    Write-Host "Restoring hosts file (removing only Windows Update entries)..." -ForegroundColor Yellow
    
    $hostsFile = "$env:windir\System32\drivers\etc\hosts"
    $domains = @(
        "update.microsoft.com",
        "windowsupdate.microsoft.com",
        "windowsupdate.com",
        "download.windowsupdate.com",
        "download.microsoft.com",
        "wustat.windows.com",
        "ntservicepack.microsoft.com",
        "stats.microsoft.com"
    )
    
    try {
        # Read the current hosts file
        $hostsContent = Get-Content -Path $hostsFile -ErrorAction Stop
        
        # Initialize an array to store the filtered content
        $newHostsContent = @()
        
        # Process each line of the hosts file
        foreach ($line in $hostsContent) {
            $shouldKeep = $true
            
            # Check if the line contains any Windows Update domain
            foreach ($domain in $domains) {
                if ($line -match $domain) {
                    $shouldKeep = $false
                    break
                }
            }
            
            # Keep the line if it doesn't contain any Windows Update domain
            if ($shouldKeep) {
                $newHostsContent += $line
            }
        }
        
        # Check if hosts file has default localhost entries, add them if missing
        $hasLocalhost = $false
        $hasIPv6Localhost = $false
        
        foreach ($line in $newHostsContent) {
            if ($line -match "127\.0\.0\.1\s+localhost") {
                $hasLocalhost = $true
            }
            if ($line -match "::1\s+localhost") {
                $hasIPv6Localhost = $true
            }
        }
        
        # Add default entries if missing
        if (-not $hasLocalhost) {
            $newHostsContent += "127.0.0.1 localhost"
        }
        if (-not $hasIPv6Localhost) {
            $newHostsContent += "::1 localhost"
        }
        
        # Write back the cleaned hosts file
        Set-Content -Path $hostsFile -Value $newHostsContent -Force
        
        Write-Host "Hosts file restored successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to restore hosts file: $_" -ForegroundColor Red
    }
}

# Function to re-enable Windows Update scheduled tasks
function Enable-WindowsUpdateTasks {
    Write-Host "Re-enabling Windows Update scheduled tasks..." -ForegroundColor Yellow
    
    try {
        # Enable the main Windows Update tasks
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\UpdateOrchestrator\" -ErrorAction SilentlyContinue | 
            Enable-ScheduledTask -ErrorAction SilentlyContinue
        
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -ErrorAction SilentlyContinue | 
            Enable-ScheduledTask -ErrorAction SilentlyContinue
        
        Get-ScheduledTask -TaskName "UsbCeip" -ErrorAction SilentlyContinue | 
            Enable-ScheduledTask -ErrorAction SilentlyContinue
        
        # Remove our blocking scheduled task if it exists
        Unregister-ScheduledTask -TaskName "BlockWindowsUpdates" -Confirm:$false -ErrorAction SilentlyContinue
        
        Write-Host "Windows Update scheduled tasks re-enabled." -ForegroundColor Green
    } catch {
        Write-Host "Failed to re-enable some scheduled tasks: $_" -ForegroundColor Yellow
    }
}

# Function to check Windows Update status
function Check-WindowsUpdateStatus {
    Write-Host "`nVerifying Windows Update restoration..." -ForegroundColor Yellow
    
    $updateService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    
    if ($updateService) {
        Write-Host "Windows Update Service: $($updateService.Status) (StartType: $($updateService.StartType))" -ForegroundColor $(
            if($updateService.Status -eq "Running" -and $updateService.StartType -eq "Automatic") { "Green" } else { "Yellow" }
        )
    } else {
        Write-Host "Windows Update Service: Not found" -ForegroundColor Red
    }
    
    # Check if important tasks are enabled
    $updateTasks = Get-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -ErrorAction SilentlyContinue
    $enabledTasks = $updateTasks | Where-Object {$_.State -eq "Ready"}
    
    if ($updateTasks) {
        Write-Host "Windows Update Tasks Enabled: $($enabledTasks.Count) of $($updateTasks.Count)" -ForegroundColor $(
            if($enabledTasks.Count -eq $updateTasks.Count) { "Green" } else { "Yellow" }
        )
    } else {
        Write-Host "Windows Update Tasks: None found" -ForegroundColor Yellow
    }
    
    # Force Windows Update to check for updates
    Write-Host "`nRunning Windows Update check to verify connectivity..." -ForegroundColor Yellow
    
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0")
        
        Write-Host "Successfully connected to Windows Update service." -ForegroundColor Green
        Write-Host "Found $($searchResult.Updates.Count) available updates." -ForegroundColor Green
    } catch {
        Write-Host "Failed to check for Windows Updates: $_" -ForegroundColor Red
        Write-Host "You may need to restart the system for changes to take effect." -ForegroundColor Yellow
    }
}

# Run all the restoration functions in sequence
Create-RestorePoint
Restore-WindowsUpdateService
Restore-WindowsUpdateRegistry
Restore-HostsFile
Enable-WindowsUpdateTasks
Check-WindowsUpdateStatus

Write-Host "`nWindows Update functionality has been restored." -ForegroundColor Green
Write-Host "You may need to restart your system for all changes to take effect." -ForegroundColor Yellow
$restart = Read-Host "Would you like to restart now? (Y/N)"
if ($restart.ToUpper() -eq "Y") {
    Write-Host "Restarting system in 10 seconds..." -ForegroundColor Red
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}