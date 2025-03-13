## Script to completely block Windows Updates
## Run as Administrator

# Script name: Block-Windows-Updates.ps1
# Author: Claude
# Description: Completely blocks Windows Update using multiple methods for maximum effectiveness

# Stop and disable Windows Update service
Write-Host "Stopping and disabling Windows Update service..." -ForegroundColor Yellow
Stop-Service -Name "wuauserv" -Force
Set-Service -Name "wuauserv" -StartupType Disabled

# Configure Windows Update registry keys
Write-Host "Configuring registry to block Windows Update..." -ForegroundColor Yellow
$WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$AUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$ShutdownPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\UX\Settings"

# Create paths if they don't exist
if (!(Test-Path $WUPath)) {
    New-Item -Path $WUPath -Force | Out-Null
}
if (!(Test-Path $AUPath)) {
    New-Item -Path $AUPath -Force | Out-Null
}
if (!(Test-Path $ShutdownPath)) {
    New-Item -Path $ShutdownPath -Force | Out-Null
}

# Configure Windows Update policies
Set-ItemProperty -Path $AUPath -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $AUPath -Name "AUOptions" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $AUPath -Name "EnableFeaturedSoftware" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $AUPath -Name "IncludeRecommendedUpdates" -Value 0 -Type DWord -Force

# Hide "Update and Shut Down" and "Update and Restart" options
Write-Host "Hiding update options from shutdown menu..." -ForegroundColor Yellow
Set-ItemProperty -Path $ShutdownPath -Name "HideShutdownUpdates" -Value 1 -Type DWord -Force

# Disable automatic updates via UsoClient
Write-Host "Disabling UsoClient scheduled tasks..." -ForegroundColor Yellow
Get-ScheduledTask -TaskName "UsbCeip" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskPath "\Microsoft\Windows\UpdateOrchestrator\" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue

# Block Windows Update domains in hosts file
Write-Host "Adding Windows Update domains to hosts file..." -ForegroundColor Yellow
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

# Explicitly NOT blocking Defender update domains
Write-Host "Ensuring Microsoft Defender update domains remain accessible..." -ForegroundColor Yellow
$defenderDomains = @(
    "wdcp.microsoft.com",
    "wdcpalt.microsoft.com",
    "go.microsoft.com"
)

# Read hosts file content safely with retry mechanism
function Update-HostsFile {
    param (
        [string]$HostsFilePath,
        [array]$DomainsToBlock
    )

    $maxRetries = 5
    $retryCount = 0
    $success = $false

    while (!$success -and $retryCount -lt $maxRetries) {
        try {
            # Read current hosts file content
            $currentHosts = Get-Content -Path $HostsFilePath -ErrorAction Stop
            
            # Check for each domain and prepare new entries if needed
            $newEntries = @()
            foreach ($domain in $DomainsToBlock) {
                if (!($currentHosts -match $domain)) {
                    $newEntries += "127.0.0.1 $domain"
                }
            }
            
            # If we have new entries, add them all at once (reduces file access)
            if ($newEntries.Count -gt 0) {
                Add-Content -Path $HostsFilePath -Value $newEntries -Force -ErrorAction Stop
            }
            
            $success = $true
            Write-Host "Successfully updated hosts file with $($newEntries.Count) entries" -ForegroundColor Green
        }
        catch {
            $retryCount++
            Write-Host "Attempt $retryCount of $maxRetries - Failed to update hosts file. Retrying in 2 seconds..." -ForegroundColor Yellow
            Write-Host "Error: $_" -ForegroundColor Red
            Start-Sleep -Seconds 2
            
            # On last retry, try alternative method
            if ($retryCount -eq $maxRetries) {
                try {
                    Write-Host "Trying alternative method..." -ForegroundColor Yellow
                    
                    # Create temp file with all content
                    $tempFile = [System.IO.Path]::GetTempFileName()
                    $currentHosts | Set-Content -Path $tempFile -Force
                    
                    # Add new entries to temp file
                    foreach ($domain in $DomainsToBlock) {
                        if (!($currentHosts -match $domain)) {
                            Add-Content -Path $tempFile -Value "127.0.0.1 $domain" -Force
                        }
                    }
                    
                    # Use copy to replace the hosts file (may require different permissions)
                    Copy-Item -Path $tempFile -Destination $HostsFilePath -Force
                    Remove-Item -Path $tempFile -Force
                    
                    $success = $true
                    Write-Host "Hosts file updated successfully using alternative method" -ForegroundColor Green
                }
                catch {
                    Write-Host "Alternative method also failed. Hosts file not fully updated." -ForegroundColor Red
                    Write-Host "Error: $_" -ForegroundColor Red
                }
            }
        }
    }
    
    return $success
}

# Try to update hosts file
$hostsUpdated = Update-HostsFile -HostsFilePath $hostsFile -DomainsToBlock $domains

# If hosts update failed, offer a manual solution
if (!$hostsUpdated) {
    Write-Host "`nUnable to automatically update the hosts file due to access issues." -ForegroundColor Red
    Write-Host "Please add the following entries manually to your hosts file ($hostsFile):" -ForegroundColor Yellow
    foreach ($domain in $domains) {
        Write-Host "127.0.0.1 $domain" -ForegroundColor Cyan
    }
}

# Set connection as metered to prevent updates (works with both Wi-Fi and Ethernet in Windows 11)
Write-Host "Setting network connections as metered..." -ForegroundColor Yellow
# Replace the "Set connection as metered" section with this improved version:

# Set connection as metered to prevent updates (works with both Wi-Fi and Ethernet in Windows 11)
Write-Host "Setting network connections as metered..." -ForegroundColor Yellow
$networkInterfaces = Get-NetConnectionProfile
foreach ($interface in $networkInterfaces) {
    $interfaceName = $interface.InterfaceAlias
    # For Wi-Fi
    if (Get-NetAdapter -Name $interfaceName | Where-Object { $_.MediaType -eq "802.11" }) {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\$interfaceName"
        if (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        try {
            Set-ItemProperty -Path $registryPath -Name "Cost" -Value 2 -Type DWord -Force -ErrorAction Stop
            Write-Host "Successfully set Wi-Fi connection '$interfaceName' as metered." -ForegroundColor Green
        } catch {
            Write-Host "Failed to set Wi-Fi connection '$interfaceName' as metered: $_" -ForegroundColor Yellow
        }
    }
    # For Ethernet
    else {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost"
        if (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        Write-Host "Attempting to set Ethernet connection as metered..." -ForegroundColor Yellow
        
        try {
            # First try direct modification
            Set-ItemProperty -Path $registryPath -Name "Ethernet" -Value 2 -Type DWord -Force -ErrorAction Stop
            Write-Host "Successfully set Ethernet connection as metered." -ForegroundColor Green
        } 
        catch {
            Write-Host "Standard method failed, trying alternative approach..." -ForegroundColor Yellow
            
            try {
                # Try using reg.exe command instead (sometimes works when PowerShell fails)
                $regResult = Start-Process -FilePath "reg.exe" -ArgumentList "add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost`" /v Ethernet /t REG_DWORD /d 2 /f" -Wait -PassThru -Verb RunAs -ErrorAction Stop
                
                if ($regResult.ExitCode -eq 0) {
                    Write-Host "Successfully set Ethernet connection as metered using reg.exe." -ForegroundColor Green
                } else {
                    throw "reg.exe returned exit code $($regResult.ExitCode)"
                }
            }
            catch {
                Write-Host "Could not set Ethernet connection as metered." -ForegroundColor Yellow
                Write-Host "This setting may need to be manually changed after script completion:" -ForegroundColor Yellow
                Write-Host "1. Open Registry Editor (regedit.exe)" -ForegroundColor Cyan
                Write-Host "2. Navigate to: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" -ForegroundColor Cyan
                Write-Host "3. Change the 'Ethernet' value to 2" -ForegroundColor Cyan
                Write-Host "Note: This is just one of multiple methods used to block updates, so the script will continue." -ForegroundColor Yellow
            }
        }
    }
}

# Create a scheduled task to run this script at startup to ensure updates stay blocked
Write-Host "Creating startup task to maintain update blocking..." -ForegroundColor Yellow
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "BlockWindowsUpdates" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force

# Verify blocked status
$updateService = Get-Service -Name "wuauserv"
$updateTasks = Get-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -ErrorAction SilentlyContinue | Where-Object {$_.State -eq "Ready"}

Write-Host "`nWindows Update Status:" -ForegroundColor Cyan
Write-Host "Windows Update Service: $($updateService.Status) (StartType: $($updateService.StartType))" -ForegroundColor $(if($updateService.Status -eq "Stopped" -and $updateService.StartType -eq "Disabled"){"Green"}else{"Red"})
Write-Host "Windows Update Tasks Enabled: $(if($updateTasks.Count -eq 0){"None (Blocked)"}else{$updateTasks.Count})" -ForegroundColor $(if($updateTasks.Count -eq 0){"Green"}else{"Red"})
Write-Host "Registry NoAutoUpdate Value: $((Get-ItemProperty -Path $AUPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate)" -ForegroundColor $(if((Get-ItemProperty -Path $AUPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate -eq 1){"Green"}else{"Red"})

Write-Host "`nWindows Updates have been blocked using multiple methods." -ForegroundColor Green
if (!$hostsUpdated) {
    Write-Host "IMPORTANT: Please manually update the hosts file as mentioned above for complete blocking." -ForegroundColor Yellow
}
Write-Host "Run Allow-Security-Updates.ps1 when you need to apply security updates." -ForegroundColor Yellow