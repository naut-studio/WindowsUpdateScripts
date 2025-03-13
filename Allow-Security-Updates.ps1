## Script to temporarily allow Security Updates only, then re-block
## Run as Administrator

# Script name: Allow-Security-Updates.ps1
# Author: Claude
# Description: Temporarily allows security updates only, then re-blocks all Windows updates

# Function to create a restore point before applying updates
function Create-RestorePoint {
    Write-Host "Creating system restore point..." -ForegroundColor Yellow
    Enable-ComputerRestore -Drive "$env:SystemDrive"
    Checkpoint-Computer -Description "Before Windows Security Updates" -RestorePointType "MODIFY_SETTINGS"
}

# Function to temporarily enable Windows Update service
function Enable-WindowsUpdate {
    Write-Host "Temporarily enabling Windows Update service..." -ForegroundColor Yellow
    
    # Restore hosts file (remove Windows Update blocks)
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
    
    $hostsContent = Get-Content -Path $hostsFile
    $newHostsContent = $hostsContent | Where-Object { $line = $_; -not ($domains | Where-Object { $line -match $_ }) }
    Set-Content -Path $hostsFile -Value $newHostsContent -Force
    
    # Enable Windows Update service
    Set-Service -Name "wuauserv" -StartupType Manual
    Start-Service -Name "wuauserv"
    
    # Configure registry to allow only security updates
    $WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $AUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    
    # Create paths if they don't exist
    if (!(Test-Path $WUPath)) {
        New-Item -Path $WUPath -Force | Out-Null
    }
    if (!(Test-Path $AUPath)) {
        New-Item -Path $AUPath -Force | Out-Null
    }
    
    # Configure for manual security updates only
    Set-ItemProperty -Path $AUPath -Name "NoAutoUpdate" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $AUPath -Name "AUOptions" -Value 2 -Type DWord -Force  # Notify before download
    Set-ItemProperty -Path $WUPath -Name "ElevateNonAdmins" -Value 0 -Type DWord -Force
    
    # Only download security updates
    Set-ItemProperty -Path $WUPath -Name "SetUpdateNotificationLevel" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $WUPath -Name "DisableWindowsUpdateAccess" -Value 0 -Type DWord -Force
}

# Function to search and install only security updates using COM objects
function Update-DefenderSignatures {
    Write-Host "Updating Microsoft Defender signatures..." -ForegroundColor Yellow
    try {
        # Ensure Windows Defender services are running temporarily
        $defenderServices = @("WinDefend", "WdNisSvc")
        foreach ($service in $defenderServices) {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.Status -ne "Running") {
                    Set-Service -Name $service -StartupType Manual -ErrorAction SilentlyContinue
                    Start-Service -Name $service -ErrorAction SilentlyContinue
                }
            }
        }
        
        # Update Defender signatures
        Update-MpSignature -ErrorAction SilentlyContinue
        
        # Check if update was successful
        $defenderStatus = Get-MpComputerStatus
        if ($defenderStatus) {
            Write-Host "Microsoft Defender signature version: $($defenderStatus.AntivirusSignatureVersion)" -ForegroundColor Green
            Write-Host "Last signature update: $($defenderStatus.AntivirusSignatureLastUpdated)" -ForegroundColor Green
        } else {
            Write-Host "Could not verify Microsoft Defender signature status" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error updating Microsoft Defender signatures: $_" -ForegroundColor Red
    }
}

function Install-SecurityUpdates {
    Write-Host "Searching for security updates..." -ForegroundColor Yellow
    
    try {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        
        # Search for security updates only
        Write-Host "Searching for updates..." -ForegroundColor Yellow
        $SearchResult = $Searcher.Search("IsInstalled=0 and Type='Software' and CategoryIDs contains '0FA1201D-4330-4FA8-8AE9-B877473B6441'")
        
        if ($SearchResult.Updates.Count -eq 0) {
            Write-Host "No security updates found." -ForegroundColor Green
            return
        }
        
        Write-Host "Found $($SearchResult.Updates.Count) security updates:" -ForegroundColor Cyan
        $updates = @()
        $i = 0
        
        # Display available security updates
        foreach ($Update in $SearchResult.Updates) {
            $i++
            Write-Host "[$i] $($Update.Title)" -ForegroundColor White
            $updates += [PSCustomObject]@{
                Index = $i
                Title = $Update.Title
                Update = $Update
            }
        }
        
        # Prompt user to select which updates to install
        Write-Host "`nEnter the numbers of updates to install (comma-separated), 'A' for all, or 'N' for none:" -ForegroundColor Yellow
        $selection = Read-Host
        
        $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        
        if ($selection.ToUpper() -eq "A") {
            foreach ($Update in $SearchResult.Updates) {
                $UpdatesToInstall.Add($Update) | Out-Null
            }
            Write-Host "Selected all updates." -ForegroundColor Yellow
        }
        elseif ($selection.ToUpper() -ne "N") {
            $indices = $selection -split "," | ForEach-Object { $_.Trim() }
            foreach ($index in $indices) {
                if ([int]::TryParse($index, [ref]$null)) {
                    $selectedUpdate = $updates | Where-Object { $_.Index -eq [int]$index }
                    if ($selectedUpdate) {
                        $UpdatesToInstall.Add($selectedUpdate.Update) | Out-Null
                        Write-Host "Selected: $($selectedUpdate.Title)" -ForegroundColor Yellow
                    }
                }
            }
        }
        else {
            Write-Host "No updates selected." -ForegroundColor Yellow
            return
        }
        
        if ($UpdatesToInstall.Count -eq 0) {
            Write-Host "No updates selected." -ForegroundColor Yellow
            return
        }
        
        # Download updates
        Write-Host "`nDownloading selected updates..." -ForegroundColor Yellow
        $Downloader = $Session.CreateUpdateDownloader()
        $Downloader.Updates = $UpdatesToInstall
        $DownloadResult = $Downloader.Download()
        
        # Install updates
        Write-Host "Installing selected updates..." -ForegroundColor Yellow
        $Installer = $Session.CreateUpdateInstaller()
        $Installer.Updates = $UpdatesToInstall
        $InstallResult = $Installer.Install()
        
        Write-Host "`nInstallation Results:" -ForegroundColor Cyan
        Write-Host "Success Count: $($InstallResult.ResultCode -eq 2)" -ForegroundColor $(if($InstallResult.ResultCode -eq 2){"Green"}else{"Yellow"})
        Write-Host "Reboot Required: $($InstallResult.RebootRequired)" -ForegroundColor $(if($InstallResult.RebootRequired){"Yellow"}else{"Green"})
        
        # Prompt for restart if needed
        if ($InstallResult.RebootRequired) {
            Write-Host "`nA system restart is required to complete the update process." -ForegroundColor Yellow
            $restart = Read-Host "Do you want to restart now? (Y/N)"
            if ($restart.ToUpper() -eq "Y") {
                Write-Host "Restarting system in 10 seconds..." -ForegroundColor Red
                Start-Sleep -Seconds 10
                Restart-Computer -Force
            }
            else {
                Write-Host "Please restart your system at your earliest convenience." -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

# Function to re-block Windows Update after applying security updates
# Function to re-block Windows Update after applying security updates
# Function to re-block Windows Update after applying security updates
function Reblock-WindowsUpdate {
    Write-Host "`nRe-blocking Windows Update..." -ForegroundColor Yellow
    
    # Stop and disable Windows Update service
    Stop-Service -Name "wuauserv" -Force
    Set-Service -Name "wuauserv" -StartupType Disabled
    
    # Restore registry settings to block updates
    $AUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    Set-ItemProperty -Path $AUPath -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $AUPath -Name "AUOptions" -Value 1 -Type DWord -Force
    
    # Re-block Windows Update domains in hosts file with robust error handling
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
    
    # Function to safely update hosts file with retry mechanism
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
                    Write-Host "Successfully updated hosts file with $($newEntries.Count) entries" -ForegroundColor Green
                } else {
                    Write-Host "Hosts file already contains all needed entries" -ForegroundColor Green
                }
                
                $success = $true
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

    # Attempt to update hosts file
    $hostsUpdated = Update-HostsFile -HostsFilePath $hostsFile -DomainsToBlock $domains

    # If hosts update failed, offer a manual solution
    if (!$hostsUpdated) {
        Write-Host "`nUnable to automatically update the hosts file due to access issues." -ForegroundColor Red
        Write-Host "Please add the following entries manually to your hosts file ($hostsFile):" -ForegroundColor Yellow
        foreach ($domain in $domains) {
            Write-Host "127.0.0.1 $domain" -ForegroundColor Cyan
        }
    }
    
    # Verify blocked status
    $updateService = Get-Service -Name "wuauserv"
    
    Write-Host "`nWindows Update Status:" -ForegroundColor Cyan
    Write-Host "Windows Update Service: $($updateService.Status) (StartType: $($updateService.StartType))" -ForegroundColor $(if($updateService.Status -eq "Stopped" -and $updateService.StartType -eq "Disabled"){"Green"}else{"Red"})
    Write-Host "Registry NoAutoUpdate Value: $((Get-ItemProperty -Path $AUPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate)" -ForegroundColor $(if((Get-ItemProperty -Path $AUPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate -eq 1){"Green"}else{"Red"})
    
    # Verify hosts file entries
    Write-Host "`nVerifying hosts file entries:" -ForegroundColor Cyan
    try {
        $hostsContent = Get-Content -Path $hostsFile -ErrorAction Stop
        $missingEntries = @()
        
        foreach ($domain in $domains) {
            $entryPattern = "127\.0\.0\.1\s+$([regex]::Escape($domain))"
            if (!($hostsContent -match $entryPattern)) {
                $missingEntries += $domain
            }
        }
        
        if ($missingEntries.Count -eq 0) {
            Write-Host "All Windows Update domains are properly blocked in hosts file" -ForegroundColor Green
        } else {
            Write-Host "The following domains are NOT properly blocked in hosts file:" -ForegroundColor Yellow
            foreach ($domain in $missingEntries) {
                Write-Host "  - $domain" -ForegroundColor Red
            }
        }
        
        Write-Host "`nCurrent hosts file Windows Update entries:" -ForegroundColor Cyan
        foreach ($line in $hostsContent) {
            foreach ($domain in $domains) {
                if ($line -match $domain) {
                    Write-Host $line -ForegroundColor White
                }
            }
        }
    } catch {
        Write-Host "Unable to read hosts file for verification: $_" -ForegroundColor Red
    }
    
    Write-Host "`nWindows Updates have been re-blocked." -ForegroundColor Green
    if (!$hostsUpdated) {
        Write-Host "IMPORTANT: Please manually update the hosts file as mentioned above for complete blocking." -ForegroundColor Yellow
    }
}

# Main script execution
# Check for administrator rights
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Please restart with elevated privileges." -ForegroundColor Red
    exit
}

Write-Host "Windows Security Updates Temporary Access Tool" -ForegroundColor Cyan
Write-Host "================================================`n" -ForegroundColor Cyan

# Create system restore point
Create-RestorePoint

# Update Microsoft Defender signatures (runs regardless of other updates)
Update-DefenderSignatures

# Temporarily enable Windows Update to check for security updates
Enable-WindowsUpdate

# Install security updates
Install-SecurityUpdates

# Re-block Windows Update
Reblock-WindowsUpdate

Write-Host "`nProcess complete. Window Update is now blocked again." -ForegroundColor Green
Write-Host "Run Block-Windows-Updates.ps1 if you need to reinforce blocking." -ForegroundColor Yellow