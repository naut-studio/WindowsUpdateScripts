# Windows Update Management Scripts

This repository contains a collection of PowerShell scripts designed to manage Windows Update functionality with precision, allowing control over when and how updates are applied to your system.

## Scripts Overview

### 1. Block-Windows-Updates.ps1
This script completely blocks Windows Update using multiple methods:
- Stops and disables the Windows Update service
- Configures registry keys to prevent automatic updates
- Blocks Windows Update domains in the hosts file
- Sets network connections as metered to prevent updates
- Creates a startup task to maintain update blocking
- Preserves Microsoft Defender update functionality

### 2. Allow-Security-Updates.ps1
Temporarily allows security updates while maintaining general update blocking:
- Creates a system restore point before making changes
- Temporarily enables Windows Update service
- Configures registry for security updates only
- Updates Microsoft Defender signatures
- Allows you to select which security updates to install
- Re-blocks Windows Update after security updates are applied

### 3. Restore-Windows-Updates.ps1
Fully restores Windows Update functionality by reversing all blocking measures:
- Creates a system restore point before making changes
- Restores Windows Update service to automatic startup
- Removes registry keys that disable updates
- Removes Windows Update blocking entries from hosts file
- Re-enables Windows Update scheduled tasks
- Verifies Windows Update connectivity

## Usage

All scripts must be run as Administrator. Right-click on the script and select "Run as Administrator".

### Typical Workflow

1. Use `Block-Windows-Updates.ps1` to completely block automatic updates
2. Periodically run `Allow-Security-Updates.ps1` to apply critical security patches
3. If you want to restore normal Windows Update functionality, run `Restore-Windows-Updates.ps1`

## Features

- **Comprehensive Blocking**: Uses multiple methods to ensure updates are completely blocked
- **Selective Security Updates**: Apply only security updates when needed
- **Defender Protection**: Maintains Microsoft Defender updates even when Windows Updates are blocked
- **System Protection**: Creates restore points before making any changes
- **Robust Error Handling**: Includes retry mechanisms and alternative methods when primary methods fail
- **Status Verification**: Provides clear information about the current state of Windows Update

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Administrator privileges

## Warning

These scripts modify system settings. Use at your own risk and always ensure you have system backups before making system-wide changes.

## License

[MIT License](LICENSE)
