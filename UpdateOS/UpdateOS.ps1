<#PSScriptInfo
.VERSION 2.2
.GUID 07e4ef9f-8341-4dc4-bc73-fc277eb6b4e6
.AUTHOR Michael Niehaus
.COMPANYNAME Microsoft
.TAGS Windows AutoPilot Update OS
.RELEASENOTES
Version 2.2: Security improvements - Added parameter validation, input sanitization, error handling, and removed unnecessary components.
Version 2.1: Added -Append for Start-Transcript. Added logic to filter out feature updates.
Version 2.0: Restructured download and install logic
#>

<#
.SYNOPSIS
Installs the latest Windows 10/11 quality updates with enhanced security.
.DESCRIPTION
This script uses the Windows Update COM objects to install the latest cumulative updates for Windows 10/11.
Includes security enhancements and input validation.
.EXAMPLE
.\UpdateOS.ps1
.EXAMPLE
.\UpdateOS.ps1 -Reboot Soft -RebootTimeout 300 -ExcludeDrivers
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $False)]
    [ValidateSet('Soft', 'Hard', 'None', 'Delayed')]
    
    [Parameter(Mandatory = $False)][ValidateRange(30, 3600)]  # Reasonable timeout range [Int32] $RebootTimeout = 120,
    
    [Parameter(Mandatory = $False)]  [switch] $ExcludeDrivers,
    
    [Parameter(Mandatory = $False)]  [switch] $ExcludeUpdates
)

# Requires elevation
#Requires -RunAsAdministrator

Process {
    # Security: Validate execution environment
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script requires administrator privileges. Please run as administrator."
        Exit 1
    }

    # Security: Set strict error handling
    $ErrorActionPreference = "Stop"
    
    try {
        # If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
        if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64") {
            if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
                $arguments = @(
                    "-ExecutionPolicy", "Bypass",
                    "-NoProfile",
                    "-File", "`"$PSCommandPath`"",
                    "-Reboot", $Reboot,
                    "-RebootTimeout", $RebootTimeout
                )
                
                if ($ExcludeDrivers) { $arguments += "-ExcludeDrivers" }
                if ($ExcludeUpdates) { $arguments += "-ExcludeUpdates" }
                
                & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" @arguments
                Exit $LASTEXITCODE
            }
        }

        # Security: Validate and create secure log directory
        $logDir = Join-Path $env:ProgramData "Microsoft\UpdateOS"
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            # Set restrictive permissions on log directory
            $acl = Get-Acl $logDir
            $acl.SetAccessRuleProtection($true, $false)
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.SetAccessRule($adminRule)
            $acl.SetAccessRule($systemRule)
            Set-Acl -Path $logDir -AclObject $acl
        }

        # Create tag file with timestamp
        $tagFile = Join-Path $logDir "UpdateOS.ps1.tag"
        Set-Content -Path $tagFile -Value "Installed on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Force

        # Start logging with error handling
        $logFile = Join-Path $logDir "UpdateOS.log"
        try {
            Start-Transcript -Path $logFile -Append -Force
        }
        catch {
            Write-Warning "Could not start transcript logging: $_"
        }

        # Main logic
        $script:needReboot = $false
        $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
        Write-Output "$timestamp Starting Windows Update process"

        # Security: Validate COM object creation
        try {
            Write-Output "$timestamp Opting into Microsoft Update"
            $ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
            $ServiceID = "7971f918-a847-4430-9279-4a52d1efe18d"  # Microsoft Update Service ID
            $ServiceManager.AddService2($ServiceId, 7, "") | Out-Null
        }
        catch {
            Write-Error "Failed to initialize Microsoft Update service: $_"
            Exit 1
        }

        # Security: Input validation for update queries
        $validQueries = @()
        if ($ExcludeDrivers) {
            $validQueries = @("IsInstalled=0 and Type='Software'")
        }
        elseif ($ExcludeUpdates) {
            $validQueries = @("IsInstalled=0 and Type='Driver'")
        }
        else {
            $validQueries = @("IsInstalled=0 and Type='Software'", "IsInstalled=0 and Type='Driver'")
        }

        # Security: Create update collection with error handling
        try {
            $WUUpdates = New-Object -ComObject Microsoft.Update.UpdateColl
            
            foreach ($query in $validQueries) {
                $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
                Write-Output "$timestamp Searching for updates with query: $query"
                
                try {
                    $updateSession = New-Object -ComObject Microsoft.Update.Session
                    $updateSearcher = $updateSession.CreateUpdateSearcher()
                    $searchResult = $updateSearcher.Search($query)
                    
                    foreach ($update in $searchResult.Updates) {
                        # Security: Validate update before processing
                        if ($null -eq $update -or [string]::IsNullOrWhiteSpace($update.Title)) {
                            Write-Warning "$timestamp Skipping invalid update object"
                            continue
                        }
                        
                        # Accept EULA if required
                        if (-not $update.EulaAccepted) { 
                            $update.AcceptEula() 
                        }
                        
                        # Filter out feature updates and preview updates
                        $featureUpdate = $update.Categories | Where-Object { $_.CategoryID -eq "3689BDC8-B205-4AF4-8D4A-A63924C5E9D5" }
                        if ($featureUpdate) {
                            Write-Output "$timestamp Skipping feature update: $($update.Title)"
                            continue
                        }
                        
                        if ($update.Title -match "Preview") {
                            Write-Output "$timestamp Skipping preview update: $($update.Title)"
                            continue
                        }
                        
                        [void]$WUUpdates.Add($update)
                    }
                }
                catch {
                    $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
                    Write-Warning "$timestamp Unable to search for updates: $_"
                }
            }
        }
        catch {
            Write-Error "Failed to create update collection: $_"
            Exit 1
        }

        $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
        if ($WUUpdates.Count -eq 0) {
            Write-Output "$timestamp No updates found"
            Exit 0
        }
        else {
            Write-Output "$timestamp Found $($WUUpdates.Count) updates to install"
        }

        # Process updates individually for better error handling
        foreach ($update in $WUUpdates) {
            try {
                $singleUpdate = New-Object -ComObject Microsoft.Update.UpdateColl
                $singleUpdate.Add($update) | Out-Null

                $updateSession = New-Object -ComObject Microsoft.Update.Session
                $WUDownloader = $updateSession.CreateUpdateDownloader()
                $WUDownloader.Updates = $singleUpdate

                $WUInstaller = $updateSession.CreateUpdateInstaller()
                $WUInstaller.Updates = $singleUpdate
                $WUInstaller.ForceQuiet = $true

                $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
                Write-Output "$timestamp Downloading update: $($update.Title)"
                
                $Download = $WUDownloader.Download()
                Write-Output "$timestamp Download result: $($Download.ResultCode) (HRESULT: $($Download.HResult))"

                if ($Download.ResultCode -eq 2) {  # Success
                    $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
                    Write-Output "$timestamp Installing update: $($update.Title)"
                    
                    $Results = $WUInstaller.Install()
                    Write-Output "$timestamp Install result: $($Results.ResultCode) (HRESULT: $($Results.HResult))"

                    if ($Results.RebootRequired) {
                        $script:needReboot = $true
                    }
                }
                else {
                    Write-Warning "$timestamp Failed to download update: $($update.Title)"
                }
            }
            catch {
                Write-Warning "$timestamp Error processing update '$($update.Title)': $_"
                continue
            }
        }

        # Handle reboot requirements
        $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
        if ($script:needReboot) {
            Write-Output "$timestamp Windows Update indicated that a reboot is required"

            switch ($Reboot) {
                "Hard" {
                    Write-Output "$timestamp Exiting with return code 1641 to indicate a hard reboot is needed"
                    Exit 1641
                }
                "Soft" {
                    Write-Output "$timestamp Exiting with return code 3010 to indicate a soft reboot is needed"
                    Exit 3010
                }
                "Delayed" {
                    Write-Output "$timestamp Scheduling reboot with $RebootTimeout second delay"
                    # Security: Use full path and validate timeout
                    & "$env:SystemRoot\System32\shutdown.exe" /r /t $RebootTimeout /c "Rebooting to complete Windows updates installation"
                    Exit 0
                }
                "None" {
                    Write-Output "$timestamp Reboot required but suppressed by parameter"
                    Exit 0
                }
            }
        }
        else {
            Write-Output "$timestamp No reboot required"
            Exit 0
        }
    }
    catch {
        $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
        Write-Error "$timestamp Critical error in UpdateOS script: $_"
        Exit 1
    }
    finally {
        # Ensure transcript is stopped
        try {
            Stop-Transcript -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore transcript stop errors
        }
    }
}