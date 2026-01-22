<#
.SYNOPSIS
    Disables all local user accounts that are not on the approved whitelist.

.DESCRIPTION
    This script is designed for CCDC (Collegiate Cyber Defense Competition) blue team operations.
    It disables all local user accounts except those explicitly whitelisted, helping secure systems
    by removing unauthorized access. Integrates with Get-WindowsInventory.ps1 baseline data.

.PARAMETER AllowedUsers
    Array of usernames that should remain enabled. All other local accounts will be disabled.

.PARAMETER AllowedUsersFile
    Path to a text file containing allowed usernames (one per line).
    Useful for maintaining a persistent whitelist.

.PARAMETER UseBaseline
    Use the baseline users from Get-WindowsInventory.ps1 baseline data as the allowed list.
    Path: ./baseline/users.csv

.PARAMETER BaselinePath
    Custom path to baseline directory (default: ./baseline)

.PARAMETER ExcludeBuiltIn
    Keep built-in system accounts (Administrator, Guest, DefaultAccount, WDAGUtilityAccount) enabled.
    Default: $true

.PARAMETER WhatIf
    Show what would be disabled without actually disabling accounts (dry-run mode).

.PARAMETER Force
    Skip confirmation prompts and disable accounts immediately.

.PARAMETER LogPath
    Path to log file. Default: ./disable_users.log

.EXAMPLE
    .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("admin","ccdc_user") -WhatIf
    Shows which accounts would be disabled (dry-run).

.EXAMPLE
    .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsersFile "C:\CCDC\allowed_users.txt" -Force
    Disables all accounts not in the file without confirmation.

.EXAMPLE
    .\Disable-NonAllowedLocalUsers.ps1 -UseBaseline
    Uses the baseline snapshot from Get-WindowsInventory.ps1 as the whitelist.

.EXAMPLE
    .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("ccdc_admin") -ExcludeBuiltIn:$false
    Disables all accounts except ccdc_admin, including built-in accounts.

.NOTES
    Version:        1.0
    Author:         CCDC Team
    Creation Date:  2026-01-22
    Purpose:        CCDC system hardening - disable unauthorized user accounts

    Requires:       PowerShell 5.1+
    Requires:       Administrator privileges

    IMPORTANT: Always test with -WhatIf first!
    IMPORTANT: Ensure your own account is in the allowed list!

.LINK
    Get-WindowsInventory.ps1 - Companion inventory and baseline script
#>

[CmdletBinding(SupportsShouldProcess=$true, DefaultParameterSetName='AllowedArray')]
param(
    [Parameter(ParameterSetName='AllowedArray')]
    [string[]]$AllowedUsers = @(),

    [Parameter(ParameterSetName='AllowedFile')]
    [string]$AllowedUsersFile,

    [Parameter(ParameterSetName='Baseline')]
    [switch]$UseBaseline,

    [Parameter(ParameterSetName='Baseline')]
    [string]$BaselinePath,

    [switch]$ExcludeBuiltIn = $true,
    [switch]$Force,
    [string]$LogPath = ".\disable_users.log"
)

#Requires -RunAsAdministrator

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARNING','ERROR','SUCCESS')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Color output to console
    switch ($Level) {
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        'WARNING' { Write-Host $logMessage -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage }
    }

    # Append to log file
    Add-Content -Path $LogPath -Value $logMessage
}

# ============================================================================
# WHITELIST LOADING FUNCTIONS
# ============================================================================

function Get-AllowedUsersList {
    param(
        [string[]]$AllowedUsersArray,
        [string]$FilePath,
        [switch]$FromBaseline,
        [string]$BaselineDir
    )

    $allowedList = @()

    # Load from baseline
    if ($FromBaseline) {
        if (-not $BaselineDir) {
            $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
            if (-not $scriptDir) { $scriptDir = Get-Location }
            $BaselineDir = Join-Path $scriptDir "baseline"
        }

        $baselineUsersCsv = Join-Path $BaselineDir "users.csv"

        if (-not (Test-Path $baselineUsersCsv)) {
            Write-Log "Baseline users file not found at: $baselineUsersCsv" -Level ERROR
            Write-Log "Run Get-WindowsInventory.ps1 first to create a baseline." -Level ERROR
            throw "Baseline not found"
        }

        Write-Log "Loading allowed users from baseline: $baselineUsersCsv" -Level INFO
        $baselineUsers = Import-Csv $baselineUsersCsv
        $allowedList = $baselineUsers | Where-Object { $_.Enabled -eq 'True' } | Select-Object -ExpandProperty Name
        Write-Log "Loaded $($allowedList.Count) enabled users from baseline" -Level INFO
    }
    # Load from file
    elseif ($FilePath) {
        if (-not (Test-Path $FilePath)) {
            Write-Log "Allowed users file not found: $FilePath" -Level ERROR
            throw "Allowed users file not found"
        }

        Write-Log "Loading allowed users from file: $FilePath" -Level INFO
        $allowedList = Get-Content $FilePath | Where-Object { $_ -and $_.Trim() -ne '' }
        Write-Log "Loaded $($allowedList.Count) users from file" -Level INFO
    }
    # Load from array parameter
    else {
        $allowedList = $AllowedUsersArray
        Write-Log "Using $($allowedList.Count) users from parameter list" -Level INFO
    }

    # Normalize to lowercase for case-insensitive comparison
    $allowedList = $allowedList | ForEach-Object { $_.Trim().ToLower() }

    return $allowedList
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Log "========================================" -Level INFO
Write-Log "Disable-NonAllowedLocalUsers.ps1 v1.0" -Level INFO
Write-Log "========================================" -Level INFO

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: This script requires Administrator privileges!" -Level ERROR
    Write-Log "Please run PowerShell as Administrator and try again." -Level ERROR
    exit 1
}

# Load allowed users list
try {
    $allowedUsersList = Get-AllowedUsersList `
        -AllowedUsersArray $AllowedUsers `
        -FilePath $AllowedUsersFile `
        -FromBaseline:$UseBaseline `
        -BaselineDir $BaselinePath
}
catch {
    Write-Log "Failed to load allowed users list: $_" -Level ERROR
    exit 1
}

if ($allowedUsersList.Count -eq 0) {
    Write-Log "ERROR: No allowed users specified! This would disable ALL accounts." -Level ERROR
    Write-Log "Please provide allowed users via -AllowedUsers, -AllowedUsersFile, or -UseBaseline" -Level ERROR
    exit 1
}

Write-Log "Allowed users whitelist:" -Level INFO
$allowedUsersList | ForEach-Object { Write-Log "  - $_" -Level INFO }

# Add built-in accounts to whitelist if requested
$builtInAccounts = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')
if ($ExcludeBuiltIn) {
    Write-Log "Excluding built-in system accounts from disable operation" -Level INFO
    $builtInAccounts | ForEach-Object {
        $allowedUsersList += $_.ToLower()
        Write-Log "  - $_ (built-in)" -Level INFO
    }
}

# Get all local users
Write-Log "Enumerating local user accounts..." -Level INFO
try {
    $allLocalUsers = Get-LocalUser -ErrorAction Stop
    Write-Log "Found $($allLocalUsers.Count) local user accounts" -Level INFO
}
catch {
    Write-Log "Failed to enumerate local users: $_" -Level ERROR
    exit 1
}

# Identify users to disable
$usersToDisable = @()
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1].ToLower()

foreach ($user in $allLocalUsers) {
    $username = $user.Name.ToLower()

    # Skip if user is in allowed list
    if ($allowedUsersList -contains $username) {
        Write-Log "KEEP: $($user.Name) - in allowed list" -Level INFO
        continue
    }

    # Skip if already disabled
    if (-not $user.Enabled) {
        Write-Log "SKIP: $($user.Name) - already disabled" -Level INFO
        continue
    }

    # Check if this is the current user
    if ($username -eq $currentUser) {
        Write-Log "WARNING: $($user.Name) is the currently logged-in user!" -Level WARNING
        Write-Log "WARNING: This account is NOT in the allowed list but will be skipped to prevent lockout" -Level WARNING
        continue
    }

    # Add to disable list
    $usersToDisable += $user
}

# Display summary
Write-Log "" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "DISABLE SUMMARY" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "Total local users: $($allLocalUsers.Count)" -Level INFO
Write-Log "Users to disable: $($usersToDisable.Count)" -Level WARNING
Write-Log "Users to keep enabled: $($allLocalUsers.Count - $usersToDisable.Count)" -Level INFO
Write-Log "" -Level INFO

if ($usersToDisable.Count -eq 0) {
    Write-Log "No users need to be disabled. System is already compliant!" -Level SUCCESS
    exit 0
}

Write-Log "The following accounts will be DISABLED:" -Level WARNING
$usersToDisable | ForEach-Object {
    $lastLogon = if ($_.LastLogon) { $_.LastLogon.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
    Write-Log "  - $($_.Name) (Last logon: $lastLogon)" -Level WARNING
}
Write-Log "" -Level INFO

# Confirmation prompt (unless -Force or -WhatIf)
if ($WhatIfPreference) {
    Write-Log "[WHATIF MODE] No accounts will actually be disabled" -Level INFO
    Write-Log "Remove -WhatIf flag to perform actual disable operation" -Level INFO
}
elseif (-not $Force) {
    Write-Log "Are you sure you want to disable these $($usersToDisable.Count) accounts?" -Level WARNING
    $confirmation = Read-Host "Type 'YES' to continue"

    if ($confirmation -ne 'YES') {
        Write-Log "Operation cancelled by user" -Level WARNING
        exit 0
    }
}

# Disable users
Write-Log "" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "DISABLING ACCOUNTS" -Level INFO
Write-Log "========================================" -Level INFO

$successCount = 0
$failCount = 0

foreach ($user in $usersToDisable) {
    try {
        if ($PSCmdlet.ShouldProcess($user.Name, "Disable user account")) {
            Disable-LocalUser -Name $user.Name -ErrorAction Stop
            Write-Log "DISABLED: $($user.Name)" -Level SUCCESS
            $successCount++
        }
        else {
            Write-Log "[WHATIF] Would disable: $($user.Name)" -Level INFO
        }
    }
    catch {
        Write-Log "FAILED to disable $($user.Name): $_" -Level ERROR
        $failCount++
    }
}

# Final summary
Write-Log "" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "OPERATION COMPLETE" -Level INFO
Write-Log "========================================" -Level INFO

if (-not $WhatIfPreference) {
    Write-Log "Successfully disabled: $successCount accounts" -Level SUCCESS
    if ($failCount -gt 0) {
        Write-Log "Failed to disable: $failCount accounts" -Level ERROR
    }
    Write-Log "Log file: $LogPath" -Level INFO
}

Write-Log "" -Level INFO

# Return summary object
return [PSCustomObject]@{
    TotalUsers = $allLocalUsers.Count
    AllowedUsers = $allowedUsersList.Count
    DisabledCount = $successCount
    FailedCount = $failCount
    WhatIfMode = $WhatIfPreference.IsPresent
}
