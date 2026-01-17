<#
.SYNOPSIS
  Log all local users, then disable all local users except an allow-list.

.DESCRIPTION
  - Exports local user inventory to CSV (before + after).
  - Writes an actions log (what would change / what changed).
  - Safety: will NOT disable the currently logged-in account.
  - By default, also protects "Administrator" unless you explicitly override protections.

.EXAMPLE
  # Audit only (default mode - no changes made)
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash")

.EXAMPLE
  # Dry run - shows what WOULD happen
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -DryRun

.EXAMPLE
  # Enforce changes
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -Enforce

.EXAMPLE
  # Enforce with confirmation prompts
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -Enforce -Confirm

.EXAMPLE
  # Enforce and allow disabling protected accounts (DANGEROUS)
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin") -Enforce -OverrideProtections

.OUTPUTS
  Returns a PSCustomObject with:
    - Success: Boolean indicating overall success
    - DisabledCount: Number of accounts disabled
    - FailedCount: Number of accounts that failed to disable
    - AuditedCount: Total accounts processed
    - LogFile: Path to the log file
    - ActionsCsv: Path to the actions CSV
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $true)]
  [string[]] $AllowedUsers,

  [Parameter(ParameterSetName = 'Enforce')]
  [switch] $Enforce,

  [Parameter(ParameterSetName = 'DryRun')]
  [switch] $DryRun,

  # If set, you may disable even protected accounts (NOT recommended).
  [switch] $OverrideProtections,

  # Optional: extra exclusions that will never be disabled unless OverrideProtections is set.
  [string[]] $ProtectedUsers = @("Administrator"),

  # Output folder for logs/CSVs
  [string] $OutDir = "C:\ProgramData\CCDC\UserControl"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Results tracking ---
$script:disabledCount = 0
$script:failedCount = 0
$script:auditedCount = 0

# --- Prep output paths ---
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile     = Join-Path $OutDir "disable_users_$ts.log"
$beforeCsv   = Join-Path $OutDir "local_users_before_$ts.csv"
$afterCsv    = Join-Path $OutDir "local_users_after_$ts.csv"
$actionsCsv  = Join-Path $OutDir "actions_$ts.csv"

function Write-Log {
  param(
    [string]$Msg,
    [ValidateSet('INFO', 'WARN', 'ERROR')]
    [string]$Level = 'INFO'
  )
  $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "s"), $Level, $Msg
  $line | Tee-Object -FilePath $logFile -Append
}

# --- Determine current interactive username (anti-lockout) ---
$currentUser = $env:USERNAME

# Check if running as SYSTEM or another service account
$isServiceAccount = $currentUser -match '\$$' -or $currentUser -eq 'SYSTEM'
if ($isServiceAccount) {
  Write-Log "WARNING: Running as service account '$currentUser'. Anti-lockout protection based on current user may not apply to interactive accounts." -Level WARN
}

# Normalize comparisons (case-insensitive)
$allowedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($u in $AllowedUsers) { [void]$allowedSet.Add($u) }

# ANTI-LOCKOUT: Always allow current user to avoid locking yourself out
[void]$allowedSet.Add($currentUser)

# Protected accounts that should not be disabled unless -OverrideProtections
$protectedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in $ProtectedUsers) { [void]$protectedSet.Add($p) }
# ANTI-LOCKOUT: Current user is also protected
[void]$protectedSet.Add($currentUser)

Write-Log "Starting local user audit. OutDir=$OutDir"
Write-Log "CurrentUser=$currentUser (IsServiceAccount=$isServiceAccount)"
Write-Log "AllowedUsers=$($AllowedUsers -join ', ')"
Write-Log "EffectiveAllowedUsers=$([string]::Join(', ', ($allowedSet)))"
Write-Log "ProtectedUsers=$([string]::Join(', ', ($protectedSet)))"

$modeDescription = if ($DryRun) { "DRYRUN" } elseif ($Enforce) { "ENFORCE" } else { "AUDIT_ONLY" }
Write-Log "Mode: $modeDescription (OverrideProtections=$OverrideProtections)"

# --- Get local users inventory ---
if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
  throw "Get-LocalUser not found. This script requires Windows 10+/Server 2016+ with the LocalAccounts module."
}

$usersBefore = Get-LocalUser | Select-Object `
  Name, Enabled, Description, LastLogon, PasswordRequired, PasswordExpires, SID, PrincipalSource

$usersBefore | Export-Csv -NoTypeInformation -Path $beforeCsv
Write-Log "Exported BEFORE inventory to: $beforeCsv"

# --- Decide actions ---
$actions = @()

foreach ($u in $usersBefore) {
  $script:auditedCount++
  $name = $u.Name

  $isAllowed   = $allowedSet.Contains($name)
  $isProtected = $protectedSet.Contains($name)

  $shouldDisable =
    (-not $isAllowed) -and
    ($u.Enabled -eq $true) -and
    ( $OverrideProtections -or (-not $isProtected) )

  $actionResult = "NO_CHANGE"

  if ($shouldDisable) {
    if ($DryRun) {
      Write-Log "WOULD DISABLE: $name (enabled=$($u.Enabled))"
      $actionResult = "WOULD_DISABLE"
    } elseif (-not $Enforce) {
      Write-Log "WOULD DISABLE: $name (enabled=$($u.Enabled)) [audit-only mode]"
      $actionResult = "WOULD_DISABLE"
    } else {
      # Enforce mode - actually disable
      if ($PSCmdlet.ShouldProcess($name, "Disable local user account")) {
        try {
          Write-Log "DISABLING: $name"
          Disable-LocalUser -Name $name -ErrorAction Stop
          Write-Log "DISABLED: $name"
          $actionResult = "DISABLED"
          $script:disabledCount++
        } catch {
          Write-Log "FAILED to disable ${name}: $_" -Level ERROR
          $actionResult = "FAILED"
          $script:failedCount++
        }
      } else {
        Write-Log "SKIPPED (user declined): $name"
        $actionResult = "SKIPPED_BY_USER"
      }
    }
  } else {
    if ($VerbosePreference -eq 'Continue') {
      Write-Log "NO CHANGE: $name (Allowed=$isAllowed Protected=$isProtected Enabled=$($u.Enabled))"
    }
  }

  $action = [pscustomobject]@{
    User            = $name
    WasEnabled      = $u.Enabled
    IsAllowed       = $isAllowed
    IsProtected     = $isProtected
    ActionTaken     = $actionResult
    Mode            = $modeDescription
    Timestamp       = (Get-Date).ToString("s")
  }
  $actions += $action
}

$actions | Export-Csv -NoTypeInformation -Path $actionsCsv
Write-Log "Exported actions to: $actionsCsv"

# --- Export after state ---
$usersAfter = Get-LocalUser | Select-Object `
  Name, Enabled, Description, LastLogon, PasswordRequired, PasswordExpires, SID, PrincipalSource

$usersAfter | Export-Csv -NoTypeInformation -Path $afterCsv
Write-Log "Exported AFTER inventory to: $afterCsv"

# --- Summary ---
Write-Log "=== SUMMARY ==="
Write-Log "Accounts audited: $script:auditedCount"
Write-Log "Accounts disabled: $script:disabledCount"
Write-Log "Accounts failed: $script:failedCount"
Write-Log "Done."

Write-Output ""
Write-Output "Artifacts:"
Write-Output "  Log:         $logFile"
Write-Output "  Before CSV:  $beforeCsv"
Write-Output "  Actions CSV: $actionsCsv"
Write-Output "  After CSV:   $afterCsv"

# --- Return structured result ---
$result = [pscustomobject]@{
  Success       = ($script:failedCount -eq 0)
  DisabledCount = $script:disabledCount
  FailedCount   = $script:failedCount
  AuditedCount  = $script:auditedCount
  LogFile       = $logFile
  BeforeCsv     = $beforeCsv
  AfterCsv      = $afterCsv
  ActionsCsv    = $actionsCsv
}

# Set exit code for automation
if ($script:failedCount -gt 0) {
  $host.SetShouldExit(1)
}

return $result
