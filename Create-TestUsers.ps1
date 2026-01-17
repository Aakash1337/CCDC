<#
.SYNOPSIS
  Creates test user accounts to simulate suspicious/backdoor accounts for testing.

.DESCRIPTION
  Creates several fake "attacker" accounts for testing Disable-NonAllowedLocalUsers.ps1.
  Run with -Cleanup to remove all test accounts.

.EXAMPLE
  # Create test accounts
  .\Create-TestUsers.ps1

.EXAMPLE
  # Remove all test accounts
  .\Create-TestUsers.ps1 -Cleanup
#>

param(
  [switch] $Cleanup
)

$ErrorActionPreference = "Stop"

# Suspicious account names that attackers commonly use
$testUsers = @(
  @{ Name = "svc_backup";     Description = "Fake service account" }
  @{ Name = "admin$";         Description = "Hidden admin attempt" }
  @{ Name = "support";        Description = "Fake support account" }
  @{ Name = "guest2";         Description = "Secondary guest" }
  @{ Name = "mysql";          Description = "Fake database service" }
  @{ Name = "debug";          Description = "Debug account" }
  @{ Name = "test";           Description = "Test account" }
  @{ Name = "backdoor";       Description = "Obvious backdoor" }
)

if ($Cleanup) {
  Write-Host "=== Removing test accounts ===" -ForegroundColor Yellow
  foreach ($user in $testUsers) {
    $name = $user.Name
    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {
      try {
        Remove-LocalUser -Name $name -ErrorAction Stop
        Write-Host "  Removed: $name" -ForegroundColor Green
      } catch {
        Write-Host "  Failed to remove ${name}: $($_.Exception.Message)" -ForegroundColor Red
      }
    } else {
      Write-Host "  Not found: $name" -ForegroundColor Gray
    }
  }
  Write-Host "`nCleanup complete."
  return
}

Write-Host "=== Creating test accounts ===" -ForegroundColor Cyan

# Generate a random password for test accounts
$password = ConvertTo-SecureString "TestPass123!" -AsPlainText -Force

foreach ($user in $testUsers) {
  $name = $user.Name
  $desc = $user.Description

  if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {
    Write-Host "  Already exists: $name" -ForegroundColor Yellow
  } else {
    try {
      New-LocalUser -Name $name -Password $password -Description $desc -ErrorAction Stop | Out-Null
      Enable-LocalUser -Name $name -ErrorAction SilentlyContinue
      Write-Host "  Created: $name" -ForegroundColor Green
    } catch {
      Write-Host "  Failed to create ${name}: $($_.Exception.Message)" -ForegroundColor Red
    }
  }
}

Write-Host "`n=== Current Local Users ===" -ForegroundColor Cyan
Get-LocalUser | Format-Table Name, Enabled, Description -AutoSize

Write-Host "`nTest accounts created. Now run:" -ForegroundColor Yellow
Write-Host '  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("Administrator", "Admin") -Enforce' -ForegroundColor White
Write-Host "`nTo clean up later:" -ForegroundColor Yellow
Write-Host '  .\Create-TestUsers.ps1 -Cleanup' -ForegroundColor White
