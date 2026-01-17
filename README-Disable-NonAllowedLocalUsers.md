# Disable-NonAllowedLocalUsers.ps1

Audit and disable local user accounts not on an allow-list. Designed for CCDC defensive hardening.

## Quick Start

```powershell
# Audit only (no changes) - see what WOULD happen
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash")

# Dry run - explicit preview mode
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -DryRun

# Enforce - actually disable accounts
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -Enforce
```

## Modes

| Mode | Flag | Description |
|------|------|-------------|
| Audit | *(default)* | Lists what would change, no modifications |
| Dry Run | `-DryRun` | Same as audit, explicit flag |
| Enforce | `-Enforce` | Actually disables accounts |

## Safety Features

- **Anti-lockout**: The currently logged-in user is always protected
- **Protected accounts**: `Administrator` is protected by default
- **Confirmation**: Add `-Confirm` to prompt before each disable

## Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-AllowedUsers` | *(required)* | Array of usernames to keep enabled |
| `-ProtectedUsers` | `@("Administrator")` | Extra accounts that won't be disabled |
| `-OverrideProtections` | off | Allow disabling protected accounts (dangerous) |
| `-OutDir` | `C:\ProgramData\CCDC\UserControl` | Output folder for logs |

## Output Files

Each run generates timestamped files in the output directory:

| File | Description |
|------|-------------|
| `local_users_before_*.csv` | User inventory before changes |
| `local_users_after_*.csv` | User inventory after changes |
| `actions_*.csv` | What action was taken per account |
| `disable_users_*.log` | Detailed execution log |

## Examples

```powershell
# Enforce with confirmation prompts
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("Admin","SvcAccount") -Enforce -Confirm

# Custom output directory
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("Admin") -OutDir "D:\Logs" -Enforce
```

## Requirements

- Windows 10+ / Server 2016+
- Run as Administrator
- LocalAccounts PowerShell module
