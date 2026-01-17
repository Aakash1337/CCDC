# Backups.ps1

A PowerShell backup utility with compression, retention policies, and CCDC-specific defaults for critical system files.

## Quick Start

```powershell
# CCDC mode - backs up all critical paths automatically
.\Backups.ps1 -CCDCDefaults -DestinationRoot "D:\Backups"

# Manual path specification
.\Backups.ps1 -SourcePaths "C:\Documents","C:\Projects" -DestinationRoot "D:\Backups"
```

## CCDC Defaults

Use `-CCDCDefaults` to automatically back up critical paths that attackers commonly target:

| Category | What's Backed Up |
|----------|------------------|
| **System Config** | hosts file, registry hives (SAM, SECURITY, SYSTEM, SOFTWARE) |
| **Persistence** | Scheduled Tasks, Startup folders, PowerShell profiles |
| **DNS** | Zone files (`%SystemRoot%\System32\dns`) |
| **Active Directory** | NTDS database, SYSVOL, Group Policy |
| **Web Servers** | IIS (inetpub, config), Apache, Nginx, XAMPP, WAMP |
| **Databases** | SQL Server, MySQL, PostgreSQL data directories |
| **Mail/FTP** | hMailServer, FileZilla Server |
| **Certificates** | Machine certificate store |
| **Logs** | Windows Event Logs (for forensics) |
| **Firewall** | Firewall log files |

The script auto-detects which services exist on the system.

```powershell
# CCDC defaults + custom paths
.\Backups.ps1 -CCDCDefaults -AdditionalPaths "C:\CustomApp\Config" -DestinationRoot "D:\Backups"

# CCDC defaults with verification
.\Backups.ps1 -CCDCDefaults -DestinationRoot "\\NAS\Backups" -Verify
```

## Backup Modes

| Mode | Flag | Description |
|------|------|-------------|
| Full | `-BackupMode Full` | Backs up all files (default) |
| Incremental | `-BackupMode Incremental` | Only files changed since last backup |
| Differential | `-BackupMode Differential` | Only files changed since last full backup |

## Common Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-CCDCDefaults` | off | Use predefined CCDC-critical paths |
| `-AdditionalPaths` | - | Extra paths to add (with `-CCDCDefaults`) |
| `-RetentionDays` | 30 | Days to keep old backups (0 = disable cleanup) |
| `-CompressionLevel` | Optimal | `Optimal`, `Fastest`, or `NoCompression` |
| `-ExcludePatterns` | `*.tmp`, `*.temp`, `~$*` | Wildcard patterns to skip |
| `-Verify` | off | Verify backup integrity after creation |

## Examples

```powershell
# Quick CCDC backup before competition starts
.\Backups.ps1 -CCDCDefaults -DestinationRoot "D:\Backups" -Verify

# Incremental backup during competition
.\Backups.ps1 -CCDCDefaults -DestinationRoot "D:\Backups" -BackupMode Incremental

# Backup to network share with fast compression
.\Backups.ps1 -CCDCDefaults -DestinationRoot "\\NAS\Backups" -CompressionLevel Fastest
```

## Email Notifications

```powershell
.\Backups.ps1 -CCDCDefaults -DestinationRoot "D:\Backups" `
  -EmailReport -SmtpServer "smtp.example.com" `
  -EmailFrom "backup@example.com" -EmailTo "admin@example.com" `
  -UseSSL -SmtpPort 587
```

## Output

Backups are saved as compressed ZIP files named:
```
Backup_<HOSTNAME>_<TIMESTAMP>_<MODE>.zip
```

Each backup includes a `backup.log` with detailed operation logs.

## Requirements

- Windows 10+ / Server 2016+
- Run as Administrator (for full access to system files)
