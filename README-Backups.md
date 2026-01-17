# Backups.ps1

A PowerShell backup utility with compression, retention policies, and email notifications.

## Quick Start

```powershell
# Basic backup
.\Backups.ps1 -SourcePaths "C:\Documents" -DestinationRoot "D:\Backups"

# Multiple folders
.\Backups.ps1 -SourcePaths "C:\Documents","C:\Projects" -DestinationRoot "D:\Backups"
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
| `-RetentionDays` | 30 | Days to keep old backups (0 = disable cleanup) |
| `-CompressionLevel` | Optimal | `Optimal`, `Fastest`, or `NoCompression` |
| `-ExcludePatterns` | `*.tmp`, `*.temp`, `~$*` | Wildcard patterns to skip |
| `-Verify` | off | Verify backup integrity after creation |

## Examples

```powershell
# Incremental backup with 90-day retention and verification
.\Backups.ps1 -SourcePaths "C:\Data" -DestinationRoot "\\NAS\Backups" `
  -BackupMode Incremental -RetentionDays 90 -Verify

# Fast compression, exclude logs
.\Backups.ps1 -SourcePaths "C:\App" -DestinationRoot "D:\Backups" `
  -CompressionLevel Fastest -ExcludePatterns "*.tmp","*.log"
```

## Email Notifications

```powershell
.\Backups.ps1 -SourcePaths "C:\Data" -DestinationRoot "D:\Backups" `
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
