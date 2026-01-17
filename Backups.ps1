<#
.SYNOPSIS
  Flexible file/folder backup script with compression, rotation, and scheduling support.

.DESCRIPTION
  Creates compressed backups of specified paths with:
    - Full/Incremental/Differential backup modes
    - Automatic retention/rotation policies
    - Email notifications (optional)
    - Detailed logging
    - Exclusion patterns
    - Verification and integrity checks
    - VSS (Volume Shadow Copy) support for locked files
    - SHA256 file manifest for integrity verification
    - Network retry logic with exponential backoff

.PARAMETER SourcePaths
  Array of paths to backup (files or folders).

.PARAMETER DestinationRoot
  Root directory where backups will be stored.

.PARAMETER BackupMode
  Type of backup: Full, Incremental, or Differential (default: Full).

.PARAMETER RetentionDays
  Number of days to keep old backups (default: 30). Set to 0 to disable cleanup.

.PARAMETER CompressionLevel
  Compression level: Optimal, Fastest, NoCompression (default: Optimal).

.PARAMETER ExcludePatterns
  Array of wildcard patterns to exclude (e.g., *.tmp, *.log, ~$*).

.PARAMETER Verify
  Verify backup integrity after creation.

.PARAMETER EmailReport
  Send email report after backup completes.

.PARAMETER SmtpServer
  SMTP server for email notifications.

.PARAMETER EmailFrom
  Sender email address.

.PARAMETER EmailTo
  Recipient email address(es).

.PARAMETER EmailSubject
  Custom email subject (default: auto-generated).

.PARAMETER UseVSS
  Use Volume Shadow Copy for backing up locked files (requires admin).

.PARAMETER GenerateManifest
  Generate SHA256 hash manifest for integrity verification.

.PARAMETER NetworkRetries
  Number of retries for network operations (default: 3).

.EXAMPLE
  .\Backup-Files.ps1 -SourcePaths "C:\Users\John\Documents","C:\Projects" -DestinationRoot "D:\Backups"

.EXAMPLE
  .\Backup-Files.ps1 -SourcePaths "C:\Important" -DestinationRoot "\\NAS\Backups" -BackupMode Incremental -RetentionDays 90 -Verify

.EXAMPLE
  .\Backup-Files.ps1 -SourcePaths "C:\Data" -DestinationRoot "D:\Backups" -EmailReport -SmtpServer "smtp.gmail.com" -EmailFrom "backup@company.com" -EmailTo "admin@company.com"

.EXAMPLE
  .\Backup-Files.ps1 -SourcePaths "C:\Windows\System32\config" -DestinationRoot "D:\Backups" -UseVSS -GenerateManifest -Verify

.NOTES
  Version: 1.1
  Schedule with Task Scheduler for automatic backups.
  VSS requires administrator privileges.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string[]]$SourcePaths,
  
  [Parameter(Mandatory)]
  [string]$DestinationRoot,
  
  [ValidateSet("Full","Incremental","Differential")]
  [string]$BackupMode = "Full",
  
  [int]$RetentionDays = 30,
  
  [ValidateSet("Optimal","Fastest","NoCompression")]
  [string]$CompressionLevel = "Optimal",
  
  [string[]]$ExcludePatterns = @("*.tmp","*.temp","~$*","Thumbs.db","desktop.ini"),
  
  [switch]$Verify,
  
  [switch]$EmailReport,
  
  [string]$SmtpServer,
  
  [string]$EmailFrom,
  
  [string[]]$EmailTo,
  
  [string]$EmailSubject,
  
  [switch]$UseSSL,
  
  [int]$SmtpPort = 587,

  [PSCredential]$SmtpCredential,

  [switch]$UseVSS,

  [switch]$GenerateManifest,

  [ValidateRange(0,10)]
  [int]$NetworkRetries = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Validate email parameters if EmailReport is requested
if ($EmailReport) {
  if (-not $SmtpServer) { throw "EmailReport requires -SmtpServer parameter" }
  if (-not $EmailFrom) { throw "EmailReport requires -EmailFrom parameter" }
  if (-not $EmailTo) { throw "EmailReport requires -EmailTo parameter" }
}

# Script-level variables
$script:StartTime = Get-Date
$script:LogPath = $null
$script:BackupLog = @()
$script:Stats = @{
  FilesProcessed = 0
  FilesSkipped = 0
  FilesFailed = 0
  BytesProcessed = 0
  BytesSkipped = 0
  Warnings = 0
  Errors = 0
}

# ---------------------------- Helper Functions ----------------------------

function Write-Log {
  param(
    [Parameter(Mandatory)]
    [string]$Message,
    [ValidateSet("INFO","SUCCESS","WARN","ERROR")]
    [string]$Level = "INFO"
  )
  
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $logEntry = "[$timestamp] [$Level] $Message"
  
  # Console output with colors
  $color = switch ($Level) {
    "SUCCESS" { "Green" }
    "WARN"    { "Yellow" }
    "ERROR"   { "Red" }
    default   { "White" }
  }
  
  Write-Host $logEntry -ForegroundColor $color
  
  # File output
  if ($script:LogPath) {
    $logEntry | Out-File -Append -FilePath $script:LogPath -Encoding UTF8
  }
  
  # Add to backup log for reporting
  $script:BackupLog += [pscustomobject]@{
    Timestamp = Get-Date
    Level = $Level
    Message = $Message
  }
  
  if ($Level -eq "WARN") { $script:Stats.Warnings++ }
  if ($Level -eq "ERROR") { $script:Stats.Errors++ }
}

function Invoke-WithRetry {
  param(
    [Parameter(Mandatory)]
    [scriptblock]$ScriptBlock,
    [int]$MaxRetries = $NetworkRetries,
    [string]$OperationName = "Operation"
  )

  $attempt = 0
  $lastError = $null

  while ($attempt -le $MaxRetries) {
    try {
      return & $ScriptBlock
    } catch {
      $lastError = $_
      $attempt++

      if ($attempt -le $MaxRetries) {
        $waitSeconds = [math]::Pow(2, $attempt)
        Write-Log "$OperationName failed (attempt $attempt/$MaxRetries), retrying in ${waitSeconds}s: $($_.Exception.Message)" -Level "WARN"
        Start-Sleep -Seconds $waitSeconds
      }
    }
  }

  throw $lastError
}

function New-VSSSnapshot {
  param([string]$DriveLetter)

  if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "VSS requires administrator privileges - skipping shadow copy" -Level "WARN"
    return $null
  }

  try {
    Write-Log "Creating VSS snapshot for drive $DriveLetter..."

    $shadowResult = (Get-WmiObject -List Win32_ShadowCopy).Create("${DriveLetter}\", "ClientAccessible")
    if ($shadowResult.ReturnValue -ne 0) {
      throw "VSS creation failed with code: $($shadowResult.ReturnValue)"
    }

    $shadowCopy = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadowResult.ShadowID }
    $shadowPath = $shadowCopy.DeviceObject + "\"

    Write-Log "VSS snapshot created: $shadowPath" -Level "SUCCESS"

    return [pscustomobject]@{
      ShadowID = $shadowResult.ShadowID
      ShadowPath = $shadowPath
      DriveLetter = $DriveLetter
    }
  } catch {
    Write-Log "Failed to create VSS snapshot: $_" -Level "WARN"
    return $null
  }
}

function Remove-VSSSnapshot {
  param([pscustomobject]$Snapshot)

  if (-not $Snapshot) { return }

  try {
    $shadowCopy = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $Snapshot.ShadowID }
    if ($shadowCopy) {
      $shadowCopy.Delete()
      Write-Log "VSS snapshot removed" -Level "SUCCESS"
    }
  } catch {
    Write-Log "Failed to remove VSS snapshot: $_" -Level "WARN"
  }
}

function Get-VSSPath {
  param(
    [string]$OriginalPath,
    [hashtable]$VSSSnapshots
  )

  if (-not $VSSSnapshots -or $VSSSnapshots.Count -eq 0) {
    return $OriginalPath
  }

  $driveLetter = Split-Path -Qualifier $OriginalPath
  if ($VSSSnapshots.ContainsKey($driveLetter)) {
    $snapshot = $VSSSnapshots[$driveLetter]
    $relativePath = $OriginalPath.Substring($driveLetter.Length)
    return $snapshot.ShadowPath + $relativePath.TrimStart('\')
  }

  return $OriginalPath
}

function New-FileManifest {
  param(
    [Parameter(Mandatory)]
    [string]$BackupFolder,
    [Parameter(Mandatory)]
    [string]$ManifestPath
  )

  Write-Log "Generating file manifest with SHA256 hashes..."

  try {
    $manifest = @()
    $files = Get-ChildItem -Path $BackupFolder -Recurse -File -ErrorAction SilentlyContinue

    $fileCount = 0
    foreach ($file in $files) {
      $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
      $relativePath = $file.FullName.Substring($BackupFolder.Length).TrimStart('\')

      $manifest += [pscustomobject]@{
        Path = $relativePath
        SHA256 = $hash
        Size = $file.Length
        Modified = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
      }
      $fileCount++
    }

    $manifest | Export-Csv -Path $ManifestPath -NoTypeInformation -Encoding UTF8
    Write-Log "Manifest generated: $fileCount files hashed" -Level "SUCCESS"

    return $ManifestPath
  } catch {
    Write-Log "Failed to generate manifest: $_" -Level "ERROR"
    return $null
  }
}

function Test-ManifestIntegrity {
  param(
    [Parameter(Mandatory)]
    [string]$BackupFolder,
    [Parameter(Mandatory)]
    [string]$ManifestPath
  )

  Write-Log "Verifying files against manifest..."

  try {
    $manifest = Import-Csv -Path $ManifestPath
    $failures = 0

    foreach ($entry in $manifest) {
      $filePath = Join-Path $BackupFolder $entry.Path
      if (-not (Test-Path $filePath)) {
        Write-Log "Missing file: $($entry.Path)" -Level "ERROR"
        $failures++
        continue
      }

      $currentHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
      if ($currentHash -ne $entry.SHA256) {
        Write-Log "Hash mismatch: $($entry.Path)" -Level "ERROR"
        $failures++
      }
    }

    if ($failures -eq 0) {
      Write-Log "Manifest verification passed: $($manifest.Count) files verified" -Level "SUCCESS"
      return $true
    } else {
      Write-Log "Manifest verification failed: $failures file(s) with issues" -Level "ERROR"
      return $false
    }
  } catch {
    Write-Log "Manifest verification failed: $_" -Level "ERROR"
    return $false
  }
}

function Initialize-BackupEnvironment {
  param([string]$Root)
  
  try {
    # Create destination root if it doesn't exist
    if (-not (Test-Path $Root)) {
      New-Item -ItemType Directory -Path $Root -Force | Out-Null
      Write-Log "Created backup destination: $Root" -Level "SUCCESS"
    }
    
    # Create timestamped backup folder
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $backupFolder = Join-Path $Root "Backup_${hostname}_${timestamp}_${BackupMode}"
    
    New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null
    
    # Initialize log
    $script:LogPath = Join-Path $backupFolder "backup.log"
    
    return $backupFolder
  } catch {
    Write-Error "Failed to initialize backup environment: $_"
    throw
  }
}

function Get-LastBackupInfo {
  param([string]$Root)
  
  try {
    $backups = Get-ChildItem -Path $Root -Directory | 
      Where-Object { $_.Name -match '^Backup_.*_\d{8}_\d{6}_' } |
      Sort-Object CreationTime -Descending
    
    if ($backups.Count -gt 0) {
      $lastFull = $backups | Where-Object { $_.Name -match '_Full$' } | Select-Object -First 1
      $lastAny = $backups | Select-Object -First 1
      
      return [pscustomobject]@{
        LastFullBackup = $lastFull
        LastBackup = $lastAny
      }
    }
    
    return $null
  } catch {
    Write-Log "Failed to get last backup info: $_" -Level "WARN"
    return $null
  }
}

function Test-ShouldBackupFile {
  param(
    [Parameter(Mandatory)]
    [System.IO.FileInfo]$File,
    [datetime]$BaselineDate
  )
  
  # Check exclusion patterns
  foreach ($pattern in $ExcludePatterns) {
    if ($File.Name -like $pattern) {
      Write-Log "Skipped (excluded): $($File.FullName)" -Level "INFO"
      $script:Stats.FilesSkipped++
      $script:Stats.BytesSkipped += $File.Length
      return $false
    }
  }
  
  # For incremental/differential, check modification date
  if ($BackupMode -ne "Full" -and $BaselineDate) {
    if ($File.LastWriteTime -le $BaselineDate) {
      $script:Stats.FilesSkipped++
      $script:Stats.BytesSkipped += $File.Length
      return $false
    }
  }
  
  return $true
}

function Copy-FileWithMetadata {
  param(
    [Parameter(Mandatory)]
    [string]$SourcePath,
    [Parameter(Mandatory)]
    [string]$DestinationPath
  )

  # Check if destination is a network path (UNC or mapped drive pointing to network)
  $isNetworkPath = $DestinationPath -match '^\\\\' -or
    ((Split-Path -Qualifier $DestinationPath -ErrorAction SilentlyContinue) -and
     (Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$(Split-Path -Qualifier $DestinationPath)'" -ErrorAction SilentlyContinue).DriveType -eq 4)

  $copyOperation = {
    # Ensure destination directory exists
    $destDir = Split-Path -Parent $DestinationPath
    if (-not (Test-Path $destDir)) {
      New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    # Copy file preserving timestamps
    Copy-Item -Path $SourcePath -Destination $DestinationPath -Force

    # Preserve timestamps
    $sourceFile = Get-Item $SourcePath
    $destFile = Get-Item $DestinationPath
    $destFile.CreationTime = $sourceFile.CreationTime
    $destFile.LastWriteTime = $sourceFile.LastWriteTime
    $destFile.LastAccessTime = $sourceFile.LastAccessTime

    return $sourceFile.Length
  }

  try {
    if ($isNetworkPath -and $NetworkRetries -gt 0) {
      $fileSize = Invoke-WithRetry -ScriptBlock $copyOperation -OperationName "Copy $SourcePath"
    } else {
      $fileSize = & $copyOperation
    }

    $script:Stats.FilesProcessed++
    $script:Stats.BytesProcessed += $fileSize

    return $true
  } catch {
    Write-Log "Failed to copy file $SourcePath : $_" -Level "ERROR"
    $script:Stats.FilesFailed++
    return $false
  }
}

function Backup-Path {
  param(
    [Parameter(Mandatory)]
    [string]$SourcePath,
    [Parameter(Mandatory)]
    [string]$DestinationFolder,
    [datetime]$BaselineDate,
    [hashtable]$VSSSnapshots
  )

  Write-Log "Processing: $SourcePath"

  if (-not (Test-Path $SourcePath)) {
    Write-Log "Source path not found: $SourcePath" -Level "ERROR"
    return
  }

  $item = Get-Item $SourcePath

  if ($item.PSIsContainer) {
    # Directory - process recursively
    $files = Get-ChildItem -Path $SourcePath -Recurse -File -ErrorAction SilentlyContinue

    foreach ($file in $files) {
      if (Test-ShouldBackupFile -File $file -BaselineDate $BaselineDate) {
        $relativePath = $file.FullName.Substring($SourcePath.Length).TrimStart('\')
        $destPath = Join-Path $DestinationFolder (Split-Path -Leaf $SourcePath)
        $destPath = Join-Path $destPath $relativePath

        # Use VSS path if available for locked file access
        $effectiveSource = Get-VSSPath -OriginalPath $file.FullName -VSSSnapshots $VSSSnapshots
        $null = Copy-FileWithMetadata -SourcePath $effectiveSource -DestinationPath $destPath
      }
    }
  } else {
    # Single file
    if (Test-ShouldBackupFile -File $item -BaselineDate $BaselineDate) {
      $destPath = Join-Path $DestinationFolder $item.Name
      $effectiveSource = Get-VSSPath -OriginalPath $item.FullName -VSSSnapshots $VSSSnapshots
      $null = Copy-FileWithMetadata -SourcePath $effectiveSource -DestinationPath $destPath
    }
  }
}

function Compress-Backup {
  param(
    [Parameter(Mandatory)]
    [string]$BackupFolder
  )
  
  Write-Log "Compressing backup..."
  
  try {
    $zipPath = "$BackupFolder.zip"
    
    $compressionParam = switch ($CompressionLevel) {
      "Optimal" { [System.IO.Compression.CompressionLevel]::Optimal }
      "Fastest" { [System.IO.Compression.CompressionLevel]::Fastest }
      "NoCompression" { [System.IO.Compression.CompressionLevel]::NoCompression }
    }
    
    Add-Type -Assembly "System.IO.Compression.FileSystem"
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
      $BackupFolder, 
      $zipPath, 
      $compressionParam, 
      $false
    )
    
    $zipSize = (Get-Item $zipPath).Length
    $originalSize = (Get-ChildItem $BackupFolder -Recurse -File | Measure-Object -Property Length -Sum).Sum
    $ratio = if ($originalSize -gt 0) {
      [math]::Round((1 - ($zipSize / $originalSize)) * 100, 2)
    } else { 0 }
    
    Write-Log "Compressed backup created: $zipPath" -Level "SUCCESS"
    Write-Log "Compression ratio: $ratio% (Original: $([math]::Round($originalSize/1MB,2))MB → Compressed: $([math]::Round($zipSize/1MB,2))MB)"

    # Move log file outside backup folder before removing it
    if ($script:LogPath -and (Test-Path $script:LogPath)) {
      $newLogPath = "$zipPath.log"
      Copy-Item -Path $script:LogPath -Destination $newLogPath -Force
      $script:LogPath = $newLogPath
    }

    # Move manifest file outside backup folder before removing it
    $manifestFile = Join-Path $BackupFolder "manifest.csv"
    if (Test-Path $manifestFile) {
      Copy-Item -Path $manifestFile -Destination "$zipPath.manifest.csv" -Force
    }

    # Remove uncompressed folder
    Remove-Item -Path $BackupFolder -Recurse -Force

    return $zipPath
  } catch {
    Write-Log "Compression failed: $_" -Level "ERROR"
    return $BackupFolder
  }
}

function Test-BackupIntegrity {
  param([string]$BackupPath)
  
  Write-Log "Verifying backup integrity..."
  
  try {
    if ($BackupPath -match '\.zip$') {
      # Verify ZIP archive
      Add-Type -Assembly "System.IO.Compression.FileSystem"
      $zip = [System.IO.Compression.ZipFile]::OpenRead($BackupPath)
      $entryCount = $zip.Entries.Count
      $zip.Dispose()
      
      Write-Log "ZIP verification passed: $entryCount entries" -Level "SUCCESS"
      return $true
    } else {
      # Verify folder
      $fileCount = (Get-ChildItem $BackupPath -Recurse -File).Count
      Write-Log "Folder verification passed: $fileCount files" -Level "SUCCESS"
      return $true
    }
  } catch {
    Write-Log "Verification failed: $_" -Level "ERROR"
    return $false
  }
}

function Remove-OldBackups {
  param(
    [string]$Root,
    [int]$Days
  )
  
  if ($Days -le 0) {
    Write-Log "Retention policy disabled (RetentionDays = 0)"
    return
  }
  
  Write-Log "Cleaning up backups older than $Days days..."
  
  try {
    $cutoffDate = (Get-Date).AddDays(-$Days)
    $oldBackups = Get-ChildItem -Path $Root | 
      Where-Object { 
        ($_.Name -match '^Backup_.*_\d{8}_\d{6}') -and 
        ($_.CreationTime -lt $cutoffDate) 
      }
    
    $removedCount = 0
    $freedSpace = 0
    
    foreach ($backup in $oldBackups) {
      $size = if ($backup.PSIsContainer) {
        (Get-ChildItem $backup.FullName -Recurse -File | Measure-Object -Property Length -Sum).Sum
      } else {
        $backup.Length
      }
      
      Remove-Item -Path $backup.FullName -Recurse -Force
      $removedCount++
      $freedSpace += $size
      
      Write-Log "Removed old backup: $($backup.Name)"
    }
    
    if ($removedCount -gt 0) {
      Write-Log "Cleanup complete: Removed $removedCount backup(s), freed $([math]::Round($freedSpace/1MB,2))MB" -Level "SUCCESS"
    } else {
      Write-Log "No old backups to remove"
    }
  } catch {
    Write-Log "Cleanup failed: $_" -Level "WARN"
  }
}

function Send-EmailNotification {
  param([string]$BackupPath)
  
  if (-not $EmailReport) { return }
  
  Write-Log "Sending email notification..."
  
  try {
    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 2)
    $status = if ($script:Stats.Errors -gt 0) { "⚠ COMPLETED WITH ERRORS" } else { "✓ SUCCESS" }
    
    $subject = if ($EmailSubject) { 
      $EmailSubject 
    } else { 
      "Backup Report: $env:COMPUTERNAME - $status"
    }
    
    $body = @"
<html>
<head>
<style>
  body { font-family: Arial, sans-serif; }
  table { border-collapse: collapse; width: 100%; margin: 20px 0; }
  th { background-color: #4CAF50; color: white; padding: 10px; text-align: left; }
  td { padding: 8px; border-bottom: 1px solid #ddd; }
  .success { color: green; font-weight: bold; }
  .error { color: red; font-weight: bold; }
  .warn { color: orange; font-weight: bold; }
</style>
</head>
<body>
<h2>Backup Report - $env:COMPUTERNAME</h2>
<p><b>Status:</b> <span class='$(if($script:Stats.Errors -gt 0){"error"}else{"success"})'>$status</span></p>
<p><b>Mode:</b> $BackupMode</p>
<p><b>Started:</b> $($script:StartTime.ToString("yyyy-MM-dd HH:mm:ss"))</p>
<p><b>Duration:</b> $duration minutes</p>

<h3>Statistics</h3>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Files Processed</td><td>$($script:Stats.FilesProcessed)</td></tr>
  <tr><td>Files Skipped</td><td>$($script:Stats.FilesSkipped)</td></tr>
  <tr><td>Files Failed</td><td class='$(if($script:Stats.FilesFailed -gt 0){"error"}else{""})'>$($script:Stats.FilesFailed)</td></tr>
  <tr><td>Data Processed</td><td>$([math]::Round($script:Stats.BytesProcessed/1MB,2)) MB</td></tr>
  <tr><td>Data Skipped</td><td>$([math]::Round($script:Stats.BytesSkipped/1MB,2)) MB</td></tr>
  <tr><td>Warnings</td><td class='$(if($script:Stats.Warnings -gt 0){"warn"}else{""})'>$($script:Stats.Warnings)</td></tr>
  <tr><td>Errors</td><td class='$(if($script:Stats.Errors -gt 0){"error"}else{""})'>$($script:Stats.Errors)</td></tr>
</table>

<h3>Backup Location</h3>
<p>$BackupPath</p>

<h3>Source Paths</h3>
<ul>
$($SourcePaths | ForEach-Object { "<li>$_</li>" } | Out-String)
</ul>

<hr>
<p style='font-size: 0.9em; color: #666;'>Generated by Backup-Files.ps1 v1.1</p>
</body>
</html>
"@

    $mailParams = @{
      From = $EmailFrom
      To = $EmailTo
      Subject = $subject
      Body = $body
      BodyAsHtml = $true
      SmtpServer = $SmtpServer
      Port = $SmtpPort
      UseSsl = $UseSSL
    }
    
    if ($SmtpCredential) {
      $mailParams.Credential = $SmtpCredential
    }
    
    Send-MailMessage @mailParams
    
    Write-Log "Email sent successfully" -Level "SUCCESS"
  } catch {
    Write-Log "Failed to send email: $_" -Level "ERROR"
  }
}

function Show-Summary {
  param([string]$BackupPath, [double]$Duration)
  
  Write-Host ""
  Write-Host "========================================" -ForegroundColor Cyan
  Write-Host "  Backup Complete!" -ForegroundColor Cyan
  Write-Host "========================================" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "Mode:             " -NoNewline
  Write-Host $BackupMode -ForegroundColor Yellow
  Write-Host "Backup Location:  " -NoNewline
  Write-Host $BackupPath -ForegroundColor Cyan
  Write-Host "Duration:         " -NoNewline
  Write-Host "$([math]::Round($Duration,2)) minutes" -ForegroundColor Yellow
  Write-Host ""
  Write-Host "Files Processed:  " -NoNewline
  Write-Host $script:Stats.FilesProcessed -ForegroundColor Green
  Write-Host "Files Skipped:    " -NoNewline
  Write-Host $script:Stats.FilesSkipped -ForegroundColor Gray
  Write-Host "Files Failed:     " -NoNewline
  Write-Host $script:Stats.FilesFailed -ForegroundColor $(if($script:Stats.FilesFailed -gt 0){"Red"}else{"Green"})
  Write-Host "Data Processed:   " -NoNewline
  Write-Host "$([math]::Round($script:Stats.BytesProcessed/1MB,2)) MB" -ForegroundColor Green
  Write-Host "Data Skipped:     " -NoNewline
  Write-Host "$([math]::Round($script:Stats.BytesSkipped/1MB,2)) MB" -ForegroundColor Gray
  Write-Host ""
  Write-Host "Warnings:         " -NoNewline
  Write-Host $script:Stats.Warnings -ForegroundColor $(if($script:Stats.Warnings -gt 0){"Yellow"}else{"Green"})
  Write-Host "Errors:           " -NoNewline
  Write-Host $script:Stats.Errors -ForegroundColor $(if($script:Stats.Errors -gt 0){"Red"}else{"Green"})
  Write-Host ""
}

# ---------------------------- Main Execution ----------------------------

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  File Backup Utility v1.1" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$vssSnapshots = @{}

try {
  # Initialize
  $backupFolder = Initialize-BackupEnvironment -Root $DestinationRoot
  Write-Log "Backup started: $BackupMode mode" -Level "SUCCESS"
  Write-Log "Destination: $backupFolder"

  # Create VSS snapshots if requested
  if ($UseVSS) {
    $drives = $SourcePaths | ForEach-Object {
      Split-Path -Qualifier $_ -ErrorAction SilentlyContinue
    } | Select-Object -Unique | Where-Object { $_ }

    foreach ($drive in $drives) {
      $snapshot = New-VSSSnapshot -DriveLetter $drive
      if ($snapshot) {
        $vssSnapshots[$drive] = $snapshot
      }
    }
  }

  # Get baseline for incremental/differential
  $baselineDate = $null
  if ($BackupMode -ne "Full") {
    $lastBackup = Get-LastBackupInfo -Root $DestinationRoot

    if ($BackupMode -eq "Incremental" -and $lastBackup.LastBackup) {
      $baselineDate = $lastBackup.LastBackup.CreationTime
      Write-Log "Incremental backup - baseline: $($lastBackup.LastBackup.Name)"
    } elseif ($BackupMode -eq "Differential" -and $lastBackup.LastFullBackup) {
      $baselineDate = $lastBackup.LastFullBackup.CreationTime
      Write-Log "Differential backup - baseline: $($lastBackup.LastFullBackup.Name)"
    } else {
      Write-Log "No baseline found, performing Full backup" -Level "WARN"
      $BackupMode = "Full"
    }
  }

  # Backup each source path
  Write-Log "Processing $($SourcePaths.Count) source path(s)..."
  foreach ($sourcePath in $SourcePaths) {
    Backup-Path -SourcePath $sourcePath -DestinationFolder $backupFolder -BaselineDate $baselineDate -VSSSnapshots $vssSnapshots
  }

  # Generate manifest before compression
  $manifestPath = $null
  if ($GenerateManifest) {
    $manifestPath = Join-Path $backupFolder "manifest.csv"
    $null = New-FileManifest -BackupFolder $backupFolder -ManifestPath $manifestPath
  }

  # Compress if requested
  if ($CompressionLevel -ne "NoCompression") {
    $backupFolder = Compress-Backup -BackupFolder $backupFolder
    # Update manifest path after compression
    if ($manifestPath) {
      $manifestPath = "$backupFolder.manifest.csv"
    }
  }

  # Verify integrity
  if ($Verify) {
    $verified = Test-BackupIntegrity -BackupPath $backupFolder
    if (-not $verified) {
      Write-Log "Backup verification failed!" -Level "ERROR"
    }
  }

  # Cleanup old backups
  Remove-OldBackups -Root $DestinationRoot -Days $RetentionDays

  # Calculate duration
  $duration = ((Get-Date) - $script:StartTime).TotalMinutes

  Write-Log "Backup completed successfully" -Level "SUCCESS"

  # Send email notification
  if ($EmailReport) {
    Send-EmailNotification -BackupPath $backupFolder
  }

  # Show summary
  Show-Summary -BackupPath $backupFolder -Duration $duration

} catch {
  Write-Log "Backup failed: $_" -Level "ERROR"
  Write-Host ""
  Write-Host "BACKUP FAILED" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
  exit 1
} finally {
  # Cleanup VSS snapshots
  foreach ($snapshot in $vssSnapshots.Values) {
    Remove-VSSSnapshot -Snapshot $snapshot
  }
}
