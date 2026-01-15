# Get-WindowsInventory.ps1 - CCDC Enhanced Edition v2.1

## 🎯 Overview

This is a **CCDC-ready** Windows system inventory and threat detection script designed specifically for Collegiate Cyber Defense Competition teams. It provides comprehensive system baselining, automated threat detection, and actionable security recommendations.

## 🆕 CCDC Enhancements (v2.1)

### Automated Threat Detection

The script now includes intelligent threat detection for:

- **Suspicious Processes**: Detects processes running from unusual locations (temp, appdata, public), double-extension executables, and potentially malicious script interpreters
- **Suspicious Services**: Identifies auto-start services in user directories, SYSTEM services from suspicious paths, and services using encoded commands
- **Suspicious Scheduled Tasks**: Flags tasks with hidden PowerShell, encoded commands, or non-Microsoft tasks in Microsoft folders
- **Suspicious Network Connections**: Identifies connections to common C2 ports (4444, 1337, etc.) and unusual processes making network connections
- **Unauthorized Administrators**: Detects potentially unauthorized members of the Administrators group
- **Security Weaknesses**: Checks for disabled UAC, enabled RDP, disabled Windows Firewall, disabled Windows Defender, and enabled Guest accounts
- **Recent System File Modifications**: Tracks changes to critical system directories in the last 24 hours

### Enhanced Reporting

- **Threat Summary Section**: The HTML report now includes a prominent threat analysis section at the top with color-coded warnings
- **Console Output**: Immediate threat summary displayed when script completes
- **CSV Exports**: All suspicious items are exported to easy-to-review CSV files with the prefix `threat_`
- **Actionable Recommendations**: Each finding includes specific remediation steps

## 🚀 Quick Start for CCDC

### Basic Usage (Recommended for Competition)

```powershell
# Run with Quick mode for fastest results
powershell -ExecutionPolicy Bypass -File .\Get-WindowsInventory.ps1 -Quick

# Run with all features (slower but more comprehensive)
powershell -ExecutionPolicy Bypass -File .\Get-WindowsInventory.ps1

# Run with compression for easy transfer
powershell -ExecutionPolicy Bypass -File .\Get-WindowsInventory.ps1 -Quick -Compress
```

### Advanced Usage

```powershell
# Custom output location with event logs
.\Get-WindowsInventory.ps1 -OutputRoot C:\CCDC\Inventory -IncludeEventLogs

# Quick scan without software/firewall enumeration
.\Get-WindowsInventory.ps1 -Quick -Software:$false -Firewall:$false

# Full scan with compression and event logs
.\Get-WindowsInventory.ps1 -IncludeEventLogs -Compress
```

## 📋 CCDC Workflow

### 1. Initial System Baseline (First 15 minutes)

```powershell
# Run on all systems as soon as competition starts
.\Get-WindowsInventory.ps1 -Quick -Compress
```

**Priority Actions:**
1. Review the threat summary in the console output
2. Open the HTML report (`system_report.html`) and check the "CCDC THREAT ANALYSIS" section
3. Address any **CRITICAL** security weaknesses immediately (Defender, Firewall, UAC)
4. Review `threat_suspicious_*.csv` files for immediate threats

### 2. Investigate Threats (Next 30 minutes)

Review these files in order of priority:

1. **`security_weaknesses.csv`**: Fix critical issues first (disabled Defender, disabled Firewall)
2. **`threat_unauthorized_admins.csv`**: Remove unauthorized administrator accounts
3. **`threat_suspicious_processes.csv`**: Kill malicious processes
4. **`threat_suspicious_services.csv`**: Stop and disable malicious services
5. **`threat_suspicious_connections.csv`**: Identify C2 connections and block them
6. **`threat_suspicious_tasks.csv`**: Disable or remove malicious scheduled tasks
7. **`recent_system_modifications_24h.csv`**: Check for backdoored system files

### 3. Establish Baseline

Save your initial inventory:
```powershell
# Archive baseline for later comparison
Copy-Item Inventory_* C:\CCDC\Baseline\
```

### 4. Periodic Monitoring (Every 30-60 minutes)

```powershell
# Re-run to detect new changes
.\Get-WindowsInventory.ps1 -Quick

# Compare with baseline manually or use file comparison tools
```

## 🔍 Understanding Threat Detection

### Suspicious Processes

The script flags processes that:
- Run from temporary directories (`%TEMP%`, `%APPDATA%\Local\Temp`, `C:\Users\Public`)
- Are script interpreters (PowerShell, cmd, wscript, etc.) - **Note**: These may be legitimate
- Have double extensions (e.g., `invoice.pdf.exe`)

**Action**: Review each process. Legitimate admin tools may be flagged, so use judgment.

### Suspicious Services

The script flags services that:
- Auto-start from user directories
- Run as SYSTEM from suspicious locations
- Use encoded PowerShell commands

**Action**: Stop and disable suspicious services immediately.

### Suspicious Network Connections

The script flags connections to:
- Common C2 ports: 4444, 5555, 6666, 7777, 8888, 1337, 31337
- Unusual processes making network connections (notepad, calc, mspaint)

**Action**: Identify the process, kill it, block the IP in the firewall.

### Security Weaknesses

The script checks:
- **UAC**: Should be enabled (EnableLUA = 1)
- **RDP**: Should be disabled unless needed
- **Windows Firewall**: Should be enabled for all profiles
- **Windows Defender**: Real-time protection and antivirus should be enabled
- **Guest Account**: Should be disabled

**Action**: Fix all Critical and High-risk issues immediately.

### Unauthorized Administrators

**IMPORTANT**: Customize the legitimate admin list in the script!

Edit line ~352 in the script:
```powershell
$legitimateAdmins = @(
  'Administrator',
  'Domain Admins',
  'Enterprise Admins',
  'YourTeamUsername1',  # Add your team accounts here
  'YourTeamUsername2'
)
```

**Action**: Remove any unauthorized accounts from the Administrators group immediately.

## 📊 Output Files

### Critical Threat Files (Review First)
- `security_weaknesses.csv` - Configuration vulnerabilities
- `threat_suspicious_processes.csv` - Potentially malicious processes
- `threat_suspicious_services.csv` - Potentially malicious services
- `threat_suspicious_connections.csv` - Suspicious network connections
- `threat_unauthorized_admins.csv` - Unexpected administrator accounts
- `threat_suspicious_tasks.csv` - Suspicious scheduled tasks
- `recent_system_modifications_24h.csv` - Recent changes to system files

### Standard Inventory Files
- `system_report.html` - Main report with threat analysis (OPEN THIS FIRST)
- `inventory.json` - Machine-readable summary
- `collection.log` - Execution log with errors
- `csv/` - Directory containing all detailed CSV exports
- `artifacts/` - Text artifacts (netstat, route, arp, systeminfo, etc.)

## ⚙️ Customization for Your Environment

### 1. Customize Legitimate Administrators

Edit the `Test-UnauthorizedAdmin` function (~line 348):

```powershell
$legitimateAdmins = @(
  'Administrator',
  'Domain Admins',
  'Enterprise Admins',
  'ccdc-team1',      # Your team accounts
  'ccdc-team2',
  'backup-admin'
)
```

### 2. Adjust Suspicious Path Detection

Edit detection functions to match your environment:
- `Test-SuspiciousProcess` (~line 276)
- `Test-SuspiciousService` (~line 300)
- `Get-RecentFileModifications` (~line 366)

### 3. Add Custom C2 Ports

Edit `Get-SuspiciousNetworkConnections` (~line 399):

```powershell
if ($conn.RemotePort -in @(4444, 5555, 6666, 7777, 8888, 31337, 1337, 8080, 9999)) {
  # Add your known malicious ports
}
```

## 🛡️ CCDC Defense Checklist

Use this script as part of your defense strategy:

- [ ] Run inventory on all systems within first 15 minutes
- [ ] Review threat analysis section immediately
- [ ] Fix all CRITICAL security weaknesses
- [ ] Remove unauthorized administrator accounts
- [ ] Kill suspicious processes
- [ ] Stop suspicious services
- [ ] Block suspicious network connections
- [ ] Disable suspicious scheduled tasks
- [ ] Review recent file modifications
- [ ] Save baseline for comparison
- [ ] Re-run periodically to detect changes
- [ ] Document all findings in incident log

## ⚡ Performance Tips

### Quick Mode
Use `-Quick` to skip:
- AppX package enumeration
- Full firewall rule export
- Certificate enumeration

**Execution Time**: ~30-60 seconds (vs 2-5 minutes full scan)

### Minimal Mode
For fastest results:
```powershell
.\Get-WindowsInventory.ps1 -Quick -Software:$false -Firewall:$false -Certs:$false
```

**Execution Time**: ~15-30 seconds

### Background Execution
Run on multiple systems simultaneously:
```powershell
# On remote systems
Invoke-Command -ComputerName Server1,Server2,Server3 -FilePath .\Get-WindowsInventory.ps1 -ArgumentList "-Quick"
```

## 🔒 Security Considerations

1. **Output Protection**: The script outputs to the current directory by default. Use `-OutputRoot` to specify a secure location not accessible to red team.

2. **Execution Policy**: The script uses `Bypass` which is appropriate for CCDC. This does not weaken system security.

3. **Admin Rights**: Run as Administrator for complete coverage. The script will work with limited rights but will miss some data.

4. **Network Transfer**: If transferring results off-system, use `-Compress` and secure channels.

## 🐛 Troubleshooting

### "Access Denied" Errors
- Run as Administrator
- Check if antivirus is blocking execution
- Review `collection.log` for specific errors

### Missing Data
- Some cmdlets require PowerShell 5.1+ (Windows 10/Server 2016+)
- Older systems fall back to WMI and legacy commands
- Check `collection.log` for details

### High False Positives
- Customize detection functions for your environment
- Review and adjust suspicious path patterns
- Update legitimate administrator list

## 📚 Additional Resources

### Quick Reference Commands

```powershell
# View threat summary
Import-Csv .\csv\threat_*.csv | Format-Table

# Count threats by category
Get-ChildItem .\csv\threat_*.csv | ForEach-Object {
  [PSCustomObject]@{
    Type = $_.Name
    Count = (Import-Csv $_.FullName).Count
  }
}

# Find critical weaknesses
Import-Csv .\csv\security_weaknesses.csv | Where-Object Risk -eq 'Critical'
```

### Recommended Next Steps After Inventory

1. **Harden Configuration**: Use findings to guide system hardening
2. **Monitor Changes**: Re-run periodically and diff results
3. **Document Baseline**: Keep records of legitimate software/services
4. **Incident Response**: Use findings as part of IR documentation
5. **Red Team Analysis**: Identify what red team may have already done

## 📝 Version History

### v2.1 (CCDC Enhanced Edition)
- Added automated threat detection for processes, services, tasks, connections
- Added security weakness identification
- Added unauthorized administrator detection
- Added recent file modification tracking
- Enhanced HTML report with prominent threat analysis
- Added console threat summary output
- Created CCDC-specific documentation

### v2.0 (Original)
- Comprehensive Windows inventory collection
- Multiple output formats (JSON, CSV, HTML)
- Read-only operations
- Error handling and graceful degradation

## 🤝 Contributing

To improve CCDC threat detection:
1. Add new detection patterns based on observed attacks
2. Improve false positive filtering
3. Add new security weakness checks
4. Enhance reporting and visualization

## 📄 License

Use freely for CCDC training and competition. No warranty provided.

---

**Good luck in your competition! 🏆**

*Remember: The best defense is a good offense... of thorough system inventory and monitoring!*
