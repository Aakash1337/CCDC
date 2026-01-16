# Windows Inventory Data Collection Reference

## 📊 Complete List of Data Collected by Get-WindowsInventory.ps1

This document provides a comprehensive list of everything the script collects from Windows systems.

---

## System Information

### Basic System Details
- **Computer Name**: NetBIOS name
- **Domain**: Domain membership status and name
- **Operating System**: Full OS name, version, build number, architecture
- **Installation Date**: When OS was installed
- **Last Boot Time**: Most recent system restart
- **Uptime**: Hours since last boot
- **BIOS Information**: Version and serial number
- **Manufacturer & Model**: Hardware vendor and model
- **Timezone**: System timezone setting
- **Time Collected**: Timestamp of inventory collection

### Hardware Information
- **CPU**: Processor name, cores, logical processors
- **Memory**: Total RAM in GB
- **Disk Drives**: All physical and logical drives
  - Drive letter, label, file system
  - Total size, free space, used space (GB)
  - Drive type (Fixed, Removable, Network, etc.)

---

## Security Configuration

### Security Settings
- **UAC (User Account Control)**: Enabled/disabled status
- **RDP (Remote Desktop)**: Enabled/disabled status
- **Windows Firewall**: Status for all profiles (Domain, Private, Public)
- **Windows Defender**:
  - Real-time protection status
  - Antivirus enabled status
  - Signature update date

### User Accounts
- **All Local Users**:
  - Username
  - Full name
  - Enabled/disabled status
  - Password required status
  - Password changeable status
  - Password expires status
  - Account type (Administrator, User, Guest)
  - Last logon time
  - SID (Security Identifier)

### Group Memberships
- **All Local Groups** with members:
  - Group name
  - Member name
  - Member type (User, Group)
  - Domain/computer source
- **Special Focus**: Administrators group members

---

## Running Processes

### Process Information
For each running process:
- **Process Name**: Executable name
- **Process ID (PID)**: Unique identifier
- **Path**: Full path to executable
- **Command Line**: Full command with arguments
- **Company**: Software vendor
- **Product**: Product name
- **File Version**: Executable version
- **Description**: Product description
- **Parent Process ID**: PPID for process tree analysis
- **Threads**: Number of threads
- **Handles**: Number of open handles
- **Working Set (MB)**: Memory usage
- **Start Time**: When process started
- **CPU (seconds)**: Total CPU time used

---

## Windows Services

### Service Details
For each service:
- **Name**: Service short name
- **Display Name**: Friendly name
- **State**: Running, Stopped, Paused, etc.
- **Start Mode**: Auto, Manual, Disabled
- **Account**: Account service runs as (LocalSystem, NetworkService, etc.)
- **Path Name**: Full path to service executable with arguments
- **Description**: Service description
- **Status**: Additional status information

---

## Scheduled Tasks

### Task Information
For each scheduled task:
- **Task Name**: Task identifier
- **Task Path**: Folder path in Task Scheduler
- **State**: Ready, Running, Disabled
- **Enabled**: True/False
- **Last Run Time**: When task last executed
- **Next Run Time**: When task will run next
- **Last Result**: Exit code from last run
- **Author**: Task creator
- **Triggers**: When task runs (time-based, event-based, etc.)
- **Actions**: What task executes (formatted with command and arguments)

---

## Network Configuration

### Network Connections
- **Active TCP/UDP Connections**:
  - Protocol (TCP/UDP)
  - Local address and port
  - Remote address and port
  - Connection state (Established, Listening, etc.)
  - Process ID
  - Process name
  - Process path
  - Process command line

### Established Connections (Separate tracking)
- All ESTABLISHED TCP connections
- Mapped to process information

### Listening Ports
- **All listening TCP/UDP ports**:
  - Protocol
  - Local address
  - Port number
  - Process information

### Network Interfaces
- **All network adapters**:
  - Interface name
  - Description
  - MAC address
  - IP addresses (all assigned IPs)
  - Subnet mask
  - Default gateway
  - DNS servers
  - DHCP enabled status
  - Interface status (Up, Down)

### Network Shares
- **All shared folders**:
  - Share name
  - Path
  - Description
  - Maximum users allowed
  - Current sessions

### Routing & ARP
- **Routing Table**: All routes
- **ARP Cache**: All ARP entries
- **DNS Cache**: All cached DNS entries

---

## Installed Software

### Software Inventory
From both Registry locations (32-bit and 64-bit):
- **Display Name**: Software name
- **Publisher**: Vendor/company
- **Version**: Software version
- **Install Date**: When installed
- **Install Location**: Installation path
- **Uninstall String**: Uninstall command

### Windows Updates/Patches
- **All installed hotfixes**:
  - Hotfix ID (KB number)
  - Description
  - Installed By (user)
  - Installed On (date)

---

## Startup and Autorun Items

### Autoruns
Registry keys and locations checked:
- **HKLM\Software\Microsoft\Windows\CurrentVersion\Run**
- **HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce**
- **HKCU\Software\Microsoft\Windows\CurrentVersion\Run**
- **HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce**
- **Startup folder items** (All Users and Current User)

For each autorun:
- **Name**: Entry name
- **Command**: Full command/path
- **Location**: Registry key or folder path
- **Type**: Run, RunOnce, Startup Folder

---

## Security & Certificates

### Certificates
From all certificate stores:
- **Thumbprint**: Unique identifier
- **Subject**: Certificate subject (CN)
- **Issuer**: Who issued certificate
- **Not Before**: Valid from date
- **Not After**: Expiration date
- **Store**: Certificate store location
- **Has Private Key**: True/False

### Firewall Rules
- **All Windows Firewall rules**:
  - Name
  - Display name
  - Description
  - Direction (Inbound/Outbound)
  - Action (Allow/Block)
  - Enabled status
  - Profile (Domain, Private, Public)
  - Local port
  - Remote port
  - Protocol
  - Program path

---

## Event Logs (Optional with -IncludeEventLogs)

### Security Events
- Logon/logoff events
- Account management
- Privilege use
- Policy changes
- System events

### System Events
- Service start/stop
- System startup/shutdown
- Error and warning events

### Application Events
- Application errors
- Application warnings

---

## Artifacts & Raw Data

### Text Files Generated
- **netstat.txt**: Raw netstat output
- **route.txt**: Route print output
- **arp.txt**: ARP table
- **ipconfig_all.txt**: Full IP configuration
- **systeminfo.txt**: System information output
- **gpresult.txt**: Group Policy results (if available)
- **drivers.txt**: Installed drivers list
- **hosts_file.txt**: Copy of hosts file
- **reg_run_*.txt**: Registry Run key exports

---

## 🔍 CCDC Threat Detection (Automated Analysis)

### Suspicious Processes
Flags processes that:
- Run from temporary directories (`%TEMP%`, `AppData\Local\Temp`, `C:\Users\Public`)
- Are script interpreters (powershell.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe)
- Have double extensions (e.g., `document.pdf.exe`)

**Output**: `csv/threat_suspicious_processes.csv`

### Suspicious Services
Flags services that:
- Auto-start from user directories or temp folders
- Run as SYSTEM from suspicious locations
- Use encoded PowerShell commands

**Output**: `csv/threat_suspicious_services.csv`

### Suspicious Scheduled Tasks
Flags tasks with:
- Hidden PowerShell execution (`-WindowStyle Hidden`)
- Encoded commands (`-EncodedCommand`)
- Non-Microsoft tasks in `\Microsoft\` folder

**Output**: `csv/threat_suspicious_tasks.csv`

### Suspicious Network Connections
Flags connections to:
- Common C2 ports (4444, 5555, 6666, 7777, 8888, 1337, 31337)
- Unusual processes with network connections (notepad, calc, mspaint)

**Output**: `csv/threat_suspicious_connections.csv`

### Unauthorized Administrators
Flags accounts in Administrators group that are not in the configured legitimate list.

**Output**: `csv/threat_unauthorized_admins.csv`

**Note**: Customize the legitimate admin list in the script!

### Security Weaknesses
Checks for:
- **Critical**:
  - UAC disabled
  - Windows Firewall disabled
  - Windows Defender disabled
- **High**:
  - RDP enabled
- **Medium**:
  - Guest account enabled

**Output**: `csv/security_weaknesses.csv`

### Recent System File Modifications
Tracks files modified in last 24 hours in:
- `C:\Windows\System32`
- `C:\Windows\SysWOW64`
- `C:\Program Files`
- `C:\Program Files (x86)`

**Output**: `csv/recent_system_modifications_24h.csv`

---

## 🔄 Baseline Comparison Features

### Integrated Baseline Management
When run multiple times, the script automatically:

1. **First Run**: Creates a baseline snapshot in `./baseline/` folder
2. **Subsequent Runs**: Compares current state with baseline
3. **Baseline Update**: Use `-UpdateBaseline` flag to refresh baseline after hardening

### Baseline Data Stored
- processes.csv
- services.csv
- tasks.csv (scheduled tasks)
- users.csv
- admins.csv (administrator group members)
- software.csv
- autoruns.csv
- shares.csv
- metadata.json (timestamp and system info)

### Comparison Detection
Automatically detects changes in:
- **Processes**: Added/removed processes
- **Services**: Added/removed services
- **Scheduled Tasks**: Added/removed tasks
- **Users**: Added/removed accounts
- **Administrators**: Added/removed admin group members (HIGH PRIORITY)
- **Software**: Added/removed applications
- **Autoruns**: Added/removed startup items
- **Network Shares**: Added/removed shares

### Comparison Output
- **HTML Report Section**: Inline display with expandable tables
  - Shows added items in green
  - Shows removed items in red
  - Displays full details (not just counts)
- **CSV Files**: Detailed comparison exports
  - `csv/comparison_processes.csv`
  - `csv/comparison_services.csv`
  - `csv/comparison_tasks.csv`
  - etc.
- **Console Output**: Summary with top changed items

### Baseline Commands
```powershell
# First run - creates baseline automatically
.\Get-WindowsInventory.ps1

# Subsequent runs - auto-compares with baseline
.\Get-WindowsInventory.ps1

# After hardening - update the baseline
.\Get-WindowsInventory.ps1 -UpdateBaseline

# Use custom baseline location
.\Get-WindowsInventory.ps1 -BaselinePath "C:\CCDC\baseline"

# Skip baseline comparison
.\Get-WindowsInventory.ps1 -SkipComparison
```

---

## 📝 Output Formats

### JSON Output
- **inventory.json**: Complete machine-readable inventory
- Nested structure with all collected data
- Includes metadata (timestamps, errors, execution time)

### CSV Output
Individual CSV files for each data category (30+ files):
- `processes.csv`
- `services.csv`
- `scheduled_tasks.csv`
- `users.csv`
- `group_members.csv`
- `software.csv`
- `patches.csv`
- `autoruns.csv`
- `network_connections_enhanced.csv`
- `established_connections.csv`
- `listening_ports.csv`
- `network_interfaces.csv`
- `shares.csv`
- `certificates.csv`
- `firewall_rules.csv`
- `threat_suspicious_*.csv` (threat detection)
- `security_weaknesses.csv`
- `recent_system_modifications_24h.csv`
- `comparison_*.csv` (baseline comparison)

### HTML Report
- **system_report.html**: Interactive web report
- Sections:
  - **Threat Analysis** (if threats detected) - Red/yellow alerts
  - **Baseline Comparison** (if baseline exists) - Expandable change tables
  - **Summary Metrics** - Key counts and statistics
  - **System Details** - OS, hardware, configuration
  - **Artifacts & Reports** - Links to all output files

### Log Files
- **collection.log**: Execution log with timestamps, errors, warnings

---

## ⚙️ Collection Methods

### PowerShell Cmdlets Used
- `Get-ComputerInfo` - System information
- `Get-CimInstance` / `Get-WmiObject` - WMI queries (legacy fallback)
- `Get-Process` - Running processes
- `Get-Service` - Windows services
- `Get-ScheduledTask` - Scheduled tasks
- `Get-LocalUser` / `Get-LocalGroup` - User/group management
- `Get-NetTCPConnection` / `Get-NetUDPEndpoint` - Network connections
- `Get-NetAdapter` / `Get-NetIPConfiguration` - Network configuration
- `Get-SmbShare` - Network shares
- `Get-ChildItem` (Registry) - Installed software, autoruns
- `Get-HotFix` - Windows updates
- `Get-ChildItem Cert:\` - Certificates
- `Get-NetFirewallRule` - Firewall rules
- `Get-MpComputerStatus` - Windows Defender status

### Legacy Commands (Fallback)
- `net user` - User enumeration
- `net localgroup` - Group enumeration
- `reg query` - Registry queries
- `netstat` - Network connections
- `route print` - Routing table
- `arp -a` - ARP cache
- `ipconfig /all` - IP configuration
- `systeminfo` - System information
- `driverquery` - Driver list
- `gpresult` - Group Policy

### File System Operations
- Read-only file operations
- No modifications to system
- No deletion or changes
- Safe for production systems

---

## 🎯 Performance Characteristics

### Execution Time
- **Full Scan**: 2-5 minutes (depending on system size)
- **Quick Mode** (`-Quick`): 30-60 seconds
- **Minimal Mode** (Quick + disabled features): 15-30 seconds

### Resource Usage
- **Memory**: < 100 MB typical
- **CPU**: Low to moderate during execution
- **Disk I/O**: Minimal (mostly writes to output folder)
- **Network**: None (all local operations)

### Output Size
- **Typical System**: 5-15 MB uncompressed
- **Large Environment**: 50-100 MB (many software/services)
- **Compressed** (`-Compress`): 10-20% of original size

---

## 🔒 Security & Privacy

### Data Sensitivity
**Collected data may include**:
- Usernames (but not passwords)
- Network configuration (IP addresses, DNS)
- Installed software
- Running processes
- System configuration

**Data does NOT include**:
- Passwords or credentials
- File contents
- Personal documents
- Browser history
- Email or communications

### Safe Operations
- Read-only operations
- No system modifications
- No service restarts
- No configuration changes
- No file deletions

### Recommended Handling
- Treat inventory reports as sensitive
- Store in secure locations
- Restrict access to authorized team members
- Encrypt if transferring over network
- Delete old reports securely when no longer needed

---

## 📚 Additional Notes

### Customization Points
The script can be customized for your environment:
- Legitimate administrator list (line ~352)
- Suspicious path detection patterns (lines ~276-400)
- C2 port list (line ~399)
- Detection thresholds

### Error Handling
- Graceful degradation if cmdlets unavailable
- Fallback to legacy commands on older systems
- Comprehensive error logging
- Continues on individual collection failures

### Compatibility
- **Minimum**: Windows 7 / Server 2008 R2 with PowerShell 2.0
- **Recommended**: Windows 10 / Server 2016+ with PowerShell 5.1+
- **Best**: Windows 11 / Server 2022 with PowerShell 7+

---

## Version Information

**Current Version**: v2.2 (CCDC Enhanced Edition with Integrated Baseline Comparison)

**Last Updated**: 2026-01-16

**Features in Current Version**:
- Comprehensive inventory collection (30+ data categories)
- Automated threat detection (7 categories)
- Security weakness identification
- Integrated baseline comparison with auto-detection
- Expandable inline change display in HTML
- CSV exports for all data
- Interactive HTML reports
- Quick mode for fast scanning
- CCDC-optimized workflows
