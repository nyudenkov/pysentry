# PySentry Windows Installation Guide

Complete guide for installing and using PySentry on Windows systems, including enterprise environments.

## Quick Installation

### Prerequisites

- Windows 10/11 (x64)
- Python 3.8+ (from [python.org](https://python.org) or Microsoft Store)
- Internet connection for downloading dependencies

### Standard Installation

```powershell
# Install via pip (recommended)
pip install pysentry-rs

# Verify installation
pysentry-rs --version
python -c "import pysentry; print('Installation successful')"
```

### Alternative Installation Methods

#### Using pipx (Isolated Installation)
```powershell
# Install pipx if not already installed
pip install pipx

# Install pysentry in isolated environment
pipx install pysentry-rs

# Use directly
pysentry-rs --help
```

#### Using Chocolatey (Package Manager)
```powershell
# Install via Chocolatey (if available)
choco install pysentry

# Or install Python via Chocolatey first
choco install python
pip install pysentry-rs
```

#### Using Scoop (Package Manager)
```powershell
# Install via Scoop (if available)
scoop bucket add extras
scoop install pysentry
```

## Windows-Specific Features

### PowerShell Integration

PySentry includes native PowerShell cmdlets for Windows environments:

```powershell
# Import PySentry PowerShell module
Import-Module PySentry

# Scan current directory
Invoke-PysentryScanning -Path . -Recursive

# Scan with custom configuration
Invoke-PysentryScanning -Path "C:\MyProject" -ConfigFile "pysentry.toml"

# Advanced scanning with filtering
Invoke-PysentryScanning -Path . -Severity Critical,High -OutputFormat SARIF
```

### Windows Terminal Integration

Add PySentry to Windows Terminal for enhanced experience:

1. Open Windows Terminal settings (`Ctrl+,`)
2. Add new profile:

```json
{
    "guid": "{12345678-1234-5678-9012-123456789abc}",
    "name": "PySentry Scanner",
    "commandline": "powershell.exe -NoExit -Command \"Import-Module PySentry\"",
    "icon": "🛡️",
    "colorScheme": "Campbell Powershell",
    "startingDirectory": "%USERPROFILE%"
}
```

### Visual Studio Code Integration

Configure VS Code for optimal PySentry development:

#### .vscode/settings.json
```json
{
    "python.terminal.activateEnvironment": true,
    "python.defaultInterpreterPath": "./venv/Scripts/python.exe",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": false,
    "python.linting.flake8Enabled": true,
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": [
        "tests",
        "--verbose",
        "--tb=short"
    ],
    "files.associations": {
        "*.toml": "toml",
        "pysentry.toml": "toml"
    },
    "extensions.recommendations": [
        "ms-python.python",
        "ms-python.vscode-pylance",
        "tamasfe.even-better-toml"
    ]
}
```

#### .vscode/tasks.json
```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "PySentry: Security Scan",
            "type": "shell",
            "command": "pysentry-rs",
            "args": [
                ".",
                "--output-format",
                "json",
                "--output",
                "security-report.json"
            ],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "presentation": {
                "echo": true,
                "reveal": "always",
                "focus": false,
                "panel": "shared"
            },
            "problemMatcher": []
        },
        {
            "label": "PySentry: SARIF Report",
            "type": "shell",
            "command": "pysentry-rs",
            "args": [
                ".",
                "--output-format",
                "sarif",
                "--output",
                "pysentry-report.sarif"
            ],
            "group": "build"
        }
    ]
}
```

## Enterprise Windows Deployment

### Group Policy Integration

For enterprise environments, configure PySentry via Group Policy:

#### Administrative Template (pysentry.admx)
```xml
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" xmlns="http://www.microsoft.com/GroupPolicy/PolicyDefinitions">
  <policyNamespaces>
    <target prefix="pysentry" namespace="PySentry.Policies.Security" />
  </policyNamespaces>
  
  <supersededAdm fileName="pysentry.adm" />
  
  <categories>
    <category name="PySentry" displayName="$(string.PySentry)">
      <parentCategory ref="System" />
    </category>
  </categories>
  
  <policies>
    <policy name="EnableAutomaticScanning" class="Machine" displayName="$(string.EnableAutomaticScanning)" explainText="$(string.EnableAutomaticScanning_Help)" key="SOFTWARE\Policies\PySentry" valueName="AutomaticScanning">
      <parentCategory ref="PySentry" />
      <supportedOn ref="windows:SUPPORTED_Windows10" />
      <enabledValue>
        <decimal value="1" />
      </enabledValue>
      <disabledValue>
        <decimal value="0" />
      </disabledValue>
    </policy>
    
    <policy name="ConfigurationPath" class="Machine" displayName="$(string.ConfigurationPath)" explainText="$(string.ConfigurationPath_Help)" key="SOFTWARE\Policies\PySentry">
      <parentCategory ref="PySentry" />
      <supportedOn ref="windows:SUPPORTED_Windows10" />
      <elements>
        <text id="ConfigPath" valueName="ConfigurationPath" />
      </elements>
    </policy>
  </policies>
</policyDefinitions>
```

### Windows Service Installation

Install PySentry as a Windows service for continuous monitoring:

```powershell
# Install as Windows service (requires admin privileges)
sc.exe create PySentryService binPath= "C:\Program Files\Python\Scripts\pysentry-rs.exe --service" start= auto

# Configure service
sc.exe description PySentryService "PySentry Security Vulnerability Scanner Service"

# Start service
sc.exe start PySentryService

# Check service status
sc.exe query PySentryService
```

### Registry Configuration

Configure PySentry via Windows Registry:

```powershell
# Set enterprise configuration path
New-Item -Path "HKLM:\SOFTWARE\PySentry" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\PySentry" -Name "ConfigPath" -Value "C:\ProgramData\PySentry\config.toml"

# Enable automatic scanning
Set-ItemProperty -Path "HKLM:\SOFTWARE\PySentry" -Name "AutomaticScanning" -Value 1

# Set log level
Set-ItemProperty -Path "HKLM:\SOFTWARE\PySentry" -Name "LogLevel" -Value "INFO"
```

## Performance Optimization

### Windows-Specific Optimizations

#### Memory Configuration
```powershell
# Configure virtual memory for large projects
# Recommended: Set page file to 1.5x RAM size
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=4096,MaximumSize=8192
```

#### Windows Defender Exclusions
```powershell
# Add PySentry to Windows Defender exclusions (as administrator)
Add-MpPreference -ExclusionProcess "pysentry-rs.exe"
Add-MpPreference -ExclusionProcess "python.exe"
Add-MpPreference -ExclusionPath "C:\Users\%USERNAME%\.pysentry"
```

#### Disk Optimization
```powershell
# Enable NTFS compression for PySentry cache
compact /c /s:"C:\Users\%USERNAME%\.pysentry" /i
```

### Parallel Processing
```toml
# pysentry.toml - Windows optimized configuration
[performance]
parallel_workers = 8  # Adjust based on CPU cores
memory_limit = "2GB"
cache_size = "500MB"
temp_directory = "C:\\Temp\\pysentry"

[windows]
use_native_paths = true
enable_long_paths = true
defender_exclusions = true
```

## Troubleshooting

### Common Windows Issues

#### Issue: "pysentry-rs not found"
```powershell
# Solution 1: Check PATH
echo $env:PATH
where.exe pysentry-rs

# Solution 2: Reinstall with user flag
pip install --user pysentry-rs

# Solution 3: Use full path
python -m pip install pysentry-rs
```

#### Issue: Long Path Limitations
```powershell
# Enable long paths in Windows (requires admin)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force

# Alternative: Use UNC paths
pysentry-rs "\\?\C:\very\long\path\to\project"
```

#### Issue: Permission Denied
```powershell
# Run as administrator
Start-Process powershell -Verb runAs

# Or change execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Issue: SSL Certificate Errors
```powershell
# Update certificates
pip install --upgrade certifi

# Use trusted hosts (temporary)
pip install --trusted-host pypi.org --trusted-host pypi.python.org pysentry-rs
```

### Debugging Windows Issues

#### Enable Debug Logging
```powershell
# Set environment variable for debug output
$env:RUST_LOG = "debug"
$env:PYSENTRY_LOG_LEVEL = "DEBUG"

# Run with verbose output
pysentry-rs --verbose --debug .
```

#### Windows Event Log Integration
```powershell
# Check Windows Event Logs for PySentry events
Get-WinEvent -LogName Application | Where-Object {$_.ProviderName -eq "PySentry"}

# Create custom event log source (as admin)
New-EventLog -LogName Application -Source "PySentry"
```

### Performance Diagnostics
```powershell
# Monitor PySentry performance
Get-Process pysentry-rs | Select-Object Name, CPU, WorkingSet, VirtualMemorySize

# Resource usage during scan
Get-Counter "\Process(pysentry-rs)\% Processor Time" -SampleInterval 1 -MaxSamples 60
```

## Integration Examples

### PowerShell Automation Script
```powershell
# automated-security-scan.ps1
param(
    [string]$ProjectPath = ".",
    [string]$OutputPath = "security-reports",
    [switch]$SendEmail
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force

# Run PySentry scan
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportFile = Join-Path $OutputPath "security-report_$timestamp.sarif"

Write-Host "Starting security scan..." -ForegroundColor Green
pysentry-rs $ProjectPath --output-format sarif --output $reportFile

if ($LASTEXITCODE -eq 0) {
    Write-Host "Scan completed successfully" -ForegroundColor Green
} else {
    Write-Host "Vulnerabilities found - check report" -ForegroundColor Yellow
}

# Send email notification if requested
if ($SendEmail) {
    Send-MailMessage -To "security@company.com" -From "pysentry@company.com" -Subject "Security Scan Complete" -Body "Security scan completed. Report attached." -Attachments $reportFile -SmtpServer "smtp.company.com"
}
```

### Task Scheduler Integration
```powershell
# Create scheduled task for regular scans
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Scripts\automated-security-scan.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "PySentry Daily Scan" -Action $action -Trigger $trigger -Settings $settings -Description "Daily PySentry security vulnerability scan"
```

## Security Considerations

### Windows Security Features

#### Code Signing Verification
```powershell
# Verify PySentry binary signature
Get-AuthenticodeSignature "C:\Program Files\Python\Scripts\pysentry-rs.exe"

# Check certificate details
Get-ChildItem Cert:\CurrentUser\TrustedPublisher | Where-Object {$_.Subject -like "*PySentry*"}
```

#### Windows Firewall Configuration
```powershell
# Allow PySentry through Windows Firewall (if needed for remote scanning)
New-NetFirewallRule -DisplayName "PySentry" -Direction Inbound -Program "C:\Program Files\Python\Scripts\pysentry-rs.exe" -Action Allow
```

### Enterprise Security Policies

#### Audit Configuration
```powershell
# Enable audit logging for security scanning
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

#### Compliance Reporting
```powershell
# Generate compliance report
pysentry-rs . --output-format sarif --compliance-mode --output compliance-report.sarif

# Convert to Excel for management reporting
python -c "
import json
import pandas as pd

with open('compliance-report.sarif') as f:
    data = json.load(f)

# Extract vulnerability summary
vulns = []
for result in data['runs'][0]['results']:
    vulns.append({
        'Package': result['properties']['package_name'],
        'Vulnerability': result['ruleId'],
        'Severity': result['properties']['vulnerability_severity'],
        'Fixed_Version': result['properties'].get('fixed_versions', ['N/A'])[0]
    })

df = pd.DataFrame(vulns)
df.to_excel('security-compliance-report.xlsx', index=False)
print('Compliance report generated: security-compliance-report.xlsx')
"
```

## Advanced Configuration

### Windows-Specific Configuration File
```toml
# pysentry-windows.toml
[general]
log_level = "INFO"
output_directory = "C:\\ProgramData\\PySentry\\Reports"
temp_directory = "C:\\Temp\\PySentry"

[windows]
use_registry_config = true
enable_event_logging = true
defender_integration = true
long_path_support = true

[enterprise]
active_directory_integration = true
group_policy_compliance = true
audit_logging = true
centralized_reporting = true

[performance]
cache_directory = "C:\\ProgramData\\PySentry\\Cache"
max_memory_usage = "2GB"
parallel_workers = 8
database_compression = true

[notifications]
windows_notifications = true
event_log_integration = true
email_alerts = "security@company.com"
slack_webhook = "https://hooks.slack.com/..."
```

---

## Support and Documentation

- **GitHub Repository**: [https://github.com/nyudenkov/pysentry](https://github.com/nyudenkov/pysentry)
- **Issue Tracker**: [https://github.com/nyudenkov/pysentry/issues](https://github.com/nyudenkov/pysentry/issues)
- **Windows-Specific Issues**: Label issues with `windows` tag
- **Enterprise Support**: Contact maintainers for enterprise deployment assistance

For additional Windows-specific help, check the [Windows Troubleshooting Guide](WINDOWS_TROUBLESHOOTING.md) and [Enterprise Deployment Guide](ENTERPRISE_DEPLOYMENT.md).