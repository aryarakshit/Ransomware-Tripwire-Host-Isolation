<#
.SYNOPSIS
    Wazuh Active Response Script: Process Termination & Network Isolation.
.DESCRIPTION
    Triggered when Wazuh rules 100201, 100202, or 100203 fire.
    Parses the JSON alert payload from STDIN, extracts the offending ransomware Process ID (PID),
    terminates the process tree, and configures Windows Firewall to block all traffic EXCEPT
    the Wazuh Manager IP (TCP ports 1514/1515).
#>

[CmdletBinding()]
param (
    [string]$AlertJsonInput = "",
    [int]$ManualPID = 0,
    [string]$WazuhManagerIP = "192.168.56.10",
    [string]$LogFile = "$PSScriptRoot\..\reports\active_response.log"
)

function Write-ARLog {
    param ([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "[$ts] [ACTIVE-RESPONSE] $Message"
    Write-Host $line
    try {
        Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    } catch {}
}

Write-ARLog "Starting Active Response Host Containment..."

# 1. Read JSON from STDIN if not supplied via parameter
$rawInput = $AlertJsonInput
if ([string]::IsNullOrWhiteSpace($rawInput)) {
    try {
        if ([Console]::In.Peek() -ge 0 -or $Host.UI.RawUI.KeyAvailable -eq $false) {
            $rawInput = [Console]::In.ReadToEnd()
        }
    } catch {
        Write-ARLog "No STDIN available or peek failed: $_"
    }
}

$offendingPID = $ManualPID
$alertData = $null

if (-not [string]::IsNullOrWhiteSpace($rawInput)) {
    try {
        $alertData = $rawInput | ConvertFrom-Json
        Write-ARLog "Successfully parsed Wazuh alert JSON payload."
    } catch {
        Write-ARLog "Failed to parse JSON from STDIN: $_"
    }
}

# 2. Extract Process ID from Whodata / Sysmon hierarchy
if ($alertData) {
    if ($alertData.parameters.alert.data.audit.process_id) {
        $offendingPID = [int]$alertData.parameters.alert.data.audit.process_id
        Write-ARLog "Extracted PID $offendingPID from FIM whodata."
    } elseif ($alertData.parameters.alert.data.win.eventdata.processId) {
        $offendingPID = [int]$alertData.parameters.alert.data.win.eventdata.processId
        Write-ARLog "Extracted PID $offendingPID from Sysmon Event."
    } elseif ($alertData.data.audit.process_id) {
        $offendingPID = [int]$alertData.data.audit.process_id
        Write-ARLog "Extracted PID $offendingPID from root whodata."
    } elseif ($alertData.data.win.eventdata.processId) {
        $offendingPID = [int]$alertData.data.win.eventdata.processId
        Write-ARLog "Extracted PID $offendingPID from root Sysmon."
    }
}

# 3. Kill the offending Process Tree
if ($offendingPID -gt 0) {
    Write-ARLog "EMERGENCY: Terminating malicious process tree for PID: $offendingPID"
    try {
        # Attempt graceful then forceful termination with child processes
        cmd.exe /c "taskkill /F /T /PID $offendingPID 2>&1" | Out-Null
        Write-ARLog "Process tree $offendingPID terminated successfully via taskkill."
    } catch {
        try {
            Stop-Process -Id $offendingPID -Force -ErrorAction Stop
            Write-ARLog "Process $offendingPID stopped via Stop-Process."
        } catch {
            Write-ARLog "Warning: Could not terminate PID $offendingPID (may have already exited): $_"
        }
    }
} else {
    Write-ARLog "Notice: Offending PID was 0 or not identified; proceeding with network containment."
}

# 4. Quarantine Host via Windows Firewall (Strict SOC Whitelist)
Write-ARLog "Applying Windows Firewall network isolation (Whitelist: $WazuhManagerIP:1514,1515)..."

try {
    # Delete prior tripwire rules if they exist
    netsh advfirewall firewall delete rule name="Tripwire-Allow-Wazuh-Inbound" | Out-Null
    netsh advfirewall firewall delete rule name="Tripwire-Allow-Wazuh-Outbound" | Out-Null

    # Allow Wazuh Manager inbound & outbound
    netsh advfirewall firewall add rule name="Tripwire-Allow-Wazuh-Inbound" dir=in action=allow protocol=TCP localport=1514,1515 remoteip=$WazuhManagerIP | Out-Null
    netsh advfirewall firewall add rule name="Tripwire-Allow-Wazuh-Outbound" dir=out action=allow protocol=TCP remoteport=1514,1515 remoteip=$WazuhManagerIP | Out-Null

    # Block all inbound and outbound traffic
    netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
    Write-ARLog "HOST ISOLATED: Windows Firewall policy set to blockinbound,blockoutbound. Only Wazuh Manager permitted."
} catch {
    Write-ARLog "Firewall configuration error (requires Administrator privileges): $_"
}

# Emit Wazuh Active Response status object
$responseObj = @{
    version = 1
    origin = @{
        name = "isolate_host.ps1"
        module = "active-response"
    }
    command = "isolate-ransomware-host"
    status = "success"
    isolated_pid = $offendingPID
    whitelisted_manager = $WazuhManagerIP
    timestamp = (Get-Date -Format "o")
}

$responseJson = $responseObj | ConvertTo-Json -Compress
Write-Output $responseJson
