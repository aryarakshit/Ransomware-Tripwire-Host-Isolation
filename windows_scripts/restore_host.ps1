<#
.SYNOPSIS
    Restoration & Rollback script for Host Network Isolation.
.DESCRIPTION
    Rolls back Windows Firewall settings configured by isolate_host.ps1 after lab testing.
    Removes tripwire rules and resets firewall policies to normal defaults (blockinbound, allowoutbound).
#>

[CmdletBinding()]
param ()

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       Ransomware Tripwire: Host Network Restoration      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

try {
    Write-Host "[*] Removing Tripwire Active Response firewall rules..." -ForegroundColor Yellow
    netsh advfirewall firewall delete rule name="Tripwire-Allow-Wazuh-Inbound" | Out-Null
    netsh advfirewall firewall delete rule name="Tripwire-Allow-Wazuh-Outbound" | Out-Null

    Write-Host "[*] Restoring default Windows Firewall policy (blockinbound, allowoutbound)..." -ForegroundColor Yellow
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null

    Write-Host "[OK] Host network isolation removed. Normal traffic restored." -ForegroundColor Green
} catch {
    Write-Error "Failed to restore firewall defaults (Administrator privileges required): $_"
}
