<#
.SYNOPSIS
    Deception-Based Canary Deployer for Windows Endpoints.
.DESCRIPTION
    Plants lexicographically prioritized canary files across specified target directories,
    records their SHA-256 baselines in canary_manifest.json, and configures Windows SACL
    File System Auditing so Wazuh FIM with whodata captures offending Process IDs.
#>

[CmdletBinding()]
param (
    [string]$ConfigPath = "$PSScriptRoot\..\config\tripwire_config.yaml",
    [string]$ManifestOutput = "$PSScriptRoot\..\canary_manifest.json"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Ransomware Tripwire: Canary Deployment & SACL Seeding  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Parse YAML config or use default fallback
$CanaryDefinitions = @(
    @{
        Filename = "!000_CONFIDENTIAL_Payroll_2026.xlsx"
        Type = "spreadsheet"
        MagicHeader = [byte[]](0x50, 0x4B, 0x03, 0x04) # PK..
        SizeKB = 45
    },
    @{
        Filename = "#000_AWS_Production_Root_Keys.txt"
        Type = "credential"
        ContentPrefix = "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`r`n"
        SizeKB = 15
    },
    @{
        Filename = "`$000_Executive_M&A_Targets.docx"
        Type = "document"
        MagicHeader = [byte[]](0x50, 0x4B, 0x03, 0x04) # PK..
        SizeKB = 65
    },
    @{
        Filename = "_000_Backup_Recovery_Seeds.pdf"
        Type = "pdf"
        MagicHeader = [System.Text.Encoding]::ASCII.GetBytes("%PDF-1.7`r`n")
        SizeKB = 85
    }
)

$TargetDirectories = @(
    "C:\Users\Public\Documents",
    "C:\Users\$($env:USERNAME)\Desktop",
    "C:\Users\$($env:USERNAME)\Documents",
    "C:\Shares\Finance_Records"
)

# 2. Plant Canaries and record Manifest
$Manifest = @{
    DeploymentTimestamp = (Get-Date -Format "o")
    Hostname = $env:COMPUTERNAME
    Canaries = @()
}

foreach ($dir in $TargetDirectories) {
    if (-not (Test-Path $dir)) {
        try {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "[+] Created target directory: $dir" -ForegroundColor Green
        } catch {
            Write-Warning "Could not create directory $dir (Check permissions): $_"
            continue
        }
    }

    foreach ($canary in $CanaryDefinitions) {
        $filePath = Join-Path $dir $canary.Filename
        
        # Build decoy content
        $stream = [System.IO.MemoryStream]::new()
        if ($canary.MagicHeader) {
            $stream.Write($canary.MagicHeader, 0, $canary.MagicHeader.Length)
        }
        if ($canary.ContentPrefix) {
            $prefixBytes = [System.Text.Encoding]::UTF8.GetBytes($canary.ContentPrefix)
            $stream.Write($prefixBytes, 0, $prefixBytes.Length)
        }

        # Pad with realistic dummy binary payload
        $dummyPayloadSize = [Math]::Max(512, ($canary.SizeKB * 1024) - $stream.Length)
        $randBytes = [byte[]]::new($dummyPayloadSize)
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($randBytes)
        $stream.Write($randBytes, 0, $randBytes.Length)
        
        [System.IO.File]::WriteAllBytes($filePath, $stream.ToArray())
        $stream.Dispose()

        # Compute SHA-256
        $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash

        # Configure Windows Audit SACL (Success & Failure for Everyone on Write/Delete)
        try {
            $acl = Get-Acl -Path $filePath -Audit
            $auditUser = [System.Security.Principal.NTAccount]::new("Everyone")
            $auditRules = [System.Security.AccessControl.FileSystemRights]"Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions"
            $auditFlags = [System.Security.AccessControl.AuditFlags]"Success, Failure"
            $auditRule = [System.Security.AccessControl.FileSystemAuditRule]::new(
                $auditUser,
                $auditRules,
                $auditFlags
            )
            $acl.AddAuditRule($auditRule)
            Set-Acl -Path $filePath -AclObject $acl -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "Audit SACL requires administrative privileges: $_"
        }

        $Manifest.Canaries += @{
            Path = $filePath
            Filename = $canary.Filename
            Type = $canary.Type
            SHA256 = $hash
            Size = (Get-Item $filePath).Length
            PlantedAt = (Get-Date -Format "o")
        }

        Write-Host "  [+] Seeded: $filePath (SHA-256: $hash)" -ForegroundColor Yellow
    }
}

# 3. Export Manifest
$Manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $ManifestOutput -Encoding UTF8
Write-Host "`n[OK] Canary deployment manifest written to: $ManifestOutput" -ForegroundColor Cyan
