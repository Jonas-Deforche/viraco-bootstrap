<# 
  install_splashtop.ps1
  - Download + silent install Splashtop Streamer DEPLOY installer
  - Optional: rename PC
  - Optional: reboot

  Usage examples:
    powershell -ExecutionPolicy Bypass -File C:\Temp\install_splashtop.ps1
    powershell -ExecutionPolicy Bypass -File C:\Temp\install_splashtop.ps1 -ComputerName "VIRACO-WGM-SIM-01" -Reboot
#>

[CmdletBinding()]
param(
  [string]$Url = "https://cloudbuild.splashtop.eu/0216F08645A60158978410FEAC1A62BF/PP3HYT3WWT7PEU/b500649f0cfe0def44b1466b561a912d/3.8.0.4/Splashtop_Streamer_Windows_DEPLOY_INSTALLER_v3.8.0.4_PP3HYT3WWT7PEU.msi",
  [string]$ComputerName = "",
  [switch]$Reboot
)

$ErrorActionPreference = "Stop"

$WorkDir = "C:\Temp\SplashtopDeploy"
$MsiPath = Join-Path $WorkDir "Splashtop_Streamer_DEPLOY.msi"
$LogPath = Join-Path $WorkDir ("install_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

function Log($msg) {
  $line = ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg)
  $line | Tee-Object -FilePath $LogPath -Append
}

function Assert-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    throw "Run dit script als Administrator (rechtsklik PowerShell -> Run as administrator)."
  }
}

Assert-Admin
Log "Start Splashtop deploy install"
Log "WorkDir: $WorkDir"
Log "MSI: $MsiPath"
Log "URL: $Url"

# 1) Download MSI
Log "Downloading MSI..."
try {
  # Force TLS 1.2+ for older Windows builds
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch { }

Invoke-WebRequest -Uri $Url -OutFile $MsiPath -UseBasicParsing

# Basic sanity check (corrupt download is common)
$size = (Get-Item $MsiPath).Length
Log ("Downloaded file size: {0} bytes" -f $size)
if ($size -lt 500000) {  # < 500 KB is almost certainly wrong for an MSI
  throw "MSI lijkt te klein (<500KB). Download is waarschijnlijk mislukt of je kreeg HTML i.p.v. MSI."
}

# 2) Install silent
Log "Installing MSI (silent)..."
$msiLog = Join-Path $WorkDir "msiexec.log"
$arguments = "/i `"$MsiPath`" /qn /norestart /L*v `"$msiLog`""
Log "Running: msiexec.exe $arguments"

$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
Log ("msiexec exit code: {0}" -f $proc.ExitCode)

# Exit codes: 0 = OK, 3010 = OK but reboot required
if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
  throw "Install failed. Check $msiLog"
}

# 3) Optional rename
$didRename = $false
if ($ComputerName -and $ComputerName.Trim().Length -gt 0) {
  $current = $env:COMPUTERNAME
  if ($current -ne $ComputerName) {
    Log "Renaming computer from '$current' to '$ComputerName'..."
    Rename-Computer -NewName $ComputerName -Force
    $didRename = $true
  } else {
    Log "Computer name is already '$ComputerName' (no change)."
  }
}

# 4) Finish + optional reboot
Log "Done."
Log "Logfile: $LogPath"
Log "msiexec log: $msiLog"

if ($Reboot -or $proc.ExitCode -eq 3010 -or $didRename) {
  Log "Reboot requested/required. Rebooting in 10 seconds..."
  Start-Sleep -Seconds 10
  Restart-Computer -Force
} else {
  Log "No reboot requested."
}
