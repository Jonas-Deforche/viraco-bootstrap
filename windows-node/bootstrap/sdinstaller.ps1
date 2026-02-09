<# 
  install_sd_launcher.ps1
  - Downloadt SD Launcher Installer.zip
  - Pakt uit
  - Installeert (MSI of EXE) silent waar mogelijk

  Run:
    powershell -ExecutionPolicy Bypass -File C:\Temp\install_sd_launcher.ps1
#>

[CmdletBinding()]
param(
  [string]$SDLauncherUrl = "https://sd-software.net/Installer.zip"
)

$ErrorActionPreference = "Stop"

function Require-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw "Run dit script als Administrator." }
}

function Log($msg) {
  Write-Host ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg)
}

Require-Admin

$WorkDir = "C:\Temp\SDLauncher"
$ZipPath = Join-Path $WorkDir "Installer.zip"
$ExtractPath = Join-Path $WorkDir "Extracted"
$MsiLog = Join-Path $WorkDir "msiexec_sd.log"

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
New-Item -ItemType Directory -Force -Path $ExtractPath | Out-Null

Log "Downloading SD Launcher ZIP..."
try {
  # Some Windows builds need TLS 1.2
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch { }

Invoke-WebRequest -Uri $SDLauncherUrl -OutFile $ZipPath -UseBasicParsing

$size = (Get-Item $ZipPath).Length
Log ("Downloaded ZIP size: {0} bytes" -f $size)
if ($size -lt 50000) { throw "ZIP lijkt te klein (<50KB). Download mislukt of je kreeg HTML i.p.v. ZIP." }

Log "Extracting..."
Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

# Zoek installer (ook in subfolders)
$installer = Get-ChildItem -Path $ExtractPath -Recurse -File |
  Where-Object { $_.Extension -in ".msi", ".exe" } |
  Sort-Object FullName |
  Select-Object -First 1

if (-not $installer) {
  throw "Geen .msi of .exe installer gevonden in de ZIP. Check inhoud in: $ExtractPath"
}

Log "Found installer: $($installer.FullName)"

if ($installer.Extension -eq ".msi") {
  Log "Installing MSI silent..."
  $args = "/i `"$($installer.FullName)`" /qn /norestart /L*v `"$MsiLog`""
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
  Log "msiexec exit code: $($p.ExitCode) (log: $MsiLog)"
  if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "MSI install failed. Zie log: $MsiLog" }
}
else {
  Log "Installing EXE..."
  # Probeer eerst silent switches (verschilt per installer)
  $silentArgs = @(
    "/S",                 # common (NSIS)
    "/silent",
    "/verysilent",
    "/quiet",
    "/qn"
  )

  $installed = $false
  foreach ($a in $silentArgs) {
    try {
      Log "Trying: $($installer.Name) $a"
      $p = Start-Process -FilePath $installer.FullName -ArgumentList $a -Wait -PassThru
      Log "Exit code: $($p.ExitCode)"
      if ($p.ExitCode -eq 0) { $installed = $true; break }
    } catch { }
  }

  if (-not $installed) {
    Log "Silent install lukte niet zeker. Start installer interactief..."
    Start-Process -FilePath $installer.FullName
    Log "Installer geopend. Volg de stappen op het scherm."
  }
}

Log "Done."
