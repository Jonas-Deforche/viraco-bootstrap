# C:\Viraco\bootstrap\30-splashtop.ps1

param(
  [string]$ConfigPath = "C:\Viraco\config\node.json"
)

. "$PSScriptRoot\00-common.ps1"

Require-Admin
$log = New-Logger "30-splashtop"

$cfg = Read-NodeConfig $log $ConfigPath
$url = $cfg.splashtopUrl

function Installed {
  Get-Service | Where-Object {
    $_.Name -match "Splashtop"
  }
}

try {

  if (Installed) {
    Log-Info $log "Splashtop already installed"
    exit 0
  }

  $tmp = "$env:TEMP\splashtop.exe"

  Download-File $log $url $tmp

  Start-Process `
    $tmp `
    "prevercheck /s /i confirm_d=0,hidewindow=1" `
    -Wait

  Log-Info $log "Splashtop OK"
  exit 0

}
catch {

  Log-Err $log $_
  exit 1
}
