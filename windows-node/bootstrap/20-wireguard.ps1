# C:\Viraco\bootstrap\20-wireguard.ps1

param(
  [string]$ConfigPath = "C:\Viraco\config\node.json"
)

. "$PSScriptRoot\00-common.ps1"

Require-Admin
$log = New-Logger "20-wireguard"

$cfg = Read-NodeConfig $log $ConfigPath

$wgConf = $cfg.wgConfigPath
$tunnel = $cfg.wgTunnel

$installer = "https://download.wireguard.com/windows-client/wireguard-installer.exe"
$wgExe = "C:\Program Files\WireGuard\wireguard.exe"

function Install-WireGuard {

  if (Test-Path $wgExe) {
    Log-Info $log "WireGuard already installed"
    return
  }

  if (Has-Winget) {

    Log-Info $log "Installing via winget"

    winget install -e `
      --id WireGuard.WireGuard `
      --silent `
      --accept-package-agreements `
      --accept-source-agreements
  }

  if (-not (Test-Path $wgExe)) {

    $tmp = "$env:TEMP\wg.exe"

    Download-File $log $installer $tmp

    Start-Process $tmp "/install /quiet" -Wait
  }
}

function Install-Tunnel {

  if (-not (Test-Path $wgConf)) {
    throw "WG config missing: $wgConf"
  }

  $dir = "C:\Program Files\WireGuard\Data\Configurations"
  Ensure-Dir $dir

  $target = "$dir\$tunnel.conf"

  Copy-Item $wgConf $target -Force

  $svc = "WireGuardTunnel`$$tunnel"

  if (-not (Get-Service $svc -ErrorAction SilentlyContinue)) {

    Start-Process `
      $wgExe `
      "/installtunnelservice `"$target`"" `
      -Wait
  }

  Start-Service $svc -ErrorAction SilentlyContinue
}

try {

  Install-WireGuard
  Install-Tunnel

  Log-Info $log "WireGuard OK"
  exit 0

}
catch {

  Log-Err $log $_
  exit 1
}
