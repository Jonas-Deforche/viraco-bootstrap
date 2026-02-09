# C:\Viraco\bootstrap\90-tag.ps1

param(
  [string]$ConfigPath = "C:\Viraco\config\node.json"
)

. "$PSScriptRoot\00-common.ps1"

Require-Admin
$log = New-Logger "90-tag"

$cfg = Read-NodeConfig $log $ConfigPath

try {

  $p = Get-ViracoPaths

  $data = @{
    hostname = $cfg.hostname
    tunnel   = $cfg.wgTunnel
    created  = (Get-Date).ToString("o")
    user     = $env:USERNAME
  } | ConvertTo-Json

  Set-Content $p.NodeJson $data -Encoding UTF8

  Log-Info $log "Node tagged"
  exit 0
}
catch {

  Log-Err $log $_
  exit 1
}
