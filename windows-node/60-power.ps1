# C:\Viraco\bootstrap\60-power.ps1

. "$PSScriptRoot\00-common.ps1"

Require-Admin
$log = New-Logger "60-power"

try {

  powercfg /change standby-timeout-ac 0
  powercfg /change monitor-timeout-ac 0
  powercfg /hibernate off

  Log-Info $log "Power settings OK"
  exit 0
}
catch {

  Log-Err $log $_
  exit 1
}
