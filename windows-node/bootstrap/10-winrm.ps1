# C:\Viraco\bootstrap\10-winrm.ps1

param(
  [string]$ConfigPath = "C:\Viraco\config\node.json"
)

. "$PSScriptRoot\00-common.ps1"

Require-Admin
$log = New-Logger "10-winrm"

try {

  Log-Info $log "Enable WinRM"

  Enable-PSRemoting -Force

  Set-Item WSMan:\localhost\Service\Auth\Basic $true
  Set-Item WSMan:\localhost\Service\AllowUnencrypted $true

  Enable-NetFirewallRule `
    -DisplayGroup "Windows Remote Management" `
    -ErrorAction SilentlyContinue

  Log-Info $log "WinRM ready"
  exit 0

}
catch {
  Log-Err $log $_
  exit 1
}
